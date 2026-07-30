#!/usr/bin/env python3
"""Validates and marks a process's in-memory PE headers through the plato driver."""

import argparse
import ctypes
from ctypes import wintypes
import socket
import struct
import sys


HOST = "127.0.0.1"
PORT = 7653
OP_READ = 0
OP_WRITE_FORCE = 1
OP_PROCESS_BASE = 2
CHECKED_MARKER_OFFSET = 0x1C
CHECKED_MARKER_MASK = 0x8000
TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260
SIZE_T = struct.Struct("<Q")
READ_MEMORY_OPERATION = struct.Struct("<I4xQQQ")
MACHINE_NAMES = {
    0x014C: "I386",
    0x8664: "AMD64",
    0xAA64: "ARM64",
}


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
kernel32.Process32NextW.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
kernel32.CloseHandle.restype = wintypes.BOOL


def find_processes(process_name: str) -> list[int]:
    expected_name = process_name if process_name.casefold().endswith(".exe") else f"{process_name}.exe"
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())

    process_ids: list[int] = []
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)

    try:
        has_entry = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while has_entry:
            if entry.szExeFile.casefold() == expected_name.casefold():
                process_ids.append(entry.th32ProcessID)
            has_entry = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    return process_ids


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("driver connection closed unexpectedly")
        data.extend(chunk)
    return bytes(data)


def send_request(
    sock: socket.socket, operation: int, pid: int, address: int, size: int, payload: bytes = b""
) -> bytes:
    packet = READ_MEMORY_OPERATION.pack(operation, address, pid, size)
    sock.sendall(SIZE_T.pack(len(packet)))
    sock.sendall(packet)
    if payload:
        sock.sendall(payload)

    response_size = SIZE_T.unpack(recv_exact(sock, SIZE_T.size))[0]
    return recv_exact(sock, response_size)


def get_process_base(sock: socket.socket, pid: int) -> int:
    response = send_request(sock, OP_PROCESS_BASE, pid, 0, 0)
    if len(response) != SIZE_T.size:
        raise RuntimeError("driver rejected the process-base request")

    base_address = SIZE_T.unpack(response)[0]
    if not base_address:
        raise RuntimeError("driver returned a null process base")

    return base_address


def read_memory(sock: socket.socket, pid: int, address: int, size: int) -> bytes:
    response = send_request(sock, OP_READ, pid, address, size)
    if len(response) != size:
        raise RuntimeError(f"driver rejected the {size}-byte read at 0x{address:X}")
    return response


def force_write_memory(sock: socket.socket, pid: int, address: int, data: bytes) -> None:
    response = send_request(sock, OP_WRITE_FORCE, pid, address, len(data), data)
    if response != b"\x01":
        raise RuntimeError(f"driver rejected the {len(data)}-byte write at 0x{address:X}")


def inspect_pe_headers(sock: socket.socket, pid: int, base_address: int) -> dict[str, int | str]:
    dos_header = read_memory(sock, pid, base_address, 0x40)
    if dos_header[:2] != b"MZ":
        raise ValueError(f"invalid DOS signature {dos_header[:2]!r}")

    marker_word = struct.unpack_from("<H", dos_header, CHECKED_MARKER_OFFSET)[0]
    pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset > 0x100000:
        raise ValueError(f"implausible e_lfanew 0x{pe_offset:X}")

    nt_headers_address = base_address + pe_offset
    nt_prefix = read_memory(sock, pid, nt_headers_address, 24)
    if nt_prefix[:4] != b"PE\0\0":
        raise ValueError(f"invalid NT signature {nt_prefix[:4]!r}")

    machine, section_count, timestamp, _, _, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", nt_prefix, 4
    )
    if not 1 <= section_count <= 96:
        raise ValueError(f"invalid section count {section_count}")
    if not 2 <= optional_size <= 0x1000:
        raise ValueError(f"invalid optional-header size 0x{optional_size:X}")

    optional_header = read_memory(sock, pid, nt_headers_address + 24, optional_size)
    optional_magic = struct.unpack_from("<H", optional_header, 0)[0]
    minimum_size = {0x10B: 96, 0x20B: 112}.get(optional_magic)
    if minimum_size is None:
        raise ValueError(f"unknown optional-header magic 0x{optional_magic:X}")
    if optional_size < minimum_size:
        raise ValueError(
            f"optional header is too small for {'PE32+' if optional_magic == 0x20B else 'PE32'}"
        )

    entry_point_rva = struct.unpack_from("<I", optional_header, 16)[0]
    section_alignment = struct.unpack_from("<I", optional_header, 32)[0]
    file_alignment = struct.unpack_from("<I", optional_header, 36)[0]
    size_of_image = struct.unpack_from("<I", optional_header, 56)[0]
    size_of_headers = struct.unpack_from("<I", optional_header, 60)[0]

    if not section_alignment or not file_alignment:
        raise ValueError("section or file alignment is zero")
    if not size_of_image or not size_of_headers or size_of_headers > size_of_image:
        raise ValueError("invalid image/header sizes")
    if entry_point_rva >= size_of_image:
        raise ValueError("entry point lies outside the image")

    return {
        "pe_offset": pe_offset,
        "machine": machine,
        "machine_name": MACHINE_NAMES.get(machine, "unknown"),
        "sections": section_count,
        "timestamp": timestamp,
        "characteristics": characteristics,
        "format": "PE32+" if optional_magic == 0x20B else "PE32",
        "entry_point": base_address + entry_point_rva,
        "size_of_image": size_of_image,
        "size_of_headers": size_of_headers,
        "marker_word": marker_word,
    }


def mark_pe_checked(sock: socket.socket, pid: int, base_address: int, marker_word: int) -> bool:
    if marker_word & CHECKED_MARKER_MASK:
        return False

    marker_address = base_address + CHECKED_MARKER_OFFSET
    updated_word = marker_word | CHECKED_MARKER_MASK
    force_write_memory(sock, pid, marker_address, struct.pack("<H", updated_word))

    verified_word = struct.unpack("<H", read_memory(sock, pid, marker_address, 2))[0]
    if verified_word != updated_word:
        raise RuntimeError(f"marker verification returned 0x{verified_word:04X}, expected 0x{updated_word:04X}")

    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate and mark a process's in-memory PE headers.")
    parser.add_argument("process_name", nargs="?", help="executable name, for example Notepad.exe")
    parser.add_argument("--pid", type=int, help="select a PID when several matching processes are running")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    process_name = args.process_name or input("Process name: ").strip()
    if not process_name:
        print("Process name cannot be empty.", file=sys.stderr)
        return 2

    try:
        process_ids = find_processes(process_name)
    except OSError as error:
        print(f"Process lookup failed: {error}", file=sys.stderr)
        return 1

    if not process_ids:
        print(f"No process named {process_name!r} is running.", file=sys.stderr)
        return 1

    if args.pid is not None:
        if args.pid not in process_ids:
            print(f"PID {args.pid} does not match {process_name!r}; matching PIDs: {process_ids}", file=sys.stderr)
            return 1
        pid = args.pid
    elif len(process_ids) == 1:
        pid = process_ids[0]
    else:
        print(f"Multiple matching processes found: {process_ids}. Select one with --pid.", file=sys.stderr)
        return 1

    try:
        with socket.create_connection((HOST, PORT), timeout=120.0) as sock:
            sock.settimeout(120.0)
            base_address = get_process_base(sock, pid)
            print(f"Process: {process_name} (PID {pid})")
            print(f"Base address: 0x{base_address:X}")
            headers = inspect_pe_headers(sock, pid, base_address)
            marker_added = mark_pe_checked(sock, pid, base_address, int(headers["marker_word"]))
    except (ConnectionError, OSError, RuntimeError, ValueError) as error:
        print(f"Operation failed: {error}", file=sys.stderr)
        return 1

    print("DOS signature: MZ")
    print(f"NT signature: PE\\0\\0 at +0x{headers['pe_offset']:X}")
    print(f"Format: {headers['format']}")
    print(f"Machine: 0x{headers['machine']:04X} ({headers['machine_name']})")
    print(f"Sections: {headers['sections']}")
    print(f"Entry point: 0x{headers['entry_point']:X}")
    print(f"Image size: 0x{headers['size_of_image']:X}")
    print(f"Header size: 0x{headers['size_of_headers']:X}")
    print("PE headers: VALID")
    if marker_added:
        print(f"Checked marker: SET (e_res[0] |= 0x{CHECKED_MARKER_MASK:04X})")
    else:
        print("Checked marker: ALREADY SET")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
