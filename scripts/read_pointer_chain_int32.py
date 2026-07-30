#!/usr/bin/env python3
"""Reads an int32 through base + 0x26ABFF8 -> uint64 pointer + 0x320."""

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
POINTER_SLOT_OFFSET = 0x26ABFF8
VALUE_OFFSET = 0x190
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF
TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260
SIZE_T = struct.Struct("<Q")
READ_MEMORY_OPERATION = struct.Struct("<I4xQQQ")


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
    sock.sendall(SIZE_T.pack(len(packet)) + packet + payload)

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


def write_memory(sock: socket.socket, pid: int, address: int, data: bytes) -> None:
    response = send_request(sock, OP_WRITE_FORCE, pid, address, len(data), data)
    if response != b"\x01":
        raise RuntimeError(f"driver rejected the {len(data)}-byte write at 0x{address:X}")


def read_uint64(sock: socket.socket, pid: int, address: int) -> int:
    return struct.unpack("<Q", read_memory(sock, pid, address, 8))[0]


def read_int32(sock: socket.socket, pid: int, address: int) -> int:
    return struct.unpack("<i", read_memory(sock, pid, address, 4))[0]


def read_float(sock: socket.socket, pid: int, address: int) -> float:
    return struct.unpack("<f", read_memory(sock, pid, address, 4))[0]


def write_int(sock: socket.socket, pid: int, address: int, value: int) -> None:
    write_memory(sock, pid, address, struct.pack("<i", value))


def write_float(sock: socket.socket, pid: int, address: int, value: float) -> None:
    write_memory(sock, pid, address, struct.pack("<f", value))


def add_user_offset(address: int, offset: int) -> int:
    result = address + offset
    if address <= 0 or result > MAX_USER_ADDRESS:
        raise ValueError(f"invalid user address 0x{result:X}")
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read int32 at *(uint64*)(process_base + 0x26ABFF8) + 0x320."
    )
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
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            base_address = get_process_base(sock, pid)
            pointer_slot = add_user_offset(base_address, POINTER_SLOT_OFFSET)
            pointer_value = read_uint64(sock, pid, pointer_slot)
            value_address = add_user_offset(pointer_value, VALUE_OFFSET)
            value = read_int32(sock, pid, value_address)
            from time import sleep
            while True:
                write_float(sock, pid, add_user_offset(pointer_value, 0x25f8), 0)
#0x45c4
    except (ConnectionError, OSError, RuntimeError, ValueError) as error:
        print(f"Operation failed: {error}", file=sys.stderr)
        return 1

    print(f"Process: {process_name} (PID {pid})")
    print(f"Base address: 0x{base_address:X}")
    print(f"Pointer slot: 0x{pointer_slot:X}")
    print(f"Pointer value: 0x{pointer_value:X}")
    print(f"Value address: 0x{value_address:X}")
    print(f"int32 value: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
