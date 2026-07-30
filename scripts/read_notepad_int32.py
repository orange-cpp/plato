#!/usr/bin/env python3
"""Changes a four-byte Notepad.exe value from 13 to 16 through the plato driver."""

import argparse
import ctypes
from ctypes import wintypes
import socket
import struct
import sys


ADDRESS = 0x26ED3CE6C88
HOST = "127.0.0.1"
PORT = 7653
OP_READ = 0
OP_WRITE_FORCE = 1
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


def find_notepad_processes() -> list[int]:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())

    process_ids: list[int] = []
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)

    try:
        has_entry = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while has_entry:
            if entry.szExeFile.casefold() == "notepad.exe":
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


def send_request(sock: socket.socket, operation: int, pid: int, data: bytes = b"") -> bytes:
    packet = READ_MEMORY_OPERATION.pack(operation, ADDRESS, pid, 4)
    sock.sendall(SIZE_T.pack(len(packet)))
    sock.sendall(packet)

    if data:
        sock.sendall(data)

    response_size = SIZE_T.unpack(recv_exact(sock, SIZE_T.size))[0]
    return recv_exact(sock, response_size)


def read_and_update_int32(pid: int) -> tuple[int, int]:
    with socket.create_connection((HOST, PORT), timeout=120.0) as sock:
        sock.settimeout(120.0)

        initial_data = send_request(sock, OP_READ, pid)
        if len(initial_data) != 4:
            raise RuntimeError("driver rejected the four-byte read")

        initial_value = int.from_bytes(initial_data, "little", signed=True)
        if initial_value != 13:
            return initial_value, initial_value

        write_response = send_request(sock, OP_WRITE_FORCE, pid, (16).to_bytes(4, "little", signed=True))
        if write_response != b"\x01":
            raise RuntimeError("driver rejected the four-byte write")

        final_data = send_request(sock, OP_READ, pid)
        if len(final_data) != 4:
            raise RuntimeError("driver rejected the verification read")

        final_value = int.from_bytes(final_data, "little", signed=True)
        if final_value != 16:
            raise RuntimeError(f"write verification returned {final_value}, expected 16")

        return initial_value, final_value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=f"Change 13 to 16 in Notepad.exe at 0x{ADDRESS:X}.")
    parser.add_argument("--pid", type=int, help="Notepad.exe PID; detected automatically when only one is running")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    pid = args.pid

    if pid is None:
        process_ids = find_notepad_processes()
        if not process_ids:
            print("Notepad.exe is not running.", file=sys.stderr)
            return 1
        if len(process_ids) > 1:
            print(f"Multiple Notepad.exe processes found: {process_ids}. Pass one with --pid.", file=sys.stderr)
            return 1
        pid = process_ids[0]
    elif pid <= 0:
        print("PID must be positive.", file=sys.stderr)
        return 2

    try:
        initial_value, final_value = read_and_update_int32(pid)
    except (ConnectionError, OSError, RuntimeError) as error:
        print(f"Operation failed: {error}", file=sys.stderr)
        return 1

    print(f"Notepad.exe PID: {pid}")
    print(f"Address: 0x{ADDRESS:X}")
    print(f"Read: {initial_value}")
    if initial_value == 13:
        print(f"Wrote and verified: {final_value}")
    else:
        print("Value was not 13; no write was performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
