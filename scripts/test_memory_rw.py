#!/usr/bin/env python3
"""Exercises plato's CR3-backed read/write operations against a test process."""

import argparse
import socket
import struct
import sys


OP_READ = 0
OP_WRITE = 1
HOST = "127.0.0.1"
PORT = 7653
SIZE_T = struct.Struct("<Q")
READ_MEMORY_OPERATION = struct.Struct("<I4xQQQ")


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed while waiting for response")
        data.extend(chunk)
    return bytes(data)


def send_request_header(sock: socket.socket, operation: int, pid: int, address: int, size: int) -> None:
    packet = READ_MEMORY_OPERATION.pack(operation, address, pid, size)
    sock.sendall(SIZE_T.pack(len(packet)))
    sock.sendall(packet)


def read_memory(sock: socket.socket, pid: int, address: int, size: int) -> bytes:
    send_request_header(sock, OP_READ, pid, address, size)
    response_size = SIZE_T.unpack(recv_exact(sock, SIZE_T.size))[0]
    response = recv_exact(sock, response_size)
    if response_size != size:
        raise RuntimeError(f"driver rejected read (response size: {response_size})")
    return response


def write_memory(sock: socket.socket, pid: int, address: int, data: bytes) -> None:
    send_request_header(sock, OP_WRITE, pid, address, len(data))
    sock.sendall(data)

    response_size = SIZE_T.unpack(recv_exact(sock, SIZE_T.size))[0]
    response = recv_exact(sock, response_size)
    if response_size != 1 or response != b"\x01":
        raise RuntimeError("driver rejected write")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read and write a plato test-process buffer through the driver.")
    parser.add_argument("--pid", type=int, required=True, help="PID printed by test_memory_target.py")
    parser.add_argument("--address", type=lambda value: int(value, 0), required=True, help="buffer address, e.g. 0x1234")
    parser.add_argument("--size", type=int, default=64, help="buffer capacity printed by test_memory_target.py")
    parser.add_argument("--expected", default="Hello World", help="initial buffer contents")
    parser.add_argument("--replacement", default="Homework done", help="text to write into the buffer")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.pid <= 0 or args.address <= 0 or args.size <= 0 or args.size > 1024 * 1024:
        print("pid, address, and size must describe a buffer of at most 1 MiB", file=sys.stderr)
        return 2

    expected = args.expected.encode("ascii")
    replacement = args.replacement.encode("ascii") + b"\0"
    if len(replacement) > args.size:
        print("replacement including its NUL terminator does not fit in the target buffer", file=sys.stderr)
        return 2

    with socket.create_connection((HOST, PORT), timeout=5.0) as sock:
        sock.settimeout(5.0)

        initial = read_memory(sock, args.pid, args.address, args.size)
        if initial[: len(expected)] != expected or initial[len(expected) : len(expected) + 1] != b"\0":
            print(f"unexpected initial bytes: {initial!r}", file=sys.stderr)
            return 1
        print(f"read: {initial.split(b'\0', 1)[0].decode('ascii')}")

        write_memory(sock, args.pid, args.address, replacement)
        final = read_memory(sock, args.pid, args.address, args.size)
        if final[: len(replacement)] != replacement:
            print(f"write verification failed: {final!r}", file=sys.stderr)
            return 1
        print(f"wrote and verified: {final.split(b'\0', 1)[0].decode('ascii')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
