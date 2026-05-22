#!/usr/bin/env python3
import argparse
import socket
import struct
import sys
import time


OP_MOVE_MOUSE_RELATIVE = 3
HOST = "127.0.0.1"
PORT = 7653
SIZE_T = struct.Struct("<Q")
MOUSE_MOVE_RELATIVE_PACKET = struct.Struct("<iii")


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed while waiting for response")
        data.extend(chunk)
    return bytes(data)


def send_mouse_move(sock: socket.socket, x: int, y: int) -> bool:
    packet = MOUSE_MOVE_RELATIVE_PACKET.pack(OP_MOVE_MOUSE_RELATIVE, x, y)
    sock.sendall(SIZE_T.pack(len(packet)))
    sock.sendall(packet)

    response_size = SIZE_T.unpack(recv_exact(sock, SIZE_T.size))[0]
    response = recv_exact(sock, response_size)
    if response_size < 1:
        raise RuntimeError("driver returned an empty response")

    return response[0] != 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Test plato TCP relative mouse movement.")
    parser.add_argument("--x", type=int, default=100, help="relative X movement")
    parser.add_argument("--y", type=int, default=0, help="relative Y movement")
    parser.add_argument("--delay", type=float, default=0.25, help="seconds before moving back")
    parser.add_argument(
        "--no-return",
        action="store_true",
        help="do not send the opposite movement after the test move",
    )
    return parser.parse_args()


def main() -> int:
    time.sleep(2.05)
    args = parse_args()

    for value_name, value in (("x", args.x), ("y", args.y)):
        if value < -2147483648 or value > 2147483647:
            print(f"{value_name} must fit in a signed 32-bit LONG", file=sys.stderr)
            return 2

    with socket.create_connection((HOST, PORT), timeout=5.0) as sock:
        sock.settimeout(5.0)

        if not send_mouse_move(sock, args.x, args.y):
            print("driver rejected mouse move", file=sys.stderr)
            return 1

        print(f"moved mouse by ({args.x}, {args.y})")

        if not args.no_return and (args.x or args.y):
            time.sleep(args.delay)
            if not send_mouse_move(sock, -args.x, -args.y):
                print("driver rejected return mouse move", file=sys.stderr)
                return 1
            print(f"moved mouse back by ({-args.x}, {-args.y})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
