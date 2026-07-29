#!/usr/bin/env python3
"""Keeps a dynamic user-mode buffer alive for the plato physical-memory test."""

import ctypes
import os
import time


BUFFER_SIZE = 64


def main() -> None:
    buffer = ctypes.create_string_buffer(BUFFER_SIZE)
    buffer.value = b"Hello World"

    print(f"pid={os.getpid()} address=0x{ctypes.addressof(buffer):X} size={ctypes.sizeof(buffer)}", flush=True)
    print("Keep this process running, then pass these values to test_memory_rw.py.", flush=True)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
