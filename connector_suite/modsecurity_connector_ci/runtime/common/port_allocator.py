#!/usr/bin/env python3
"""Allocate one currently available localhost TCP port."""
from __future__ import annotations
import argparse
import socket
import sys


def port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
        return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--end", type=int, default=0)
    args = parser.parse_args()
    if args.start == 0 and args.end == 0:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((args.host, 0))
            print(sock.getsockname()[1])
            return 0
    if args.start <= 0 or args.end < args.start:
        print("invalid port range", file=sys.stderr)
        return 2
    for port in range(args.start, args.end + 1):
        if port_available(args.host, port):
            print(port)
            return 0
    print("no available port", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
