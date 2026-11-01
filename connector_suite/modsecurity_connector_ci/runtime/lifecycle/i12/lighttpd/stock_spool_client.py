"""Independent bounded client holding a declared request before its body.

Only an actual private loopback socket and physical release file drive this
client. It supplies no expected server result and cannot manufacture EOF/EOS.
"""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--length', type=int, required=True)
    parser.add_argument('--count', type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        raise ValueError('private loopback TCP port required')
    if not 1 <= args.length <= 32 * 1024 * 1024 or not 1 <= args.count <= 8:
        raise ValueError('bounded declared length required')
    directory = args.directory
    if '..' in directory.parts or not directory.is_relative_to('/task'):
        raise ValueError('private task receipt directory required')
    if any(path.is_symlink() for path in (*directory.parents, directory)):
        raise ValueError('receipt aliases forbidden')
    directory.mkdir(mode=0o700)
    os.umask(0o077)
    request = (f'POST /i12/stock/held HTTP/1.1\r\nHost: 127.0.0.1:{args.port}\r\n'
               f'Content-Type: text/plain\r\nContent-Length: {args.length}\r\n'
               'X-Request-Id: stock-independent-held\r\nConnection: close\r\n\r\n').encode()
    receipt = {'pid': os.getpid(), 'uid': os.geteuid(), 'declared_length': args.length,
               'body_bytes_sent': 0, 'connection_count': args.count,
               'peer_eof_observed': None, 'started_ns': time.monotonic_ns()}
    with ExitStack() as connections:
        for _index in range(args.count):
            connection = connections.enter_context(socket.create_connection(('127.0.0.1', args.port), timeout=5))
            connection.sendall(request)
        receipt['headers_sent_ns'] = time.monotonic_ns()
        (directory / 'ready.json').write_text(json.dumps(receipt, indent=2) + '\n')
        deadline = time.monotonic() + 20
        while not (directory / 'release').exists():
            if time.monotonic() >= deadline:
                raise TimeoutError('bounded holder release not received')
            time.sleep(0.01)
        receipt['local_close_started_ns'] = time.monotonic_ns()
    receipt['local_close_completed_ns'] = time.monotonic_ns()
    (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
