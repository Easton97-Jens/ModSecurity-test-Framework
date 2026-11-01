"""Bounded, independent HTTP/1 client; observations never assert native EOS."""
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time


def main():
    port, name = int(sys.argv[1]), sys.argv[2]
    root = Path('/task/client');root.mkdir(mode=0o700, exist_ok=True)
    identity = 'i12-auth-' + name
    bodies = {'p2-deny': b'i12-block-request', 'engine-limit': b'x' * 1500,
              'host-limit': b'x' * 4097, 'limit-boundary': b'x' * 4096}
    body = bodies.get(name, b'i12-benign-body')
    marker = 'X-Modsec-Smoke: block\r\n' if name == 'p1-deny' else ''
    request = (f'POST /{name} HTTP/1.1\r\nHost: example.test\r\n'
        f'X-Request-Id: {identity}\r\nContent-Type: text/plain; charset=utf-8\r\n'
        f'{marker}Content-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode() + body
    (root / (name + '.request.raw')).write_bytes(request)
    received = bytearray(); receipt = {'case': name, 'transaction_id': identity,
        'pid': os.getpid(), 'started_ns': time.monotonic_ns(), 'request_body_bytes': len(body),
        'tcp_eof_observed': False, 'native_eos_inferred': False}
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=10) as connection:
            connection.settimeout(10);connection.sendall(request)
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    receipt['tcp_eof_observed'] = True; break
                receipt.setdefault('first_recv_ns', time.monotonic_ns())
                received.extend(chunk)
                if len(received) > 65536:raise RuntimeError('response bound exceeded')
        head, body = bytes(received).split(b'\r\n\r\n', 1)
        receipt.update(status=int(head.split(b' ')[1]), wire_body_bytes=len(body),
            wire_body_sha256=hashlib.sha256(body).hexdigest(), response_status_lines=bytes(received).count(b'HTTP/1.1 '))
    except Exception as error:
        receipt['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        (root / (name + '.response.raw')).write_bytes(received)
        receipt['finished_ns'] = time.monotonic_ns()
        (root / (name + '.receipt.json')).write_text(json.dumps(receipt, indent=2) + '\n')
    if 'error' in receipt:raise SystemExit(1)

if __name__ == '__main__':main()
