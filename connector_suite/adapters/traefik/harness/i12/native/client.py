"""Independent bounded HTTP/1 client. TCP EOF is never native EOS evidence."""
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time


def run(port, label, expected):
    root = Path('/task/client')
    root.mkdir(mode=0o700, exist_ok=True)
    payload = ('i12-request-marker:' + label + '\n').encode()
    if label == 'p2-deny':
        payload += b'i12-p2-deny'
    content_type = {'request-type-missing': '', 'request-charset-missing': 'Content-Type: text/plain\r\n',
                    'request-charset-iso': 'Content-Type: text/plain; charset=iso-8859-1\r\n'}.get(label, 'Content-Type: text/plain; charset=utf-8\r\n')
    headers = (f'POST /i12-eos-{label} HTTP/1.1\r\nHost: example.test\r\n'
               f'X-Request-Id: tf-{label}\r\n{content_type}'
               'Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n').encode()
    parts = [payload[:7], payload[7:19], payload[19:]]
    request = headers + b''.join(f'{len(p):x}\r\n'.encode() + p + b'\r\n' for p in parts) + b'0\r\n\r\n'
    received = bytearray()
    receipt = {'pid': os.getpid(), 'label': label, 'started_ns': time.monotonic_ns(),
               'expected_status': expected, 'tcp_eof': False, 'native_eos': None,
               'request_body_sha256': hashlib.sha256(payload).hexdigest(), 'send_chunks': len(parts)}
    error = None
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=15) as connection:
            connection.settimeout(15)
            connection.sendall(headers)
            for part in parts:
                connection.sendall(f'{len(part):x}\r\n'.encode() + part + b'\r\n')
                time.sleep(0.03)
            connection.sendall(b'0\r\n\r\n')
            if label == 'client-cancel':
                time.sleep(0.15)
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                receipt['client_cancel_sent_ns'] = time.monotonic_ns()
                receipt['oracle_pass'] = None
                return receipt
            while True:
                block = connection.recv(4096)
                if not block:
                    receipt['tcp_eof'] = True
                    break
                receipt.setdefault('first_recv_ns', time.monotonic_ns())
                received.extend(block)
                if len(received) > 65536:
                    raise RuntimeError('response bound exceeded')
        head, body = bytes(received).split(b'\r\n\r\n', 1)
        receipt['status'] = int(head.split(b'\r\n')[0].split()[1])
        receipt['status_line_count'] = sum(line.startswith(b'HTTP/1.') for line in bytes(received).split(b'\r\n'))
        receipt['body_bytes'] = len(body)
        receipt['body_sha256'] = hashlib.sha256(body).hexdigest()
        receipt['oracle_pass'] = receipt['status'] == expected and receipt['status_line_count'] == 1
        if expected == 200:
            wanted = ('i12-response-marker:' + label + '\n').encode()
            receipt['body_oracle_pass'] = body == wanted
            receipt['oracle_pass'] &= receipt['body_oracle_pass']
    except Exception as failure:
        error = {'type': type(failure).__name__, 'message': str(failure)}
        receipt['oracle_pass'] = False
    finally:
        receipt.update(error=error, completed_ns=time.monotonic_ns())
        (root / f'{label}.request.raw').write_bytes(request)
        (root / f'{label}.response.raw').write_bytes(received)
        (root / f'{label}.receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    # Measurement failures are retained and reviewed; do not skip neighbor checks.
    return receipt


if __name__ == '__main__':
    run(int(sys.argv[1]), sys.argv[2], int(sys.argv[3]))
