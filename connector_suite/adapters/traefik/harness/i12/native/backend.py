"""Separate physical backend with request-byte and response-write receipts."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import hashlib
import http.server
import json
import os
from pathlib import Path
import signal
import sys
import time

ROOT = Path('/task/backend')
ROOT.mkdir(mode=0o700)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def read_chunked_body(self):
        pieces = []
        while True:
            count = int(self.rfile.readline().strip(), 16)
            if count == 0:
                self.rfile.readline()
                break
            if count > 4096 or sum(map(len, pieces)) + count > 4096:
                raise ValueError('bounded backend body exceeded')
            pieces.append(self.rfile.read(count))
            if self.rfile.read(2) != b'\r\n':
                raise ValueError('invalid framing')
        return b''.join(pieces)

    def read_body(self):
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            return self.read_chunked_body()
        count = int(self.headers.get('Content-Length', '0'))
        if not 0 <= count <= 4096:
            raise ValueError('bounded backend body exceeded')
        return self.rfile.read(count)

    def do_POST(self):
        body = self.read_body()
        label = self.path.removeprefix('/i12-eos-')
        response = ('i12-response-marker:' + label + '\n').encode()
        if label in ('fault-postcommit', 'client-cancel'):
            response = response + b'x' * (16384 - len(response))
        mime = {'mime-out': 'application/octet-stream', 'response-type-missing': None,
                'response-charset-missing': 'text/plain', 'response-charset-iso': 'text/plain; charset=iso-8859-1'}.get(label, 'text/plain; charset=utf-8')
        receipt = {'pid': os.getpid(), 'path': self.path, 'request_id': self.headers.get('X-Request-Id'),
                   'body_bytes': len(body), 'body_sha256': hashlib.sha256(body).hexdigest(),
                   'response_body_sha256': hashlib.sha256(response).hexdigest(), 'content_type': mime,
                   'request_received_ns': time.monotonic_ns(), 'write_error': None}
        (ROOT / f'{label}.request-body.raw').write_bytes(body)
        (ROOT / f'{label}.response-body.raw').write_bytes(response)
        self.write_response(label, response, mime, receipt)

    def write_response(self, label, response, mime, receipt):
        try:
            self.send_response(200)
            if mime is not None:
                self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(response)))
            self.send_header('X-I12-P3', 'deny' if label == 'p3-deny' else 'allow')
            self.send_header('Connection', 'close')
            self.end_headers()
            pieces = (response[:8192], response[8192:12288], response[12288:]) if len(response) > 8192 else (response[:7], response[7:19], response[19:])
            for part in pieces:
                self.wfile.write(part)
                self.wfile.flush()
                time.sleep(0.4 if label in ('fault-postcommit', 'client-cancel') else 0.04)
            receipt['response_written_ns'] = time.monotonic_ns()
        except (BrokenPipeError, ConnectionResetError) as error:
            receipt['write_error'] = type(error).__name__
        finally:
            self.close_connection = True
            with (source_path('receipts.jsonl', root=ROOT)).open('a') as output:
                output.write(json.dumps(receipt) + '\n')

    def log_message(self, *_):
        return None  # Physical receipts above own bounded HTTP evidence.


if __name__ == '__main__':
    server = http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), Handler)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()
