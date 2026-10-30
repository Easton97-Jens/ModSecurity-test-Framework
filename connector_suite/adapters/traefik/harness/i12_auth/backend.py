"""Independent bounded synthetic backend with actual write receipts."""
import hashlib
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import sys
import time

root = Path('/task/backend');root.mkdir(mode=0o700)
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 <= length <= 8192:self.send_error(400);return
        body = self.rfile.read(length);name = self.path.lstrip('/')
        (root / (name + '.request-body.raw')).write_bytes(body)
        response = b'i12-response-marker:' + name.encode() + b'\n'
        if name == 'p4-safe':response = b'i12-block-response\n'
        if name == 'large-response':response = b'i12-large-response-' + b'x' * 40000
        self.send_response(200);self.send_header('Content-Type', 'text/plain; charset=utf-8')
        if name == 'p3-deny':self.send_header('X-I12-Response', 'deny')
        self.send_header('Content-Length', str(len(response) + (100 if name == 'observer-abort' else 0)))
        self.send_header('Connection', 'close');self.end_headers()
        error = None;written = 0
        try:
            for chunk in (response[:8], response[8:]):
                written += self.wfile.write(chunk);self.wfile.flush();time.sleep(0.03)
        except OSError as exc:error = type(exc).__name__
        self.close_connection = True
        record = {'case': name, 'pid': os.getpid(), 'transaction_id': self.headers.get('X-Request-Id'),
            'request_body_bytes': len(body), 'request_body_sha256': hashlib.sha256(body).hexdigest(),
            'response_status': 200, 'response_written_bytes': written, 'response_error': error,
            'response_body_sha256': hashlib.sha256(response).hexdigest(), 'finished_ns': time.monotonic_ns()}
        (root / (name + '.response-body.raw')).write_bytes(response)
        with (root / 'receipts.jsonl').open('a') as stream:stream.write(json.dumps(record) + '\n')
    def log_message(self, *_args):
        return None  # Physical receipts own bounded HTTP evidence.
server = http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), Handler)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
try:server.serve_forever(poll_interval=0.1)
finally:server.server_close()
