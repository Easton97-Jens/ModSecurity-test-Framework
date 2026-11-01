"""Transparent bounded authorization TCP relay, retaining synthetic samples."""
import hashlib
import argparse
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import ssl
import sys
import time

root = Path('/task/authorization');root.mkdir(mode=0o700)


def port(value):
    number = int(value)
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError('TCP port outside valid range')
    return number


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_POST(self):self.forward()
    def do_GET(self):self.forward()
    def forward(self):
        if self.path != '/authorize':
            self.send_error(400);return
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 <= length <= 8192:self.send_error(400);return
        body = self.rfile.read(length)
        identity = self.headers.get('X-Request-Id', '')
        if not identity.startswith('i12-auth-') or not identity[9:].replace('-', '').isalnum():
            self.send_error(400);return
        name = identity[9:]
        (root / (name + '.sample.raw')).write_bytes(body)
        record = {'case': name, 'transaction_id': identity, 'pid': os.getpid(),
            'sample_declared_length': length, 'sample_actual_bytes': len(body),
            'sample_sha256': hashlib.sha256(body).hexdigest(), 'received_ns': time.monotonic_ns()}
        connection = http.client.HTTPConnection('127.0.0.1', self.server.engine_port, timeout=10)
        try:
            connection.request(self.command, '/authorize', body=body, headers=dict(self.headers))
            response = connection.getresponse();data = response.read(65537)
            if len(data) > 65536:raise RuntimeError('authorization response bound exceeded')
            record.update(authorization_status=response.status, authorization_body_bytes=len(data),
                response_handle_count=len(response.headers.get_all('X-Msconnector-Response-Handle', [])))
            self.write_authorization(name, response, data, record)
        except OSError as error:
            record['transport_error'] = type(error).__name__;self.send_error(502)
        finally:
            connection.close();self.close_connection = True
            record['finished_ns'] = time.monotonic_ns()
            (root / (name + '.receipt.json')).write_text(json.dumps(record, indent=2) + '\n')
    def write_authorization(self, name, response, data, record):
        if name in ('auth-cap-boundary','auth-cap-overlimit'):
            data=b'i' * (32768 if name=='auth-cap-boundary' else 32769)
            record['explicit_relay_fault']='synthetic authorization response capacity boundary'
        record['relay_response_bytes']=len(data)
        self.send_response(response.status)
        for key, value in response.getheaders():
            if key.lower() == 'x-msconnector-response-handle':
                if name == 'observer-no-handle':continue
                if name == 'observer-invalid-handle':value = 'i12-invalid-correlation-handle'
            if key.lower() not in ('connection', 'content-length', 'transfer-encoding'):self.send_header(key, value)
        self.send_header('Content-Length', str(len(data)));self.send_header('Connection', 'close');self.end_headers()
        self.wfile.write(data);self.wfile.flush()
    def log_message(self, *_args):
        return None  # Physical receipts own bounded HTTP evidence.


TLS_ROOT = Path('/task/authorization-tls')


def make_server(listen_port, engine_port, certificate_directory=TLS_ROOT):
    directory = Path(certificate_directory)
    paths = (directory / 'server.crt', directory / 'server.key')
    for path in paths:
        if (any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file()
                or path.stat().st_uid != os.getuid()):
            raise ValueError('actual private TLS certificate files required')
    if (paths[1].stat().st_mode & 0o077 or directory.stat().st_mode & 0o077):
        raise ValueError('relay TLS private key and directory must be private')
    server = http.server.HTTPSServer(('127.0.0.1', listen_port), Handler,
                                    certfile=str(paths[0]), keyfile=str(paths[1]),
                                    alpn_protocols=['http/1.1'])
    server.socket.context.minimum_version = ssl.TLSVersion.TLSv1_2
    server.engine_port = engine_port
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('listen_port', type=port)
    parser.add_argument('engine_port', type=port)
    args = parser.parse_args()
    server = make_server(args.listen_port, args.engine_port)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:server.serve_forever(poll_interval=0.1)
    finally:server.server_close()


if __name__ == '__main__':
    main()
