"""Independent HTTP backend: connection/header arrivals precede body reads."""
import hashlib
import argparse
from email.message import Message
from email.utils import formatdate
from http import HTTPStatus
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import sys
import threading
import time

MAX_BODY = 8 * 1024 * 1024
MAX_LINE = 8192
MAX_HEADERS = 65536
HEADER_TOKEN = b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
LOCK = threading.Lock()
LOOPBACK = '127.0.0.1'
MANIFEST = '/mnt/fixtures/acceptance-manifest.json'


def manifest_cases(value):
    if value != MANIFEST or Path(value).resolve(strict=True) != Path(MANIFEST):
        raise ValueError('sealed physical acceptance manifest required')
    return json.loads(Path(MANIFEST).read_text())


def bounded_port(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError('bounded loopback port required')
    return port


def record(root, value):
    value = value | {'pid': os.getpid(), 'monotonic_ns': time.monotonic_ns()}
    with LOCK, (root / 'receipts.jsonl').open('a') as stream:
        stream.write(json.dumps(value) + '\n')


class Backend(socketserver.ThreadingMixIn, socketserver.BaseServer):
    daemon_threads = True
    block_on_close = True

    def __init__(self, address, handler):
        # This fixture deliberately serves HTTP inside the isolated network
        # namespace. Its constructor cannot admit an external bind address.
        host, port = address
        if host != LOOPBACK or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError('only an isolated loopback bind is admitted')
        super().__init__((LOOPBACK, port), handler)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.bind((LOOPBACK, port))
            self.server_address = self.socket.getsockname()
            self.socket.listen(5)
        except OSError:
            self.socket.close()
            raise
        self.server_name = LOOPBACK
        self.server_port = self.server_address[1]

    def fileno(self):
        return self.socket.fileno()

    def server_close(self):
        self.socket.close()
        super().server_close()

    def shutdown_request(self, connection):
        try:
            connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        finally:
            connection.close()

    def get_request(self):
        connection, address = self.socket.accept()
        if address[0] != LOOPBACK:
            connection.close()
            raise OSError('only isolated loopback clients are admitted')
        record(self.root, {'operation': 'accept', 'peer': list(address), 'socket_fd': connection.fileno()})
        connection.settimeout(12)
        return connection, address


def response_fixture(case, key, neighbor):
    if neighbor:
        return {'status': 200, 'headers': [['Content-Type', 'text/plain']],
                'body_hex': b'independent-healthy-neighbor\n'.hex(), 'chunk_lengths': [7, 12, 10]}, 'independent_neighbor'
    if key.startswith(('main-before-', 'main-after-')) and 'main_control_backend' in case['fixture']:
        return case['fixture']['main_control_backend'], 'explicit_main_control_override'
    return case['fixture']['backend'], 'original_target_fixture'


class Handler(socketserver.StreamRequestHandler):
    """One bounded HTTP request on an admitted private-loopback connection."""

    protocol_version = 'HTTP/1.1'

    def read_line(self, limit):
        line = self.rfile.readline(limit + 1)
        if not line:
            raise EOFError('EOF before CRLF line')
        if len(line) > limit or not line.endswith(b'\r\n'):
            raise ValueError('bounded CRLF line required')
        return line[:-2]

    def parse_request(self):
        parts = self.read_line(MAX_LINE).split(b' ')
        if len(parts) != 3 or parts[0] not in (b'GET', b'POST', b'PUT'):
            raise ValueError('unsupported request method or request line')
        if parts[2] != b'HTTP/1.1' or not parts[1].startswith(b'/') or parts[1].startswith(b'//'):
            raise ValueError('HTTP/1.1 origin-form target required')
        if any(byte <= 32 or byte == 127 or byte == 92 for byte in parts[1]):
            raise ValueError('invalid request target')
        self.command = parts[0].decode('ascii')
        self.path = parts[1].decode('iso-8859-1')
        self.read_headers()
        self.validate_framing()
        if self.headers.get('Expect', '').lower() == '100-continue':
            self.wfile.write(b'HTTP/1.1 100 Continue\r\n\r\n')
            self.wfile.flush()

    def add_header(self, line):
        name, separator, value = line.partition(b':')
        if not separator or not name or any(byte not in HEADER_TOKEN for byte in name):
            raise ValueError('invalid header field name')
        if any(byte < 32 and byte != 9 or byte == 127 for byte in value):
            raise ValueError('invalid header value')
        self.headers[name.decode('ascii')] = value.decode('iso-8859-1').strip(' \t')

    def read_headers(self):
        self.headers = Message()
        total = 0
        count = 0
        while True:
            line = self.read_line(MAX_LINE)
            total += len(line) + 2
            if total > MAX_HEADERS:
                raise ValueError('bounded header section exceeded')
            if not line:
                break
            count += 1
            if count > 100:
                raise ValueError('excessive header fields')
            self.add_header(line)

    def validate_framing(self):
        lengths = self.headers.get_all('Content-Length', [])
        encodings = self.headers.get_all('Transfer-Encoding', [])
        if len(lengths) > 1 or len(encodings) > 1 or lengths and encodings:
            raise ValueError('ambiguous request body framing')
        if lengths and (not lengths[0].isascii() or not lengths[0].isdecimal()):
            raise ValueError('invalid content length')
        if encodings and encodings[0].lower() != 'chunked':
            raise ValueError('unsupported transfer encoding')

    def handle(self):
        self.close_connection = True
        try:
            self.parse_request()
        except (OSError, EOFError, ValueError) as error:
            record(self.server.root, {'operation': 'request-rejected',
                'error': type(error).__name__, 'detail': str(error)[:256]})
            try:
                self.send_error(400)
            except OSError:
                pass
            return
        self.handle_request()

    def send_response(self, status):
        if not isinstance(status, int) or not 100 <= status <= 599:
            raise ValueError('bounded response status required')
        try:
            reason = HTTPStatus(status).phrase
        except ValueError:
            reason = ''
        self.wfile.write(f'HTTP/1.1 {status} {reason}\r\n'.encode('ascii'))
        self.send_header('Server', 'BaseHTTP/0.6 Python/' + sys.version.split()[0])
        self.send_header('Date', formatdate(usegmt=True))

    def send_header(self, name, value):
        encoded_name = str(name).encode('ascii')
        encoded_value = str(value).encode('iso-8859-1')
        if not encoded_name or any(byte not in HEADER_TOKEN for byte in encoded_name):
            raise ValueError('invalid response header name')
        if any(byte < 32 or byte == 127 for byte in encoded_value):
            raise ValueError('invalid response header value')
        self.wfile.write(encoded_name + b': ' + encoded_value + b'\r\n')

    def end_headers(self):
        self.wfile.write(b'\r\n')
        self.wfile.flush()

    def send_error(self, status):
        self.send_response(status)
        self.send_header('Content-Length', '0')
        self.send_header('Connection', 'close')
        self.end_headers()

    def read_chunked_body(self, body):
        while True:
            line = self.read_line(128)
            digits = line.split(b';', 1)[0]
            if not digits or any(byte not in b'0123456789abcdefABCDEF' for byte in digits):
                raise ValueError('invalid chunk size')
            size = int(digits, 16)
            if size == 0:
                if self.read_line(4096):
                    raise ValueError('unsupported trailers')
                return
            if size < 0 or size > MAX_BODY or len(body) + size > MAX_BODY:
                raise ValueError('bounded backend body exceeded')
            part = self.rfile.read(size)
            body.extend(part)
            if len(part) != size or self.rfile.read(2) != b'\r\n':
                raise EOFError('incomplete body chunk')

    def read_sized_body(self, body):
        size = int(self.headers.get('Content-Length', '0'))
        if not 0 <= size <= MAX_BODY:
            raise ValueError('bounded backend body exceeded')
        while len(body) < size:
            part = self.rfile.read(min(8192, size - len(body)))
            if not part:
                raise EOFError('incomplete content length')
            body.extend(part)

    def read_body(self, key):
        body = bytearray()
        try:
            if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
                self.read_chunked_body(body)
            else:
                self.read_sized_body(body)
            record(self.server.root, {'operation': 'body-complete', 'key': key,
                'body_bytes': len(body), 'body_sha256': hashlib.sha256(body).hexdigest()})
            return bytes(body)
        except (OSError, EOFError, ValueError) as error:
            record(self.server.root, {'operation': 'body-incomplete', 'key': key,
                'body_bytes': len(body), 'body_sha256': hashlib.sha256(body).hexdigest(),
                'error': type(error).__name__, 'detail': str(error)[:256]})
            raise
        finally:
            (self.server.root / (key + '.request-body.raw')).write_bytes(body)

    def wait_barrier(self, key):
        marker = self.server.barriers / key
        record(self.server.root, {'operation': 'upstream-barrier-enter', 'key': key})
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not marker.exists():
            raise TimeoutError('client did not observe prefix before upstream release')
        record(self.server.root, {'operation': 'upstream-barrier-release', 'key': key,
            'client_marker_sha256': hashlib.sha256(marker.read_bytes()).hexdigest()})

    def write_body(self, key, fixture, body):
        position = 0
        for index, size in enumerate(fixture['chunk_lengths']):
            piece = body[position:position + size]
            if len(piece) != size:
                raise ValueError('response fixture chunk mismatch')
            self.wfile.write(piece)
            self.wfile.flush()
            position += size
            record(self.server.root, {'operation': 'response-chunk-flushed', 'key': key,
                'index': index, 'bytes': size, 'sha256': hashlib.sha256(piece).hexdigest()})
            if index == 0 and fixture.get('barrier'):
                self.wait_barrier(key)
            time.sleep(0.15 if len(body) < 65536 else 0.01)
        if position != len(body):
            raise ValueError('response fixture not exhausted')
        record(self.server.root, {'operation': 'response-complete', 'key': key,
            'body_bytes': position, 'body_sha256': hashlib.sha256(body).hexdigest()})

    def handle_request(self):
        key = self.headers.get('X-I12-Acceptance-Key', '')
        neighbor = key.startswith('neighbor-')
        lookup = key.removeprefix('neighbor-').removeprefix('main-before-').removeprefix('main-after-')
        for index in range(10):
            lookup = lookup.removeprefix('readiness-' + str(index) + '-')
        for index in range(3):
            lookup = lookup.removeprefix('sequence-' + str(index) + '-')
        if lookup not in self.server.cases:
            self.send_error(400)
            return
        case = self.server.cases[lookup]
        record(self.server.root, {'operation': 'headers-arrived', 'key': key, 'method': self.command,
            'path': self.path[:8192], 'request_id': self.headers.get('X-Request-Id'),
            'headers': list(self.headers.items()), 'peer': list(self.client_address)})
        try:
            self.read_body(key)
            fixture, selection = response_fixture(case, key, neighbor)
            body = bytes.fromhex(fixture['body_hex'])
            record(self.server.root, {'operation': 'response-fixture-selected', 'key': key,
                'selection': selection, 'body_bytes': len(body), 'body_sha256': hashlib.sha256(body).hexdigest(),
                'override_reason': case['fixture'].get('main_control_override_reason') if selection == 'explicit_main_control_override' else None})
            (self.server.root / (key + '.response-body.raw')).write_bytes(body)
            self.send_response(fixture['status'])
            for name, value in fixture['headers']:
                self.send_header(name, value)
            # Missing Content-Type fixture must not silently gain one.
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            record(self.server.root, {'operation': 'response-headers-flushed', 'key': key,
                                      'status': fixture['status'], 'declared_bytes': len(body)})
            self.write_body(key, fixture, body)
        except (OSError, EOFError, ValueError) as error:
            record(self.server.root, {'operation': 'handler-error', 'key': key,
                                      'error': type(error).__name__, 'detail': str(error)[:256]})
        finally:
            self.close_connection = True
            record(self.server.root, {'operation': 'handler-end', 'key': key})


def serve_private(server):
    """Dispatch admitted private connections; termination owns listener cleanup."""
    try:
        while True:
            try:
                connection, address = server.get_request()
            except OSError:
                time.sleep(0.01)
                continue
            try:
                if server.verify_request(connection, address):
                    server.process_request(connection, address)
                else:
                    server.shutdown_request(connection)
            except Exception:
                try:
                    server.handle_error(connection, address)
                finally:
                    server.shutdown_request(connection)
            except (SystemExit, KeyboardInterrupt):
                server.shutdown_request(connection)
                raise
    finally:
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('port', type=bounded_port)
    parser.add_argument('manifest', choices=(MANIFEST,))
    args = parser.parse_args()
    specification = manifest_cases(args.manifest)
    root = Path('/task/backend')
    root.mkdir(mode=0o700)
    server = Backend((LOOPBACK, args.port), Handler)
    server.root = root
    server.barriers = Path('/task/barriers')
    server.barriers.mkdir(mode=0o700)
    server.cases = {c['key']: c for c in specification['cases'] + specification.get('supplementary_executions', [])}
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    serve_private(server)


if __name__ == '__main__':
    main()
