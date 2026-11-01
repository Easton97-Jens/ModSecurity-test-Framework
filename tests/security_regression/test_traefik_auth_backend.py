"""Exercise the actual bounded backend without launching its module-level server."""

from email.message import Message
import hashlib
import http.server
import importlib
import io
import json
from pathlib import Path
import signal
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock


# The physical fixture is a script. Suppress only startup side effects during
# import; every Handler method below is the unchanged, real implementation.
with mock.patch.object(Path, 'mkdir'), mock.patch.object(http.server, 'HTTPServer'), \
        mock.patch.object(signal, 'signal'), mock.patch.object(sys, 'argv', ['backend.py', '0']):
    BACKEND = importlib.import_module('connector_suite.adapters.traefik.harness.i12_auth.backend')


class BackendTargetTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='traefik-backend-')
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.root = self.parent / 'backend'
        self.root.mkdir()
        patch = mock.patch.object(BACKEND, 'root', self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def handler(self, target='/allow', body=b'actual-request-body'):
        handler = object.__new__(BACKEND.Handler)
        handler.path = target
        handler.command = 'POST'
        handler.request_version = 'HTTP/1.1'
        handler.requestline = 'POST ' + target + ' HTTP/1.1'
        handler.headers = Message()
        handler.headers['Content-Length'] = str(len(body))
        handler.headers['X-Request-Id'] = 'i12-auth-' + target[1:]
        handler.rfile = mock.Mock(wraps=io.BytesIO(body))
        handler.wfile = io.BytesIO()
        handler.close_connection = False
        handler.send_error = mock.Mock(wraps=handler.send_error)
        return handler

    def invoke(self, handler):
        with mock.patch.object(BACKEND.time, 'sleep'):
            handler.do_POST()

    def test_noncanonical_targets_reject_before_body_or_files(self):
        targets = (
            '/../escape', '/../../escape', '/allow/../escape', '/allow/child',
            '/allow\\child', '/..\\escape', 'allow', '//allow', '///allow',
            '', '/', 'http://example.test/allow', 'example.test:80', '*',
            '/allow?query=1', '/allow#fragment', '/%2e%2e%2fescape',
            '/%252e%252e%252fescape', '/allow%2fchild', '/allow%5cchild',
            '/Allow', '/caf\u00e9', '/a' + 'b' * 23,
        ) + tuple('/allow' + chr(value) for value in (*range(33), 127))
        for target in targets:
            with self.subTest(target=repr(target)):
                handler = self.handler(target)
                with mock.patch.object(Path, 'write_bytes') as write, \
                        mock.patch.object(Path, 'open') as opened:
                    self.invoke(handler)
                handler.send_error.assert_called_once_with(400)
                handler.rfile.read.assert_not_called()
                write.assert_not_called()
                opened.assert_not_called()
                self.assertTrue(handler.close_connection)
                self.assertEqual(handler.wfile.getvalue().count(b'HTTP/1.1 400 '), 1)
                self.assertEqual(list(self.root.iterdir()), [])

    def test_literal_traversal_leaves_real_outside_artifacts_unchanged(self):
        outside = [self.parent / ('escape.' + kind + '-body.raw')
                   for kind in ('request', 'response')]
        for path in outside:
            path.write_bytes(b'outside-sentinel')
        handler = self.handler('/../escape')
        self.invoke(handler)
        self.assertEqual([path.read_bytes() for path in outside],
                         [b'outside-sentinel', b'outside-sentinel'])
        self.assertEqual(list(self.root.iterdir()), [])
        handler.send_error.assert_called_once_with(400)

    def test_raw_parser_rejects_normalized_targets_without_continue(self):
        targets = (b'//allow', b'///allow', b'/allow\t', b'/allow\x0b',
                   b'/allow\r', b'/allow\x00', b'/allow\x7f', b'/allow?x',
                   b'/allow#x', b'/%61llow', b'/allow/../neighbor', b'allow',
                   b'', b'http://example.test/allow', b'example.test:80',
                   b'/'+b'a'*24)
        for target in targets:
            with self.subTest(target=target):
                handler = self.handler()
                stream = io.BytesIO(b'POST ' + target + b' HTTP/1.1\r\n'
                                    b'Expect: 100-continue\r\nContent-Length: 9\r\n\r\n')
                handler.raw_requestline = stream.readline()
                handler.rfile = mock.Mock(wraps=stream)
                self.assertFalse(handler.parse_request())
                handler.send_error.assert_called_once_with(400)
                handler.rfile.read.assert_not_called()
                self.assertTrue(handler.close_connection)
                wire = handler.wfile.getvalue()
                self.assertEqual(wire.count(b'HTTP/1.1 400 '), 1)
                self.assertNotIn(b'100 Continue', wire)
                self.assertEqual(list(self.root.iterdir()), [])

    def test_all_catalog_cases_preserve_artifacts_receipts_and_responses(self):
        prepare = Path(BACKEND.__file__).with_name('prepare.py')
        # Read the literal catalog without importing the unrelated source exporter.
        import ast
        tree = ast.parse(prepare.read_text())
        cases = next(ast.literal_eval(node.value) for node in tree.body
                     if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == 'CASES'
                             for target in node.targets))
        expected_cases = ('allow', 'p1-deny', 'p2-deny', 'engine-limit',
                          'limit-boundary', 'host-limit', 'p3-deny', 'p4-safe',
                          'large-response', 'observer-abort', 'observer-no-handle',
                          'observer-invalid-handle', 'mrc1-error',
                          'auth-cap-boundary', 'auth-cap-overlimit', 'neighbor')
        self.assertEqual(cases, expected_cases)
        for name in cases:
            with self.subTest(case=name):
                body = b'actual-request-' + name.encode('ascii')
                handler = self.handler('/' + name, body)
                self.invoke(handler)
                handler.send_error.assert_not_called()
                handler.rfile.read.assert_called_once_with(len(body))
                head, received = handler.wfile.getvalue().split(b'\r\n\r\n', 1)
                expected = b'i12-response-marker:' + name.encode('ascii') + b'\n'
                if name == 'p4-safe':
                    expected = b'i12-block-response\n'
                if name == 'large-response':
                    expected = b'i12-large-response-' + b'x' * 40000
                    self.assertEqual(len(expected), 40019)
                self.assertEqual(received, expected)
                self.assertEqual((self.root / (name + '.request-body.raw')).read_bytes(), body)
                self.assertEqual((self.root / (name + '.response-body.raw')).read_bytes(), expected)
                self.assertIn(b'HTTP/1.1 200 OK', head)
                self.assertEqual(b'X-I12-Response: deny' in head, name == 'p3-deny')
                claimed = len(expected) + (100 if name == 'observer-abort' else 0)
                self.assertIn(('Content-Length: ' + str(claimed)).encode(), head)
                self.assertIn(b'Connection: close', head)
                self.assertTrue(handler.close_connection)
                record = json.loads((self.root / 'receipts.jsonl').read_text().splitlines()[-1])
                self.assertEqual(record['case'], name)
                self.assertEqual(record['transaction_id'], 'i12-auth-' + name)
                self.assertEqual(record['request_body_bytes'], len(body))
                self.assertEqual(record['request_body_sha256'], hashlib.sha256(body).hexdigest())
                self.assertEqual(record['response_body_sha256'], hashlib.sha256(expected).hexdigest())
                self.assertEqual(record['response_written_bytes'], len(expected))
                self.assertEqual(record['response_status'], 200)
                self.assertIsNone(record['response_error'])
                self.assertGreater(record['finished_ns'], 0)
        self.assertEqual(len((self.root / 'receipts.jsonl').read_text().splitlines()), 16)

    def test_loopback_rejects_unread_body_and_preserves_valid_wire(self):
        server = http.server.HTTPServer(('127.0.0.1', 0), BACKEND.Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        try:
            for target in (b'/../escape', b'//allow', b'/allow?query=1', b'/allow'):
                with self.subTest(target=target):
                    valid = target == b'/allow'
                    with socket.create_connection(server.server_address, timeout=2) as connection:
                        connection.settimeout(2)
                        # No rejected body is sent: returning 400 also proves no
                        # blocking body read was reached on the real socket.
                        length, body = (3, b'abc') if valid else (8192, b'')
                        connection.sendall(b'POST ' + target + b' HTTP/1.1\r\n'
                                           b'Content-Length: ' + str(length).encode() +
                                           b'\r\nConnection: close\r\n\r\n' + body)
                        wire = bytearray()
                        while chunk := connection.recv(4096):
                            wire.extend(chunk)
                    status = b'200 OK' if valid else b'400 Bad Request'
                    self.assertTrue(wire.startswith(b'HTTP/1.1 ' + status + b'\r\n'))
                    self.assertEqual(wire.count(b'HTTP/1.1 '), 1)
                    if valid:
                        self.assertTrue(wire.endswith(b'\r\n\r\ni12-response-marker:allow\n'))
                    else:
                        self.assertEqual(list(self.root.iterdir()), [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(server.fileno(), -1)
        self.assertEqual((self.root / 'allow.request-body.raw').read_bytes(), b'abc')
        self.assertEqual(len((self.root / 'receipts.jsonl').read_text().splitlines()), 1)


if __name__ == '__main__':
    unittest.main()
