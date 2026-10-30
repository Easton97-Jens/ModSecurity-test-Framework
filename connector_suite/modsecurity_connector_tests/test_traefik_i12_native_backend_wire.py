"""Real private-loopback wire controls for the independent acceptance backend."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock


REPO = connector_root()
SOURCE = REPO / 'connectors/traefik/harness/i12/native/acceptance_backend.py'
EXTERNAL = Path(os.environ.get('CODEX_TEMP_ROOT', '/var/tmp/codex/ModSecurity-conector'))


class ProductionDispatchTests(unittest.TestCase):
    def setUp(self):
        specification = importlib.util.spec_from_file_location('native_backend_dispatch', SOURCE)
        self.backend = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(self.backend)
        self.server = mock.Mock()
        self.connection = object()
        self.address = ('127.0.0.1', 1234)
        self.server.get_request.side_effect = [(self.connection, self.address), SystemExit(0)]

    def run_until_termination(self):
        with self.assertRaises(SystemExit):
            self.backend.serve_private(self.server)
        self.server.server_close.assert_called_once_with()

    def test_dispatch_transfers_socket_to_threading_mixin(self):
        self.server.verify_request.return_value = True
        self.run_until_termination()
        self.server.process_request.assert_called_once_with(self.connection, self.address)
        self.server.shutdown_request.assert_not_called()

    def test_rejection_closes_without_dispatch(self):
        self.server.verify_request.return_value = False
        self.run_until_termination()
        self.server.process_request.assert_not_called()
        self.server.shutdown_request.assert_called_once_with(self.connection)

    def test_dispatch_exception_records_error_and_closes(self):
        self.server.process_request.side_effect = RuntimeError('fixture failure')
        self.run_until_termination()
        self.server.handle_error.assert_called_once_with(self.connection, self.address)
        self.server.shutdown_request.assert_called_once_with(self.connection)

    def test_accept_error_can_recover_before_dispatch_and_termination(self):
        self.server.get_request.side_effect = [OSError('accept interrupted'),
            (self.connection, self.address), SystemExit(0)]
        with mock.patch.object(self.backend.time, 'sleep') as paused:
            self.run_until_termination()
        paused.assert_called_once_with(0.01)
        self.server.process_request.assert_called_once_with(self.connection, self.address)

    def test_error_report_failure_still_closes_connection_and_listener(self):
        self.server.process_request.side_effect = RuntimeError('fixture failure')
        self.server.handle_error.side_effect = ValueError('receipt failure')
        with self.assertRaisesRegex(ValueError, 'receipt failure'):
            self.backend.serve_private(self.server)
        self.server.shutdown_request.assert_called_once_with(self.connection)
        self.server.server_close.assert_called_once_with()

    def test_termination_during_dispatch_closes_connection_and_listener(self):
        for termination in (SystemExit, KeyboardInterrupt):
            with self.subTest(termination=termination):
                self.server.reset_mock()
                self.server.get_request.side_effect = [(self.connection, self.address)]
                self.server.process_request.side_effect = termination()
                with self.assertRaises(termination):
                    self.backend.serve_private(self.server)
                self.server.server_close.assert_called_once_with()
                self.server.shutdown_request.assert_called_once_with(self.connection)
                self.server.handle_error.assert_not_called()


class BackendWireTests(unittest.TestCase):
    def setUp(self):
        specification = importlib.util.spec_from_file_location('native_backend_wire', SOURCE)
        self.backend = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(self.backend)
        self.temporary = tempfile.TemporaryDirectory(prefix='backend-wire-', dir=EXTERNAL)
        self.root = Path(self.temporary.name)
        self.server = self.backend.Backend(('127.0.0.1', 0), self.backend.Handler)
        self.server.root = self.root
        self.server.barriers = self.root
        self.server.cases = {'case': {'fixture': {'backend': {
            'status': 201, 'headers': [['Content-Type', 'text/plain; charset=utf-8'],
                                    ['X-Fixture', 'kept']],
            'body_hex': b'abcdef'.hex(), 'chunk_lengths': [2, 4]}}}}
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': 0.01})
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()
        self.temporary.cleanup()

    def exchange(self, wire):
        with socket.create_connection(self.server.server_address, timeout=2) as connection:
            connection.sendall(wire)
            connection.shutdown(socket.SHUT_WR)
            received = bytearray()
            while True:
                part = connection.recv(8192)
                if not part:
                    return bytes(received)
                received.extend(part)

    def receipts(self):
        return [json.loads(line) for line in (self.root / 'receipts.jsonl').read_text().splitlines()]

    def test_content_length_response_and_physical_receipts(self):
        wire = self.exchange(b'POST /target?x=1 HTTP/1.1\r\nHost: example.test\r\n'
            b'X-I12-Acceptance-Key: case\r\nContent-Length: 4\r\n\r\nbody')
        head, body = wire.split(b'\r\n\r\n', 1)
        self.assertTrue(head.startswith(b'HTTP/1.1 201 Created\r\n'))
        self.assertIn(b'Content-Type: text/plain; charset=utf-8\r\n', head)
        self.assertIn(b'X-Fixture: kept\r\n', head)
        self.assertIn(b'Content-Length: 6\r\n', head)
        self.assertEqual(body, b'abcdef')
        self.assertEqual((self.root / 'case.request-body.raw').read_bytes(), b'body')
        rows = self.receipts()
        self.assertEqual([row['bytes'] for row in rows
                          if row['operation'] == 'response-chunk-flushed'], [2, 4])
        self.assertEqual(sum(row['operation'] == 'handler-end' for row in rows), 1)
        self.assertLess([r['operation'] for r in rows].index('headers-arrived'),
                        [r['operation'] for r in rows].index('body-complete'))

    def test_chunked_body_and_missing_response_mime(self):
        self.server.cases['case']['fixture']['backend']['headers'] = []
        wire = self.exchange(b'PUT / HTTP/1.1\r\nHost: example.test\r\n'
            b'X-I12-Acceptance-Key: case\r\nTransfer-Encoding: chunked\r\n\r\n'
            b'2;fixture=yes\r\nab\r\n1\r\nc\r\n0\r\n\r\n')
        self.assertTrue(wire.endswith(b'abcdef'))
        self.assertNotIn(b'Content-Type:', wire)
        self.assertEqual((self.root / 'case.request-body.raw').read_bytes(), b'abc')

    def test_ambiguous_framing_is_rejected_before_case_or_body(self):
        for framing in (b'Content-Length: 1\r\nContent-Length: 1\r\n',
                        b'Content-Length: 1\r\nTransfer-Encoding: chunked\r\n',
                        b'Transfer-Encoding: gzip\r\n', b'Content-Length: +1\r\n'):
            with self.subTest(framing=framing):
                response = self.exchange(b'POST / HTTP/1.1\r\n'
                    b'X-I12-Acceptance-Key: case\r\n' + framing + b'\r\n')
                self.assertTrue(response.startswith(b'HTTP/1.1 400 Bad Request\r\n'))
        self.assertFalse((self.root / 'case.request-body.raw').exists())
        self.assertNotIn('headers-arrived', [row['operation'] for row in self.receipts()])

    def test_invalid_and_oversized_lines_are_rejected(self):
        for wire in (b'GET / HTTP/1.0\r\n\r\n', b'GET / HTTP/1.1\n\n',
                     b'GET / HTTP/1.1\r\n Folded: value\r\n\r\n',
                     b'GET /' + b'a' * 8192 + b' HTTP/1.1\r\n\r\n'):
            with self.subTest(size=len(wire)):
                self.assertTrue(self.exchange(wire).startswith(b'HTTP/1.1 400 Bad Request\r\n'))

    def test_bad_chunk_is_recorded_without_complete_body_or_response(self):
        wire = self.exchange(b'POST / HTTP/1.1\r\nX-I12-Acceptance-Key: case\r\n'
            b'Transfer-Encoding: chunked\r\n\r\n+1\r\na\r\n0\r\n\r\n')
        self.assertEqual(wire, b'')
        operations = [row['operation'] for row in self.receipts()]
        self.assertIn('body-incomplete', operations)
        self.assertNotIn('body-complete', operations)
        self.assertNotIn('response-complete', operations)

    def test_connection_closes_after_one_response_and_retains_custom_status(self):
        self.server.cases['case']['fixture']['backend']['status'] = 499
        request = b'GET / HTTP/1.1\r\nX-I12-Acceptance-Key: case\r\n\r\n'
        wire = self.exchange(request + request)
        self.assertTrue(wire.startswith(b'HTTP/1.1 499 \r\n'))
        self.assertEqual(wire.count(b'HTTP/1.1'), 1)
        self.assertEqual(sum(row['operation'] == 'headers-arrived'
                             for row in self.receipts()), 1)

    def test_excessive_header_count_and_body_capacity_fail_explicitly(self):
        wire = self.exchange(b'GET / HTTP/1.1\r\n' + b'X-Extra: x\r\n' * 101 + b'\r\n')
        self.assertTrue(wire.startswith(b'HTTP/1.1 400 Bad Request\r\n'))
        wire = self.exchange(b'POST / HTTP/1.1\r\nX-I12-Acceptance-Key: case\r\n'
            b'Content-Length: 8388609\r\n\r\n')
        self.assertEqual(wire, b'')
        operations = [row['operation'] for row in self.receipts()]
        self.assertIn('request-rejected', operations)
        self.assertIn('body-incomplete', operations)
        self.assertNotIn('body-complete', operations)

    def test_authority_aliases_and_backslashes_are_rejected_before_body(self):
        for target in (b'//other.test/path', b'/path\\alias', b'/path\x00', b'/path\x7f'):
            with self.subTest(target=target):
                wire = self.exchange(b'GET ' + target + b' HTTP/1.1\r\n'
                    b'X-I12-Acceptance-Key: case\r\n\r\n')
                self.assertTrue(wire.startswith(b'HTTP/1.1 400 Bad Request\r\n'))
        self.assertFalse((self.root / 'case.request-body.raw').exists())

    def test_invalid_response_header_never_writes_field_bytes(self):
        handler = object.__new__(self.backend.Handler)
        handler.wfile = io.BytesIO()
        for name, value in (('', 'value'), ('Invalid Name', 'value'), ('X:bad', 'value'),
                            ('X-Name', 'bad\r\nInjected: yes'), ('X-Name', 'bad\x00'),
                            ('X-Name', 'bad\t'), ('X-Name', 'bad\x7f')):
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                handler.send_header(name, value)
        self.assertEqual(handler.wfile.getvalue(), b'')

    def test_expect_continue_is_flushed_before_client_sends_body(self):
        with socket.create_connection(self.server.server_address, timeout=2) as connection:
            connection.sendall(b'POST / HTTP/1.1\r\nX-I12-Acceptance-Key: case\r\n'
                b'Content-Length: 4\r\nExpect: 100-continue\r\n\r\n')
            interim = bytearray()
            while not interim.endswith(b'\r\n\r\n'):
                part = connection.recv(1)
                self.assertTrue(part, 'EOF before interim response')
                interim.extend(part)
            self.assertEqual(interim, b'HTTP/1.1 100 Continue\r\n\r\n')
            connection.sendall(b'body')
            connection.shutdown(socket.SHUT_WR)
            final = bytearray()
            while True:
                part = connection.recv(8192)
                if not part:
                    break
                final.extend(part)
        self.assertTrue(final.startswith(b'HTTP/1.1 201 Created\r\n'))
        self.assertTrue(final.endswith(b'abcdef'))
        self.assertEqual((self.root / 'case.request-body.raw').read_bytes(), b'body')

    def test_unknown_expectation_preserves_normal_response(self):
        wire = self.exchange(b'POST / HTTP/1.1\r\nX-I12-Acceptance-Key: case\r\n'
            b'Content-Length: 4\r\nExpect: fixture-extension\r\n\r\nbody')
        self.assertTrue(wire.startswith(b'HTTP/1.1 201 Created\r\n'))
        self.assertNotIn(b'100 Continue', wire)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
