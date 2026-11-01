"""Backend fixture wire regressions; these are not Apache lifecycle evidence."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import base64
import hashlib
import importlib.util
import io
import multiprocessing
import os
from pathlib import Path
import socket
import tempfile
import time
from unittest import mock
import unittest

SOURCE = connector_root() / 'ci/runtime/lifecycle/apache-i12/acceptance/backend.py'
BACKEND = load_source(SOURCE)


def blob(data):
    return {'data': base64.b64encode(data).decode(), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


class BackendWireTests(unittest.TestCase):
    def test_chunked_wire_retains_chunk_boundaries_and_one_terminator(self):
        class Handler:
            wfile = io.BytesIO()

        selected = {'body': blob(b'onetwo'), 'chunks': [blob(b'one'), blob(b'two')]}
        chunks, payload = BACKEND.response_chunks(selected)
        events = []
        handler = Handler()
        BACKEND.write_response_body(handler, selected, chunks, True, 'principal', Path('.'), events.append)
        self.assertEqual(handler.wfile.getvalue(), b'3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n')
        self.assertEqual(payload, b'onetwo')
        self.assertEqual([row['chunk_index'] for row in events], [0, 1])
        self.assertEqual([row['request_id'] for row in events], ['principal', 'principal'])

    def test_mismatched_declared_body_is_rejected_before_wire_write(self):
        selected = {'body': blob(b'one'), 'chunks': [blob(b'two')]}
        with self.assertRaisesRegex(ValueError, 'chunks do not equal'):
            BACKEND.response_chunks(selected)

    def test_empty_body_keeps_no_data_chunks(self):
        self.assertEqual(BACKEND.response_chunks({'body': blob(b'')}), ([], b''))
        self.assertTrue(BACKEND.valid_token('principal_1-A'))
        for token in ('', 'a' * 257, 'a b', 'ä', 'a\r\nb'):
            self.assertFalse(BACKEND.valid_token(token))

    def test_backend_rejects_nonprivate_port(self):
        self.assertEqual(BACKEND.private_loopback_port('18123'), 18123)
        self.assertEqual(BACKEND.private_loopback_port(18123), 18123)
        for value in (443, '443', True, '18123 ', '١٨١٢٣', object()):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'private loopback port'):
                BACKEND.private_loopback_port(value)

    def test_listener_rejects_nonloopback_address_before_binding(self):
        listener = object.__new__(BACKEND.PrivateLoopbackHTTPServer)
        for address in ('0.0.0.0', 'localhost', '192.0.2.1', '::1'):
            listener.server_address = (address, 18123)
            with self.subTest(address=address), self.assertRaisesRegex(ValueError, 'literal private loopback'):
                listener.server_bind()

    def test_listener_admits_only_private_loopback_port(self):
        listener = object.__new__(BACKEND.PrivateLoopbackHTTPServer)
        listener.server_address = ('127.0.0.1', 443)
        with self.assertRaisesRegex(ValueError, 'private loopback port'):
            listener.server_bind()
        listener.server_address = ('127.0.0.1', 18123)
        with mock.patch.object(BACKEND.socketserver.ThreadingTCPServer, 'server_bind') as bind:
            listener.server_bind()
        bind.assert_called_once_with()

    def test_private_listener_preserves_real_http_request_and_response(self):
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        plan = {'request': {'path': '/principal'}, 'controls': [], 'backend': {
            'status': 200, 'headers': [['Content-Type', 'text/plain']],
            'body': blob(b'physical-body'), 'chunks': [], 'framing': 'content_length'}}
        base = Path(os.environ.get('CODEX_TEST_TMP_ROOT', '/var/tmp/codex/ModSecurity-conector'))
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='apache-backend-wire-', dir=base) as temporary:
            process = multiprocessing.get_context('fork').Process(
                target=BACKEND.serve, args=(plan, Path(temporary), port))
            process.start()
            try:
                deadline = time.monotonic() + 5
                while True:
                    try:
                        client = socket.create_connection(('127.0.0.1', port), timeout=1)
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.01)
                with client:
                    client.sendall(b'GET /principal HTTP/1.1\r\nHost: localhost\r\n'
                                   b'X-I12-ID: principal\r\nConnection: close\r\n\r\n')
                    response = bytearray()
                    while chunk := client.recv(4096):
                        response.extend(chunk)
                self.assertTrue(response.startswith(b'HTTP/1.1 200 OK\r\n'))
                self.assertTrue(response.endswith(b'\r\n\r\nphysical-body'))
                self.assertIn('backend_eos_write', (Path(temporary) / 'requests.jsonl').read_text())
            finally:
                process.terminate()
                process.join(5)
                if process.is_alive():
                    process.kill()
                    process.join(5)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
