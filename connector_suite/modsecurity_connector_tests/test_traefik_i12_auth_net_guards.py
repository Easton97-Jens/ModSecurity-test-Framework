"""Exercise the physical fixture's fixed HTTP, path and child-command boundaries."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import io
from email.message import Message
import os
from pathlib import Path
import socket
import threading
from types import SimpleNamespace
import unittest
from unittest import mock


HARNESS = connector_root() / 'connectors/traefik/harness/i12_auth'


def load(name):
    module = load_source(HARNESS / (name + '.py'))
    return module


class NetBoundaries(unittest.TestCase):
    def setUp(self):
        self.net = load('acceptance_net')
        self.signal = load('acceptance_signal')
        self.root = Path('/task/cases/ac-' + 'a' * 20)

    def test_authorization_sample_labels_cannot_choose_paths(self):
        self.assertEqual(self.net.authorization_sample_path(self.root, 'readiness-9'),
                         self.root / 'auth-readiness-9.sample.raw')
        for label in ('../escape', '/other', 'readiness-10', 'sequence-3'):
            with self.assertRaises(ValueError):
                self.net.authorization_sample_path(self.root, label)

    def test_relay_refuses_api_paths_outside_fixed_authorization_endpoint(self):
        relay = object.__new__(self.net.Relay)
        relay.path = '/other-native-api'
        relay.send_error = mock.Mock()
        relay.forward()
        relay.send_error.assert_called_once_with(404)

    def test_relay_uses_fixed_native_api_and_preserves_forwarded_original_uri(self):
        relay = object.__new__(self.net.Relay)
        relay.path = '/authorize'
        relay.command = 'POST'
        relay.root = self.root
        relay.engine_port = 18081
        relay.spec = {'probe_id': 'sample', 'fixture': {'request': {}}}
        relay.headers = Message()
        relay.headers['X-Forwarded-Uri'] = '/original?inspection=1'
        relay.rfile = io.BytesIO(b'')
        relay.relay_response = mock.Mock()
        upstream = mock.Mock()
        upstream.getresponse.return_value.status = 403
        upstream.getresponse.return_value.read.return_value = b'deny'
        with mock.patch.object(self.net, 'loopback_connection', return_value=upstream), \
                mock.patch.object(self.net, 'authorization_sample_path'), \
                mock.patch.object(self.net, 'dump'):
            relay.forward()
        upstream.putrequest.assert_called_once_with('POST', '/authorize', skip_host=True, skip_accept_encoding=True)
        upstream.putheader.assert_any_call('X-Forwarded-Uri', '/original?inspection=1')
        self.assertEqual(relay.relay_response.call_args.args[1], b'deny')

    def test_socket_pair_requires_fixed_paths_and_private_owned_directory(self):
        observer = self.root / 'sockets/observer.sock'
        native = self.root / 'sockets/companion.sock'
        observer_argument = str(observer)
        native_argument = str(native)
        with mock.patch.object(Path, 'resolve', autospec=True, side_effect=lambda path, **_: path), \
                mock.patch.object(Path, 'is_dir', return_value=True), \
                mock.patch.object(Path, 'is_symlink', return_value=False), \
                mock.patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=os.geteuid(), st_mode=0o40700)):
            self.assertEqual(self.net.companion_paths(self.root, observer_argument, native_argument),
                             (observer, native))
            with self.assertRaises(ValueError):
                self.net.companion_paths(self.root, '/other/observer.sock', native_argument)
            with mock.patch.object(Path, 'is_symlink', return_value=True):
                with self.assertRaises(ValueError):
                    self.net.companion_paths(self.root, observer_argument, native_argument)
            with mock.patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=os.geteuid(), st_mode=0o40777)):
                with self.assertRaises(ValueError):
                    self.net.companion_paths(self.root, observer_argument, native_argument)

    def test_signal_child_command_is_built_from_validated_case(self):
        with mock.patch.object(self.signal, 'validate_case', return_value={}) as validate:
            argv = self.signal.client_arguments(self.root, 18081)
        validate.assert_called_once_with(self.root, 18081)
        self.assertEqual(argv, ['/usr/local/bin/python3', '-P', '/mnt/fixtures/acceptance_net.py',
                               'client', '--spec', str(self.root / 'case.json'),
                               '--root', str(self.root), '--port', '18081'])
        with mock.patch.object(self.signal, 'validate_case', side_effect=ValueError('unadmitted')), \
                mock.patch.object(self.signal.os, 'fork') as fork:
            with self.assertRaises(ValueError):
                self.signal.start_client(self.root, 18081)
        fork.assert_not_called()

    def test_loopback_server_keeps_plain_http_wire_semantics(self):
        class Handler(self.net.EvidenceRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '3')
                self.end_headers()
                self.wfile.write(b'ok\n')

            def log_message(self, *_):
                return

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        server = self.net.LoopbackEvidenceServer(port, Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        try:
            self.assertEqual(server.server_address[0], '127.0.0.1')
            with socket.create_connection(('127.0.0.1', port), timeout=2) as connection:
                connection.sendall(b'GET /physical-http HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
                response = bytearray()
                while True:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)
            self.assertTrue(bytes(response).startswith(b'HTTP/1.1 200 OK\r\n'))
            self.assertTrue(bytes(response).endswith(b'\r\n\r\nok\n'))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive(), 'fixture accept loop must terminate')
        self.assertEqual(server.fileno(), -1, 'fixture listener must be closed')

    def parsed_request(self, raw):
        handler = object.__new__(self.net.EvidenceRequestHandler)
        handler.rfile = io.BytesIO(raw)
        handler.wfile = io.BytesIO()
        handler.raw_requestline = handler.rfile.readline()
        return handler, handler.parse_request()

    def test_parser_preserves_duplicate_order_and_leaves_chunk_wire_unread(self):
        payload = b'3\r\nabc\r\n0\r\n\r\n'
        handler, accepted = self.parsed_request(
            b'POST /authorize?sample=1 HTTP/1.1\r\nX-Probe: one\r\nx-probe: two\r\n'
            b'Transfer-Encoding: chunked\r\n\r\n' + payload)
        self.assertTrue(accepted)
        self.assertEqual(handler.headers.get_all('X-Probe'), ['one', 'two'])
        self.assertEqual(list(handler.headers.raw_items())[:2], [('X-Probe', 'one'), ('x-probe', 'two')])
        self.assertEqual(handler.rfile.read(), payload)
        self.assertFalse(handler.close_connection)

    def test_parser_rejects_invalid_or_unbounded_heads_with_single_response(self):
        malformed = [
            b'GET http://external/ HTTP/1.1\r\n\r\n',
            b'GET //external/ HTTP/1.1\r\n\r\n',
            b'GET / HTTP/2.0\r\n\r\n',
            b'GET / HTTP/1.1\n\n',
            b'GET / HTTP/1.1\r\n Bad-Fold: value\r\n\r\n',
            b'GET / HTTP/1.1\r\nX: bad\x00value\r\n\r\n',
            b'GET / HTTP/1.1\r\nX: ' + b'a' * 65536 + b'\r\n\r\n',
            b'GET / HTTP/1.1\r\n' + b'X: a\r\n' * 101 + b'\r\n',
        ]
        for request in malformed:
            with self.subTest(request=request[:80]):
                handler, accepted = self.parsed_request(request)
                self.assertFalse(accepted)
                self.assertTrue(handler.close_connection)
                self.assertEqual(handler.wfile.getvalue().count(b'HTTP/1.1 400 '), 1)

    def test_expect_continue_precedes_body_and_invalid_expectation_closes(self):
        handler, accepted = self.parsed_request(
            b'POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nabc')
        self.assertTrue(accepted)
        self.assertEqual(handler.wfile.getvalue(), b'HTTP/1.1 100 Continue\r\n\r\n')
        self.assertEqual(handler.rfile.read(), b'abc')
        handler, accepted = self.parsed_request(b'POST / HTTP/1.1\r\nExpect: other\r\n\r\n')
        self.assertFalse(accepted)
        self.assertTrue(handler.wfile.getvalue().startswith(b'HTTP/1.1 417 '))
        self.assertTrue(handler.close_connection)

    def test_response_preserves_nonstandard_status_and_rejects_injection(self):
        handler, accepted = self.parsed_request(b'GET / HTTP/1.1\r\n\r\n')
        self.assertTrue(accepted)
        handler.send_response(499)
        handler.send_header('Content-Length', '0')
        handler.end_headers()
        self.assertTrue(handler.wfile.getvalue().startswith(b'HTTP/1.1 499 \r\n'))
        for status in (True, 99, 1000, '403'):
            with self.assertRaises(ValueError):
                handler.send_response(status)
        with self.assertRaises(ValueError):
            handler.send_response(200, 'OK\r\nInjected: yes')
        with self.assertRaises(ValueError):
            handler.send_header('X-Probe', 'ok\r\nInjected: yes')

    def test_connection_tokens_are_case_insensitive_and_close_wins(self):
        handler, accepted = self.parsed_request(
            b'GET / HTTP/1.1\r\nConnection: Keep-Alive, CLOSE \r\n\r\n')
        self.assertTrue(accepted)
        self.assertTrue(handler.close_connection)
        handler, accepted = self.parsed_request(
            b'GET / HTTP/1.0\r\nConnection: upgrade, Keep-Alive \r\n\r\n')
        self.assertTrue(accepted)
        self.assertFalse(handler.close_connection)

    def test_rejected_head_records_failure_and_never_dispatches(self):
        handler = object.__new__(self.net.EvidenceRequestHandler)
        handler.root = self.root
        handler.rfile = io.BytesIO(b'GET //external/ HTTP/1.1\r\n\r\n')
        handler.wfile = io.BytesIO()
        handler.do_GET = mock.Mock()
        with mock.patch.object(self.net, 'dump') as dump:
            handler.handle()
        handler.do_GET.assert_not_called()
        self.assertEqual(dump.call_args.args[1], self.net.AUTH_LOG)
        self.assertEqual(dump.call_args.args[2]['event'], 'http_request_rejected')
        self.assertEqual(handler.wfile.getvalue().count(b'HTTP/1.1 400 '), 1)

    def test_request_line_read_failure_retains_zero_byte_receipt(self):
        for error in (TimeoutError('timeout'), OSError('read failure')):
            with self.subTest(error=type(error).__name__):
                handler = object.__new__(self.net.EvidenceRequestHandler)
                handler.root = self.root
                handler.rfile = mock.Mock()
                handler.rfile.readline.side_effect = error
                handler.wfile = io.BytesIO()
                with mock.patch.object(self.net, 'dump') as dump:
                    handler.handle()
                dump.assert_called_once()
                receipt = dump.call_args.args[2]
                self.assertEqual(receipt['event'], 'http_connection_error')
                self.assertEqual(receipt['error'], type(error).__name__)
                self.assertEqual(receipt['request_line_bytes'], 0)
                self.assertTrue(handler.close_connection)
                self.assertEqual(handler.wfile.getvalue(), b'')

    def test_production_accept_loop_dispatches_and_closes_listener_on_termination(self):
        server = mock.Mock()
        request = object()
        address = ('127.0.0.1', 18081)
        server.get_request.side_effect = [(request, address), SystemExit(0)]
        server.verify_request.return_value = True
        with self.assertRaises(SystemExit):
            self.net.serve_private_http(server)
        server.verify_request.assert_called_once_with(request, address)
        server.process_request.assert_called_once_with(request, address)
        server.shutdown_request.assert_not_called()  # The dispatched worker owns shutdown.
        server.server_close.assert_called_once_with()

    def test_production_accept_loop_rejects_socket_without_dispatch(self):
        server = mock.Mock()
        request = object()
        address = ('127.0.0.1', 18081)
        server.get_request.side_effect = [(request, address), SystemExit(0)]
        server.verify_request.return_value = False
        with self.assertRaises(SystemExit):
            self.net.serve_private_http(server)
        server.process_request.assert_not_called()
        server.shutdown_request.assert_called_once_with(request)
        server.server_close.assert_called_once_with()

    def test_production_accept_loop_closes_socket_and_records_dispatch_error(self):
        for operation in ('verify_request', 'process_request'):
            with self.subTest(operation=operation):
                server = mock.Mock()
                request = object()
                address = ('127.0.0.1', 18081)
                server.get_request.side_effect = [(request, address), SystemExit(0)]
                server.verify_request.return_value = True
                getattr(server, operation).side_effect = OSError('dispatch failure')
                with self.assertRaises(SystemExit):
                    self.net.serve_private_http(server)
                server.handle_error.assert_called_once_with(request, address)
                server.shutdown_request.assert_called_once_with(request)
                server.server_close.assert_called_once_with()

    def test_production_accept_loop_retries_accept_error_and_closes_on_interrupt(self):
        server = mock.Mock()
        request = object()
        address = ('127.0.0.1', 18081)
        server.get_request.side_effect = [OSError('accept failure'), (request, address)]
        server.verify_request.return_value = True
        server.process_request.side_effect = KeyboardInterrupt()
        with mock.patch.object(self.net.time, 'sleep') as sleep:
            with self.assertRaises(KeyboardInterrupt):
                self.net.serve_private_http(server)
        sleep.assert_called_once_with(0.01)
        server.shutdown_request.assert_called_once_with(request)
        server.server_close.assert_called_once_with()
        server.handle_error.assert_not_called()

    def test_persistent_connection_keeps_body_framing_and_then_ends(self):
        net = self.net
        receipts = []

        class Handler(net.EvidenceRequestHandler):
            def do_POST(self):
                entity, wire, framing = net.read_backend_body(self.rfile, self.headers)
                receipts.append((entity, wire, framing))
                self.send_response(200)
                self.send_header('Content-Length', str(len(entity)))
                self.send_header('Connection', self.headers.get('Connection'))
                self.end_headers()
                self.wfile.write(entity)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        server = net.LoopbackEvidenceServer(port, Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
        thread.start()
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=2) as connection:
                stream = connection.makefile('rb')
                try:
                    connection.sendall(b'POST /one HTTP/1.1\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\r\nabc')
                    self.assertEqual(self.read_wire_response(stream), b'abc')
                    connection.sendall(b'POST /two HTTP/1.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nde\r\n0\r\n\r\n')
                    self.assertEqual(self.read_wire_response(stream), b'de')
                    self.assertEqual(stream.read(1), b'')
                finally:
                    stream.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual([receipt[0] for receipt in receipts], [b'abc', b'de'])
        self.assertEqual(receipts[1][1], b'2\r\nde\r\n0\r\n\r\n')
        self.assertTrue(all(receipt[2]['http_eos'] for receipt in receipts))

    def read_wire_response(self, stream):
        self.assertEqual(stream.readline(), b'HTTP/1.1 200 OK\r\n')
        headers = Message()
        while True:
            line = stream.readline()
            if line == b'\r\n':
                break
            self.assertTrue(line, 'response headers must terminate')
            name, value = line.decode('latin1').split(':', 1)
            headers[name] = value.strip()
        return stream.read(int(headers['Content-Length']))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == '__main__':
    unittest.main()
