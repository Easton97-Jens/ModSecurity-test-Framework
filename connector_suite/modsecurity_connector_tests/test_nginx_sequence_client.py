"""The sequence client must prove reuse without silently reconnecting."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
from pathlib import Path
import socketserver
import threading
import unittest
from unittest.mock import Mock, patch

CLIENT = load_source(connector_root() / 'ci/runtime/lifecycle/nginx_sequence_client.py')


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.server.connections += 1
        for _ in range(3):
            first = self.rfile.readline(4096)
            if not first:
                return
            headers = []
            while True:
                line = self.rfile.readline(4096)
                if line == b"\r\n":
                    break
                headers.append(line)
            code = 403 if b"X-Modsec-Smoke: block\r\n" in headers else 200
            mode = b"close" if self.server.force_close else b"keep-alive"
            length = b"3" if self.server.partial else b"2"
            self.wfile.write(b"HTTP/1.1 " + str(code).encode() + b" Test\r\nContent-Length: " + length + b"\r\nConnection: " + mode + b"\r\n\r\nok")
            self.wfile.flush()
            if self.server.force_close or b"Connection: close\r\n" in headers:
                return


class ClientTests(unittest.TestCase):
    def server(self, close=False, partial=False):
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        server.force_close = close
        server.partial = partial
        server.connections = 0
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def test_actual_three_requests_use_one_connection(self):
        server = self.server()
        actual = CLIENT.run_sequence(server.server_address[1], ["/no-crs/sequence/0", "/no-crs/sequence/1", "/no-crs/sequence/2"], (200, 403, 200), keepalive=True)
        self.assertEqual([row["observed_status"] for row in actual], [200, 403, 200])
        self.assertEqual(server.connections, 1)

    def test_close_is_not_repaired_by_hidden_reconnect(self):
        server = self.server(close=True)
        with self.assertRaisesRegex(ValueError, "closed the connection"):
            CLIENT.run_sequence(server.server_address[1], ["/no-crs/sequence/0", "/no-crs/sequence/1"], (200, 200), keepalive=True)
        self.assertEqual(server.connections, 1)

    def test_sequential_independent_connections_are_distinct(self):
        server = self.server()
        CLIENT.run_sequence(server.server_address[1], ["/no-crs/sequence/0", "/no-crs/sequence/1"], (200, 200), keepalive=False)
        self.assertEqual(server.connections, 2)

    def test_path_injection_is_rejected_before_connection(self):
        with self.assertRaises(ValueError):
            CLIENT.run_sequence(19000, ["/x\r\nX: y"], (200,), keepalive=True)

    def test_actual_unclosed_partial_content_length_is_not_accepted(self):
        server = self.server(close=True, partial=True)
        with self.assertRaisesRegex(ValueError, "bounded complete HTTP message"):
            CLIENT.run_sequence(server.server_address[1], ["/no-crs/sequence/0"],
                                (200,), keepalive=False, expect_first_abort=True)
        self.assertEqual(server.connections, 1)

    def test_body_accounting_keeps_pre_read_declared_length(self):
        class ClosedResponse:
            length = 3

            def read(self, amount):
                self.length = 1
                return b"ok"

            def isclosed(self):
                return True

        response = ClosedResponse()
        body, aborted = CLIENT.read_response_body(response, 65536, True, response.length)
        self.assertEqual(body, b"ok")
        self.assertTrue(aborted)
        self.assertEqual(response.length, 1)

    def test_complete_actual_response_cannot_satisfy_expected_abort(self):
        server = self.server(close=True)
        with self.assertRaisesRegex(ValueError, "strict abort requires"):
            CLIENT.run_sequence(server.server_address[1], ["/no-crs/sequence/0"],
                                (200,), keepalive=False, expect_first_abort=True)

    def test_observation_snapshots_declared_length_before_callback_and_read(self):
        order = []
        response = Mock(length=3, chunked=False, status=200, version=11, will_close=True)

        def read(amount):
            order.append(("read", amount))
            response.length = 1
            return b"ok"

        response.read.side_effect = read
        response.isclosed.return_value = True
        response.begin.side_effect = lambda: order.append("headers")
        response.close.side_effect = lambda: order.append("close")
        callback = lambda index: order.append(("callback", index))
        delay = lambda seconds: order.append(("delay", seconds))
        with patch.object(CLIENT.http.client, "HTTPResponse", return_value=response), \
                patch.object(CLIENT.time, "sleep", side_effect=delay):
            actual, close = CLIENT.observe_response(object(), 0, "/no-crs/sequence/0",
                headers_seen=callback, expect_first_abort=True, backpressure=True)
        self.assertEqual(actual["declared_length"], 3)
        self.assertEqual(actual["transport_result"], "connection_aborted")
        self.assertTrue(close)
        self.assertEqual(order, ["headers", ("callback", 0), ("delay", 0.25),
                                 ("read", 262145), "close"])

    def test_partial_abort_controls_keep_body_closed_and_first_response_guards(self):
        controls = (
            (b"ok", True, 0, True),
            (b"", True, 0, True),
            (b"ok", False, 0, True),
            (b"ok", True, 1, True),
            (b"ok", True, 0, False),
        )
        for partial, closed, index, allowed in controls:
            with self.subTest(partial=partial, closed=closed, index=index, allowed=allowed):
                response = Mock(length=None, chunked=True, status=200, version=11, will_close=True)
                response.read.side_effect = CLIENT.http.client.IncompleteRead(partial, 4)
                response.isclosed.return_value = closed
                with patch.object(CLIENT.http.client, "HTTPResponse", return_value=response):
                    if partial and closed and index == 0 and allowed:
                        actual, _ = CLIENT.observe_response(object(), index, "/no-crs/sequence/0",
                            headers_seen=None, expect_first_abort=allowed, backpressure=False)
                        self.assertEqual(actual["framing"], "chunked")
                        self.assertEqual(actual["transport_result"], "connection_aborted")
                    else:
                        with self.assertRaises((ValueError, CLIENT.http.client.IncompleteRead)):
                            CLIENT.observe_response(object(), index, "/no-crs/sequence/0",
                                headers_seen=None, expect_first_abort=allowed, backpressure=False)

    def test_body_limit_rejects_oversize_without_promoting_abort(self):
        for limit in (65536, 262144):
            with self.subTest(limit=limit):
                response = Mock()
                response.read.return_value = b"x" * (limit + 1)
                response.isclosed.return_value = True
                with self.assertRaisesRegex(ValueError, "bounded complete HTTP message"):
                    CLIENT.read_response_body(response, limit, True, limit + 2)

    def test_callback_failure_closes_original_socket_without_reconnecting(self):
        connection = Mock()
        response = Mock(length=2, chunked=False)
        callback = Mock(side_effect=ValueError("controlled callback failure"))
        with patch.object(CLIENT.socket, "socket", return_value=connection) as socket_factory, \
                patch.object(CLIENT.http.client, "HTTPResponse", return_value=response):
            with self.assertRaisesRegex(ValueError, "controlled callback failure"):
                CLIENT.run_sequence(19000, ["/no-crs/sequence/0"], (200,),
                                    keepalive=True, headers_seen=callback)
        socket_factory.assert_called_once_with()
        connection.close.assert_called_once_with()
        response.read.assert_not_called()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
