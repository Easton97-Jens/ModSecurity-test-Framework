"""Verify wire observations against real independent loopback peers."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

CLIENT = load_source(connector_root() / 'ci/runtime/lifecycle/i12/lighttpd/diagnostic_transport.py')


class DiagnosticTransportTests(unittest.TestCase):
    def exchange(self, replies):
        seen, errors = [], []
        with tempfile.TemporaryDirectory() as temporary, socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            server.settimeout(3)
            def peer():
                try:
                    with server.accept()[0] as connection:
                        connection.settimeout(3)
                        for reply in replies:
                            request = bytearray()
                            while not request.endswith(b"\r\n\r\n"):
                                chunk = connection.recv(4096)
                                if not chunk:
                                    raise EOFError("Unexpected client close")
                                request.extend(chunk)
                            seen.append(bytes(request))
                            connection.sendall(reply)
                except (OSError, EOFError) as error:
                    errors.append(error)
            thread = threading.Thread(target=peer)
            thread.start()
            output = Path(temporary) / "client.json"
            requests = [{"path": f"/request-{index}", "wire_hex":
                f"GET /request-{index} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n".encode().hex()}
                for index in range(len(replies))]
            try:
                code = CLIENT.capture(server.getsockname()[1], requests, output)
            finally:
                thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertFalse(errors, errors)
            return code, json.loads(output.read_text()), seen, output.with_suffix(".wire").read_bytes()

    def test_three_transactions_use_one_actual_socket(self):
        replies = [f"HTTP/1.1 {status} observed\r\nContent-Length: 1\r\n\r\nx".encode()
                   for status in (200, 403, 200)]
        code, receipt, seen, wire = self.exchange(replies)
        self.assertEqual(code, 0)
        self.assertEqual([row["status"] for row in receipt["all_requests"]], [200, 403, 200])
        self.assertEqual([row["connection_reused"] for row in receipt["all_requests"]], [False, True, True])
        self.assertEqual(len({json.dumps(row["connection_identity"]) for row in receipt["all_requests"]}), 1)
        self.assertEqual(len(seen), 3)
        self.assertEqual(wire, b"".join(replies))

    def test_incomplete_body_keeps_actual_status_bytes_and_failure(self):
        reply = b"HTTP/1.1 200 observed\r\nContent-Length: 8\r\n\r\nabc"
        code, receipt, _, wire = self.exchange([reply])
        self.assertEqual((code, receipt["status"], receipt["entity_bytes"]), (1, 200, 3))
        self.assertFalse(receipt["actual_message_complete"])
        self.assertEqual(receipt["entity_sha256"], hashlib.sha256(b"abc").hexdigest())
        self.assertTrue(receipt["tcp_eof_observed"])
        self.assertEqual(wire, reply)

    def test_conflicting_actual_response_lengths_are_not_accepted(self):
        reply = b"HTTP/1.1 200 observed\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx"
        code, receipt, _, wire = self.exchange([reply])
        self.assertEqual(code, 1)
        self.assertIn("Ambiguous", receipt["error"]["message"])
        self.assertEqual(wire, reply)

    def test_intentional_abort_reaches_peer_as_tcp_reset(self):
        observed = []
        with tempfile.TemporaryDirectory() as temporary, socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            server.settimeout(3)
            def peer():
                with server.accept()[0] as connection:
                    connection.settimeout(3)
                    request = bytearray()
                    while not request.endswith(b"\r\n\r\n"):
                        request.extend(connection.recv(4096))
                    connection.sendall(b"HTTP/1.1 200 observed\r\nContent-Length: 100\r\n\r\nx")
                    try:
                        observed.append(connection.recv(1))
                    except ConnectionResetError:
                        observed.append("actual_tcp_reset")
            thread = threading.Thread(target=peer)
            thread.start()
            output = Path(temporary) / "client.json"
            request = {"path": "/abort", "abort_after_first_receive": True,
                "wire_hex": b"GET /abort HTTP/1.1\r\nHost: localhost\r\n\r\n".hex()}
            try:
                code = CLIENT.capture(server.getsockname()[1], [request], output)
            finally:
                thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(observed, ["actual_tcp_reset"])
            result = json.loads(output.read_text())
            self.assertEqual((code, result["status"]), (0, 200))
            self.assertTrue(result["intentional_client_reset"])
            self.assertFalse(result["actual_message_complete"])
            self.assertFalse(result["tcp_reset_observed"])
            self.assertLessEqual(result["first_response_recv_completed_ns"], result["actual_reset_socket_close_completed_ns"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
