"""A raw socket capture must retain actual HTTP framing bytes."""
import socketserver
import threading
import unittest

from tests import test_nginx_sequence_client as client_tests
from tests import test_nginx_sequence_driver as driver_tests


class WireHandler(socketserver.StreamRequestHandler):
    def handle(self):
        lines = []
        while True:
            line = self.rfile.readline(4096)
            if not line:
                return
            lines.append(line)
            if line == b"\r\n":
                break
        self.server.received_request = b"".join(lines)
        for fragment in self.server.fragments:
            self.wfile.write(fragment)
            self.wfile.flush()


class WireClientTests(unittest.TestCase):
    def capture(self, fragments):
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), WireHandler)
        server.daemon_threads = True
        server.fragments = fragments
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = client_tests.CLIENT.capture_http11_wire(server.server_address[1], "/no-crs/sequence/owned/0")
            return result, server.received_request
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_actual_content_length_wire_is_preserved(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: 22\r\nConnection: close\r\n\r\ntransport fixture body"
        (request, response), received = self.capture([raw[:30], raw[30:]])
        self.assertEqual(response, raw)
        self.assertEqual(request, received)
        self.assertIn(b"HTTP/1.1\r\n", request)

    def test_actual_chunk_boundaries_and_terminal_chunk_are_preserved(self):
        raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n9\r\ntransport\r\nd\r\n fixture body\r\n0\r\n\r\n"
        (request, response), received = self.capture([raw[:73], raw[73:88], raw[88:]])
        self.assertEqual(response, raw)
        self.assertEqual(request, received)

    def test_oversized_wire_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "bounded"):
            self.capture([b"x" * 32769])

    def test_real_chunked_origin_receipt_tracks_received_request_and_written_wire(self):
        origin = driver_tests.DRIVER.FramingUpstream("/no-crs/sequence/owned/0")
        origin.start()
        try:
            request, response = client_tests.CLIENT.capture_http11_wire(origin.port, "/no-crs/sequence/owned/0")
            observed = origin.observation()
            self.assertEqual(observed["request_hex"], request.hex())
            self.assertEqual(observed["response_hex"], response.hex())
            self.assertEqual(observed["request_count"], 1)
            self.assertTrue(observed["write_complete"])
            self.assertFalse(observed["upstream_write_failed"])
            self.assertIn(b"Transfer-Encoding: chunked\r\n", response)
            self.assertTrue(response.endswith(b"0\r\n\r\n"))
        finally:
            origin.stop()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
