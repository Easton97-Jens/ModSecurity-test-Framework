"""Strict raw framing proof, independent of client-decoded metadata."""
import importlib.util
from pathlib import Path
import unittest


class FramingParserTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).parents[1] / "runners/nginx_http11_framing.py"
        spec = importlib.util.spec_from_file_location("wire_parser", path)
        self.parser = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.parser)

    def test_actual_content_length_and_chunked_decode_identically(self):
        content_length = b"HTTP/1.1 200 OK\r\nContent-Length: 22\r\n\r\ntransport fixture body"
        chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\ntransport\r\nd\r\n fixture body\r\n0\r\n\r\n"
        for raw, framing in ((content_length, "content_length"), (chunked, "chunked")):
            value = self.parser.parse_http11_response(raw)
            self.assertEqual(value["body"], b"transport fixture body")
            self.assertEqual(value["framing"], framing)
            self.assertEqual(value["http_version"], 11)

    def test_ambiguous_incomplete_or_non_http11_framing_is_rejected(self):
        invalid = [
            b"HTTP/1.0 200 OK\r\nContent-Length: 22\r\n\r\ntransport fixture body",
            b"HTTP/1.1 200 OK\r\nContent-Length: 22\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 22\r\nContent-Length: 22\r\n\r\ntransport fixture body",
            b"HTTP/1.1 200 OK\r\nContent-Length: 23\r\n\r\ntransport fixture body",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n16\r\ntransport fixture body\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n16\r\ntransport fixture body\r\n0\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n16\r\ntransport fixture body\r\n0\r\n\r\nextra",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        ]
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.parser.parse_http11_response(raw)

    def test_capture_limits_are_enforced_before_parsing(self):
        for raw in (b"x" * 32769, b"HTTP/1.1 200 OK\r\nX: " + b"x" * 8192 + b"\r\n\r\n"):
            with self.assertRaises(ValueError):
                self.parser.parse_http11_response(raw)


if __name__ == "__main__":
    unittest.main()
