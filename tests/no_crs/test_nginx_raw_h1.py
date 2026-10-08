"""Closed H1 fault inputs and retained native-host receipt controls, not E2E."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/runners"))
import nginx_raw_h1 as raw_h1


class NginxRawH1Test(unittest.TestCase):
    def test_exact_closed_malformed_inputs(self):
        expected = {
            "invalid_content_length": b"Content-Length: not-a-number\r\n",
            "conflicting_content_length": b"Content-Length: 1\r\nContent-Length: 2\r\n",
            "duplicate_transfer_encoding": b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
            "content_length_overflow": b"Content-Length: 18446744073709551616\r\n",
        }
        self.assertEqual(set(raw_h1.RECORD_IDS), set(expected))
        for case_id, fault in expected.items():
            with self.subTest(case_id=case_id):
                wire = raw_h1.request_bytes(case_id, "unit-run")
                self.assertIn(fault, wire)
                self.assertIn(raw_h1.request_path(case_id, "unit-run").encode(), wire)
                self.assertLess(len(wire), 1024)
                control = raw_h1.request_bytes(case_id, "unit-run", control=True)
                self.assertNotIn(fault, control)
                self.assertIn(b"Content-Length: 1\r\n", control)

    def test_untrusted_identity_cannot_change_wire_or_operation(self):
        for case_id in ("unknown", "../invalid_content_length", None):
            with self.assertRaises(ValueError):
                raw_h1.request_bytes(case_id, "unit-run")
        for run_id in ("", "x\r\nInjected: yes", "../x", "a" * 129, None):
            with self.assertRaises(ValueError):
                raw_h1.request_bytes("invalid_content_length", run_id)

    def test_host_rejection_is_not_inferred_from_status_alone(self):
        case_id, run_id = "invalid_content_length", "unit-run"
        response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        access = {"method": "POST", "uri": raw_h1.request_path(case_id, run_id), "status": 400}
        diagnostic = b'client sent invalid "Content-Length" header'
        self.assertEqual(raw_h1.validate_host_rejection(case_id, run_id, response, access, diagnostic), [])
        self.assertTrue(raw_h1.validate_host_rejection(case_id, run_id, response, access, b""))
        self.assertTrue(raw_h1.validate_host_rejection(case_id, run_id, response, dict(access, uri="/foreign"), diagnostic))
        self.assertTrue(raw_h1.validate_host_rejection(case_id, run_id, response.replace(b"400", b"500"), access, diagnostic))
        self.assertTrue(raw_h1.validate_host_rejection(case_id, run_id, response, dict(access, status=True), diagnostic))

    def test_truncated_or_ambiguous_http_response_is_rejected(self):
        for response in (b"", b"HTTP/1.1 400 Bad Request\r\n", b"HTTP/1.1 400 Bad Request\r\nContent-Length: 1\r\n\r\n", b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n"):
            with self.subTest(response=response), self.assertRaises(ValueError):
                raw_h1.response_status(response)
