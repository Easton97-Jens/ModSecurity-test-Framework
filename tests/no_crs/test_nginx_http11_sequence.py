"""Raw framing, native completion and cleanup are separate mandatory facts."""
import copy
import hashlib
import unittest

from tests.no_crs import test_nginx_lifecycle_sequence as sequence_tests


class FramingSequenceTests(unittest.TestCase):
    setUp = sequence_tests.SequenceContractTests.setUp

    def observation(self, chunked=False):
        value = sequence_tests.SequenceContractTests.observation(self)
        case = "transport_http11_chunked" if chunked else "transport_http11_content_length"
        path = "/no-crs/sequence/owned/0"
        framing = (b"Transfer-Encoding: chunked\r\n" if chunked else b"Content-Length: 22\r\n")
        encoded = (b"9\r\ntransport\r\nd\r\n fixture body\r\n0\r\n\r\n" if chunked else b"transport fixture body")
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" + framing + b"\r\n" + encoded
        request = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode()
        parsed = self.helper.WIRE.parse_http11_response(raw)
        parsed.pop("body")
        value.update(case_id=case, requests=[dict(parsed, path=path, transport_result="completed", client_error=None)],
                     native_access=[dict(value["native_access"][0], uri=path)],
                     wire={"request_hex": request.hex(), "response_hex": raw.hex(), "eof_seen": True})
        shared = {"connector": "nginx", "integration_mode": "native-nginx-http-module", "rule_id": "",
                  "transaction_id": "a" * 32, "uri": path, "status": "ok", "actual_action": "allow"}
        value["native_events"] = [
            dict(shared, event="phase4_completion", message_id="MSCONN_PHASE4_COMPLETE", phase="response_body",
                 eos_seen=True, content_type="text/plain", body_bytes_seen=22, body_bytes_inspected=22,
                 reason="engine_retained_bytes=22;append_calls=2"),
            dict(shared, event="transaction_cleanup", message_id="MSCONN_TRANSACTION_CLEANUP", phase="logging",
                 cleanup_reason="normal", reason="common_return=0;common_complete=1;native_cleanup_completed=1;error_class=none")]
        if chunked:
            value["upstream_wire"] = {"request_hex": request.hex(), "response_hex": raw.hex(),
                                       "request_count": 1, "write_complete": True, "upstream_write_failed": False}
        return value

    def errors(self, value):
        return self.helper.observation_errors(value, value["case_id"], "run-1")

    def test_complete_raw_wire_and_native_lifecycle_are_accepted(self):
        for chunked in (False, True):
            self.assertEqual(self.errors(self.observation(chunked)), [])

    def test_decoded_client_metadata_cannot_replace_actual_raw_framing(self):
        for chunked in (False, True):
            value = self.observation(chunked)
            value.pop("wire")
            self.assertTrue(self.errors(value))
        value = self.observation(True)
        value["wire"]["response_hex"] = self.observation(False)["wire"]["response_hex"]
        self.assertTrue(self.errors(value))

    def test_wrong_body_is_rejected_even_with_matching_client_digest(self):
        value = self.observation()
        wrong = b"transport fixture bodX"
        raw = bytes.fromhex(value["wire"]["response_hex"]).replace(b"transport fixture body", wrong)
        value["wire"]["response_hex"] = raw.hex()
        value["requests"][0]["body_sha256"] = hashlib.sha256(wrong).hexdigest()
        self.assertTrue(self.errors(value))

    def test_foreign_native_tx_missing_phase_or_cleanup_cannot_be_inferred(self):
        base = self.observation()
        for index in (0, 1):
            value = copy.deepcopy(base)
            value["native_events"].pop(index)
            self.assertTrue(self.errors(value))
            value = copy.deepcopy(base)
            value["native_events"][index]["transaction_id"] = "b" * 32
            self.assertTrue(self.errors(value))
        value = self.observation()
        value["native_events"][0]["body_bytes_inspected"] = 0
        self.assertTrue(self.errors(value))
        value = self.observation()
        value["native_events"][1]["reason"] = "common_return=0;common_complete=1;native_cleanup_completed=0;error_class=none"
        self.assertTrue(self.errors(value))

    def test_origin_bytes_cannot_substitute_downstream_or_foreign_request(self):
        value = self.observation(True)
        value.pop("wire")
        self.assertTrue(self.errors(value))
        value = self.observation(True)
        value["upstream_wire"]["request_hex"] = b"GET /foreign HTTP/1.1\r\n\r\n".hex()
        self.assertTrue(self.errors(value))
        value = self.observation(True)
        value["upstream_wire"]["write_complete"] = False
        self.assertTrue(self.errors(value))


if __name__ == "__main__":
    unittest.main()
