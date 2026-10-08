"""Synthetic unit fixtures check validators, never create runtime evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "runners/nginx_mime_operations.py"
spec = importlib.util.spec_from_file_location("mime_operations", PATH)
mime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mime)


def refresh(receipt, raw):
    raw["phase4-events.jsonl"] = b"".join(json.dumps(event).encode() + b"\n"
                                          for event in receipt["native_events"])
    receipt["raw_sha256"] = {leaf: hashlib.sha256(data).hexdigest() for leaf, data in raw.items()}


def unit_operation(case):
    content_type = mime.CONTENT_TYPES[case]
    retained = 27 if content_type.startswith("text/plain") else 0
    common = dict(connector="nginx", integration_mode="native-nginx-http-module", phase="response_body",
                  method="GET", uri="/no-crs/content-type/" + case, transaction_id="unit-2-1",
                  content_type=content_type, connection_aborted=False, rule_id="",
                  body_bytes_seen=27, body_bytes_inspected=27)
    append = dict(common, event="phase4_append", message_id="MSCONN_PHASE4_APPEND", actual_action="allow",
                  reason=f"native_return=1;append_size=27;append_index=1;engine_retained_bytes={retained}", eos_seen=False)
    complete = dict(common, event="phase4_completion", message_id="MSCONN_PHASE4_COMPLETE",
                    reason=f"engine_retained_bytes={retained};append_calls=1", eos_seen=True)
    events = [append, complete]
    if retained:
        events.append(dict(common, event="phase4_intervention", message_id="MSCONN_EVENT_PHASE4_LATE_INTERVENTION",
                           rule_id="1100301", requested_action="deny", actual_action="log_only", http_status=403,
                           original_http_status=200, visible_http_status=200, reason="response_committed_safe",
                           transport_result="log_only", late_intervention_mode="safe", late_intervention=True,
                           response_committed=True, eos_seen=True))
    receipt = dict(case_id=case, source_record_id=case, run_id="unit", operation="native_phase4_request",
                   request_method="GET", request_path=common["uri"], effective_phase4_mode="safe",
                   configtest_exit_code=0, client_exit_code=0, observed_http_status=200,
                   response_bytes_received=27, native_events=events, driver_error=None)
    fixture = dict(headers=[["Content-Type", content_type]], status=200) if content_type else dict(
        headers=[], omit_headers=["Content-Type"], status=200)
    headers = b"HTTP/1.1 200 OK\r\nContent-Length: 27\r\n"
    if content_type:
        headers += b"Content-Type: " + content_type.encode() + b"\r\n"
    raw = {"response.bin": mime.BODY, "response.headers": headers + b"\r\n", "client.stdout": b"200",
           "client.stderr": b"", "response-header-fixture.json": json.dumps(fixture).encode(),
           "nginx.conf": f'types {{ }}\ndefault_type "{content_type}";\nmodsecurity_phase4_mode safe;'.encode(),
           "rules.conf": (b"SecRuleEngine On\nSecResponseBodyAccess On\n"
                          b"SecResponseBodyMimeType text/plain application/json\n"
                          b'SecRule RESPONSE_BODY "@contains ' + mime.BODY + b'" "id:1100301,phase:4,deny,status:403"\n')}
    refresh(receipt, raw)
    return receipt, raw


class MimeOperationTests(unittest.TestCase):
    def test_closed_input_is_fresh_and_retains_native_operation_identity(self):
        for case in mime.CONTENT_TYPES:
            value = mime.operation(case)
            self.assertEqual(value["request_path"], "/no-crs/content-type/" + case)
            self.assertEqual(value["response_chunks"], [mime.BODY.decode()])
            self.assertEqual(value["nginx_phase4_mode"], "safe")
            value["backend_fixture"]["headers"].append(["Foreign", "value"])
            self.assertNotIn(["Foreign", "value"], mime.operation(case)["backend_fixture"]["headers"])
        with self.assertRaises(ValueError):
            mime.operation("foreign")

    def test_four_complete_wire_and_native_shapes(self):
        for case in mime.CONTENT_TYPES:
            with self.subTest(case=case):
                receipt, raw = unit_operation(case)
                self.assertEqual(mime.validate_mime_operation(case, receipt, raw), [])

    def test_http200_and_no_rule_alone_cannot_prove_native_exclusion(self):
        for case in mime.CONTENT_TYPES:
            for kind in ("phase4_completion", "phase4_append"):
                receipt, raw = unit_operation(case)
                receipt["native_events"] = [event for event in receipt["native_events"] if event["event"] != kind]
                refresh(receipt, raw)
                with self.subTest(case=case, kind=kind):
                    self.assertTrue(mime.validate_mime_operation(case, receipt, raw))

    def test_native_return_retention_tx_rule_and_bool_negatives(self):
        for case in mime.CONTENT_TYPES:
            negatives = ((0, "reason", "native_return=0;append_size=27;append_index=1;engine_retained_bytes=0"),
                         (0, "transaction_id", "unit-9-9"), (0, "body_bytes_inspected", True),
                         (1, "reason", "engine_retained_bytes=1;append_calls=1"),
                         (1, "rule_id", "1100301"), (1, "eos_seen", False),
                         (1, "content_type", "text/html"))
            for index, field, value in negatives:
                receipt, raw = unit_operation(case)
                receipt["native_events"][index][field] = value
                refresh(receipt, raw)
                with self.subTest(case=case, field=field, index=index):
                    self.assertTrue(mime.validate_mime_operation(case, receipt, raw))
            receipt, raw = unit_operation(case)
            receipt["native_events"].append(dict(receipt["native_events"][1]))
            refresh(receipt, raw)
            self.assertTrue(mime.validate_mime_operation(case, receipt, raw))

    def test_wire_type_body_framing_hash_and_fixture_negatives(self):
        for case in mime.CONTENT_TYPES:
            wrong_headers = b"HTTP/1.1 200 OK\r\nContent-Length: 27\r\nContent-Type: text/html\r\n\r\n"
            mutations = (("response.headers", wrong_headers), ("response.bin", b"wrong-body"),
                         ("response.headers", b"HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\n"),
                         ("response-header-fixture.json", b'{"headers":[],"status":200}'),
                         ("rules.conf", b"SecResponseBodyMimeTypesClear\n"),
                         ("client.stderr", b"curl: (18) incomplete response"))
            for leaf, value in mutations:
                receipt, raw = unit_operation(case)
                raw[leaf] = value
                refresh(receipt, raw)
                with self.subTest(case=case, leaf=leaf):
                    self.assertTrue(mime.validate_mime_operation(case, receipt, raw))
            receipt, raw = unit_operation(case)
            raw["response.bin"] = b"tampered"
            self.assertTrue(mime.validate_mime_operation(case, receipt, raw))

    def test_duplicate_raw_keys_and_foreign_projection_rejected(self):
        case = "phase4_out_of_scope_content_type"
        receipt, raw = unit_operation(case)
        raw["phase4-events.jsonl"] = b'{"event":"phase4_append","event":"phase4_completion"}\n'
        receipt["raw_sha256"]["phase4-events.jsonl"] = hashlib.sha256(raw["phase4-events.jsonl"]).hexdigest()
        self.assertTrue(mime.validate_mime_operation(case, receipt, raw))
        receipt, raw = unit_operation(case)
        receipt["native_events"] = []
        self.assertTrue(mime.validate_mime_operation(case, receipt, raw))
        self.assertTrue(mime.validate_mime_operation("unknown", None, None))

    def test_raw_readiness_records_are_not_mime_observations(self):
        case = "phase4_out_of_scope_content_type"
        receipt, raw = unit_operation(case)
        readiness = dict(receipt["native_events"][1], uri="/__modsec_smoke_ready", transaction_id="unit-1-1")
        raw["phase4-events.jsonl"] = json.dumps(readiness).encode() + b"\n" + raw["phase4-events.jsonl"]
        receipt["raw_sha256"]["phase4-events.jsonl"] = hashlib.sha256(raw["phase4-events.jsonl"]).hexdigest()
        self.assertEqual(mime.validate_mime_operation(case, receipt, raw), [])


if __name__ == "__main__":
    unittest.main()
