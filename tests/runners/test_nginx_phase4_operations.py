"""Pure Phase-4 receipt tests; fixtures are unit inputs, never runtime proof."""
from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nginx_phase4_contracts as contracts


def fixture(record):
    spec = contracts.operation(record)
    body = "".join(spec["response_chunks"]).encode()
    partial = len(body) > 64
    retained = min(len(body), 64) if "engine_limit_bytes" in spec else len(body)
    event = {"connector": "nginx", "integration_mode": "native-nginx-http-module",
             "transaction_id": "unit-run-2-1", "phase": "response_body", "method": "GET",
             "uri": spec["request_path"], "event": "phase4_completion", "message_id": "MSCONN_PHASE4_COMPLETE", "eos_seen": True,
             "reason": f"engine_retained_bytes={retained};append_calls={len(spec['response_chunks'])}",
             "body_bytes_seen": len(body), "body_bytes_inspected": len(body),
             "content_type": "text/plain", "body_truncated": partial,
             "connection_aborted": False}
    intervention = {**event, "event": "phase4_intervention",
                    "message_id": "MSCONN_EVENT_PHASE4_LATE_INTERVENTION",
                    "reason": "response_committed_safe", "rule_id": "1100301",
                    "http_status": 403, "visible_http_status": 200,
                    "requested_action": "deny", "actual_action": "log_only",
                    "transport_result": "log_only", "late_intervention": True,
                    "late_intervention_mode": "safe", "response_committed": True}
    lengths = [len(chunk.encode()) for chunk in spec["response_chunks"]]
    appends = []
    supplied = 0
    for index, size in enumerate(lengths, 1):
        supplied += size
        appends.append({**event, "event": "phase4_append", "message_id": "MSCONN_PHASE4_APPEND",
                        "reason": f"native_return={int(not partial)};append_size={size};append_index={index};engine_retained_bytes={min(supplied, retained)}",
                        "body_bytes_seen": supplied, "body_bytes_inspected": supplied,
                        "rule_id": "", "actual_action": "allow", "eos_seen": False})
    events = appends + [intervention, event]
    raw = {"phase4-events.jsonl": ("\n".join(json.dumps(item) for item in events) + "\n").encode(),
           "response.bin": body, "response.headers": f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nContent-Type: text/plain\r\n\r\n".encode(),
           "client.stdout": b"200", "client.stderr": b"", "rules.conf": spec["rules"].encode(),
           "nginx.conf": b"modsecurity_phase4_mode safe;\n", "nginx-error.log": b""}
    receipt = {"case_id": record, "source_record_id": spec["source_record_id"],
               "operation": "native_phase4_request", "run_id": "unit-run",
               "request_path": spec["request_path"], "request_method": "GET",
               "effective_phase4_mode": "safe", "configtest_exit_code": 0,
               "client_exit_code": 0, "observed_http_status": 200,
               "response_bytes_received": len(body), "driver_error": None,
               "native_events": events,
               "first_body_byte_before_upstream_eos": spec["pause_between_chunks"],
               "upstream": {"chunk_sizes_sent": lengths, "eos_sent": True, "error_class": "none"},
               "raw_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in raw.items()}}
    return receipt, raw


def rebind(receipt, raw):
    raw["phase4-events.jsonl"] = ("\n".join(json.dumps(item) for item in receipt["native_events"])+"\n").encode()
    receipt["raw_sha256"] = {name: hashlib.sha256(value).hexdigest() for name, value in raw.items()}


def rejection_fixture(committed=True):
    record = "phase4_body_reject"
    receipt, raw = fixture(record)
    append = receipt["native_events"][0]
    append["reason"] = "native_return=1;append_size=65;append_index=1;engine_retained_bytes=0"
    event = {**append, "event": "body_limit", "message_id": "MSCONN_EVENT_BODY_LIMIT",
             "reason": "response_body_limit_exceeded", "body_limit_outcome": "reject", "http_status": 403,
             "visible_http_status": 200 if committed else 0, "rule_id": "",
             "status": "blocked", "action": "abort_connection" if committed else "deny",
             "requested_action": "deny",
             "actual_action": "abort_connection" if committed else "deny",
             "transport_result": "connection_aborted" if committed else "not_observable",
             "response_committed": committed, "headers_sent": committed,
             "connection_aborted": committed, "body_truncated": True, "eos_seen": False}
    receipt["native_events"] = [append, event]
    receipt["observed_http_status"] = 200 if committed else 403
    receipt["client_exit_code"] = 18 if committed else 0
    receipt["response_bytes_received"] = 0 if committed else 6
    raw["response.bin"] = b"" if committed else b"denied"
    raw["response.headers"] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" if committed else b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\n"
    raw["client.stdout"] = b"200" if committed else b"403"
    raw["client.stderr"] = b"curl: (18) transfer closed with outstanding read data remaining\n" if committed else b""
    raw["nginx-error.log"] = b"[error] Response body limit is marked to reject the request\n"
    rebind(receipt, raw)
    return receipt, raw


class Phase4OperationsTest(unittest.TestCase):
    def validate(self, record, receipt, raw):
        helper = importlib.import_module("nginx_phase4_operations")
        return helper.validate_phase4_operation(record, receipt, raw)

    def test_closed_nonreject_operations_accept_complete_observed_inputs(self):
        for record in sorted(contracts.RECORD_IDS - {"phase4_body_reject"}):
            with self.subTest(record=record):
                self.assertEqual(self.validate(record, *fixture(record)), [])

    def test_receipt_mismatch_controls(self):
        record = contracts.SPLIT_ID
        for field, value in (("source_record_id", "phase4_body_at_limit"),
                             ("effective_phase4_mode", "off"), ("client_exit_code", 18),
                             ("observed_http_status", 403), ("response_bytes_received", 26),
                             ("request_path", "/wrong"), ("run_id", "wrong"),
                             ("first_body_byte_before_upstream_eos", False),
                             ("native_events", [])):
            with self.subTest(field=field):
                receipt, raw = fixture(record)
                receipt[field] = value
                self.assertTrue(self.validate(record, receipt, raw))

    def test_raw_mismatch_and_absent_completion_controls(self):
        record = "phase4_body_process_partial"
        for leaf in fixture(record)[1]:
            with self.subTest(leaf=leaf):
                receipt, raw = fixture(record)
                raw[leaf] += b"x"
                self.assertTrue(self.validate(record, receipt, raw))
        receipt, raw = fixture(record)
        event = deepcopy(receipt["native_events"][-1])
        for field, value in (("reason", "engine_retained_bytes=65;append_calls=1"),
                             ("eos_seen", False), ("body_bytes_inspected", 64),
                             ("body_bytes_seen", True), ("transaction_id", "unit-run-3-1")):
            with self.subTest(field=field):
                altered = deepcopy(event)
                altered[field] = value
                candidate = deepcopy(raw)
                bound = deepcopy(receipt)
                bound["native_events"][-1] = altered
                candidate["phase4-events.jsonl"] = ("\n".join(json.dumps(item) for item in bound["native_events"])+"\n").encode()
                bound["raw_sha256"]["phase4-events.jsonl"] = hashlib.sha256(candidate["phase4-events.jsonl"]).hexdigest()
                self.assertTrue(self.validate(record, bound, candidate))

    def test_upstream_split_alone_does_not_prove_native_split(self):
        receipt, raw = fixture(contracts.SPLIT_ID)
        for lengths in ([27], [15, 12], [16, 10], [True, 26]):
            with self.subTest(lengths=lengths):
                candidate = deepcopy(raw)
                bound = deepcopy(receipt)
                bound["native_events"] = [item for item in bound["native_events"] if item["event"] != "phase4_append"]
                for index, size in enumerate(lengths, 1):
                    bound["native_events"].insert(index-1, {**receipt["native_events"][0], "reason": f"native_return=1;append_size={size};append_index={index};engine_retained_bytes=27"})
                candidate["phase4-events.jsonl"] = ("\n".join(json.dumps(item) for item in bound["native_events"])+"\n").encode()
                bound["raw_sha256"]["phase4-events.jsonl"] = hashlib.sha256(candidate["phase4-events.jsonl"]).hexdigest()
                self.assertTrue(self.validate(contracts.SPLIT_ID, bound, candidate))

    def test_immediate_reject_supports_exact_committed_and_precommit_wire(self):
        for committed in (False, True):
            with self.subTest(committed=committed):
                self.assertEqual(self.validate("phase4_body_reject", *rejection_fixture(committed)), [])

    def test_reject_action_projection_requires_actual_host_action(self):
        for committed in (False, True):
            for field, value in (("action", "deny" if committed else "abort_connection"),
                                 ("requested_action", "abort_connection"),
                                 ("actual_action", "deny" if committed else "abort_connection"),
                                 ("transport_result", "not_observable" if committed else "connection_aborted")):
                with self.subTest(committed=committed, field=field):
                    receipt, raw = rejection_fixture(committed)
                    receipt["native_events"][-1][field] = value
                    rebind(receipt, raw)
                    self.assertTrue(self.validate("phase4_body_reject", receipt, raw))

    def test_committed_reject_requires_visible_headers_and_incomplete_framing(self):
        receipt, raw = rejection_fixture()
        receipt["client_exit_code"] = 52
        receipt["observed_http_status"] = 0
        raw["response.headers"] = b""
        raw["client.stdout"] = b"000"
        raw["client.stderr"] = b"curl: (52) Empty reply from server\n"
        rebind(receipt, raw)
        self.assertTrue(self.validate("phase4_body_reject", receipt, raw))

    def test_reject_never_accepts_old_late_full_body_invalid_engine(self):
        receipt, raw = rejection_fixture()
        raw["response.bin"] = contracts.MARKER.encode() + b"x" * (65-len(contracts.MARKER))
        receipt["response_bytes_received"] = 65
        rebind(receipt, raw)
        self.assertTrue(self.validate("phase4_body_reject", receipt, raw))
        for field, value in (("message_id", "MSCONN_EVENT_INVALID_ENGINE_RESPONSE"),
                             ("rule_id", "1100301"), ("eos_seen", True),
                             ("http_status", 500), ("response_committed", False),
                             ("reason", "ENGINE_RESPONSE_BODY_LIMIT_REJECT suffix")):
            with self.subTest(field=field):
                receipt, raw = rejection_fixture()
                receipt["native_events"][-1][field] = value
                rebind(receipt, raw)
                self.assertTrue(self.validate("phase4_body_reject", receipt, raw))

    def test_completion_and_rule_fields_are_observed_not_fixture_defaults(self):
        for index, field, value in ((-1, "message_id", "other"), (-1, "connection_aborted", True),
                                    (-2, "rule_id", "wrong"), (-2, "actual_action", "deny"),
                                    (-2, "late_intervention_mode", "off")):
            with self.subTest(field=field):
                receipt, raw = fixture(contracts.SPLIT_ID)
                receipt["native_events"][index][field] = value
                rebind(receipt, raw)
                self.assertTrue(self.validate(contracts.SPLIT_ID, receipt, raw))

    def test_duplicate_native_keys_and_non_objects_are_rejected(self):
        for extra in (b'{"event":"one","event":"two"}\n', b'[]\n', b'{"value":NaN}\n'):
            receipt, raw = fixture(contracts.SPLIT_ID)
            raw["phase4-events.jsonl"] += extra
            receipt["raw_sha256"]["phase4-events.jsonl"] = hashlib.sha256(raw["phase4-events.jsonl"]).hexdigest()
            self.assertTrue(self.validate(contracts.SPLIT_ID, receipt, raw))


if __name__ == "__main__":
    unittest.main()
