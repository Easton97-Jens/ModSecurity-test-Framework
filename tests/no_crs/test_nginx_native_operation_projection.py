"""Pure projection fixtures are not native runtime or canonical acceptance."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from tests.runners import nginx_native_operation_bundle as bundle
from tests.runners import nginx_native_operation_projection as projection

ROOT = Path(__file__).resolve().parents[2]


class NativeProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        catalog = json.loads((ROOT / "tests/cases/no-crs-baseline/catalog.json").read_text())
        cls.cases = {case["case_id"]: case for case in catalog["cases"] if case["case_id"] in bundle.CASE_IDS}

    def fixture(self, case_id):
        case = deepcopy(self.cases[case_id])
        operation = bundle.route(case_id)[0]
        event = {"connector": "nginx", "integration_mode": bundle.MODE, "transaction_id": "unit-tx", "rule_id": "",
                 "phase": "logging", "event": "transaction_cleanup", "message_id": "MSCONN_TRANSACTION_CLEANUP",
                 "status": "ok", "action": "allow", "actual_action": "allow", "uri": "/unit",
                 "cleanup_reason": "normal", "reason": "common_return=0;common_complete=1;native_cleanup_completed=1;error_class=none"}
        proof = {"case_id": case_id, "run_id": "unit", "operation": operation, "errors": [], "layer_verified": True,
                 "actual_status": 200, "transaction_ids": ["unit-tx"], "events": [event],
                 "receipt": {"case_id": case_id, "run_id": "unit", "operation": operation},
                 "invocation_receipts": {}, "raw_artifacts": {}, "files": {}}
        if case_id in bundle.RAW_CASES:
            proof.update(actual_status=400, events=[], transaction_ids=[])
        elif case_id in projection._TECHNICAL:
            name, message, phase = projection._TECHNICAL[case_id]
            technical = {**event, "phase": phase, "event": name, "message_id": message, "status": "error"}
            if case_id == "finish_failure_propagation":
                technical.update(http_status=0, original_http_status=200, visible_http_status=200)
            if case_id.startswith("engine_timeout_"):
                technical["http_status"] = 504
            proof["events"].insert(0, technical)
            if case_id in bundle.INPUT_CASES:
                proof["actual_status"] = 400
            if case_id == "early_mapping_failure_cleanup":
                technical["transaction_id"] = ""
                proof.update(events=[technical], transaction_ids=[], actual_status=500)
            if case_id.startswith("engine_timeout_"):
                proof["events"].insert(0, {**technical, "event": "engine_call_budget_exceeded", "message_id": "MSCONN_ENGINE_CALL_BUDGET",
                                          "reason": "budget_ms=10;elapsed_ns=25000001;native_return=1;common_completed=0"})
                if case_id.endswith("before_commit"):
                    proof["actual_status"] = 504
        elif case_id in bundle.PHASE4_CASES | bundle.MIME_CASES:
            proof["events"].insert(0, {**event, "phase": "response_body", "event": "phase4_completion", "message_id": "MSCONN_PHASE4_COMPLETE",
                                      "reason": "engine_retained_bytes=22;append_calls=1", "body_bytes_seen": 22, "eos_seen": True})
        elif case_id in bundle.EVENT_CASES:
            proof["events"].insert(0, {**event, "phase": "request_headers", "event": "rule_match", "message_id": "MSCONN_EVENT_RULE_MATCHED",
                                      "rule_id": "1100402", "truncated": True, "redacted": True})
        if case_id == "event_json_limit":
            proof["events"] += [{**row, "transaction_id": "unit-other-tx"} for row in proof["events"]]
            proof["transaction_ids"].append("unit-other-tx")
        names = ("at", "over") if case_id == "event_json_limit" else ("main",)
        for name in names:
            variant = {"at": "at255", "over": "over256", "main": "long-query"}[name] if case_id in bundle.EVENT_CASES else None
            proof["invocation_receipts"][name] = {**proof["receipt"], "run_id": "unit-" + variant if variant else "unit"}
            proof["raw_artifacts"][name] = {}
        if case_id == "transport_http11_content_length":
            proof["raw_artifacts"]["main"]["response-wire.bin"] = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"
        if case_id == "transport_http11_chunked":
            proof["raw_artifacts"]["main"]["response-wire.bin"] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
        return case, proof

    def test_cleanup_allow_is_not_request_allow_and_inputs_remain_unchanged(self):
        case, proof = self.fixture("clean_shutdown")
        originals = deepcopy((case, proof))
        result = projection.project_native_operation(case, proof)
        self.assertEqual(result["actual_status"], 200)
        self.assertEqual(result["selected_native_events"], [])
        self.assertEqual(result["observed_event_fields"], [])
        self.assertEqual(result["cleanup_native_events"][0]["phase"], "logging")
        self.assertNotIn("status", result)
        self.assertNotIn("canonical_status", result)
        actual_inputs = (case, proof)
        self.assertEqual(actual_inputs, originals)

    def test_null_foreign_and_unverified_proofs_fail(self):
        case, proof = self.fixture("clean_shutdown")
        for field, value in (("layer_verified", False), ("errors", ["failed"]), ("case_id", "foreign"),
                             ("run_id", None), ("operation", "native_phase4_request"), ("actual_status", True)):
            changed = deepcopy(proof)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                projection.project_native_operation(case, changed)
        for left, right in ((None, proof), (case, None)):
            with self.assertRaises(ValueError):
                projection.project_native_operation(left, right)
        for field in ("invocation_receipts", "raw_artifacts"):
            changed = deepcopy(proof)
            changed[field] = {}
            with self.subTest(field=field), self.assertRaises(ValueError):
                projection.project_native_operation(case, changed)

    def test_all42_exact_descriptors_routes_and_genuine_native_keys(self):
        self.assertEqual(set(projection.NATIVE_DESCRIPTORS), bundle.CASE_IDS)
        self.assertEqual(len(self.cases), 42)
        for case_id in sorted(bundle.CASE_IDS):
            case, proof = self.fixture(case_id)
            with self.subTest(case=case_id):
                value = projection.project_native_operation(case, proof)
                self.assertEqual(value["operation"], bundle.route(case_id)[0])
                self.assertEqual(value["native_events"], proof["events"])
                self.assertEqual(value["observed_event_fields"], sorted({key for event in value["selected_native_events"] for key in event}))
                self.assertNotIn("expected_status", value["mappingEvidenceFacts"])
                self.assertNotIn("canonical_status", value)

    def test_schema_descriptor_case_run_phase_rule_and_null_negatives(self):
        case, proof = self.fixture("body_size_nonzero_with_null_data")
        for field, value in (("operation", "request_sequence"), ("contract_case_id", "header_count_nonzero_with_null_headers"),
                             ("expected_overrides", {"expected_status": 400, "phase": True}), ("unexpected", 1)):
            changed = deepcopy(case)
            changed["native_invocations"]["nginx"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                projection.project_native_operation(changed, proof)
        for field, value in (("phase", "response_body"), ("rule_id", "invented"), ("transaction_id", "foreign"), ("message_id", "foreign")):
            changed = deepcopy(proof)
            changed["events"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                projection.project_native_operation(case, changed)
        changed = deepcopy(proof)
        changed["receipt"]["run_id"] = "foreign"
        with self.assertRaises(ValueError):
            projection.project_native_operation(case, changed)

    def test_explicit_overrides_immutable_and_generic_case_not_migrated(self):
        case, proof = self.fixture("body_size_nonzero_with_null_data")
        value = projection.project_native_operation(case, proof)
        self.assertEqual(case["phase"], 2)
        self.assertEqual(case["expected_status"], 500)
        self.assertEqual(dict(value["native_expected_overrides"]), {"phase": 1, "expected_status": 400})
        with self.assertRaises(TypeError):
            value["native_expected_overrides"]["phase"] = 2
        with self.assertRaises(TypeError):
            value["native_descriptor"]["operation"] = "foreign"
        case, proof = self.fixture("phase4_deny_after_commit_log_only_minimal")
        value = projection.project_native_operation(case, proof)
        self.assertEqual(value["native_expected_overrides"]["nginx_phase4_mode"], "safe")
        self.assertEqual(case["expected_result"], "late_intervention_log_only_minimal")
        case, proof = self.fixture("clean_shutdown")
        value = projection.project_native_operation(case, proof)
        self.assertEqual(value["native_expected_overrides"]["expected_status"], 200)
        self.assertEqual(case["expected_status"], 0)

    def test_receipt_measurements_never_become_native_event_keys_or_payload(self):
        case, proof = self.fixture("phase4_body_at_limit")
        receipt = {**proof["receipt"], "response_bytes_received": 22, "effective_phase4_mode": "safe", "response_body": "unit-body"}
        proof["invocation_receipts"] = {"main": receipt}
        proof["raw_artifacts"] = {"main": {"response.bin": b"actual retained unit bytes"}}
        value = projection.project_native_operation(case, proof)
        facts = value["mappingEvidenceFacts"]
        self.assertEqual(facts["invocations"]["main"]["receipt_fields"]["response_bytes_received"], 22)
        self.assertNotIn("response_body", facts["invocations"]["main"]["receipt_fields"])
        self.assertNotIn("response_bytes_received", value["observed_event_fields"])
        self.assertNotIn("engine_retained_bytes", value["observed_event_fields"])
        self.assertEqual(facts["native_reason_measurements"][0]["reason_fields"]["engine_retained_bytes"], 22)
        value["native_events"][0]["body_bytes_seen"] = 999
        self.assertEqual(proof["events"][0]["body_bytes_seen"], 22)

    def test_counterfactual_terminal_cleanup_and_deny_contradictions_fail(self):
        case, proof = self.fixture("body_size_nonzero_with_null_data")
        proof["events"].insert(1, {**proof["events"][0], "phase": "response_body", "event": "engine_timeout"})
        with self.assertRaises(ValueError):
            projection.project_native_operation(case, proof)
        case, proof = self.fixture("phase4_body_at_limit")
        proof["events"].reverse()
        with self.assertRaises(ValueError):
            projection.project_native_operation(case, proof)
        case, proof = self.fixture("keepalive_allow_deny_allow")
        denial = {**proof["events"][0], "event": "engine_decision", "message_id": "MSCONN_EVENT_ENGINE_DECISION", "phase": "request_headers",
                  "rule_id": "1100001", "status": "blocked", "action": "deny", "requested_action": "deny", "actual_action": "", "http_status": 403,
                  "visible_http_status": 0, "transport_result": "not_observable"}
        proof["events"].insert(0, denial)
        self.assertEqual(projection.project_native_operation(case, proof)["selected_native_events"], [denial])
        for field, value in (("actual_action", "allow"), ("actual_action", "deny"), ("http_status", 200),
                             ("visible_http_status", 403), ("event", "request_rule_match")):
            changed = deepcopy(proof)
            changed["events"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                projection.project_native_operation(case, changed)

    def test_finish_budget_wire_distinction_and_raw_framing_measurements(self):
        case, proof = self.fixture("finish_failure_propagation")
        value = projection.project_native_operation(case, proof)
        self.assertEqual(value["actual_status"], 200)
        self.assertEqual(value["selected_native_events"][0]["http_status"], 0)
        for case_id, wanted in (("engine_timeout_before_commit", 504), ("engine_timeout_after_commit", 200)):
            case, proof = self.fixture(case_id)
            self.assertEqual(projection.project_native_operation(case, proof)["actual_status"], wanted)
            proof["actual_status"] = 400
            with self.assertRaises(ValueError):
                projection.project_native_operation(case, proof)
        case, proof = self.fixture("transport_http11_content_length")
        proof["invocation_receipts"] = {"main": proof["receipt"]}
        proof["raw_artifacts"] = {"main": {"response-wire.bin": b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"}}
        value = projection.project_native_operation(case, proof)
        measured = value["mappingEvidenceFacts"]["invocations"]["main"]["downstream_wire_measurements"]
        self.assertEqual(measured["framing"], "content_length")
        self.assertEqual(measured["bytes_received"], 3)
        self.assertNotIn("body", measured)
        self.assertNotIn("framing", value["observed_event_fields"])


if __name__ == "__main__":
    unittest.main()
