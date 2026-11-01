"""Synthetic qualification guard tests; these do not constitute host evidence."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import copy
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest import mock


ROOT = connector_root()


def load(name, path):
    module = load_source(path)
    return module


QUALIFY = load("nginx_qualify", source_path('ci/runtime/lifecycle/i12/nginx/qualify.py', root=ROOT))
FIXTURES = load("nginx_ledger_test_fixtures", source_path('tests/test_i12_nginx_ledger.py', root=ROOT))


class QualificationTests(unittest.TestCase):
    def setUp(self):
        fixture = FIXTURES.NginxLedgerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
        run_root = validate_output_root(ROOT, fixture.path)
        configured_root = mock.patch.dict(os.environ, {"CODEX_RUN_ROOT": str(run_root)})
        configured_root.start()
        self.addCleanup(configured_root.stop)
        record = fixture.packet(1)
        self.packet_path = Path(record["packet"]["path"])
        self.packet = json.loads(self.packet_path.read_text())
        values = {
            "client_exit": {"exit": 0, "pid": 77, "observation_pid": 77, "direct_child_wait": True},
            "client_signal": {"signal": None, "pid": 77, "process_waited": True, "direct_child_wait": True},
            "client_headers": {"http_status": 200, "raw_latin1": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"},
            "transport_framing": {"framing_complete": True, "error": None, "socket_eof": True, "socket_reset": False},
            "backend_request_count": {"selected": 1},
            "native_api_returns": {"measured_calls": [{"function": "native_process_request_body"},
                                                         {"function": "native_process_response_body"}],
                                   "scoped_fixture_events": {}},
            "native_eos": {"request_terminal_precedes_single_p2": True, "response_terminal_precedes_single_p4": True},
            "native_events": [{"event": "transaction_cleanup", "status": "ok"}],
            "finish_calls": {"common_finish": [{}], "native_logging": [{}]},
            "native_free_calls": {"count": 1},
            "client_bytes": {"body_hex": "6f6b", "size": 2},
            "native_body_chunks": {"request": [], "response": [{"input_size": 2}], "host_buffer_state": []},
            "mime_gate": {"selected_debug": ["Synthetic text/plain MIME selected"],
                          "sdk_fixture_semantics": "3.0.14 MIME list retained; no Clear reset inferred"},
            "neighbor_health": {"actual_followup_clients": [{"exit_code": 0, "signal": None,
                "direct_child_wait": True, "pid": 78, "observation": {"pid": 78, "status": 200, "framing_complete": True}}]},
        }
        for field, value in values.items():
            self.packet["observations"][field]["value"] = value
        self.provenance = {"run_id": self.packet["run_id"],
                           "transport_case_id": self.packet["run_scoped_case_id"],
                           "transaction_id": record["request_identity"]["transaction_id"]}
        self.packet["observations"]["native_events"]["value"][0].update(self.provenance)
        self.physical_events = None
        self.candidate = {"run_scoped_case_id": self.packet["run_scoped_case_id"],
                          "request_identity": record["request_identity"], "unknown_fields": [], "gaps": [],
                          "measured_assertions": dict.fromkeys(QUALIFY.REQUIRED_ASSERTIONS, True)}
        self.candidates = {"controller_exit": 0, "driver_exit": 0, "cases": [self.candidate]}
        self.checks = {"http_status": 200, "client_exit": 0, "client_signal": None,
            "framing_complete": True, "backend_count": 1,
            "required_native_functions": {"native_process_request_body": 1, "native_process_response_body": 1},
            "forbidden_native_functions": [], "required_events": [{"event": "transaction_cleanup", "fields": {"status": "ok"}, "count": 1}],
            "forbidden_events": ["error"], "request_eos": True, "response_eos": True,
            "common_finish_count": 1, "native_logging_count": 1, "native_free_count": 1,
            "body": {"exact_hex": "6f6b"}, "neighbor_success": True, "scoped_fixture_events": {},
            "allowed_absent_phases": [], "client_error": None, "socket_eof": True, "socket_reset": False,
            "request_body": {"exact_hex": ""}, "request_append_count": 0, "request_append_bytes": 0,
            "response_append_count": 1, "response_append_bytes": 2, "require_request_temp_file": False,
            "require_response_in_file": False, "required_content_type": "text/plain", "forbidden_event_fields": ["payload"],
            "required_request_content_type": None, "required_mime_debug_fragments": ["text/plain MIME selected"],
            "required_sdk_mime_semantics": "3.0.14 MIME list retained; no Clear reset inferred",
            "oracle_event_fields": [], "oracle_event_fields_in_single_event": True, "native_return_checks": []}
        self.decision = {"run_scoped_case_id": self.packet["run_scoped_case_id"], "outcome": "PASS", "checks": self.checks}

    def run_materializer(self):
        events = self.packet["observations"]["native_events"]
        raw = self.fixture.path / "events.jsonl"
        raw.write_text("".join(json.dumps(event) + "\n" for event in (
            events["value"] if self.physical_events is None else self.physical_events)))
        events["evidence"] = [{**QUALIFY.LEDGER.ORACLES.reference(raw), "role": "physical_event_sink"}]
        self.packet_path.write_text(json.dumps(self.packet))
        self.candidate["packet"] = QUALIFY.LEDGER.ORACLES.reference(self.packet_path)
        return QUALIFY.materialize(self.fixture.baseline, self.candidates, [self.decision], self.fixture.path / "approved")

    def test_explicit_measured_decision_produces_shared_validated_packet(self):
        records = self.run_materializer()
        packet = json.loads(Path(records[0]["packet"]["path"]).read_text())
        self.assertEqual(packet["reviewed_by"], "root")
        self.assertTrue(packet["full_lifecycle_qualified"])
        self.assertEqual(records[0]["request_identity"], self.candidate["request_identity"])
        self.assertEqual(QUALIFY.LEDGER.build_ledger(self.fixture.baseline, records)["summary"]["full_lifecycle_pass"], 1)

    def test_wrong_http_and_missing_explicit_semantics_are_rejected(self):
        self.checks["http_status"] = 403
        with self.assertRaisesRegex(ValueError, "HTTP status"):
            self.run_materializer()
        self.checks.pop("http_status")
        with self.assertRaisesRegex(ValueError, "Every semantic checks"):
            self.run_materializer()

    def test_unspecified_oracle_status_accepts_explicit_actual_status(self):
        self.fixture.baseline["rows"][1]["selected_requirement"]["expected_oracle"]["visible_status"] = None
        self.assertEqual(len(self.run_materializer()), 1)

    def test_concrete_oracle_status_mismatch_cannot_pass(self):
        self.fixture.baseline["rows"][1]["selected_requirement"]["expected_oracle"]["visible_status"] = 403
        with self.assertRaisesRegex(ValueError, "PASS oracle visible status"):
            self.run_materializer()

    def test_event_fields_cannot_override_the_requested_event_or_use_a_list(self):
        for fields in ({"event": "transaction_cleanup"}, []):
            with self.subTest(fields=fields):
                self.checks["required_events"] = [{"event": "missing_event", "fields": fields}]
                with self.assertRaisesRegex(ValueError, "without an event override"):
                    self.run_materializer()

    def test_request_content_type_is_case_insensitive_and_header_block_only(self):
        request_path = Path(self.candidate["request_identity"]["physical_request_path"])
        request_path.write_bytes(b"POST /synthetic-fixture HTTP/1.1\r\ncOnTeNt-TyPe: text/plain; charset=utf-8\r\n\r\nContent-Type: forged/body")
        self.checks["required_request_content_type"] = "text/plain; charset=utf-8"
        self.checks["request_body"] = {"exact_hex": b"Content-Type: forged/body".hex()}
        receipt_proof = self.packet["observations"]["client_exit"]["evidence"][0]
        receipt_path = Path(receipt_proof["path"])
        receipt = json.loads(receipt_path.read_text())
        receipt["clients"][0]["observation"]["request_sha256"] = QUALIFY.LEDGER.ORACLES.reference(request_path)["sha256"]
        receipt_path.write_text(json.dumps(receipt))
        receipt_proof.update(QUALIFY.LEDGER.ORACLES.reference(receipt_path))
        self.assertEqual(len(self.run_materializer()), 1)

    def test_request_content_type_absence_and_mime_debug_semantics_must_match(self):
        for field, expected, error in (("required_request_content_type", "application/json", "request Content-Type"),
                                       ("required_mime_debug_fragments", ["not measured"], "MIME debug fragment"),
                                       ("required_sdk_mime_semantics", "Clear resets MIME", "SDK MIME semantics")):
            with self.subTest(field=field):
                original = self.checks[field]
                self.checks[field] = expected
                with self.assertRaisesRegex(ValueError, error):
                    self.run_materializer()
                self.checks[field] = original

    def test_duplicate_request_content_type_is_rejected(self):
        request_path = Path(self.candidate["request_identity"]["physical_request_path"])
        request_path.write_bytes(b"POST / HTTP/1.1\r\nContent-Type: text/plain\r\ncontent-type: text/plain\r\n\r\n")
        proof = self.packet["observations"]["client_exit"]["evidence"][0]
        receipt_path = Path(proof["path"])
        receipt = json.loads(receipt_path.read_text())
        receipt["clients"][0]["observation"]["request_sha256"] = QUALIFY.LEDGER.ORACLES.reference(request_path)["sha256"]
        receipt_path.write_text(json.dumps(receipt))
        proof.update(QUALIFY.LEDGER.ORACLES.reference(receipt_path))
        with self.assertRaisesRegex(ValueError, "duplicate Content-Type"):
            self.run_materializer()

    def test_downstream_failures_leave_no_approved_output_or_private_packets(self):
        stages = ((QUALIFY.LEDGER.SHARED, "reviewed_packet"),
                  (QUALIFY.LEDGER, "physical_identity"), (QUALIFY.LEDGER, "build_ledger"))
        for owner, stage in stages:
            with self.subTest(stage=stage), mock.patch.object(owner, stage, side_effect=ValueError("downstream rejection")):
                with self.assertRaisesRegex(ValueError, "downstream rejection"):
                    self.run_materializer()
            self.assertFalse((self.fixture.path / "approved").exists())
            self.assertEqual(list(self.fixture.path.glob(".nginx-qualification-*")), [])

    def test_unknown_measurements_gaps_and_failed_base_integrity_rejected(self):
        for field, value in (("unknown_fields", ["native_eos"]), ("gaps", ["missing producer"]),
                             ("measured_assertions", {"raw_artifact_digests_match": False})):
            with self.subTest(field=field):
                original = self.candidate[field]
                self.candidate[field] = value
                with self.assertRaises(ValueError):
                    self.run_materializer()
                self.candidate[field] = original

    def test_client_wrapper_cannot_supply_actual_client_signal(self):
        self.packet["observations"]["client_exit"]["value"]["pid"] = 88
        with self.assertRaisesRegex(ValueError, "direct wait"):
            self.run_materializer()

    def test_neighbor_missing_actual_pid_cannot_qualify(self):
        neighbor = self.packet["observations"]["neighbor_health"]["value"]["actual_followup_clients"][0]
        neighbor.pop("pid")
        neighbor["observation"].pop("pid")
        with self.assertRaisesRegex(ValueError, "Neighbor health/direct wait"):
            self.run_materializer()

    def test_fabricated_oracle_cannot_replace_independent_review(self):
        self.decision["effective_oracle"] = copy.deepcopy(self.fixture.oracle)
        with self.assertRaisesRegex(ValueError, "Oracle review must bind"):
            self.run_materializer()

    def test_event_payload_and_wrong_native_byte_count_are_rejected(self):
        self.packet["observations"]["native_events"]["value"][0]["payload"] = "secret"
        with self.assertRaisesRegex(ValueError, "Forbidden event field"):
            self.run_materializer()
        del self.packet["observations"]["native_events"]["value"][0]["payload"]
        self.checks["response_append_bytes"] = 3
        with self.assertRaisesRegex(ValueError, "response append bytes"):
            self.run_materializer()

    def test_absent_phase_needs_forbidden_native_function_and_false_eos(self):
        self.candidate["measured_assertions"]["response_terminal_to_p4_once"] = False
        self.checks["allowed_absent_phases"] = [4]
        with self.assertRaisesRegex(ValueError, "Absent phase must explicitly forbid"):
            self.run_materializer()

    def test_unknown_diagnostic_id_and_nonzero_driver_cannot_qualify(self):
        self.decision["run_scoped_case_id"] = "I12::nginx-native::control-empty-get"
        with self.assertRaisesRegex(ValueError, "diagnostic"):
            self.run_materializer()
        self.decision["run_scoped_case_id"] = self.packet["run_scoped_case_id"]
        self.candidates["driver_exit"] = 1
        with self.assertRaisesRegex(ValueError, "driver must exit zero"):
            self.run_materializer()

    def test_oracle_event_fields_cannot_be_split_between_physical_events(self):
        self.fixture.baseline["rows"][1]["selected_requirement"]["expected_oracle"]["event_fields"] = ["rule_id", "phase"]
        self.checks["oracle_event_fields"] = ["rule_id", "phase"]
        events = self.packet["observations"]["native_events"]["value"]
        events.extend([{**self.provenance, "event": "rule", "rule_id": 101},
                       {**self.provenance, "event": "phase", "phase": 4}])
        with self.assertRaisesRegex(ValueError, "one physical event"):
            self.run_materializer()
        events[-1]["rule_id"] = 101
        self.assertEqual(len(self.run_materializer()), 1)

    def test_root_decision_cannot_drop_effective_oracle_event_fields(self):
        self.fixture.baseline["rows"][1]["selected_requirement"]["expected_oracle"]["event_fields"] = ["rule_id", "phase"]
        self.checks["oracle_event_fields"] = ["rule_id"]
        with self.assertRaisesRegex(ValueError, "exact effective oracle event_fields"):
            self.run_materializer()

    def test_wrong_or_missing_event_provenance_cannot_qualify(self):
        event = self.packet["observations"]["native_events"]["value"][0]
        for field in self.provenance:
            original = event[field]
            for value in (None, "different-physical-identity"):
                with self.subTest(field=field, value=value):
                    if value is None:
                        event.pop(field, None)
                    else:
                        event[field] = value
                    with self.assertRaisesRegex(ValueError, "physical event provenance " + field):
                        self.run_materializer()
            event[field] = original

    def test_observation_cannot_relabel_the_physical_event_row(self):
        self.physical_events = copy.deepcopy(self.packet["observations"]["native_events"]["value"])
        self.physical_events[0]["run_id"] = "original-wrong-run"
        with self.assertRaisesRegex(ValueError, "exact physical event-sink row"):
            self.run_materializer()

    def test_one_physical_row_cannot_be_counted_twice(self):
        events = self.packet["observations"]["native_events"]["value"]
        self.physical_events = copy.deepcopy(events)
        events.append(copy.deepcopy(events[0]))
        with self.assertRaisesRegex(ValueError, "exact physical event-sink row"):
            self.run_materializer()

    def test_optional_receipt_connection_and_request_ids_are_exact(self):
        proof = self.packet["observations"]["client_exit"]["evidence"][0]
        path = Path(proof["path"])
        receipt = json.loads(path.read_text())
        receipt["clients"][0]["observation"].update(connection_id="nginx-42", request_id="request-1")
        path.write_text(json.dumps(receipt))
        proof.update(QUALIFY.LEDGER.ORACLES.reference(path))
        event = self.packet["observations"]["native_events"]["value"][0]
        for field in ("connection_id", "request_id"):
            with self.assertRaisesRegex(ValueError, "physical event provenance " + field):
                self.run_materializer()
            event[field] = receipt["clients"][0]["observation"][field]
        self.assertEqual(len(self.run_materializer()), 1)

    def test_matching_oracle_fields_on_wrong_run_cannot_supply_pass(self):
        self.fixture.baseline["rows"][1]["selected_requirement"]["expected_oracle"]["event_fields"] = ["rule_id", "phase"]
        self.checks["oracle_event_fields"] = ["rule_id", "phase"]
        self.packet["observations"]["native_events"]["value"].append(
            {**self.provenance, "run_id": "neighbor-run", "event": "rule", "rule_id": 101, "phase": 4})
        with self.assertRaisesRegex(ValueError, "physical event provenance run_id"):
            self.run_materializer()

    def test_pass_cannot_declare_missing_oracle_fields_but_fail_can(self):
        self.fixture.baseline["rows"][1]["selected_requirement"]["expected_oracle"]["event_fields"] = ["rule_id"]
        self.checks["oracle_event_fields"] = ["rule_id"]
        self.checks["oracle_event_fields_in_single_event"] = False
        with self.assertRaisesRegex(ValueError, "PASS requires"):
            self.run_materializer()
        self.decision["outcome"] = "FAIL"
        records = self.run_materializer()
        self.assertEqual(json.loads(Path(records[0]["packet"]["path"]).read_text())["outcome"], "FAIL")

    def test_run_root_requires_explicit_protected_configuration(self):
        with mock.patch.dict(os.environ, {"CODEX_RUN_ROOT": ""}):
            with self.assertRaisesRegex(ValueError, "CODEX_RUN_ROOT"):
                QUALIFY.publication_path(self.fixture.path / "approved")
        for configured in ("relative", str(self.fixture.path / ".."), "/"):
            with self.subTest(configured=configured):
                with mock.patch.dict(os.environ, {"CODEX_RUN_ROOT": configured}):
                    with self.assertRaises(ValueError):
                        QUALIFY.evidence_root()
        self.fixture.path.chmod(0o777)
        self.addCleanup(self.fixture.path.chmod, 0o700)
        with mock.patch.dict(os.environ, {"CODEX_RUN_ROOT": str(self.fixture.path)}):
            with self.assertRaisesRegex(ValueError, "protected"):
                QUALIFY.evidence_root()

    def test_native_return_counts_bind_process_partial_and_negative_returns(self):
        calls = self.packet["observations"]["native_api_returns"]["value"]["measured_calls"]
        calls[0]["result"] = 1
        calls.extend([{"function": "native_append_request_body", "result": 0, "input_size": 8},
                      {"function": "native_append_request_body", "result": 0, "input_size": 8},
                      {"function": "native_intervention", "result": -9}])
        self.checks["native_return_checks"] = [
            {"function": "native_append_request_body", "result": 0, "input_size": 8, "count": 2},
            {"function": "native_process_request_body", "result": 1, "count": 1},
            {"function": "native_intervention", "result": -9, "count": 1}]
        calls[-2]["result"] = 1
        with self.assertRaisesRegex(ValueError, "native return subset count"):
            self.run_materializer()
        calls[-2]["result"] = 0
        self.assertEqual(len(self.run_materializer()), 1)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
