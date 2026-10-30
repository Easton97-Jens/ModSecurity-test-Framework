"""Explicit specialist regressions for migrated host result producers.

These tests exercise persistence and failure boundaries without claiming a
hosted connector run. Selection is on-demand in the authoritative inventory.
"""
from __future__ import annotations

from email.message import Message
import contextlib
import hashlib
import http.client
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from modsecurity_test_framework.connector_context import load_tool, test_root


collector = load_tool("ci/runtime/lifecycle/collect-no-crs-source.py")
envoy_helper = load_tool("connectors/envoy/harness/envoy_smoke_helper.py")
baseline = importlib.import_module("ci.checks.catalog.no_crs_baseline")


def shell_function(source: str, name: str) -> str:
    start = source.index(name + "() {")
    return source[start:source.index("\n}\n", start) + 3]


def ledger_digest(rows: list[dict]) -> str:
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ResultMigrationRegressions(unittest.TestCase):
    def client_observation(self, root, *, revision=None):
        from modsecurity_connector_tests.test_result_identity_contract import RequestObservationContractTests
        return RequestObservationContractTests().result(root, revision=revision)

    def test_request_bound_collector_and_canonical_projection_keep_closed_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = self.client_observation(root)
            observations, events = collector.case_row_observations(
                row, "apache", {"allow_without_marker": (200, None, 1)}, root, [], None)
            self.assertEqual(len(observations), 1)
            self.assertEqual(events, [])
            observed = observations[0]
            self.assertEqual(observed["request_observation"], row["request_observation"])
            self.assertEqual(observed["evidence_identity"], "request_bound")
            self.assertIsNone(observed["transaction_id"])
            self.assertFalse(observed["promotion_allowed"])
            catalog = {case["case_id"]: case for case in baseline.catalog_cases(baseline.load_catalog())}
            record = baseline.normalize_case_record(observed, "apache", catalog, [])
            self.assertEqual(record["status"], "PASS")
            self.assertEqual(record["request_id"], row["request_id"])
            self.assertEqual(record["request_observation"], row["request_observation"])
            self.assertEqual(record["observed_rule_ids"], [])
            self.assertEqual(record["transaction_ids"], [])
            self.assertFalse(record["event_metadata_verified"])
            schema = baseline.load_json(test_root() / "tests/schemas/no-crs-baseline/case-result.schema.json")
            self.assertEqual(baseline.case_result_schema_errors([record], schema, "apache"), [])
            self.assertEqual(baseline.generic_pass_case_completeness_errors(record, [], "apache", None), [])
            self.assertEqual(baseline.finalize_capability_sets([record], {"capabilities": {}})[0], [])
            facts, _ = baseline.status_record_facts([record])
            self.assertEqual(facts["capabilities_verified"], [])
            self.assertFalse(facts["request_headers_verified"])

    def test_request_bound_collector_rejects_altered_proof_nonce_and_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = self.client_observation(root)
            catalog = {case["case_id"]: case for case in baseline.catalog_cases(baseline.load_catalog())}
            for changes in ({"request_id": "request-" + "b" * 32}, {"run_id": "borrowed-run"},
                            {"source_revision": "b" * 40}, {"case_id": "deny_header_marker_403"},
                            {"request_observation": {**row["request_observation"], "receipt_sha256": "0" * 64}},
                            {"native_operation_receipt": {}}):
                with self.subTest(changes=changes):
                    altered = {**row, **changes}
                    with self.assertRaises(ValueError):
                        collector.case_row_observations(
                            altered, "apache", {"allow_without_marker": (200, None, 1),
                                                "deny_header_marker_403": (403, "1100001", 1)}, root, [], None)
                    with self.assertRaises(ValueError):
                        baseline.normalize_case_record(altered, "apache", catalog, [])

    def test_request_bound_collector_never_treats_nonce_as_a_transaction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = self.client_observation(root)
            foreign = root / "foreign.jsonl"
            foreign.write_text(json.dumps({"transaction_id": row["request_id"], "event": "phase4_intervention",
                                           "rule_id": 1100301, "phase": 4, "http_status": 403}) + "\n")
            self.assertEqual(collector.record_transaction_ids(row), set())
            borrowed = {**row, "connector_phase4_log_path": str(foreign), "rule_id": 1100301}
            observed, events = collector.case_row_observations(
                borrowed, "apache", {"allow_without_marker": (200, None, 1)}, root, [], None)
            self.assertEqual(events, [])
            self.assertEqual(observed[0]["observed_rule_ids"], [])
            self.assertEqual(observed[0]["transaction_ids"], [])
            self.assertNotIn("actual_action", observed[0])
            self.assertFalse(observed[0]["promotion_allowed"])

    def test_client_and_host_collection_validate_context_and_nonce_in_both_orders(self):
        with tempfile.TemporaryDirectory() as temporary:
            row = self.client_observation(Path(temporary))
            row["status"] = "PASS"
            host = {"case_id": "deny_header_marker_403", "status": "PASS", "actual_status": 403,
                    "run_id": row["run_id"], "source_revision": row["source_revision"],
                    "request_id": "host-request", "transaction_id": "host-tx",
                    "transaction_ids": ["host-tx"], "observed_rule_ids": [1100001],
                    "evidence_identity": "bound"}
            for reverse in (False, True):
                ordered = lambda item: [row, item] if reverse else [item, row]
                with self.subTest(order=reverse, case="same-context"):
                    self.assertEqual(len(collector.unique_case_observations(ordered(host))), 2)
                with self.subTest(order=reverse, case="existing-host-alias"):
                    aliases = [host, {**host, "case_id": "event_contains_rule_id"}]
                    self.assertEqual(len(collector.unique_case_observations(
                        [row, *aliases] if reverse else [*aliases, row])), 3)
                for changes in ({"run_id": "foreign-run"}, {"source_revision": "b" * 40},
                                {"request_id": row["request_id"]}):
                    with self.subTest(order=reverse, changes=changes):
                        observations = ordered({**host, **changes})
                        with self.assertRaises(ValueError):
                            collector.unique_case_observations(observations)

    def test_completed_client_observation_survives_finalize_and_status_readback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row_root = root / "client"; row_root.mkdir()
            row = self.client_observation(row_root, revision=os.environ["CONNECTOR_REVISION"])
            observations, _ = collector.case_row_observations(
                row, "apache", {"allow_without_marker": (200, None, 1)}, row_root, [], None)
            capabilities = root / "capabilities.json"
            capabilities.write_text(json.dumps({
                "schema_version": 1, "connector": "apache", "host_name": "apache",
                "integration_mode": "unit-test-host-model", "host_model_constraints": [],
                "capabilities": {name: {"state": "verified" if name in {"request_headers", "phase1", "deny"}
                                       else "unsupported_by_host_model", "reason": "unit fixture"}
                                 for name in baseline.CAPABILITIES},
                "evidence_stages": {stage: {"status": "not_executed", "reason": "unit fixture", "evidence": []}
                                   for stage in baseline.EVIDENCE_STAGES}}))
            source = root / "source.json"
            source.write_text(json.dumps({"schema_version": 1, "connector": "apache", "status": "FAIL",
                                         "run_id": row["run_id"], "connector_commit": row["source_revision"],
                                         "started": True, "requests_sent": True, "cases": observations}))
            run = root / "run"
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                self.assertEqual(baseline.main([
                    "init", "--connector", "apache", "--run-id", row["run_id"], "--run-dir", str(run),
                    "--capabilities", str(capabilities), "--connector-commit", row["source_revision"],
                    "--connector-root", os.environ["CONNECTOR_ROOT"],
                    "--host-version", "2.4.66", "--libmodsecurity-version", "3.0.17"]), 0)
                self.assertEqual(baseline.main([
                    "finalize", "--run-dir", str(run), "--capabilities", str(capabilities),
                    "--connector-root", os.environ["CONNECTOR_ROOT"],
                    "--source-result", str(source), "--stage-rc", "1"]), 1)
            self.assertTrue((run / baseline.CASE_RESULTS_FILE_NAME).is_file(), captured.getvalue())
            records = baseline.read_jsonl(run / baseline.CASE_RESULTS_FILE_NAME)
            observed = next(record for record in records if record["case_id"] == "allow_without_marker")
            self.assertEqual(observed["status"], "PASS")
            self.assertEqual(observed["request_observation"], row["request_observation"])
            self.assertEqual(observed["request_id"], row["request_id"])
            self.assertFalse(observed["promotion_allowed"])
            self.assertIsNone(observed["transaction_id"])
            self.assertEqual(json.loads((run / "result.json").read_text())["capabilities_verified"], [])
            self.assertEqual(json.loads((run / "result.json").read_text())["cases_passed"], 1)
            self.assertEqual(baseline.status_errors(run), [])
            index = records.index(observed)
            for changes in ({"request_id": "request-" + "c" * 32}, {"runtime_verified": True},
                            {"promotion_allowed": True}, {"source_revision": "b" * 40},
                            {"observed_rule_ids": [1100301]}, {"actual_action": "deny"},
                            {"request_observation": {**observed["request_observation"], "receipt_sha256": "0" * 64}}):
                with self.subTest(readback_tamper=changes):
                    records[index] = {**observed, **changes}
                    (run / baseline.CASE_RESULTS_FILE_NAME).write_text("".join(json.dumps(record) + "\n" for record in records))
                    self.assertTrue(baseline.status_errors(run))

    def test_failed_precase_traffic_survives_finalize_and_status_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capabilities = root / "capabilities.json"
            capabilities.write_text(json.dumps({
                "schema_version": 1, "connector": "envoy", "host_name": "envoy",
                "integration_mode": "unit-test-host-model", "host_model_constraints": [],
                "capabilities": {name: {"state": "unsupported_by_host_model", "reason": "unit fixture"}
                                 for name in baseline.CAPABILITIES},
                "evidence_stages": {stage: {"status": "not_executed", "reason": "unit fixture", "evidence": []}
                                    for stage in baseline.EVIDENCE_STAGES},
            }))
            run = root / "run"
            row = {"schema_version": 1, "evidence_type": "envoy_http_client_probe",
                   "run_id": "before-case-failure", "source_revision": os.environ["CONNECTOR_REVISION"],
                   "request_id": "readiness-observed", "status": "FAIL", "actual_status": 500,
                   "http_status": 500, "response_bytes": 0, "body_payload_persisted": False,
                   "response_headers_observed": True, "live_executed": True}
            rows = [row]
            source = root / "source.json"
            source.write_text(json.dumps({"connector": "envoy", "status": "FAIL", "started": True,
                "run_id": row["run_id"], "connector_commit": row["source_revision"],
                "executed_request_observations": rows,
                "executed_request_observations_sha256": hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            }))
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(baseline.main([
                    "init", "--connector", "envoy", "--run-id", row["run_id"], "--run-dir", str(run),
                    "--capabilities", str(capabilities), "--evidence-stage", "minimal_runtime_smoke",
                    "--connector-root", os.environ["CONNECTOR_ROOT"], "--host-version", "1.0", "--libmodsecurity-version", "3.0.15",
                ]), 0)
                self.assertEqual(baseline.main([
                    "finalize", "--run-dir", str(run), "--connector-root", os.environ["CONNECTOR_ROOT"],
                    "--capabilities", str(capabilities), "--source-result", str(source), "--stage-rc", "1",
                    "--host-version", "1.0", "--libmodsecurity-version", "3.0.15",
                ]), 1)
            result = json.loads((run / "result.json").read_text())
            self.assertEqual(result["status"], "FAIL")
            self.assertTrue(result["started"])
            self.assertTrue(result["requests_sent"])
            self.assertFalse(result["blocked_before_execution"])
            self.assertEqual(result["cases_passed"], 0)
            records = baseline.read_jsonl(run / baseline.CASE_RESULTS_FILE_NAME)
            self.assertNotIn("readiness-observed", {record["case_id"] for record in records})
            self.assertEqual(baseline.status_errors(run), [])

    def test_precase_executed_traffic_survives_canonical_accounting_without_adding_a_case(self) -> None:
        identity = {"run_id": "run-one", "connector_commit": "a" * 40, "connector": "envoy"}
        row = {"schema_version": 1, "evidence_type": "envoy_http_client_probe",
               "run_id": "run-one", "source_revision": "a" * 40, "request_id": "readiness-one",
               "status": "FAIL", "actual_status": 500, "http_status": 500, "response_bytes": 0,
               "body_payload_persisted": False, "response_headers_observed": True, "live_executed": True}
        source = {"connector": "envoy", "status": "FAIL", "executed_request_observations": [row],
                  "executed_request_observations_sha256": ledger_digest([row])}
        self.assertTrue(baseline.validated_source_request_observed([source], identity))
        facts, pass_ids = baseline.status_record_facts([], source_payloads=[source], identity=identity)
        self.assertTrue(facts["requests_sent"])
        self.assertEqual(pass_ids, set())
        self.assertEqual(facts["capabilities_verified"], [])
        self.assertFalse(facts["request_headers_verified"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "inventory").mkdir()
            path = root / "inventory/source-result-0.json"
            path.write_text(json.dumps(source))
            manifest = {**identity, "artifacts": {"source_result_0": {
                "state": "produced", "path": "inventory/source-result-0.json",
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }}}
            retained = baseline.retained_request_observation_sources(root, manifest)
            self.assertTrue(baseline.validated_source_request_observed(retained, identity))
            path.write_text(json.dumps({**source, "status": "PASS"}))
            with self.assertRaisesRegex(baseline.ContractError, "digest mismatch"):
                baseline.retained_request_observation_sources(root, manifest)
        for field, value in (("run_id", "foreign"), ("source_revision", "b" * 40), ("response_headers_observed", False)):
            with self.subTest(field=field):
                changed = {**row, field: value}
                invalid = {**source, "executed_request_observations": [changed],
                           "executed_request_observations_sha256": ledger_digest([changed])}
                with self.assertRaises(baseline.ContractError):
                    baseline.validated_source_request_observed([invalid], identity)
        self.assertFalse(baseline.validated_source_request_observed([{"requests_sent": True}], identity))

    def test_explicit_transaction_is_not_widened_by_the_request_attempt_identifier(self) -> None:
        self.assertEqual(collector.record_transaction_ids({
            "transaction_id": "actual-host-tx", "request_id": "independent-attempt-id",
        }), {"actual-host-tx"})

    def test_audit_rules_cannot_be_paired_with_another_line_or_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.log"
            path.write_text('[id "1100001"] (phase 1) [unique_id "foreign"]\n'
                            '[id "1100504"] (phase 1) [unique_id "actual"]\n')
            event = collector.audit_event(path, "apache", 200, {"actual"})
            self.assertEqual(event["rule_id"], 1100504)
            self.assertEqual(event["transaction_id"], "actual")
            self.assertIsNone(collector.audit_event(path, "apache", 200, {"missing"}))
            path.write_text('[id "1100001"] (phase 1)\n[unique_id "actual"]\n')
            self.assertIsNone(collector.audit_event(path, "apache", 200, {"actual"}))

    def test_unbound_source_cannot_borrow_an_audit_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.log"
            path.write_text('[id "1100001"] (phase 1) [unique_id "foreign"]\n')
            self.assertEqual(collector.audit_fallback_events(
                "deny_header_marker_403", 1, [], path, "apache", 403), [])

    def test_retries_count_once_and_retain_failed_executed_attempts(self) -> None:
        failed = {"case_id": "case-one", "status": "FAIL", "actual_status": 500,
                  "live_executed": True, "run_id": "run-one", "source_revision": "a" * 40,
                  "request_id": "request-one", "transaction_ids": ["tx-one"]}
        retry = {**failed, "status": "PASS", "actual_status": 200,
                 "request_id": "request-two", "transaction_ids": ["tx-two"]}
        cases = collector.unique_case_observations([failed, retry])
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["status"], "FAIL")
        self.assertEqual(cases[0]["attempt_count"], 2)
        self.assertEqual(cases[0]["attempts"], [failed, retry])
        with self.assertRaisesRegex(ValueError, "conflicting"):
            collector.unique_case_observations([failed, {**failed, "actual_status": 200}])

    def test_unbound_row_cannot_borrow_a_foreign_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events.jsonl"
            events.write_text(json.dumps({"transaction_id": "foreign", "http_status": 403}) + "\n")
            self.assertEqual(collector.row_runtime_records({}, events, root, []), [])

    def test_same_transaction_with_wrong_run_or_revision_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events.jsonl"
            for field in ("run_id", "case_id", "request_id", "source_revision"):
                with self.subTest(field=field):
                    events.write_text(json.dumps({"transaction_id": "tx", field: "foreign"}) + "\n")
                    with self.assertRaisesRegex(ValueError, "identity mismatch"):
                        collector.row_runtime_records({"transaction_id": "tx", field: "expected"}, events, root, [])

    def test_failed_native_summary_keeps_executed_statuses(self) -> None:
        records = collector.native_host_summary_cases([{
            "status": "FAIL", "common_runtime_bridge": True,
            "rule_evaluation": "libmodsecurity", "allowed_request_status": 200,
            "phase1_deny_status": 500,
        }])
        self.assertEqual({row["case_id"]: row["actual_status"] for row in records}, {
            "allow_without_marker": 200, "deny_header_marker_403": 500,
        })
        self.assertTrue(all(row["live_executed"] and row["status"] == "FAIL" for row in records))
        self.assertTrue(all(row["promotion_allowed"] is False for row in records))

    def test_probe_persists_completed_traffic_before_header_assertion_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_log = root / "events.jsonl"
            event_log.write_text(json.dumps({"transaction_id": "actual-host-tx"}) + "\n")
            headers = Message()
            headers["X-Forbidden"] = "do-not-persist-this-value"
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.status, response.headers = 200, headers
            response.read.return_value = b"do-not-persist-this-body"
            opener = mock.Mock()
            opener.open.return_value = response
            with mock.patch.dict(os.environ, {
                "COMMON_EVENT_LOG_PATH": str(event_log), "NO_CRS_RUN_ID": "run-one",
                "CONNECTOR_REVISION": "a" * 40,
            }), mock.patch.object(envoy_helper, "trusted_loopback_tls_context", return_value=None), \
                    mock.patch.object(envoy_helper.urllib.request, "build_opener", return_value=opener):
                with self.assertRaisesRegex(RuntimeError, "forbidden response header"):
                    envoy_helper.probe(str(root), str(root / "unused.crt"), "https://127.0.0.1:1/allowed",
                                       ["X-Request-Id: actual-host-tx"], "GET", None, False,
                                       forbid_response_header=["X-Forbidden"])
            text = (root / "probe-observations.jsonl").read_text()
            row = json.loads(text)
            self.assertEqual(row["actual_status"], 200)
            self.assertEqual(row["status"], "FAIL")
            self.assertTrue(row["live_executed"])
            self.assertEqual(row["transaction_ids"], ["actual-host-tx"])
            self.assertNotIn("do-not-persist", text)

    def test_probe_retains_a_started_stream_when_reading_its_body_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.status, response.headers = 200, Message()
            response.read.side_effect = http.client.IncompleteRead(b"private-partial-body", 20)
            opener = mock.Mock()
            opener.open.return_value = response
            with mock.patch.dict(os.environ, {"COMMON_EVENT_LOG_PATH": ""}), \
                    mock.patch.object(envoy_helper, "trusted_loopback_tls_context", return_value=None), \
                    mock.patch.object(envoy_helper.urllib.request, "build_opener", return_value=opener):
                with self.assertRaisesRegex(RuntimeError, "body did not complete"):
                    envoy_helper.probe(str(root), str(root / "unused.crt"), "https://127.0.0.1:1/streamed",
                                       ["X-Request-Id: started-stream"], "GET", None, False)
            text = (root / "probe-observations.jsonl").read_text()
            row = json.loads(text)
            self.assertEqual(row["actual_status"], 200)
            self.assertEqual(row["status"], "FAIL")
            self.assertTrue(row["live_executed"])
            self.assertFalse(row["response_body_completed"])
            self.assertNotIn("private-partial-body", text)

    def test_envoy_failure_finalizer_publishes_the_durable_observation_reference(self) -> None:
        source = (test_root() / "connector_suite/adapters/envoy/harness/run_envoy_ext_proc_runtime.sh").read_text()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "probe-observations.jsonl").write_text('{"live_executed":true}\n')
            command = shell_function(source, "finalize_runtime") + '\ncleanup() { return 0; }\ntrap finalize_runtime EXIT\nexit 7\n'
            result = subprocess.run(["sh", "-eu", "-c", command], env={**os.environ,
                "RUNTIME_ROOT": str(root), "SUMMARY": str(root / "runtime-summary.txt"),
                "RESULT_RUN_ID": "run-one", "CONNECTOR_REVISION": "a" * 40,
                "COMMON_EVENT_LOG_PATH": str(root / "events.jsonl"),
            }, capture_output=True, text=True)
            self.assertEqual(result.returncode, 7, result.stderr)
            summary = collector.parse_key_value_text(root / "runtime-summary.txt")
            self.assertEqual(summary["status"], "FAIL")
            self.assertEqual(summary["probe_observations_path"], str(root / "probe-observations.jsonl"))
            self.assertEqual(summary["source_revision"], "a" * 40)

    def test_native_observations_require_matching_summary_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "observations.jsonl"
            row = {"evidence_type": "envoy_http_client_probe", "case_id": "allow_without_marker",
                   "run_id": "run-one", "source_revision": "a" * 40, "actual_status": 200,
                   "live_executed": True, "status": "FAIL"}
            path.write_text(json.dumps(row) + "\n")
            summary = {"probe_observations_path": str(path), "run_id": "run-one", "source_revision": "a" * 40}
            self.assertEqual(collector.native_probe_rows([summary], root), [row])
            for field in ("run_id", "source_revision"):
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, "identity mismatch"):
                    collector.native_probe_rows([{**summary, field: "foreign"}], root)

    def test_apache_and_nginx_abort_on_result_write_failure_or_missing_required_row(self) -> None:
        for connector in ("apache", "nginx"):
            source = (test_root() / f"connector_suite/adapters/{connector}/harness/run_{connector}_smoke.sh").read_text()
            for writer_status in (0, 9):
                with self.subTest(connector=connector, writer_status=writer_status), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    for directory in ("logs", "results", "runtime"):
                        (root / directory).mkdir()
                    child = root / "child.sh"
                    child.write_text("#!/bin/sh\nexit 0\n")
                    stubs = "\n".join(name + "() { return 0; }" for name in (
                        "require_absolute_generated_path", "prepare_runtime_directory",
                        "append_selected_phase4_fixtures", "validate_nginx_docroot_projection_mode",
                        "validate_nginx_external_projection_authority",
                    ))
                    command = stubs + '\nlist_case_files() { printf "/fixture/selected-case.yaml\\n"; }\n'
                    command += f"write_case_result() {{ return {writer_status}; }}\n"
                    if connector == "apache":
                        command += shell_function(source, "fail") + "\n"
                    command += shell_function(source, "run_all_cases") + "\nrun_all_cases\n"
                    result = subprocess.run(["sh", "-eu", "-c", command, str(child)], env={**os.environ,
                        "BUILD_ROOT": str(root), "LOG_DIR": str(root / "logs"),
                        "RESULTS_DIR": str(root / "results"), "RUNTIME_BASE": str(root / "runtime"),
                        "STATUS_FILE": str(root / "status.txt"),
                        "APACHE_CASE_OUTPUT_ROOT": str(root), "APACHE_LOG_DIR_LABEL": "LOG_DIR",
                        "APACHE_RESULTS_DIR_LABEL": "RESULTS_DIR", "BASE_PORT": "19000",
                        "MSCONNECTOR_SMOKE_STAGE": "minimal", "MSCONNECTOR_SMOKE_STAGE_BOUNDED_SOAK": "soak",
                        "NGINX_DOCROOT_PROJECTION": "0", "NGINX_DOCROOT_PROJECTION_ROOT": str(root / "projection"),
                        "PYTHON_BIN": sys.executable,
                        "OBSERVED_TRANSPORT_HTTP_STATUS": "http_status",
                    }, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertFalse((root / "results" / f"{connector}-summary.json").exists())

    def test_both_harness_writers_bind_only_the_actual_matching_host_transaction(self) -> None:
        framework = test_root()
        for connector in ("apache", "nginx"):
            source = (framework / f"connector_suite/adapters/{connector}/harness/run_{connector}_smoke.sh").read_text()
            with self.subTest(connector=connector), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                from modsecurity_test_framework.runners import case_cli
                case_path = framework / "tests/cases/no-crs-baseline/allow_without_marker.yaml"
                bracket = ["request-window", "--case", str(case_path), "--event-log", str(root / "phase4.log"),
                           "--receipt", str(root / "request-window.json"), "--output-root", str(root),
                           "--run-id", "run-one", "--source-revision", os.environ["CONNECTOR_REVISION"]]
                self.assertEqual(case_cli.main(bracket + ["--phase", "begin"]), 0)
                (root / "phase4.log").write_text("".join(json.dumps(record) + "\n" for record in (
                    {"transaction_id": "real-allow-tx", "method": "GET", "uri": "/no-crs/allow", "event": "request_completion"},
                    {"transaction_id": "foreign-deny-tx", "method": "GET", "uri": "/no-crs/deny", "event": "phase4_intervention", "http_status": 403},
                )))
                self.assertEqual(case_cli.main(bracket + ["--phase", "end"]), 0)
                command = shell_function(source, "write_case_result")
                command += '\nwrite_case_result "$CASE" pass 200 "$OUT" http_status\n'
                result = subprocess.run(["sh", "-eu", "-c", command], env={**os.environ,
                    "PYTHON_BIN": sys.executable, "CASE_CLI": str(framework / "tests/runners/case_cli.py"),
                    "CASE": str(framework / "tests/cases/no-crs-baseline/allow_without_marker.yaml"),
                    "OUT": str(root / "result.json"), "RESULT_RUN_ID": "run-one",
                    "APACHE_CASE_OUTPUT_ROOT": str(root), "NGINX_HARNESS_WORK_ROOT": str(root),
                    "PYTHONPATH": os.pathsep.join((str(framework), str(framework / "connector_suite"),
                                                   os.environ.get("PYTHONPATH", ""))),
                }, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                row = json.loads((root / "result.json").read_text())
                self.assertEqual(row["actual_status"], 200)
                self.assertEqual(row["visible_http_status"], 200)
                self.assertEqual(row["transaction_ids"], ["real-allow-tx"])
                self.assertEqual(row["request_id"], json.loads((root / "request-window.json").read_text())["request_id"])
                self.assertEqual(row["source_revision"], os.environ["CONNECTOR_REVISION"])
                self.assertNotIn("intervention_http_status", row)


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
