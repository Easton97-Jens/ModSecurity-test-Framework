from __future__ import annotations

import importlib.util
import io
import json
from contextlib import redirect_stderr
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("no_crs_baseline", ROOT / "ci/no_crs_baseline.py")
assert SPEC is not None and SPEC.loader is not None
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)
from runner_core import load_case, write_rules_file  # noqa: E402
from case_cli import phase4_runtime_evidence  # noqa: E402


def manifest(connector: str = "envoy", executable: set[str] | None = None) -> dict[str, object]:
    executable = executable or {"request_headers", "phase1", "deny"}
    capabilities = {
        name: {
            "state": "verified" if name in executable else "unsupported_by_host_model",
            "reason": "unit-test executable capability" if name in executable else "unit-test host boundary",
        }
        for name in no_crs.CAPABILITIES
    }
    return {
        "schema_version": 1,
        "connector": connector,
        "host_name": connector,
        "integration_mode": "unit-test-host-model",
        "host_model_constraints": [],
        "capabilities": capabilities,
        "evidence_stages": {
            stage: {"status": "not_executed", "reason": "unit-test stage not executed", "evidence": []}
            for stage in no_crs.EVIDENCE_STAGES
        },
    }


class NoCrsBaselineTest(unittest.TestCase):
    def normalize_phase4(
        self,
        case_id: str,
        event: dict[str, object],
        *,
        raw: dict[str, object] | None = None,
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "case_id": case_id,
            "status": "PASS",
            "live_executed": True,
            "observed_rule_ids": [1100301],
        }
        if raw:
            payload.update(raw)
        catalog = no_crs.load_catalog()
        record = no_crs.normalize_case_record(
            payload,
            "apache",
            {case["case_id"]: case for case in no_crs.catalog_cases(catalog)},
            [event],
        )
        self.assertIsNotNone(record)
        return record  # type: ignore[return-value]

    @staticmethod
    def phase4_event(**fields: object) -> dict[str, object]:
        event: dict[str, object] = {
            "connector": "apache",
            "event": "phase4_intervention",
            "message_id": "phase4-1100301",
            "transaction_id": "tx-phase4",
            "rule_id": 1100301,
            "phase": 4,
            "status": "intervened",
        }
        event.update(fields)
        return event

    def test_source_records_accepts_collector_case_list(self) -> None:
        records = no_crs.source_records({
            "cases": [
                {"case_id": "allow_without_marker", "status": "PASS"},
                {"case_id": "deny_header_marker_403", "status": "PASS"},
            ]
        })
        self.assertEqual(
            ["allow_without_marker", "deny_header_marker_403"],
            [record["case_id"] for record in records],
        )

    def test_makefile_propagates_connector_root_to_finalize_and_validation(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        validation_recipe = makefile.split("define RUN_NO_CRS_CHECK", 1)[1].split("endef", 1)[0]
        finalize_recipe = makefile.split("no-crs-finalize:", 1)[1].split("no-crs-summary:", 1)[0]
        expected = '--connector-root "$(CONNECTOR_ROOT)"'
        self.assertIn(expected, validation_recipe)
        self.assertIn(expected, finalize_recipe)
        self.assertIn("NO_CRS_ARTIFACT_PROFILE ?= generic", makefile)
        self.assertIn('--artifact-profile "$(NO_CRS_ARTIFACT_PROFILE)"', makefile)

    def test_generic_artifact_profile_keeps_optional_legacy_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
            plan_path = root / "legacy-generic-plan.json"
            run_dir = root / "evidence/envoy/generic"
            self.assertEqual(0, no_crs.main([
                "select", "--connector", "envoy", "--capabilities", str(capability_path),
                "--output", str(plan_path),
            ]))
            legacy_plan = no_crs.load_json(plan_path)
            self.assertEqual("generic", legacy_plan["artifact_profile"])
            legacy_plan.pop("artifact_profile")
            no_crs.write_json(plan_path, legacy_plan)
            self.assertEqual(0, no_crs.main([
                "init", "--connector", "envoy", "--capabilities", str(capability_path),
                "--plan", str(plan_path), "--run-dir", str(run_dir), "--run-id", "generic",
            ]))
            self.assertEqual(0, no_crs.main([
                "finalize", "--run-dir", str(run_dir), "--capabilities", str(capability_path),
                "--stage-rc", "0",
            ]))
            result = no_crs.load_json(run_dir / "result.json")
            manifest_payload = no_crs.load_json(run_dir / "manifest.json")
            self.assertEqual("generic", result["artifact_profile"])
            self.assertEqual("generic", manifest_payload["artifact_profile"])
            self.assertFalse((run_dir / "events.jsonl").exists())
            self.assertFalse((run_dir / "logs/stdout.log").exists())
            self.assertFalse((run_dir / "logs/stderr.log").exists())
            self.assertFalse((run_dir / "logs/host.log").exists())
            self.assertEqual([], no_crs.layout_errors(run_dir))

            # Existing generic runs and pre-profile external plans do not gain
            # a new required field merely because the strict profile exists.
            for relative_path in ("result.json", "inventory/run.json"):
                path = run_dir / relative_path
                payload = no_crs.load_json(path)
                payload.pop("artifact_profile")
                no_crs.write_json(path, payload)
            legacy_manifest = no_crs.load_json(run_dir / "manifest.json")
            legacy_manifest.pop("artifact_profile")
            legacy_manifest["artifacts"]["result"]["sha256"] = no_crs.sha256_file(
                run_dir / "result.json"
            )
            legacy_manifest["artifacts"]["inventory"]["sha256"] = no_crs.sha256_file(
                run_dir / "inventory/run.json"
            )
            self.assertNotIn("artifact_profile", no_crs.load_json(run_dir / "plan.json"))
            no_crs.write_json(run_dir / "manifest.json", legacy_manifest)
            capabilities = no_crs.load_capability_manifest(capability_path, "envoy")
            self.assertEqual(
                [],
                no_crs.validate_run(
                    run_dir, "envoy", capabilities, tuple(no_crs.VALID_CHECKS),
                ),
            )

    def test_full_lifecycle_artifact_profile_requires_host_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
            plan_path = root / "full-lifecycle-plan.json"
            run_dir = root / "evidence/envoy/full-lifecycle"
            self.assertEqual(0, no_crs.main([
                "select", "--connector", "envoy", "--capabilities", str(capability_path),
                "--artifact-profile", "full_lifecycle", "--output", str(plan_path),
            ]))
            plan = no_crs.load_json(plan_path)
            self.assertEqual("full_lifecycle", plan["artifact_profile"])
            self.assertEqual(0, no_crs.main([
                "init", "--connector", "envoy", "--capabilities", str(capability_path),
                "--artifact-profile", "full_lifecycle", "--plan", str(plan_path),
                "--run-dir", str(run_dir), "--run-id", "full-lifecycle",
            ]))
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(1, no_crs.main([
                    "finalize", "--run-dir", str(run_dir), "--capabilities", str(capability_path),
                    "--stage-rc", "0",
                ]))
            self.assertIn(
                "full_lifecycle artifact profile requires host-produced",
                stderr.getvalue(),
            )

            events_path = root / "events.jsonl"
            stdout_path = root / "stdout.log"
            stderr_path = root / "stderr.log"
            host_log_path = root / "host.log"
            events_path.write_text('{"connector":"envoy"}\n', encoding="utf-8")
            for path in (stdout_path, stderr_path, host_log_path):
                path.write_text("", encoding="utf-8")
            self.assertEqual(0, no_crs.main([
                "finalize", "--run-dir", str(run_dir), "--capabilities", str(capability_path),
                "--source-events", str(events_path), "--stdout-log", str(stdout_path),
                "--stderr-log", str(stderr_path), "--host-log", str(host_log_path),
                "--stage-rc", "0",
            ]))
            expected_paths = dict(no_crs.FULL_LIFECYCLE_REQUIRED_ARTIFACTS)
            for name, relative_path in expected_paths.items():
                with self.subTest(artifact=name):
                    self.assertTrue((run_dir / relative_path).is_file())
            for path in ("result.json", "manifest.json", "inventory/run.json"):
                payload = no_crs.load_json(run_dir / path)
                self.assertEqual("full_lifecycle", payload["artifact_profile"])
            self.assertEqual([], no_crs.layout_errors(run_dir))
            capabilities = no_crs.load_capability_manifest(capability_path, "envoy")
            self.assertEqual(
                [],
                no_crs.validate_run(
                    run_dir, "envoy", capabilities, tuple(no_crs.VALID_CHECKS),
                ),
            )

    def test_post_execution_missing_evidence_is_fail_not_exit_77(self) -> None:
        source = (ROOT / "ci/connector-smoke-common.sh").read_text(encoding="utf-8")
        block = source[source.index('if [ "$rc" -eq 0 ] && [ "${RUN_ONE_CASE:-0}" = "1" ]'):]
        block = block[:block.index('    exit "$rc"')]
        self.assertIn('FAIL 1 failed "RUN_ONE_CASE result.json missing after execution"', block)
        self.assertIn("<<'PY_RUN_ONE_CASE' || exit 1", block)
        self.assertIn('FAIL 1 failed "runtime harness produced no case evidence after execution"', block)
        self.assertNotIn("exit 77", block)

    def test_catalog_has_complete_mandatory_core_and_native_rule_contract(self) -> None:
        catalog = no_crs.load_catalog()
        self.assertEqual([], no_crs.validate_catalog(catalog))
        self.assertEqual(104, len(no_crs.catalog_cases(catalog)))
        by_id = {case["case_id"]: case for case in no_crs.catalog_cases(catalog)}
        self.assertTrue(
            {
                "phase4_rule_observed",
                "phase4_deny_before_commit",
                "phase4_deny_after_commit_log_only",
                "phase4_deny_after_commit_abort",
                "phase4_event_contains_original_status",
                "phase4_event_contains_late_intervention_action",
            }.issubset(set(no_crs.PHASE4_CASE_IDS))
        )
        self.assertTrue(no_crs.FULL_LIFECYCLE_REQUIRED_IDS.issubset(by_id))
        self.assertEqual(
            {"minimal", "safe", "strict"},
            {
                by_id[case_id]["request"]["late_intervention_mode"]
                for case_id in (
                    "phase4_deny_after_commit_log_only_minimal",
                    "phase4_deny_after_commit_log_only_safe",
                    "phase4_deny_after_commit_abort_strict",
                )
            },
        )
        self.assertEqual(
            {
                "request_body_incremental_ingest",
                "response_body_incremental_ingest",
                "phase4_end_of_stream_evaluation",
                "no_full_response_buffering",
                "first_byte_before_response_end",
                "content_type_scope",
                "request_body_limits",
                "response_body_limits",
                "header_limits",
                "transport_metadata",
            },
            {
                capability
                for case in by_id.values()
                for capability in case["required_capabilities"]
                if capability in {
                    "request_body_incremental_ingest",
                    "response_body_incremental_ingest",
                    "phase4_end_of_stream_evaluation",
                    "no_full_response_buffering",
                    "first_byte_before_response_end",
                    "content_type_scope",
                    "request_body_limits",
                    "response_body_limits",
                    "header_limits",
                    "transport_metadata",
                }
            },
        )
        self.assertEqual(
            "phase4_deny_before_commit",
            by_id["deny_response_body_marker_403"]["deprecated_alias_for"],
        )
        self.assertEqual(403, by_id["deny_response_body_marker_403"]["expected_status"])
        self.assertNotIn("runner_case", by_id["deny_response_body_marker_403"])
        self.assertEqual(
            "deny_response_body_marker_403.yaml",
            by_id["phase4_deny_before_commit"]["runner_case"],
        )
        runner_cases = [case for case in no_crs.catalog_cases(catalog) if case.get("runner_case")]
        self.assertEqual(8, len(runner_cases))
        self.assertNotIn("deny_response_header_marker_403", {case["case_id"] for case in runner_cases})
        rules = no_crs.RULES_PATH.read_text(encoding="utf-8")
        self.assertIn('REQUEST_HEADERS:X-Modsec-Smoke "@streq block"', rules)
        self.assertIn("id:1100001,phase:1,deny,status:403", rules)
        self.assertIn("id:1100202,phase:3,redirect", rules)
        self.assertNotIn("Include", rules)

    def test_all_declared_runner_cases_materialize_the_full_ruleset_once(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            for catalog_case in no_crs.catalog_cases(no_crs.load_catalog()):
                runner_case = catalog_case.get("runner_case")
                if not runner_case:
                    continue
                case = load_case(no_crs.CATALOG_PATH.parent / str(runner_case))
                output = root / f"{catalog_case['case_id']}.conf"
                write_rules_file(
                    case, output, root / "audit.log", root / "audit",
                    no_crs.RULES_PATH,
                )
                content = output.read_text(encoding="utf-8")
                self.assertEqual(1, content.count("id:1100001,"))
                self.assertIn("id:1100403,", content)
                self.assertNotIn("@@AUDIT_LOG@@", content)

    def test_full_lifecycle_fixtures_are_future_inventory_until_a_host_runs_them(self) -> None:
        catalog = no_crs.load_catalog()
        fixture_cases = [
            case for case in no_crs.catalog_cases(catalog)
            if isinstance(case.get("request"), dict) and case["request"].get("fixture")
        ]
        self.assertGreaterEqual(len(fixture_cases), 8)
        for catalog_case in fixture_cases:
            with self.subTest(case_id=catalog_case["case_id"]):
                fixture_path = no_crs.CATALOG_PATH.parent / catalog_case["request"]["fixture"]
                fixture = load_case(fixture_path)
                self.assertEqual("future", fixture["status"])
                self.assertEqual("not_executed_until_real_host", fixture["full_lifecycle"]["evidence_status"])
                self.assertNotIn("runner_case", catalog_case)

    def test_full_lifecycle_phase2_split_requires_chunk_evidence(self) -> None:
        catalog = no_crs.load_catalog()
        case_by_id = {case["case_id"]: case for case in no_crs.catalog_cases(catalog)}
        event = {
            "connector": "apache",
            "transaction_id": "tx-phase2-split",
            "rule_id": 1100101,
            "phase": 2,
            "status": 403,
            "marker_split_across_chunks": True,
            "body_bytes_seen": 27,
            "body_bytes_inspected": 27,
        }
        raw = {
            "case_id": "phase2_marker_split_across_chunks",
            "status": "PASS",
            "live_executed": True,
            "actual_status": 403,
            "observed_rule_ids": [1100101],
            "transaction_id": "tx-phase2-split",
        }
        record = no_crs.normalize_case_record(raw, "apache", case_by_id, [event])
        self.assertIsNotNone(record)
        self.assertEqual("PASS", record["status"])
        missing = dict(event)
        missing.pop("marker_split_across_chunks")
        record = no_crs.normalize_case_record(raw, "apache", case_by_id, [missing])
        self.assertIsNotNone(record)
        self.assertEqual("FAIL", record["status"])

    def test_full_lifecycle_first_byte_proof_requires_a_causal_barrier_event(self) -> None:
        event = self.phase4_event(
            marker_split_across_chunks=True,
            end_of_stream_evaluation=True,
            no_full_response_buffering=True,
            first_byte_before_response_end=True,
            upstream_response_finished_at_first_byte=False,
        )
        record = self.normalize_phase4("phase4_first_byte_before_response_end", event)
        self.assertEqual("PASS", record["status"])
        missing_barrier = dict(event)
        missing_barrier.pop("upstream_response_finished_at_first_byte")
        record = self.normalize_phase4("phase4_first_byte_before_response_end", missing_barrier)
        self.assertEqual("FAIL", record["status"])
        buffered = dict(event)
        buffered["upstream_response_finished_at_first_byte"] = True
        record = self.normalize_phase4("phase4_no_full_response_buffering", buffered)
        self.assertEqual("FAIL", record["status"])

    def test_full_lifecycle_late_modes_require_their_actual_runtime_mode(self) -> None:
        base = {
            "http_status": 403,
            "requested_action": "deny",
            "original_http_status": 200,
            "visible_http_status": 200,
            "late_intervention": True,
            "headers_sent": True,
        }
        minimal = self.phase4_event(
            **base,
            actual_action="log_only",
            late_intervention_mode="minimal",
            connection_aborted=False,
        )
        self.assertEqual(
            "PASS",
            self.normalize_phase4(
                "phase4_deny_after_commit_log_only_minimal", minimal,
                raw={"actual_status": 200},
            )["status"],
        )
        wrong_mode = dict(minimal)
        wrong_mode["late_intervention_mode"] = "safe"
        self.assertEqual(
            "FAIL",
            self.normalize_phase4(
                "phase4_deny_after_commit_log_only_minimal", wrong_mode,
                raw={"actual_status": 200},
            )["status"],
        )
        strict = self.phase4_event(
            **base,
            actual_action="abort_connection",
            late_intervention_mode="strict",
            connection_aborted=True,
            transport_result="connection_aborted",
        )
        self.assertEqual(
            "PASS",
            self.normalize_phase4("phase4_deny_after_commit_abort_strict", strict)["status"],
        )

    def test_selection_is_capability_driven(self) -> None:
        payload = manifest(executable={"request_headers", "phase1", "deny", "request_body_buffered", "phase2"})
        payload["capabilities"]["request_body_buffered"]["state"] = "implemented_not_asserted"  # type: ignore[index]
        payload["capabilities"]["phase2"]["state"] = "configured_not_exercised"  # type: ignore[index]
        plan = no_crs.select_cases("envoy", payload, no_crs.load_catalog())
        by_id = {item["case_id"]: item for item in plan["cases"]}
        self.assertEqual("SELECTED", by_id["deny_request_body_marker_403"]["selection_status"])
        self.assertEqual("UNSUPPORTED", by_id["deny_response_header_marker_403"]["selection_status"])
        self.assertEqual("NOT IMPLEMENTED", no_crs.capability_cell({
            "capabilities_verified": [], "capability_states": {"phase4": "not_implemented"},
        }, "phase4"))
        self.assertEqual("IMPLEMENTED, NOT ASSERTED", no_crs.capability_cell({
            "capabilities_verified": [], "capability_states": {"phase3": "implemented_not_asserted"},
        }, "phase3"))

    def test_full_lifecycle_cases_stay_not_executed_without_the_new_host_capability(self) -> None:
        catalog = no_crs.load_catalog()
        case = next(
            item for item in no_crs.catalog_cases(catalog)
            if item["case_id"] == "phase4_first_byte_before_response_end"
        )
        payload = manifest(executable=set(case["required_capabilities"]))
        payload["capabilities"]["first_byte_before_response_end"]["state"] = "not_implemented"  # type: ignore[index]
        payload["capabilities"]["first_byte_before_response_end"]["reason"] = "unit-test no host barrier driver"  # type: ignore[index]
        plan = no_crs.select_cases("envoy", payload, catalog)
        by_id = {item["case_id"]: item for item in plan["cases"]}
        self.assertEqual(
            "NOT_EXECUTED",
            by_id["phase4_first_byte_before_response_end"]["selection_status"],
        )

    def test_phase4_selection_keeps_not_implemented_distinct_from_host_unsupported(self) -> None:
        executable = {
            "response_body_buffered", "phase4", "phase4_rule_evaluation", "event_jsonl",
            "phase4_pre_commit_deny", "deny", "late_intervention_status_metadata",
        }
        lighttpd = manifest("lighttpd", executable=executable)
        lighttpd["capabilities"]["phase4_pre_commit_deny"]["state"] = "not_implemented"  # type: ignore[index]
        lighttpd["capabilities"]["phase4_pre_commit_deny"]["reason"] = "unit-test missing implementation"  # type: ignore[index]
        plan = no_crs.select_cases("lighttpd", lighttpd, no_crs.load_catalog())
        by_id = {item["case_id"]: item for item in plan["cases"]}
        self.assertEqual("NOT_EXECUTED", by_id["phase4_deny_before_commit"]["selection_status"])

        envoy = manifest("envoy", executable=executable)
        envoy["capabilities"]["phase4"]["state"] = "unsupported_by_host_model"  # type: ignore[index]
        envoy["capabilities"]["phase4"]["reason"] = "unit-test host boundary"  # type: ignore[index]
        plan = no_crs.select_cases("envoy", envoy, no_crs.load_catalog())
        by_id = {item["case_id"]: item for item in plan["cases"]}
        self.assertEqual("UNSUPPORTED", by_id["phase4_rule_observed"]["selection_status"])

    def test_phase4_normalizer_observes_rule_without_rewriting_a_visible_200(self) -> None:
        record = self.normalize_phase4(
            "phase4_rule_observed",
            self.phase4_event(
                visible_http_status=200,
                original_http_status=200,
                response_started=True,
                body_truncated=False,
            ),
            raw={"actual_status": 200},
        )
        self.assertEqual("PASS", record["status"])
        self.assertEqual(200, record["actual_status"])
        self.assertEqual(200, record["visible_http_status"])
        self.assertTrue(record["response_started"])
        self.assertFalse(record["body_truncated"])

    def test_phase4_log_extraction_projects_only_runtime_metadata(self) -> None:
        evidence = phase4_runtime_evidence({
            "wanted_action": "deny",
            "actual_action": "connection_abort",
            "waf_status": 403,
            "upstream_status": 200,
            "client_status": 200,
            "intervention": True,
            "header_sent": True,
            "response_started": True,
            "response_body_seen": True,
            "response_body_truncated": False,
            "strict_abort": True,
            "observed_transport_result": "aborted",
            "response_body": "must-not-be-projected",
        })
        self.assertEqual("deny", evidence["requested_action"])
        self.assertEqual("abort_connection", evidence["actual_action"])
        self.assertEqual(403, evidence["http_status"])
        self.assertEqual(200, evidence["original_http_status"])
        self.assertEqual(200, evidence["visible_http_status"])
        self.assertTrue(evidence["late_intervention"])
        self.assertTrue(evidence["headers_sent"])
        self.assertTrue(evidence["response_started"])
        self.assertTrue(evidence["body_started"])
        self.assertFalse(evidence["body_truncated"])
        self.assertTrue(evidence["connection_aborted"])
        self.assertEqual("connection_aborted", evidence["transport_result"])
        self.assertNotIn("response_committed", evidence)
        self.assertNotIn("response_body", evidence)

    def test_phase4_log_extraction_projects_full_lifecycle_metadata_without_payload(self) -> None:
        evidence = phase4_runtime_evidence({
            "late_intervention_mode": "safe",
            "content_type_scope": "out-of-scope",
            "body_limit_outcome": "process-partial",
            "marker_split_across_chunks": True,
            "end_of_stream_evaluation": True,
            "no_full_response_buffering": True,
            "first_byte_before_response_end": True,
            "upstream_response_finished_at_first_byte": False,
            "transport_protocol": "HTTP/1.1",
            "transfer_encoding": "Content-Length",
            "connection_reused": True,
            "client_aborted": False,
            "upstream_aborted": False,
            "response_body": "must-not-be-projected",
        })
        self.assertEqual("safe", evidence["late_intervention_mode"])
        self.assertEqual("out_of_scope", evidence["content_type_scope"])
        self.assertEqual("process_partial", evidence["body_limit_outcome"])
        self.assertTrue(evidence["marker_split_across_chunks"])
        self.assertTrue(evidence["end_of_stream_evaluation"])
        self.assertTrue(evidence["no_full_response_buffering"])
        self.assertTrue(evidence["first_byte_before_response_end"])
        self.assertFalse(evidence["upstream_response_finished_at_first_byte"])
        self.assertEqual("http1", evidence["transport_protocol"])
        self.assertEqual("content_length", evidence["transfer_encoding"])
        self.assertNotIn("response_body", evidence)

    def test_phase4_pre_commit_deny_requires_uncommitted_headers(self) -> None:
        event = self.phase4_event(
            http_status=403,
            requested_action="deny",
            actual_action="deny",
            original_http_status=200,
            visible_http_status=403,
            headers_sent=False,
            connection_aborted=False,
        )
        record = self.normalize_phase4(
            "phase4_deny_before_commit", event, raw={"actual_status": 403},
        )
        self.assertEqual("PASS", record["status"])
        record = self.normalize_phase4(
            "phase4_deny_before_commit", {**event, "headers_sent": True},
            raw={"actual_status": 403},
        )
        self.assertEqual("FAIL", record["status"])

    def test_phase4_log_only_requires_late_runtime_evidence(self) -> None:
        event = self.phase4_event(
            http_status=403,
            requested_action="deny",
            actual_action="log_only",
            original_http_status=200,
            visible_http_status=200,
            late_intervention=True,
            headers_sent=True,
            connection_aborted=False,
        )
        record = self.normalize_phase4(
            "phase4_deny_after_commit_log_only", event, raw={"actual_status": 200},
        )
        self.assertEqual("PASS", record["status"])
        without_late = dict(event)
        without_late.pop("late_intervention")
        record = self.normalize_phase4(
            "phase4_deny_after_commit_log_only", without_late, raw={"actual_status": 200},
        )
        self.assertEqual("FAIL", record["status"])
        missing_rule = dict(event)
        missing_rule["rule_id"] = 1100302
        record = self.normalize_phase4(
            "phase4_deny_after_commit_log_only", missing_rule, raw={"actual_status": 200},
        )
        self.assertEqual("FAIL", record["status"])

    def test_phase4_normalizer_binds_multiple_events_by_transaction_id(self) -> None:
        pre_commit = self.phase4_event(
            transaction_id="tx-pre",
            http_status=403,
            requested_action="deny",
            actual_action="deny",
            original_http_status=200,
            visible_http_status=403,
            headers_sent=False,
            connection_aborted=False,
        )
        log_only = self.phase4_event(
            transaction_id="tx-safe",
            http_status=403,
            requested_action="deny",
            actual_action="log_only",
            original_http_status=200,
            visible_http_status=200,
            late_intervention=True,
            headers_sent=True,
            connection_aborted=False,
        )
        catalog = no_crs.load_catalog()
        record = no_crs.normalize_case_record(
            {
                "case_id": "phase4_deny_after_commit_log_only",
                "status": "PASS",
                "live_executed": True,
                "observed_rule_ids": [1100301],
                "transaction_id": "tx-safe",
                "actual_status": 200,
            },
            "apache",
            {case["case_id"]: case for case in no_crs.catalog_cases(catalog)},
            [pre_commit, log_only],
        )
        self.assertIsNotNone(record)
        self.assertEqual("PASS", record["status"])
        self.assertEqual(200, record["visible_http_status"])

    def test_phase4_abort_requires_a_real_abort_action(self) -> None:
        event = self.phase4_event(
            http_status=403,
            requested_action="deny",
            actual_action="abort_connection",
            original_http_status=200,
            visible_http_status=200,
            late_intervention=True,
            headers_sent=True,
            connection_aborted=True,
        )
        record = self.normalize_phase4("phase4_deny_after_commit_abort", event)
        self.assertEqual("PASS", record["status"])
        record = self.normalize_phase4(
            "phase4_deny_after_commit_abort", {**event, "connection_aborted": False},
        )
        self.assertEqual("FAIL", record["status"])
        record = self.normalize_phase4(
            "phase4_deny_after_commit_abort", {**event, "actual_action": "log_only"},
        )
        self.assertEqual("FAIL", record["status"])

    def test_phase4_client_status_matches_visible_status_when_observable(self) -> None:
        pre_commit = self.phase4_event(
            http_status=403,
            requested_action="deny",
            actual_action="deny",
            original_http_status=200,
            visible_http_status=403,
            headers_sent=False,
            connection_aborted=False,
        )
        self.assertEqual(
            "FAIL",
            self.normalize_phase4(
                "phase4_deny_before_commit", pre_commit, raw={"actual_status": 200},
            )["status"],
        )
        log_only = self.phase4_event(
            http_status=403,
            requested_action="deny",
            actual_action="log_only",
            original_http_status=200,
            visible_http_status=200,
            late_intervention=True,
            headers_sent=True,
            connection_aborted=False,
        )
        self.assertEqual(
            "FAIL",
            self.normalize_phase4(
                "phase4_deny_after_commit_log_only", log_only, raw={"actual_status": 403},
            )["status"],
        )

        abort = self.phase4_event(
            http_status=403,
            requested_action="deny",
            actual_action="abort_connection",
            original_http_status=200,
            visible_http_status=200,
            late_intervention=True,
            headers_sent=True,
            connection_aborted=True,
        )
        # A connection-reset transport has no observable final HTTP response,
        # so a supplied status is not compared to the already-visible status.
        self.assertEqual(
            "PASS",
            self.normalize_phase4(
                "phase4_deny_after_commit_abort",
                abort,
                raw={"actual_status": 418, "transport_result": "connection_aborted"},
            )["status"],
        )
        self.assertEqual(
            "FAIL",
            self.normalize_phase4(
                "phase4_deny_after_commit_abort",
                abort,
                raw={"actual_status": 418, "transport_result": "http_status"},
            )["status"],
        )

    def test_phase4_metadata_cases_require_actions_and_statuses_from_the_event(self) -> None:
        pre_commit = self.phase4_event(
            http_status=403,
            requested_action="deny",
            actual_action="deny",
            original_http_status=200,
            visible_http_status=403,
            late_intervention=False,
            headers_sent=False,
            connection_aborted=False,
        )
        self.assertEqual(
            "PASS",
            self.normalize_phase4("phase4_event_contains_original_status", pre_commit)["status"],
        )
        self.assertEqual(
            "PASS",
            self.normalize_phase4("phase4_event_contains_late_intervention_action", pre_commit)["status"],
        )
        for field in ("requested_action", "actual_action", "original_http_status", "visible_http_status"):
            with self.subTest(field=field):
                event = dict(pre_commit)
                event.pop(field)
                case_id = (
                    "phase4_event_contains_late_intervention_action"
                    if field in {"requested_action", "actual_action"}
                    else "phase4_event_contains_original_status"
                )
                self.assertEqual("FAIL", self.normalize_phase4(case_id, event)["status"])

    def test_phase4_normalizer_rejects_unknown_or_payload_event_fields(self) -> None:
        event = self.phase4_event(visible_http_status=200, original_http_status=200)
        for field, value in (
            ("unreviewed_field", "unexpected"),
            ("response_body", "no-crs-response-body-marker"),
            ("matched_value", "sensitive match"),
        ):
            with self.subTest(field=field):
                self.assertEqual(
                    "FAIL",
                    self.normalize_phase4("phase4_rule_observed", {**event, field: value})["status"],
                )
        for field in ("event", "message_id"):
            with self.subTest(missing_phase4_identity=field):
                missing = dict(event)
                missing.pop(field)
                self.assertTrue(any(
                    f"{field}: phase-4 events require a non-empty string" in error
                    for error in no_crs.canonical_event_errors(missing)
                ))
                self.assertEqual(
                    "FAIL",
                    self.normalize_phase4("phase4_rule_observed", missing)["status"],
                )

    def test_common_bounded_event_metadata_is_accepted_without_payload(self) -> None:
        event = {
            "timestamp": "2026-07-11T00:00:00Z",
            "level": "warn",
            "message_id": "MSCONN_EVENT_PHASE4_LATE_INTERVENTION",
            "message": "Phase 4 intervention occurred after response output started.",
            "event": "phase4_intervention",
            "connector": "apache",
            "transaction_id": "tx-common-event",
            "phase": "response_body",
            "status": "blocked",
            "action": "log_only",
            "requested_action": "deny",
            "actual_action": "log_only",
            "http_status": 403,
            "original_http_status": 200,
            "visible_http_status": 200,
            "transport_result": "log_only",
            "http_reason_phrase": "Forbidden",
            "http_default_message": "Forbidden",
            "rule_id": "1100301",
            "reason": "late_intervention",
            "method": "GET",
            "uri": "/no-crs/response",
            "client_ip": "127.0.0.1",
            "content_type": "text/plain",
            "body_bytes_seen": 12,
            "body_bytes_inspected": 12,
            "late_intervention": True,
            "response_started": True,
            "response_committed": True,
            "headers_sent": True,
            "body_started": True,
            "body_truncated": False,
            "connection_aborted": False,
            "redacted": True,
            "truncated": False,
            "sequence": 1,
            "previous_event_hash": 0,
            "event_hash": 1,
        }
        self.assertEqual([], no_crs.canonical_event_errors(event, connector="apache"))
        initialized_common_event = {
            **event,
            "timestamp": "",
            "level": "info",
            "message_id": "",
            "message": "",
            "event": "",
            "transaction_id": "",
            "phase": "connection",
            "status": "ok",
            "action": "",
            "requested_action": "",
            "actual_action": "",
            "transport_result": "",
            "http_reason_phrase": "",
            "http_default_message": "",
            "rule_id": "",
            "reason": "",
            "method": "",
            "uri": "",
            "client_ip": "",
            "content_type": "",
            "body_bytes_seen": 0,
            "body_bytes_inspected": 0,
            "late_intervention": False,
            "response_started": False,
            "response_committed": False,
            "headers_sent": False,
            "body_started": False,
            "body_truncated": False,
            "connection_aborted": False,
            "redacted": False,
            "truncated": False,
            "sequence": 0,
            "previous_event_hash": 0,
            "event_hash": 0,
        }
        self.assertEqual([], no_crs.canonical_event_errors(
            initialized_common_event, connector="apache",
        ))
        self.assertTrue(no_crs.canonical_event_errors({
            **event,
            "response_body": "no-crs-response-body-marker",
        }, connector="apache"))

    def test_common_phase_labels_normalize_to_closed_canonical_phase_values(self) -> None:
        expected = {
            "connection": 0,
            "uri": 1,
            "request_headers": 1,
            "request_body": 2,
            "response_headers": 3,
            "response_body": 4,
            "logging": 5,
        }
        for label, phase in expected.items():
            with self.subTest(label=label):
                self.assertEqual(phase, no_crs.normalize_canonical_phase(label))
                self.assertEqual(phase, no_crs.canonicalize_event_phase({"phase": label})["phase"])
        for value in (True, -1, 6, "6", "response-body", "unknown"):
            with self.subTest(value=value):
                self.assertIsNone(no_crs.normalize_canonical_phase(value))
        self.assertTrue(any(
            "unsupported Common/canonical phase" in error
            for error in no_crs.canonical_event_errors({
                "connector": "apache", "phase": "response-body",
            })
        ))

    def test_common_response_body_label_matches_phase4_evidence(self) -> None:
        event = self.phase4_event(
            phase="response_body",
            http_status=403,
            requested_action="deny",
            actual_action="deny",
            original_http_status=200,
            visible_http_status=403,
            headers_sent=False,
            connection_aborted=False,
        )
        self.assertTrue(no_crs.phase4_event_matches_outcome(event, "deny_before_commit"))
        self.assertEqual(
            "PASS",
            self.normalize_phase4(
                "phase4_deny_before_commit", event, raw={"actual_status": 403},
            )["status"],
        )

    def test_phase4_statuses_and_legacy_alias_are_never_promoted_without_evidence(self) -> None:
        event = self.phase4_event(
            http_status=403,
            requested_action="deny",
            actual_action="deny",
            original_http_status=200,
            visible_http_status=403,
            headers_sent=False,
            connection_aborted=False,
        )
        for status in ("UNSUPPORTED", "NOT_EXECUTED"):
            with self.subTest(status=status):
                record = self.normalize_phase4(
                    "phase4_deny_before_commit", event, raw={"status": status},
                )
                self.assertEqual(status, record["status"])

        catalog = no_crs.load_catalog()
        case_by_id = {case["case_id"]: case for case in no_crs.catalog_cases(catalog)}
        alias = self.normalize_phase4(
            "deny_response_body_marker_403", event, raw={"actual_status": 403},
        )
        self.assertEqual("PASS", alias["status"])
        failed_target = dict(alias)
        failed_target.update({"case_id": "phase4_deny_before_commit", "status": "FAIL"})
        records = [alias, failed_target]
        no_crs.resolve_deprecated_aliases(records, case_by_id)
        self.assertEqual("FAIL", records[0]["status"])

        target = self.normalize_phase4(
            "phase4_deny_before_commit", event, raw={"actual_status": 403},
        )
        records = [dict(alias, status="NOT_EXECUTED"), target]
        no_crs.resolve_deprecated_aliases(records, case_by_id)
        self.assertEqual("PASS", records[0]["status"])
        self.assertEqual("legacy_phase4_deny_before_commit", records[0]["expected_result"])

    def test_valid_phase4_outcomes_derive_only_their_narrower_facts(self) -> None:
        catalog = no_crs.load_catalog()
        case_by_id = {case["case_id"]: case for case in no_crs.catalog_cases(catalog)}
        plan = no_crs.select_cases(
            "apache", manifest("apache", executable=set(no_crs.CAPABILITIES)), catalog,
        )
        outcomes = (
            (
                "phase4_deny_before_commit",
                self.phase4_event(
                    http_status=403,
                    requested_action="deny",
                    actual_action="deny",
                    original_http_status=200,
                    visible_http_status=403,
                    late_intervention=False,
                    headers_sent=False,
                    connection_aborted=False,
                ),
                {"actual_status": 403},
                {"phase4_deny_after_commit_log_only", "phase4_deny_after_commit_abort"},
            ),
            (
                "phase4_deny_after_commit_log_only",
                self.phase4_event(
                    http_status=403,
                    requested_action="deny",
                    actual_action="log_only",
                    original_http_status=200,
                    visible_http_status=200,
                    late_intervention=True,
                    headers_sent=True,
                    connection_aborted=False,
                ),
                {"actual_status": 200},
                {"phase4_deny_before_commit", "phase4_deny_after_commit_abort"},
            ),
            (
                "phase4_deny_after_commit_abort",
                self.phase4_event(
                    http_status=403,
                    requested_action="deny",
                    actual_action="abort_connection",
                    original_http_status=200,
                    visible_http_status=200,
                    late_intervention=True,
                    headers_sent=True,
                    connection_aborted=True,
                ),
                {"transport_result": "connection_aborted"},
                {"phase4_deny_before_commit", "phase4_deny_after_commit_log_only"},
            ),
        )
        for base_case_id, event, raw, absent_outcomes in outcomes:
            with self.subTest(base_case_id=base_case_id):
                base = self.normalize_phase4(base_case_id, event, raw=raw)
                self.assertEqual("PASS", base["status"])
                records = [base]
                no_crs.append_derived_phase4_records(records, plan, case_by_id, [event])
                by_id = {record["case_id"]: record for record in records}
                self.assertEqual("PASS", by_id["phase4_rule_observed"]["status"])
                self.assertEqual("PASS", by_id["phase4_event_contains_original_status"]["status"])
                self.assertEqual("PASS", by_id["phase4_event_contains_late_intervention_action"]["status"])
                self.assertTrue(absent_outcomes.isdisjoint(by_id))

    def test_phase1_deny_remains_strict(self) -> None:
        catalog = no_crs.load_catalog()
        record = no_crs.normalize_case_record(
            {
                "case_id": "deny_header_marker_403",
                "status": "PASS",
                "live_executed": True,
                "actual_status": 200,
                "observed_rule_ids": [1100001],
            },
            "apache",
            {case["case_id"]: case for case in no_crs.catalog_cases(catalog)},
            [{
                "connector": "apache", "transaction_id": "tx-phase1", "rule_id": 1100001,
                "phase": 1, "status": "blocked",
            }],
        )
        self.assertIsNotNone(record)
        self.assertEqual("FAIL", record["status"])

    def test_zero_exit_without_case_evidence_is_not_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
            run_dir = root / "evidence/envoy/run-1"
            self.assertEqual(0, no_crs.main([
                "init", "--connector", "envoy", "--capabilities", str(capability_path),
                "--run-dir", str(run_dir), "--run-id", "run-1", "--host-version", "1.0",
            ]))
            self.assertFalse((run_dir / "result.json").exists())
            self.assertEqual(0, no_crs.main([
                "finalize", "--run-dir", str(run_dir), "--capabilities", str(capability_path),
                "--stage-rc", "0", "--host-version", "1.0",
            ]))
            result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
            self.assertEqual("NOT_EXECUTED", result["status"])
            self.assertEqual(0, result["cases_passed"])
            self.assertFalse(result["requests_sent"])
            tampered = dict(result)
            tampered.pop("status_counts")
            no_crs.write_json(run_dir / "result.json", tampered)
            schema_errors = no_crs.schema_errors(run_dir, "envoy", no_crs.load_capability_manifest(capability_path, "envoy"))
            self.assertTrue(any("missing required property status_counts" in error for error in schema_errors))
            self.assertEqual(1, no_crs.main([
                "validate", "--evidence-root", str(run_dir), "--connector", "envoy",
                "--capabilities", str(capability_path), "--check", "schema",
            ]))
            tampered = json.loads(json.dumps(result))
            tampered.pop("evidence_stages")
            no_crs.write_json(run_dir / "result.json", tampered)
            schema_errors = no_crs.schema_errors(
                run_dir, "envoy", no_crs.load_capability_manifest(capability_path, "envoy")
            )
            self.assertTrue(any("missing required property evidence_stages" in error for error in schema_errors))
            no_crs.write_json(run_dir / "result.json", result)
            manifest_payload = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            original_manifest = dict(manifest_payload)
            fake_commit = "f" * 40
            result["connector_commit"] = fake_commit
            manifest_payload["connector_commit"] = fake_commit
            no_crs.write_json(run_dir / "result.json", result)
            no_crs.write_json(run_dir / "manifest.json", manifest_payload)
            self.assertTrue(any("result/inventory connector_commit mismatch" in error for error in no_crs.status_errors(run_dir)))
            result["connector_commit"] = original_manifest["connector_commit"]
            no_crs.write_json(run_dir / "result.json", result)
            no_crs.write_json(run_dir / "manifest.json", original_manifest)
            (run_dir / "raw").mkdir()
            (run_dir / "raw/untracked.log").write_text("untracked\n", encoding="utf-8")
            self.assertTrue(any("unmanifested artifact" in error for error in no_crs.layout_errors(run_dir)))

    def test_schemas_reject_unreviewed_result_and_case_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
            run_dir = root / "evidence/envoy/strict-schema"
            self.assertEqual(0, no_crs.main([
                "init", "--connector", "envoy", "--capabilities", str(capability_path),
                "--run-dir", str(run_dir), "--run-id", "strict-schema", "--host-version", "1.0",
            ]))
            self.assertEqual(0, no_crs.main([
                "finalize", "--run-dir", str(run_dir), "--capabilities", str(capability_path),
                "--stage-rc", "0", "--host-version", "1.0",
            ]))
            capabilities = no_crs.load_capability_manifest(capability_path, "envoy")
            result = no_crs.load_json(run_dir / "result.json")
            self.assertIsInstance(result, dict)
            result["unreviewed_result_field"] = "must be rejected"  # type: ignore[index]
            no_crs.write_json(run_dir / "result.json", result)
            self.assertTrue(any(
                "result.json schema: $: unexpected property unreviewed_result_field" in error
                for error in no_crs.schema_errors(run_dir, "envoy", capabilities)
            ))

            result.pop("unreviewed_result_field")  # type: ignore[union-attr]
            no_crs.write_json(run_dir / "result.json", result)
            records = no_crs.read_jsonl(run_dir / "results.jsonl")
            self.assertTrue(records)
            records[0]["unreviewed_case_field"] = "must be rejected"
            no_crs.write_jsonl(run_dir / "results.jsonl", records)
            self.assertTrue(any(
                "results.jsonl[0] schema: $: unexpected property unreviewed_case_field" in error
                for error in no_crs.schema_errors(run_dir, "envoy", capabilities)
            ))

    def test_init_requires_fresh_run_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
            run_dir = root / "already-created"
            run_dir.mkdir()
            self.assertEqual(1, no_crs.main([
                "init", "--connector", "envoy", "--capabilities", str(capability_path),
                "--run-dir", str(run_dir), "--run-id", "run-existing",
            ]))

    def test_validator_rejects_evidence_from_other_current_commits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
            run_dir = root / "evidence/envoy/stale-commit"
            self.assertEqual(0, no_crs.main([
                "init", "--connector", "envoy", "--capabilities", str(capability_path),
                "--run-dir", str(run_dir), "--run-id", "stale-commit",
            ]))
            self.assertEqual(0, no_crs.main([
                "finalize", "--run-dir", str(run_dir), "--capabilities", str(capability_path),
                "--stage-rc", "0", "--host-version", "1.0",
            ]))
            fake_commit = "f" * 40
            for name in ("result.json", "manifest.json", "inventory/run.json"):
                path = run_dir / name
                payload = json.loads(path.read_text(encoding="utf-8"))
                payload["connector_commit"] = fake_commit
                payload["framework_commit"] = fake_commit
                no_crs.write_json(path, payload)
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                rc = no_crs.main([
                    "validate", "--evidence-root", str(run_dir), "--connector", "envoy",
                    "--connector-root", str(ROOT.parents[1]),
                    "--capabilities", str(capability_path), "--check", "status",
                ])
            self.assertEqual(1, rc)
            self.assertIn("does not match current", stderr.getvalue())

    def test_init_rejects_symlink_in_run_parent_chain(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
            real_parent = root / "real-parent"
            real_parent.mkdir()
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            run_dir = linked_parent / "envoy/run-parent-link"
            self.assertEqual(1, no_crs.main([
                "init", "--connector", "envoy", "--capabilities", str(capability_path),
                "--run-dir", str(run_dir), "--run-id", "run-parent-link",
            ]))
            self.assertFalse((real_parent / "envoy/run-parent-link").exists())

    def test_init_rejects_tampered_same_connector_plan(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            capability_payload = manifest()
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(capability_payload), encoding="utf-8")
            plan = no_crs.select_cases("envoy", capability_payload, no_crs.load_catalog())
            plan["cases"][0]["selection_status"] = "UNSUPPORTED"
            plan_path = root / "tampered-plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            run_dir = root / "evidence/envoy/tampered"
            self.assertEqual(1, no_crs.main([
                "init", "--connector", "envoy", "--capabilities", str(capability_path),
                "--plan", str(plan_path), "--run-dir", str(run_dir), "--run-id", "tampered",
            ]))
            self.assertFalse(run_dir.exists())

    def test_finalize_refuses_symlink_log_destination_without_touching_victim(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
            run_dir = root / "evidence/envoy/run-symlink"
            self.assertEqual(0, no_crs.main([
                "init", "--connector", "envoy", "--capabilities", str(capability_path),
                "--run-dir", str(run_dir), "--run-id", "run-symlink",
            ]))
            victim = root / "victim.txt"
            victim.write_text("do-not-overwrite\n", encoding="utf-8")
            source_log = root / "source.log"
            source_log.write_text("observed stdout\n", encoding="utf-8")
            (run_dir / "logs/stdout.log").symlink_to(victim)
            self.assertEqual(1, no_crs.main([
                "finalize", "--run-dir", str(run_dir), "--capabilities", str(capability_path),
                "--stdout-log", str(source_log), "--stage-rc", "0",
            ]))
            self.assertEqual("do-not-overwrite\n", victim.read_text(encoding="utf-8"))
            self.assertTrue((run_dir / "logs/stdout.log").is_symlink())
            self.assertTrue(any("symlink" in error for error in no_crs.layout_errors(run_dir)))

    def test_finalize_rejects_raw_forbidden_event_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
            run_dir = root / "evidence/envoy/run-payload"
            self.assertEqual(0, no_crs.main([
                "init", "--connector", "envoy", "--capabilities", str(capability_path),
                "--run-dir", str(run_dir), "--run-id", "run-payload",
            ]))
            events = root / "raw-events.jsonl"
            events.write_text(json.dumps({"connector": "envoy", "request_body": "sensitive"}) + "\n", encoding="utf-8")
            self.assertEqual(1, no_crs.main([
                "finalize", "--run-dir", str(run_dir), "--capabilities", str(capability_path),
                "--source-events", str(events), "--stage-rc", "0",
            ]))
            self.assertFalse((run_dir / "events.jsonl").exists())

    def test_finalize_rejects_unreviewed_or_nested_event_metadata(self) -> None:
        base_event = {
            "connector": "envoy", "transaction_id": "tx-event-contract",
            "rule_id": 1100001, "phase": "request_headers", "status": "blocked",
        }
        self.assertEqual([], no_crs.canonical_event_errors(base_event))
        for suffix, extra in (
            ("unknown", {"data": "arbitrary unreviewed payload"}),
            ("nested", {"metadata": {"snippet": "arbitrary unreviewed payload"}}),
            ("container", {"status": {"value": "blocked"}}),
            ("wrong-connector", {"connector": "apache"}),
        ):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
                root = Path(temporary)
                capability_path = root / "capabilities.json"
                capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
                run_dir = root / f"evidence/envoy/{suffix}"
                self.assertEqual(0, no_crs.main([
                    "init", "--connector", "envoy", "--capabilities", str(capability_path),
                    "--run-dir", str(run_dir), "--run-id", suffix,
                ]))
                events = root / "events.jsonl"
                events.write_text(json.dumps({**base_event, **extra}) + "\n", encoding="utf-8")
                self.assertTrue(no_crs.canonical_event_errors(
                    {**base_event, **extra}, connector="envoy",
                ))
                self.assertEqual(1, no_crs.main([
                    "finalize", "--run-dir", str(run_dir), "--capabilities", str(capability_path),
                    "--source-events", str(events), "--stage-rc", "0",
                ]))
                self.assertFalse((run_dir / "events.jsonl").exists())

    def test_event_schema_detects_post_finalize_tampering(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
            run_dir = root / "evidence/envoy/tampered-event"
            source = root / "source.json"
            source.write_text(json.dumps({
                "connector": "envoy", "status": "PASS", "started": True,
                "requests_sent": True, "allowed_request_status": 200,
                "blocked_request_status": 403, "observed_rule_ids": [1100001],
            }), encoding="utf-8")
            events = root / "events.jsonl"
            events.write_text(json.dumps({
                "connector": "envoy", "transaction_id": "tx-tampered", "rule_id": 1100001,
                "phase": 1, "status": 403,
            }) + "\n", encoding="utf-8")
            self.assertEqual(0, no_crs.main([
                "init", "--connector", "envoy", "--capabilities", str(capability_path),
                "--evidence-stage", "minimal_runtime_smoke", "--run-dir", str(run_dir),
                "--run-id", "tampered-event", "--host-version", "1.0",
                "--libmodsecurity-version", "3.0.15",
            ]))
            self.assertEqual(0, no_crs.main([
                "finalize", "--run-dir", str(run_dir), "--capabilities", str(capability_path),
                "--source-result", str(source), "--source-events", str(events),
                "--stage-rc", "0", "--host-version", "1.0",
                "--libmodsecurity-version", "3.0.15",
            ]))
            (run_dir / "events.jsonl").write_text(json.dumps({
                "connector": "envoy", "transaction_id": "tx-tampered", "rule_id": 1100001,
                "phase": 1, "status": 403, "metadata": {"payload": "unreviewed"},
            }) + "\n", encoding="utf-8")
            capabilities = no_crs.load_capability_manifest(capability_path, "envoy")
            self.assertTrue(any("unexpected property metadata" in error for error in no_crs.schema_errors(
                run_dir, "envoy", capabilities,
            )))
            self.assertTrue(any("unexpected property metadata" in error for error in no_crs.body_payload_errors(run_dir)))
            self.assertEqual((False, False), no_crs.canonical_core_event_contract(
                no_crs.read_jsonl(run_dir / "events.jsonl"), "envoy",
            ))

    def test_http_403_without_observed_rule_id_is_not_deny_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
            run_dir = root / "evidence/envoy/run-2"
            source = root / "source-result.json"
            source.write_text(json.dumps({
                "connector": "envoy", "status": "PASS", "runtime_verified": True,
                "started": True, "requests_sent": True,
                "allowed_request_status": 200, "blocked_request_status": 403,
                "observed_rule_ids": [],
            }), encoding="utf-8")
            self.assertEqual(0, no_crs.main([
                "init", "--connector", "envoy", "--capabilities", str(capability_path),
                "--run-dir", str(run_dir), "--run-id", "run-2", "--host-version", "1.0",
            ]))
            self.assertEqual(1, no_crs.main([
                "finalize", "--run-dir", str(run_dir), "--capabilities", str(capability_path),
                "--source-result", str(source), "--stage-rc", "0", "--host-version", "1.0",
            ]))
            records = {record["case_id"]: record for record in no_crs.read_jsonl(run_dir / "results.jsonl")}
            result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
            self.assertEqual("PASS", records["allow_without_marker"]["status"])
            self.assertEqual("FAIL", records["deny_header_marker_403"]["status"])
            self.assertEqual([], records["deny_header_marker_403"]["observed_rule_ids"])
            partitions = [
                set(result["capabilities_verified"]), set(result["capabilities_unsupported"]),
                set(result["capabilities_not_exercised"]),
            ]
            self.assertFalse(partitions[0] & partitions[1])
            self.assertFalse(partitions[0] & partitions[2])
            self.assertFalse(partitions[1] & partitions[2])
            self.assertEqual(set(no_crs.CAPABILITIES), set.union(*partitions))

    def test_minimal_runtime_stage_uses_same_schema_with_only_two_core_cases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
            plan_path = root / "minimal-plan.json"
            self.assertEqual(0, no_crs.main([
                "select", "--connector", "envoy", "--capabilities", str(capability_path),
                "--evidence-stage", "minimal_runtime_smoke", "--output", str(plan_path),
            ]))
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            self.assertEqual(2, len(plan["cases"]))
            run_dir = root / "evidence/envoy/minimal"
            self.assertEqual(0, no_crs.main([
                "init", "--connector", "envoy", "--capabilities", str(capability_path),
                "--evidence-stage", "minimal_runtime_smoke", "--plan", str(plan_path),
                "--run-dir", str(run_dir), "--run-id", "minimal", "--host-version", "1.0",
                "--libmodsecurity-version", "3.0.15",
            ]))
            source = root / "source.json"
            source.write_text(json.dumps({
                "connector": "envoy", "status": "PASS", "started": True,
                "requests_sent": True, "allowed_request_status": 200,
                "blocked_request_status": 403, "observed_rule_ids": [1100001],
            }), encoding="utf-8")
            events = root / "events.jsonl"
            events.write_text(json.dumps({
                "connector": "envoy", "transaction_id": "tx-minimal", "rule_id": 1100001,
                "phase": "request_headers", "status": 403,
            }) + "\n", encoding="utf-8")
            self.assertEqual(0, no_crs.main([
                "finalize", "--run-dir", str(run_dir), "--capabilities", str(capability_path),
                "--source-result", str(source), "--source-events", str(events),
                "--stage-rc", "0", "--host-version", "1.0",
                "--libmodsecurity-version", "3.0.15",
            ]))
            result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
            self.assertEqual("minimal_runtime_smoke", result["evidence_stage"])
            self.assertEqual("PASS", result["status"])
            self.assertEqual(2, result["cases_total"])
            self.assertEqual(2, result["cases_passed"])
            self.assertTrue(result["event_metadata_verified"])
            self.assertTrue(result["body_payload_absent_from_events"])
            self.assertEqual(1, no_crs.read_jsonl(run_dir / "events.jsonl")[0]["phase"])
            self.assertEqual("PASS", no_crs.result_cell(result, "minimal_runtime_smoke"))
            self.assertEqual("NOT EXECUTED", no_crs.result_cell(result, "no_crs_baseline"))

            tampered = json.loads(json.dumps(result))
            tampered["status_counts"]["PASS"] = 999
            no_crs.write_json(run_dir / "result.json", tampered)
            self.assertTrue(any(
                "status_counts=" in error for error in no_crs.status_errors(run_dir)
            ))

            tampered = json.loads(json.dumps(result))
            tampered["allowed_request_status"] = None
            tampered["blocked_request_status"] = None
            no_crs.write_json(run_dir / "result.json", tampered)
            core_code_errors = no_crs.status_errors(run_dir)
            self.assertTrue(any("allowed_request_status" in error for error in core_code_errors))
            self.assertTrue(any("blocked_request_status" in error for error in core_code_errors))

            for field in (
                "request_headers_verified", "request_body_verified",
                "response_headers_verified", "response_body_verified",
                "late_intervention_verified",
            ):
                tampered = json.loads(json.dumps(result))
                tampered[field] = not tampered[field]
                no_crs.write_json(run_dir / "result.json", tampered)
                self.assertTrue(any(
                    field in error for error in no_crs.status_errors(run_dir)
                ), field)
            no_crs.write_json(run_dir / "result.json", result)

            inventory = json.loads((run_dir / "inventory/run.json").read_text(encoding="utf-8"))
            self.assertEqual("minimal_runtime_smoke", inventory["evidence_stage"])
            self.assertEqual("no-crs-baseline", inventory["ruleset"])
            inventory["evidence_stage"] = "no_crs_baseline"
            no_crs.write_json(run_dir / "inventory/run.json", inventory)
            self.assertTrue(any(
                "result/inventory evidence_stage mismatch" in error
                for error in no_crs.status_errors(run_dir)
            ))

    def test_minimal_runtime_pass_requires_event_and_concrete_versions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
            source = root / "source.json"
            source.write_text(json.dumps({
                "connector": "envoy", "status": "PASS", "started": True,
                "requests_sent": True, "allowed_request_status": 200,
                "blocked_request_status": 403, "observed_rule_ids": [1100001],
            }), encoding="utf-8")
            for run_id, with_event, lib_version in (
                ("missing-event", False, "3.0.15"),
                ("missing-lib-version", True, "not_provisioned"),
            ):
                run_dir = root / "evidence/envoy" / run_id
                init_args = [
                    "init", "--connector", "envoy", "--capabilities", str(capability_path),
                    "--evidence-stage", "minimal_runtime_smoke", "--run-dir", str(run_dir),
                    "--run-id", run_id, "--host-version", "1.0",
                    "--libmodsecurity-version", lib_version,
                ]
                self.assertEqual(0, no_crs.main(init_args))
                finalize_args = [
                    "finalize", "--run-dir", str(run_dir), "--capabilities", str(capability_path),
                    "--source-result", str(source), "--stage-rc", "0", "--host-version", "1.0",
                    "--libmodsecurity-version", lib_version,
                ]
                if with_event:
                    events = root / f"{run_id}-events.jsonl"
                    events.write_text(json.dumps({
                        "connector": "envoy", "transaction_id": run_id, "rule_id": 1100001,
                        "phase": "request_headers", "status": "blocked",
                    }) + "\n", encoding="utf-8")
                    finalize_args.extend(["--source-events", str(events)])
                self.assertEqual(1, no_crs.main(finalize_args))
                result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
                self.assertEqual("FAIL", result["status"])
                if with_event:
                    self.assertTrue(result["pass_gate_failures"])
                else:
                    self.assertFalse(result["event_metadata_verified"])
                    self.assertGreater(result["cases_failed"], 0)

    def test_finalize_rechecks_worktrees_and_commits_before_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            connector_root = root / "connector-checkout"
            connector_root.mkdir()
            capability_path = root / "capabilities.json"
            capability_path.write_text(json.dumps(manifest()), encoding="utf-8")
            run_dir = root / "evidence/envoy/provenance-race"
            source = root / "source.json"
            source.write_text(json.dumps({
                "connector": "envoy", "status": "PASS", "started": True,
                "requests_sent": True, "allowed_request_status": 200,
                "blocked_request_status": 403, "observed_rule_ids": [1100001],
            }), encoding="utf-8")
            events = root / "events.jsonl"
            events.write_text(json.dumps({
                "connector": "envoy", "transaction_id": "tx-provenance",
                "rule_id": 1100001, "phase": 1, "status": 403,
            }) + "\n", encoding="utf-8")

            connector_commit = "c" * 40
            framework_commit = "f" * 40
            state = {
                "connector_commit": connector_commit,
                "framework_commit": framework_commit,
                "connector_clean": True,
                "framework_clean": True,
            }

            def fake_git_value(checkout: Path, *arguments: str) -> str:
                self.assertEqual(("rev-parse", "HEAD"), arguments)
                if Path(checkout).resolve() == connector_root.resolve():
                    return str(state["connector_commit"])
                if Path(checkout).resolve() == no_crs.FRAMEWORK_ROOT.resolve():
                    return str(state["framework_commit"])
                return "unknown"

            def fake_git_worktree_clean(checkout: Path | None) -> bool:
                if checkout is not None and Path(checkout).resolve() == connector_root.resolve():
                    return bool(state["connector_clean"])
                if checkout is not None and Path(checkout).resolve() == no_crs.FRAMEWORK_ROOT.resolve():
                    return bool(state["framework_clean"])
                return True

            with (
                mock.patch.object(no_crs, "git_value", side_effect=fake_git_value),
                mock.patch.object(
                    no_crs, "git_worktree_clean", side_effect=fake_git_worktree_clean,
                ),
            ):
                self.assertEqual(0, no_crs.main([
                    "init", "--connector", "envoy", "--capabilities", str(capability_path),
                    "--evidence-stage", "minimal_runtime_smoke", "--run-dir", str(run_dir),
                    "--run-id", "provenance-race", "--connector-root", str(connector_root),
                    "--host-version", "1.0", "--libmodsecurity-version", "3.0.15",
                ]))
                state.update({
                    "connector_commit": "d" * 40,
                    "framework_commit": "e" * 40,
                    "connector_clean": False,
                    "framework_clean": False,
                })
                self.assertEqual(1, no_crs.main([
                    "finalize", "--run-dir", str(run_dir),
                    "--connector-root", str(connector_root),
                    "--capabilities", str(capability_path), "--source-result", str(source),
                    "--source-events", str(events), "--stage-rc", "0",
                    "--host-version", "1.0", "--libmodsecurity-version", "3.0.15",
                ]))

            result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
            self.assertEqual("FAIL", result["status"])
            self.assertFalse(result["connector_worktree_clean"])
            self.assertFalse(result["framework_worktree_clean"])
            self.assertEqual("d" * 40, result["connector_commit_at_finalize"])
            self.assertEqual("e" * 40, result["framework_commit_at_finalize"])
            self.assertIn("PASS requires a clean connector worktree", result["pass_gate_failures"])
            self.assertIn("PASS requires a clean framework worktree", result["pass_gate_failures"])
            self.assertIn(
                "PASS requires an unchanged connector commit through finalize",
                result["pass_gate_failures"],
            )
            self.assertIn(
                "PASS requires an unchanged framework commit through finalize",
                result["pass_gate_failures"],
            )
            self.assertEqual([], no_crs.status_errors(run_dir))

    def test_body_payload_scanner_rejects_body_and_secret_fields(self) -> None:
        errors = no_crs.forbidden_payload_errors({
            "request_body": "redacted?", "nested": {"authorization": "Bearer example"},
        })
        self.assertEqual(2, len(errors))
        self.assertEqual([], no_crs.forbidden_payload_errors({
            "request_body_size": 32, "body_bytes_inspected": 32, "truncated": False,
        }))

    def test_summary_never_promotes_missing_results(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            output_json = root / "summary.json"
            output_md = root / "summary.md"
            output_de = root / "summary.de.md"
            self.assertEqual(0, no_crs.main([
                "summarize", "--evidence-root", str(root / "missing"),
                "--run-id", "missing-run", "--output-json", str(output_json),
                "--output-md", str(output_md), "--output-md-de", str(output_de),
            ]))
            payload = json.loads(output_json.read_text(encoding="utf-8"))
            self.assertEqual({"NOT_EXECUTED": 6}, payload["status_counts"])
            english = output_md.read_text(encoding="utf-8")
            german = output_de.read_text(encoding="utf-8")
            self.assertNotIn("| PASS |", english)
            self.assertIn("**Language:** English | [Deutsch]", english)
            self.assertIn("Overall canonical status: `NOT EXECUTED`", english)
            self.assertIn("**Sprache:** [English]", german)
            self.assertIn("Kanonischer Gesamtstatus: `NOT EXECUTED`", german)
            connector_report = no_crs.render_connector_report("envoy", None)
            self.assertIn("| Phase 1 | NOT EXECUTED |", connector_report)
            self.assertIn("| Events | NOT EXECUTED |", connector_report)

    def test_summary_rejects_partial_or_claim_bearing_result(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-test-") as temporary:
            root = Path(temporary)
            result_path = root / "envoy/run/result.json"
            result_path.parent.mkdir(parents=True)
            result_path.write_text(json.dumps({
                "connector": "envoy", "status": "PASS", "production_ready": True,
            }), encoding="utf-8")
            output_json = root / "summary.json"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(1, no_crs.main([
                    "summarize", "--evidence-root", str(root), "--run-id", "run",
                    "--output-json", str(output_json), "--output-md", str(root / "summary.md"),
                    "--output-md-de", str(root / "summary.de.md"),
                ]))
            self.assertFalse(output_json.exists())
            self.assertIn("refusing to summarize invalid canonical result", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
