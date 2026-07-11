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
        self.assertEqual(53, len(no_crs.catalog_cases(catalog)))
        runner_cases = [case for case in no_crs.catalog_cases(catalog) if case.get("runner_case")]
        self.assertEqual(8, len(runner_cases))
        self.assertNotIn("deny_response_header_marker_403", {case["case_id"] for case in runner_cases})
        rules = no_crs.RULES_PATH.read_text(encoding="utf-8")
        self.assertIn('REQUEST_HEADERS:X-Modsec-Smoke "@streq block"', rules)
        self.assertIn("id:1100001,phase:1,deny,status:403", rules)
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
                self.assertTrue(no_crs.canonical_event_errors({**base_event, **extra}))
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
                "phase": 1, "status": 403,
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


if __name__ == "__main__":
    unittest.main()
