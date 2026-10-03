from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "no_crs_baseline", ROOT / "ci/checks/catalog/no_crs_baseline.py"
)
assert SPEC is not None
assert SPEC.loader is not None
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)


class SelectedScopeStatusTest(unittest.TestCase):
    @staticmethod
    def capability_manifest() -> dict[str, object]:
        return {
            "schema_version": 1,
            "connector": "envoy",
            "host_name": "envoy",
            "integration_mode": "unit-test-host-model",
            "host_model_constraints": [],
            "capabilities": {
                name: {"state": "verified", "reason": "unit capability"}
                for name in no_crs.CAPABILITIES
            },
            "evidence_stages": {
                stage: {"status": "not_executed", "reason": "unit stage"}
                for stage in no_crs.EVIDENCE_STAGES
            },
        }

    @staticmethod
    def record(case_id: str, status: str) -> dict[str, object]:
        return {"case_id": case_id, "status": status, "live_executed": status == "PASS"}

    def test_out_of_scope_not_executed_does_not_block_selected_pass(self) -> None:
        records = [
            self.record("selected", "PASS"),
            self.record("not_selected", "NOT_EXECUTED"),
        ]
        self.assertEqual(
            no_crs.aggregate_status(records, 0, selected_case_ids={"selected"}),
            ("PASS", False),
        )

    def test_selected_missing_evidence_still_blocks_pass(self) -> None:
        records = [
            self.record("selected", "NOT_EXECUTED"),
            self.record("not_selected", "PASS"),
        ]
        self.assertEqual(
            no_crs.aggregate_status(records, 0, selected_case_ids={"selected"}),
            ("NOT_EXECUTED", False),
        )

    def test_legacy_unscoped_aggregation_keeps_pass_precedence(self) -> None:
        self.assertEqual(
            no_crs.aggregate_status(
                [self.record("pass", "PASS"), self.record("unsupported", "UNSUPPORTED")],
                0,
            ),
            ("PASS", False),
        )
        for status in ("UNSUPPORTED", "NOT_APPLICABLE"):
            with self.subTest(status=status):
                self.assertNotEqual(
                    no_crs.aggregate_status(
                        [self.record("selected", status), self.record("also_selected", "PASS")],
                        0,
                        selected_case_ids={"selected", "also_selected"},
                    )[0],
                    "PASS",
                )
        self.assertEqual(
            no_crs.aggregate_status(
                [self.record("not_selected", "PASS")],
                0,
                selected_case_ids={"selected"},
            ),
            ("NOT_EXECUTED", False),
        )

    def test_fail_blocked_and_exit_77_keep_their_precedence(self) -> None:
        selected = self.record("selected", "PASS")
        for status, expected in (("FAIL", "FAIL"), ("BLOCKED", "BLOCKED")):
            with self.subTest(status=status):
                records = [selected, self.record("not_selected", status)]
                self.assertEqual(
                    no_crs.aggregate_status(records, 0, selected_case_ids={"selected"})[0],
                    expected,
                )
        self.assertEqual(
            no_crs.aggregate_status(
                [self.record("selected", "NOT_EXECUTED")],
                77,
                selected_case_ids={"selected"},
            ),
            ("BLOCKED", True),
        )

    def test_pass_completeness_uses_selected_scope_without_rewriting_counts(self) -> None:
        result = {
            "status": "PASS",
            "started": True,
            "requests_sent": True,
            "host_version": "nginx:1.27.0",
            "libmodsecurity_version": "libmodsecurity:3.0.13",
            "cases_passed": 1,
            "cases_failed": 0,
            "cases_blocked": 0,
            "cases_not_executed": 1,
            "evidence_stage": "no_crs_baseline",
        }
        records = [
            self.record("selected", "PASS"),
            self.record("not_selected", "NOT_EXECUTED"),
        ]
        self.assertEqual(
            no_crs.result_pass_completeness_errors(
                result, records, True, True, selected_case_ids={"selected"}
            ),
            [],
        )
        records[0] = self.record("selected", "NOT_EXECUTED")
        self.assertTrue(
            no_crs.result_pass_completeness_errors(
                result, records, True, True, selected_case_ids={"selected"}
            )
        )
        records[0] = self.record("selected", "UNSUPPORTED")
        self.assertTrue(
            no_crs.result_pass_completeness_errors(
                result, records, True, True, selected_case_ids={"selected"}
            )
        )

    def test_validator_recomputes_status_from_the_same_selected_scope(self) -> None:
        result = {
            "status": "PASS",
            "connector": "nginx",
            "evidence_stage": "no_crs_baseline",
            "artifact_profile": "generic",
            "host_version": "nginx:1.27.0",
            "libmodsecurity_version": "libmodsecurity:3.0.13",
            "connector_worktree_clean": True,
            "framework_worktree_clean": True,
            "provenance_required": False,
            "event_metadata_verified": False,
            "body_payload_absent_from_events": False,
            "pass_gate_failures": [],
            "blocked_before_execution": False,
            "exit_code": 0,
            "source_failure": False,
        }
        records = [
            self.record("selected", "PASS"),
            self.record("not_selected", "NOT_EXECUTED"),
        ]
        plan = {"cases": [
            {"case_id": "selected", "selection_status": "SELECTED"},
            {"case_id": "not_selected", "selection_status": "NOT_EXECUTED"},
        ]}
        with tempfile.TemporaryDirectory(
            prefix="no-crs-selected-status-"
        ) as temporary:
            self.assertEqual(
                no_crs.status_event_and_gate_errors(
                    Path(temporary), result, records, {"selected"}, plan
                ),
                [],
            )
            records[0] = self.record("selected", "NOT_EXECUTED")
            errors = no_crs.status_event_and_gate_errors(
                Path(temporary), result, records, set(), plan
            )
            self.assertTrue(any("aggregate status mismatch" in item for item in errors), errors)

    def test_selection_scope_cannot_be_narrowed_by_tampering_with_plan(self) -> None:
        catalog = no_crs.load_catalog()
        capabilities = {
            "capabilities": {
                name: {"state": "verified", "reason": "unit selection capability"}
                for name in no_crs.CAPABILITIES
            }
        }
        plan = no_crs.select_cases(
            "nginx", capabilities, catalog,
            artifact_profile="full_lifecycle", downstream_protocol="http1",
        )
        self.assertEqual(
            no_crs.plan_capability_errors(
                plan, "nginx", capabilities, catalog, "no_crs_baseline", "full_lifecycle"
            ),
            [],
        )
        target = next(case for case in plan["cases"] if case["case_id"] == "multiple_headers")
        self.assertEqual(target["selection_status"], "SELECTED")
        target["selection_status"] = "NOT_APPLICABLE"
        errors = no_crs.plan_capability_errors(
            plan, "nginx", capabilities, catalog, "no_crs_baseline", "full_lifecycle"
        )
        self.assertTrue(any("plan" in error for error in errors), errors)

    def test_malformed_capability_inventory_rejects_plan_without_crashing(self) -> None:
        catalog = no_crs.load_catalog()
        capabilities = {
            "capabilities": {
                name: {"state": "verified", "reason": "unit capability"}
                for name in no_crs.CAPABILITIES
            }
        }
        plan = no_crs.select_cases(
            "nginx", capabilities, catalog,
            artifact_profile="full_lifecycle", downstream_protocol="http1",
        )
        del capabilities["capabilities"]["request_headers"]
        errors = no_crs.plan_capability_errors(
            plan, "nginx", capabilities, catalog, "no_crs_baseline", "full_lifecycle"
        )
        self.assertTrue(any("plan selection" in error for error in errors), errors)

    def test_post_init_plan_tamper_is_rejected_by_finalize_and_status_validator(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="no-crs-plan-tamper-"
        ) as temporary:
            root = Path(temporary)
            capability_path = root / "capabilities.json"
            no_crs.write_json(capability_path, self.capability_manifest())
            for run_id, finalize_first in (("before-finalize", False), ("after-finalize", True)):
                with self.subTest(run_id=run_id):
                    run_dir = root / "evidence" / "envoy" / run_id
                    self.assertEqual(no_crs.main([
                        "init", "--connector", "envoy", "--capabilities", str(capability_path),
                        "--run-dir", str(run_dir), "--run-id", run_id,
                    ]), 0)
                    if finalize_first:
                        self.assertEqual(no_crs.main([
                            "finalize", "--run-dir", str(run_dir),
                            "--capabilities", str(capability_path), "--stage-rc", "0",
                        ]), 0)
                    plan_path = run_dir / "plan.json"
                    plan = no_crs.load_json(plan_path)
                    selected = next(
                        case for case in plan["cases"] if case["selection_status"] == "SELECTED"
                    )
                    selected["selection_status"] = "NOT_APPLICABLE"
                    no_crs.write_json(plan_path, plan)
                    manifest_path = run_dir / "manifest.json"
                    manifest = no_crs.load_json(manifest_path)
                    manifest["artifacts"]["plan"]["sha256"] = no_crs.sha256_file(plan_path)
                    no_crs.write_json(manifest_path, manifest)
                    if finalize_first:
                        errors = no_crs.status_errors(run_dir)
                        self.assertTrue(
                            any("plan selection" in error for error in errors), errors
                        )
                    else:
                        self.assertEqual(no_crs.main([
                            "finalize", "--run-dir", str(run_dir),
                            "--capabilities", str(capability_path), "--stage-rc", "0",
                        ]), 1)
                        self.assertFalse((run_dir / "result.json").exists())


if __name__ == "__main__":
    unittest.main()
