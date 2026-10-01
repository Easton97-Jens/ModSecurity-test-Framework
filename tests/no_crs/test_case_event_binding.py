"""Event-backed case claims must agree with their catalog and run context."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "no_crs_case_event_binding", ROOT / "ci/checks/catalog/no_crs_baseline.py"
)
assert SPEC is not None and SPEC.loader is not None
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)


class CaseEventBindingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cases = {
            case["case_id"]: case for case in no_crs.catalog_cases(no_crs.load_catalog())
        }
        self.mode = "native-nginx-http-module"
        self.manifest = {"run_id": "unit-run", "integration_mode": self.mode}

    def evidence(self, case_id: str) -> tuple[dict[str, object], dict[str, object]]:
        case = self.cases[case_id]
        raw = {
            "case_id": case_id,
            "status": "PASS",
            "live_executed": True,
            "run_id": "unit-run",
            "integration_mode": self.mode,
            "actual_status": case["expected_status"],
            "observed_rule_ids": [case["expected_rule_id"]],
            "transaction_ids": [f"unit-{case_id}"],
        }
        event = {
            "connector": "nginx",
            "run_id": "unit-run",
            "integration_mode": self.mode,
            "transaction_id": f"unit-{case_id}",
            "rule_id": case["expected_rule_id"],
            "phase": 1,
            "status": "allowed",
            "http_status": 200,
        }
        return raw, event

    def normalize(self, raw: dict[str, object], event: dict[str, object]) -> dict[str, object]:
        record = no_crs.normalize_case_record(
            raw, "nginx", self.cases, [event], self.mode,
        )
        self.assertIsNotNone(record)
        return record

    def test_normalizer_rejects_explicit_foreign_run_and_wrong_phase(self) -> None:
        for case_id in ("multiple_headers", "transaction_id_generated_or_fallback"):
            raw, event = self.evidence(case_id)
            for label, mismatch in (
                ("foreign-run", {"run_id": "foreign-run"}),
                ("wrong-phase", {"phase": 2}),
            ):
                with self.subTest(case_id=case_id, mismatch=label):
                    record = self.normalize(raw, {**event, **mismatch})
                    self.assertEqual(record["status"], "FAIL", record)

    def test_manifest_rejects_foreign_event_when_source_omits_identity(self) -> None:
        for case_id in ("multiple_headers", "transaction_id_generated_or_fallback"):
            with self.subTest(case_id=case_id):
                raw, event = self.evidence(case_id)
                raw.pop("run_id")
                raw["transaction_ids"] = []
                record = self.normalize(raw, {**event, "run_id": "foreign-run"})
                no_crs.bind_case_protocol_provenance(
                    [record], self.manifest, self.cases,
                    [{**event, "run_id": "foreign-run"}], self.mode,
                )
                self.assertEqual(record["status"], "FAIL", record)

    def test_completeness_rechecks_event_identity_for_a_stored_pass(self) -> None:
        for case_id in ("multiple_headers", "transaction_id_generated_or_fallback"):
            raw, event = self.evidence(case_id)
            record = self.normalize(raw, event)
            self.assertEqual(record["status"], "PASS", record)
            for label, mismatch in (
                ("foreign-run", {"run_id": "foreign-run"}),
                ("wrong-phase", {"phase": 2}),
            ):
                with self.subTest(case_id=case_id, mismatch=label):
                    self.assertTrue(no_crs.pass_case_completeness_errors(
                        record, [{**event, **mismatch}], "nginx", self.mode,
                    ))

    def test_run_local_event_without_optional_run_id_keeps_legacy_support(self) -> None:
        for case_id in ("multiple_headers", "transaction_id_generated_or_fallback"):
            with self.subTest(case_id=case_id):
                raw, event = self.evidence(case_id)
                event.pop("run_id")
                record = self.normalize(raw, event)
                no_crs.bind_case_protocol_provenance(
                    [record], self.manifest, self.cases, [event], self.mode,
                )
                self.assertEqual(record["status"], "PASS", record)
                self.assertEqual(no_crs.pass_case_completeness_errors(
                    record, [event], "nginx", self.mode,
                ), [])

    def test_common_phase_label_matches_the_catalog_phase(self) -> None:
        raw, event = self.evidence("transaction_id_generated_or_fallback")
        record = self.normalize(raw, {**event, "phase": "request_headers"})
        self.assertEqual(record["status"], "PASS", record)


if __name__ == "__main__":
    unittest.main()
