"""Regression checks for the catalog's narrowly specified evidence reuse."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "no_crs_baseline_exact_reuse", ROOT / "ci/checks/catalog/no_crs_baseline.py"
)
assert SPEC is not None and SPEC.loader is not None
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)


class ExactReuseMappingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cases = {
            case["case_id"]: case for case in no_crs.catalog_cases(no_crs.load_catalog())
        }
        self.selected = {
            "allow", "deny", "phase3_original_and_visible_status",
            "event_has_no_response_body_payload", "phase4_no_payload_event",
            "phase4_deny_after_commit_abort_strict",
        }
        self.plan = {
            "connector": "nginx",
            "cases": [
                {"case_id": case_id, "selection_status": "SELECTED"}
                for case_id in sorted(self.selected)
            ],
        }

    @staticmethod
    def event(phase: int, transaction_id: str, **values: object) -> dict[str, object]:
        event: dict[str, object] = {
            "connector": "nginx",
            "integration_mode": "native-nginx-http-module",
            "event": f"phase{phase}_intervention",
            "message_id": f"phase{phase}-rule",
            "transaction_id": transaction_id,
            "rule_id": {1: 1100001, 3: 1100201, 4: 1100301}[phase],
            "phase": phase,
            "status": "blocked",
            "http_status": 403,
        }
        event.update(values)
        return event

    def base(
        self, case_id: str, transaction_id: str, events: list[dict[str, object]],
        **values: object,
    ) -> dict[str, object]:
        raw: dict[str, object] = {
            "case_id": case_id,
            "status": "PASS",
            "live_executed": True,
            "run_id": "unit-run",
            "integration_mode": "native-nginx-http-module",
            "transaction_ids": [transaction_id],
        }
        raw.update(values)
        record = no_crs.normalize_case_record(
            raw, "nginx", self.cases, events, "native-nginx-http-module",
        )
        self.assertIsNotNone(record)
        self.assertEqual(record["status"], "PASS", record["reason"])
        return record

    def derive(
        self, records: list[dict[str, object]], events: list[dict[str, object]],
    ) -> dict[str, dict[str, object]]:
        no_crs.append_explicit_reuse_records(
            records, self.plan, self.cases, events, "native-nginx-http-module",
        )
        no_crs.resolve_deprecated_aliases(records, self.cases, self.selected)
        return {record["case_id"]: record for record in records}

    def test_reuses_only_matching_live_evidence(self) -> None:
        deny_event = self.event(
            1, "tx-deny", requested_action="deny", visible_http_status=403,
        )
        phase3_event = self.event(
            3, "tx-phase3", requested_action="deny", actual_action="deny",
            original_http_status=200, visible_http_status=403,
            headers_sent=False, connection_aborted=False, transport_result="http_status",
        )
        phase4_event = self.event(
            4, "tx-phase4", requested_action="deny", actual_action="log_only",
            original_http_status=200, visible_http_status=200,
            late_intervention=True, late_intervention_mode="safe",
            headers_sent=True, connection_aborted=False,
            transport_result="log_only",
        )
        strict_event = self.event(
            4, "tx-strict", requested_action="deny", actual_action="abort_connection",
            original_http_status=200, visible_http_status=200,
            late_intervention=True, late_intervention_mode="strict",
            headers_sent=True, connection_aborted=True,
            transport_result="connection_aborted",
        )
        events = [deny_event, phase3_event, phase4_event, strict_event]
        records = [
            self.base("allow_without_marker", "tx-allow", events, actual_status=200),
            self.base("deny_header_marker_403", "tx-deny", events,
                      actual_status=403, observed_rule_ids=[1100001]),
            self.base("phase3_deny_before_commit", "tx-phase3", events,
                      actual_status=403, observed_rule_ids=[1100201]),
            self.base("phase4_rule_observed", "tx-phase4", events,
                      actual_status=200, observed_rule_ids=[1100301]),
            self.base("phase4_deny_after_commit_abort", "tx-strict", events,
                      observed_rule_ids=[1100301], transport_result="connection_aborted"),
        ]
        by_id = self.derive(records, events)
        for case_id in self.selected:
            with self.subTest(case_id=case_id):
                self.assertEqual(by_id[case_id]["status"], "PASS", by_id[case_id]["reason"])
                self.assertIs(by_id[case_id]["live_executed"], True)
                self.assertEqual(len(by_id[case_id]["transaction_ids"]), 1)

    def test_missing_or_mismatched_evidence_never_fills_target(self) -> None:
        event = self.event(
            4, "tx-phase4", requested_action="deny", actual_action="log_only",
            original_http_status=200, visible_http_status=200,
            late_intervention=True, late_intervention_mode="safe",
            headers_sent=True, connection_aborted=False,
        )
        base = self.base(
            "phase4_rule_observed", "tx-phase4", [event],
            actual_status=200, observed_rule_ids=[1100301],
        )
        controls = (
            ("not_live", dict(base, live_executed=False), [event]),
            ("not_pass", dict(base, status="NOT_EXECUTED"), [event]),
            ("wrong_base_phase", dict(base, phase=3), [event]),
            ("wrong_base_rule", dict(base, expected_rule_id=1100201), [event]),
            ("wrong_run", dict(base, run_id="foreign"), [event]),
            ("no_transaction", dict(base, transaction_ids=[]), [event]),
            ("two_transactions", dict(base, transaction_ids=["tx-phase4", "other"]), [event]),
            ("other_transaction", base, [dict(event, transaction_id="other")]),
            ("other_phase", base, [dict(event, phase=3)]),
            ("other_rule", base, [dict(event, rule_id=1100201)]),
            ("other_connector", base, [dict(event, connector="apache")]),
            ("other_integration", base, [dict(event, integration_mode="foreign")]),
            ("foreign_explicit_event_run", base, [dict(event, run_id="foreign")]),
            ("payload_leak", base, [dict(event, message="no-crs-response-body-marker")]),
            ("ambiguous_event", base, [event, dict(event)]),
        )
        for name, candidate, events in controls:
            with self.subTest(name=name):
                self.plan["run_id"] = "unit-run"
                by_id = self.derive([candidate], events)
                self.assertNotIn("event_has_no_response_body_payload", by_id)
                self.assertNotIn("phase4_no_payload_event", by_id)

    def test_safe_abort_does_not_prove_strict_abort(self) -> None:
        event = self.event(
            4, "tx-abort", requested_action="deny", actual_action="abort_connection",
            original_http_status=200, visible_http_status=200,
            late_intervention=True, late_intervention_mode="safe",
            headers_sent=True, connection_aborted=True,
            transport_result="connection_aborted",
        )
        base = self.base(
            "phase4_deny_after_commit_abort", "tx-abort", [event],
            observed_rule_ids=[1100301], transport_result="connection_aborted",
        )
        self.assertNotIn("phase4_deny_after_commit_abort_strict", self.derive([base], [event]))

    def test_strict_requires_client_abort_and_declared_reuse(self) -> None:
        event = self.event(
            4, "tx-abort", requested_action="deny", actual_action="abort_connection",
            original_http_status=200, visible_http_status=200,
            late_intervention=True, late_intervention_mode="strict",
            headers_sent=True, connection_aborted=True,
            transport_result="connection_aborted",
        )
        base = self.base(
            "phase4_deny_after_commit_abort", "tx-abort", [event],
            observed_rule_ids=[1100301], transport_result="connection_aborted",
        )
        without_client_abort = dict(base, transport_result="http_status", connection_aborted=False)
        self.assertNotIn(
            "phase4_deny_after_commit_abort_strict",
            self.derive([without_client_abort], [event]),
        )
        strict_case = dict(self.cases["phase4_deny_after_commit_abort_strict"])
        strict_case["request"] = {"fixture": "full-lifecycle/phase4_late_intervention.yaml"}
        self.cases["phase4_deny_after_commit_abort_strict"] = strict_case
        self.assertNotIn(
            "phase4_deny_after_commit_abort_strict", self.derive([base], [event]),
        )

    def test_manifest_binds_raw_source_without_case_provenance(self) -> None:
        event = self.event(
            4, "tx-source", requested_action="deny", actual_action="log_only",
            original_http_status=200, visible_http_status=200,
            late_intervention=True, late_intervention_mode="safe",
            headers_sent=True, connection_aborted=False,
            transport_result="log_only",
        )
        raw_source = {
            "case_id": "phase4_rule_observed", "status": "PASS",
            "live_executed": True, "actual_status": 200,
            "observed_rule_ids": [1100301],
            # Parent emits these rows without a per-case run or mode stamp.
        }
        base = no_crs.normalize_case_record(
            raw_source, "nginx", self.cases, [event], "native-nginx-http-module",
        )
        self.assertIsNotNone(base)
        self.assertEqual(base["status"], "PASS", base["reason"])
        self.assertIsNone(base["run_id"])
        self.assertIsNone(base["integration_mode"])
        self.assertEqual(base["transaction_ids"], ["tx-source"])
        self.assertNotIn("event_has_no_response_body_payload", self.derive([base], [event]))

        records = [base]
        no_crs.append_explicit_reuse_records(
            records, self.plan, self.cases, [event], "native-nginx-http-module",
            expected_run_id="unit-run",
            expected_integration_mode="native-nginx-http-module",
        )
        by_id = {record["case_id"]: record for record in records}
        derived = by_id["event_has_no_response_body_payload"]
        self.assertEqual(derived["status"], "PASS")
        self.assertEqual(derived["run_id"], "unit-run")
        self.assertEqual(derived["integration_mode"], "native-nginx-http-module")
        self.assertEqual(derived["transaction_ids"], ["tx-source"])


if __name__ == "__main__":
    unittest.main()
