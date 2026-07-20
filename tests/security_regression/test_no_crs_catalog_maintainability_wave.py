"""Fokussierte Regressionen für die wartbare No-CRS-Katalognormalisierung."""

from __future__ import annotations

from collections import Counter
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "no_crs_catalog_maintainability_wave",
    ROOT / "ci/checks/catalog/no_crs_baseline.py",
)
assert SPEC is not None and SPEC.loader is not None
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)


class NoCrsCatalogMaintainabilityWaveTests(unittest.TestCase):
    def test_capability_plan_accepts_exact_semantics_and_rejects_mismatch(self) -> None:
        expected = {
            "schema_version": 1,
            "connector": "apache",
            "catalog": "no-crs-baseline",
            "ruleset": "no-crs-baseline",
            "evidence_stage": "no_crs_baseline",
            "artifact_profile": no_crs.DEFAULT_ARTIFACT_PROFILE,
            "counts": {},
            "cases": [],
        }
        with mock.patch.object(no_crs, "select_cases", return_value=expected):
            no_crs.validate_plan_against_capabilities(
                dict(expected), "apache", {}, {}, "no_crs_baseline",
            )
            mismatches = {
                "schema_version": 2,
                "connector": "nginx",
                "catalog": "other-catalog",
                "ruleset": "other-ruleset",
                "evidence_stage": "other-stage",
                "artifact_profile": "other-profile",
                "counts": {"PASS": 1},
                "cases": [{"case_id": "other-case"}],
            }
            for field, value in mismatches.items():
                with self.subTest(field=field):
                    mismatched = {**expected, field: value}
                    with self.assertRaisesRegex(
                        no_crs.ContractError,
                        "plan does not match a fresh capability-driven selection",
                    ):
                        no_crs.validate_plan_against_capabilities(
                            mismatched, "apache", {}, {}, "no_crs_baseline",
                        )

    def test_normalized_case_record_keeps_success_and_status_mismatch_failure(self) -> None:
        catalog = no_crs.load_catalog()
        case_by_id = {
            case["case_id"]: case
            for case in no_crs.catalog_cases(catalog)
        }
        common = {
            "case_id": "allow_without_marker",
            "status": "PASS",
            "live_executed": True,
        }
        matched = no_crs.normalize_case_record(
            {**common, "actual_status": 200}, "apache", case_by_id, [],
        )
        self.assertIsNotNone(matched)
        self.assertEqual("PASS", matched["status"])
        self.assertEqual(200, matched["actual_status"])

        mismatched = no_crs.normalize_case_record(
            {**common, "actual_status": 418}, "apache", case_by_id, [],
        )
        self.assertIsNotNone(mismatched)
        self.assertEqual("FAIL", mismatched["status"])
        self.assertIn("actual status does not match expected status", mismatched["reason"])

    def test_finalize_summary_preserves_named_values(self) -> None:
        values = {
            "status": "PASS",
            "blocked_before_execution": False,
            "source_statuses": ["PASS"],
            "source_failure": False,
            "counts": Counter({"PASS": 1}),
            "observed_rule_ids": [1100001],
            "transaction_ids": ["tx-maintainability"],
            "pass_ids": {"allow_without_marker"},
            "verified_capabilities": ["phase1"],
            "unsupported_capabilities": [],
            "not_exercised_capabilities": [],
            "requests_sent": True,
            "started": True,
            "event_metadata_verified": True,
            "body_payload_absent_from_events": True,
            "host_version": "1.0",
            "libmodsecurity_version": "3.0",
            "minimal_runtime_verified": True,
            "pass_gate_failures": [],
            "allowed_record": {"actual_status": 200},
            "blocked_record": {"actual_status": 403},
            "evidence_stages": {"no_crs_baseline": {"status": "passed"}},
        }
        summary = no_crs.FinalizeSummary(values)
        self.assertEqual("PASS", summary.status)
        self.assertEqual(Counter({"PASS": 1}), summary.counts)
        self.assertEqual({"actual_status": 403}, summary.blocked_record)
        self.assertEqual({"no_crs_baseline": {"status": "passed"}}, summary.evidence_stages)

    def test_protocol_validation_preserves_success_and_error_order(self) -> None:
        valid_event = {
            "negotiated_protocol": "h3",
            "transport": "quic_udp",
            "connection_id": "sha256:" + ("a" * 32),
            "stream_reset": True,
        }
        self.assertEqual(
            [],
            no_crs.canonical_event_protocol_errors(valid_event, "event"),
        )
        invalid_event = {
            "requested_protocol": [],
            "transport": "quic_udp",
            "connection_id": "raw-quic-connection-id",
            "stream_reset": True,
        }
        self.assertEqual(
            [
                "event.requested_protocol: unsupported transport provenance",
                "event.connection_id: raw QUIC connection identifiers are forbidden",
                "event.stream_reset: requires h2, h2c, or h3 downstream protocol",
            ],
            no_crs.canonical_event_protocol_errors(invalid_event, "event"),
        )

    def test_body_payload_json_errors_preserve_success_and_error_order(self) -> None:
        with tempfile.TemporaryDirectory(prefix="no-crs-maintainability-wave-") as temporary:
            run_dir = Path(temporary)
            metadata_path = run_dir / "before-events.json"
            events_path = run_dir / no_crs.EVENTS_FILE_NAME
            metadata_path.write_text(json.dumps({"phase": 1}), encoding="utf-8")
            events_path.write_text(json.dumps({"connector": "apache"}) + "\n", encoding="utf-8")
            events, errors = no_crs.body_payload_json_artifact_errors(
                run_dir, [events_path, metadata_path],
            )
            self.assertEqual([{"connector": "apache"}], events)
            self.assertEqual([], errors)

            metadata_path.write_text(
                json.dumps({"response_body": "body"}), encoding="utf-8",
            )
            events_path.write_text(
                json.dumps({"response_body": "body"}) + "\n", encoding="utf-8",
            )
            events, errors = no_crs.body_payload_json_artifact_errors(
                run_dir, [events_path, metadata_path],
            )
            self.assertEqual([{"response_body": "body"}], events)
            self.assertEqual(
                [
                    "before-events.json.response_body: forbidden payload/secret field",
                    "events.jsonl[0]: missing required property connector",
                    "events.jsonl[0]: unexpected property response_body",
                    "events.jsonl[0].response_body: forbidden payload/secret field",
                ],
                errors,
            )


if __name__ == "__main__":
    unittest.main()
