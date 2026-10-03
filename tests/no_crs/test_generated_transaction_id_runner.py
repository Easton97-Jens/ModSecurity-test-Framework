from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "no_crs_generated_transaction_id", ROOT / "ci/checks/catalog/no_crs_baseline.py"
)
assert SPEC is not None
assert SPEC.loader is not None
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)
sys.path.insert(0, str(ROOT / "tests/runners"))
from runner_core import assert_audit_log, load_case, request_headers, write_rules_file  # noqa: E402


class GeneratedTransactionIdRunnerTest(unittest.TestCase):
    def test_case_has_an_independent_logged_request_without_supplied_id(self) -> None:
        catalog_path = ROOT / "tests/cases/no-crs-baseline/catalog.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        row = next(
            case for case in catalog["cases"]
            if case["case_id"] == "transaction_id_generated_or_fallback"
        )
        self.assertEqual(row.get("runner_case"), "transaction_id_generated_or_fallback.yaml")
        self.assertEqual(row["expected_rule_id"], 1100502)
        self.assertEqual(row["expected_event_fields"], ["transaction_id", "rule_id", "phase"])
        fixture = load_case(catalog_path.parent / row["runner_case"])
        self.assertEqual(fixture["name"], row["case_id"])
        self.assertEqual(fixture["request"]["method"], "GET")
        self.assertEqual(fixture["request"]["path"], "/no-crs/generated-transaction-id")
        self.assertNotIn("X-Modsec-Transaction-Id", request_headers(fixture))
        self.assertEqual(request_headers(fixture), {})
        self.assertEqual(fixture["expect"]["status"], 200)
        self.assertEqual(fixture["expect"]["intervention"], "none")
        self.assertEqual(fixture["expect"]["rule_id"], 1100502)
        self.assertEqual(fixture["expect"]["audit_log"]["rule_id"], 1100502)
        self.assertIn(
            'SecRule REQUEST_URI "@streq /no-crs/generated-transaction-id"',
            fixture["rules"],
        )
        self.assertIn("id:1100502,phase:1,pass,log,t:none", fixture["rules"])
        with tempfile.TemporaryDirectory(prefix="generated-tx-runner-") as temporary:
            output_root = Path(temporary)
            audit_dir = output_root / "audit"
            audit_dir.mkdir(mode=0o700)
            rules_path = output_root / "rules.conf"
            write_rules_file(
                fixture,
                rules_path,
                output_root=output_root,
                audit_log_file=output_root / "audit.log",
                audit_log_dir=audit_dir,
                rules_preamble_file=ROOT / "tests/rules/no-crs-baseline.conf",
            )
            rendered = rules_path.read_text(encoding="utf-8")
            self.assertEqual(rendered.count("id:1100502,"), 1)
            self.assertEqual(rendered.count("id:1100001,"), 1)
            self.assertEqual(
                assert_audit_log(fixture, output_root / "audit.log", timeout_seconds=0.0),
                [f"audit log file missing or empty: {output_root / 'audit.log'}"],
            )

    def test_canonical_pass_requires_real_nonempty_bound_transaction_id(self) -> None:
        cases = {
            case["case_id"]: case
            for case in no_crs.catalog_cases(no_crs.load_catalog())
        }
        raw = {
            "case_id": "transaction_id_generated_or_fallback",
            "status": "PASS",
            "live_executed": True,
            "run_id": "unit-run",
            "integration_mode": "native-nginx-http-module",
            "actual_status": 200,
            "observed_rule_ids": [1100502],
            "transaction_ids": ["nginx-generated-tx-1"],
        }
        event = {
            "connector": "nginx",
            "run_id": "unit-run",
            "integration_mode": "native-nginx-http-module",
            "transaction_id": "nginx-generated-tx-1",
            "rule_id": 1100502,
            "phase": 1,
            "status": "allowed",
            "http_status": 200,
        }
        for label, supplied, events in (
            ("missing-event", raw, []),
            ("empty-transaction", raw, [{**event, "transaction_id": ""}]),
            ("different-transaction", raw, [{**event, "transaction_id": "other"}]),
        ):
            with self.subTest(label=label):
                record = no_crs.normalize_case_record(
                    supplied, "nginx", cases, events, "native-nginx-http-module"
                )
                self.assertIsNotNone(record)
                self.assertNotEqual(record["status"], "PASS", record)
        # Unit validator control only: this is not runtime evidence.
        record = no_crs.normalize_case_record(
            raw, "nginx", cases, [event], "native-nginx-http-module"
        )
        self.assertIsNotNone(record)
        self.assertEqual(record["status"], "PASS", record["reason"])
        # A native event is allowed to supply the observed ID when the host
        # result did not already extract it from the same request.
        record = no_crs.normalize_case_record(
            {**raw, "transaction_ids": []}, "nginx", cases, [event],
            "native-nginx-http-module",
        )
        self.assertIsNotNone(record)
        self.assertEqual(record["status"], "PASS", record["reason"])


if __name__ == "__main__":
    unittest.main()
