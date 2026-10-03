"""Require the empty-header scenario to reach a real bound phase-1 rule."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "no_crs_empty_header", ROOT / "ci/checks/catalog/no_crs_baseline.py"
)
assert SPEC is not None
assert SPEC.loader is not None
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)
sys.path.insert(0, str(ROOT / "tests/runners"))
from runner_core import load_case, request_headers, write_headers_file  # noqa: E402


class EmptyHeaderRunnerTest(unittest.TestCase):
    def test_fixture_requires_both_header_presence_and_empty_value(self) -> None:
        catalog_path = ROOT / "tests/cases/no-crs-baseline/catalog.json"
        cases = json.loads(catalog_path.read_text(encoding="utf-8"))["cases"]
        row = next(case for case in cases if case["case_id"] == "empty_header_value")
        self.assertEqual(row.get("runner_case"), "empty_header_value.yaml")
        fixture = load_case(catalog_path.parent / row["runner_case"])
        self.assertEqual(fixture["name"], row["case_id"])
        self.assertEqual(fixture["request"]["path"], row["request"]["path"])
        self.assertEqual(request_headers(fixture), {"X-No-Crs-Empty": ""})
        self.assertEqual(fixture["expect"]["status"], row["expected_status"])
        self.assertEqual(row["expected_rule_id"], 1100503)
        self.assertEqual(row["expected_event_fields"], ["rule_id", "phase"])
        # Keep selection scope unchanged; evidence requirements are strengthened,
        # not a new capability prerequisite used to exclude previously required cases.
        self.assertEqual(row["required_capabilities"], ["request_headers", "phase1"])
        self.assertEqual(fixture["expect"]["audit_log"]["rule_id"], 1100503)
        self.assertIs(fixture["expect"]["audit_log"]["required"], True)
        self.assertIn('SecRule &REQUEST_HEADERS:X-No-Crs-Empty "@eq 1"', fixture["rules"])
        self.assertIn('SecRule REQUEST_HEADERS:X-No-Crs-Empty "@rx ^$"', fixture["rules"])
        self.assertIn("id:1100503,phase:1,pass,log,t:none,chain", fixture["rules"])
        with tempfile.TemporaryDirectory(prefix="empty-header-runner-") as temporary:
            output_root = Path(temporary)
            path = output_root / "headers.txt"
            write_headers_file(fixture, path, output_root=output_root)
            self.assertEqual(path.read_text(encoding="utf-8"), "X-No-Crs-Empty: \n")

    def test_result_without_native_rule_event_cannot_pass(self) -> None:
        cases = {case["case_id"]: case for case in no_crs.catalog_cases(no_crs.load_catalog())}
        raw = {
            "case_id": "empty_header_value", "status": "PASS",
            "live_executed": True, "run_id": "unit-run",
            "integration_mode": "native-nginx-http-module",
            "actual_status": 200, "observed_rule_ids": [1100503],
            "transaction_ids": ["unit-tx"],
        }
        # Unit negative control only. No runtime/canonical artifact is written.
        record = no_crs.normalize_case_record(raw, "nginx", cases, [], "native-nginx-http-module")
        self.assertIsNotNone(record)
        self.assertEqual(record["status"], "FAIL")
        self.assertIn("canonical event is missing expected fields", record["reason"])


if __name__ == "__main__":
    unittest.main()
