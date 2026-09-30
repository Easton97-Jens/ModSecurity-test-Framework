from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "no_crs_multiple_headers", ROOT / "ci/checks/catalog/no_crs_baseline.py"
)
assert SPEC is not None and SPEC.loader is not None
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)
sys.path.insert(0, str(ROOT / "tests/runners"))
from runner_core import (  # noqa: E402
    assert_audit_log,
    load_case,
    request_headers,
    write_headers_file,
    write_rules_file,
)


class MultipleHeadersRunnerTest(unittest.TestCase):
    def test_audit_only_event_cannot_replace_declared_native_event(self) -> None:
        cases = {
            case["case_id"]: case
            for case in no_crs.catalog_cases(no_crs.load_catalog())
        }
        raw = {
            "case_id": "multiple_headers",
            "status": "PASS",
            "live_executed": True,
            "run_id": "unit-run",
            "integration_mode": "native-nginx-http-module",
            "actual_status": 200,
            "observed_rule_ids": [1100501],
            "transaction_ids": ["unit-tx"],
        }
        # Shape emitted by the Parent's text-audit fallback, not a JSONL event.
        audit_only = {
            "connector": "nginx",
            "rule_id": 1100501,
            "phase": 1,
            "status": "allowed",
            "transaction_id": "unit-tx",
            "http_status": 200,
        }
        record = no_crs.normalize_case_record(
            raw, "nginx", cases, [audit_only], "native-nginx-http-module"
        )
        self.assertIsNotNone(record)
        self.assertEqual(record["status"], "FAIL")
        self.assertIn("event.integration_mode", record["reason"])

        # Unit validator control only; no runtime or canonical artifact is emitted.
        native_event = {
            **audit_only,
            "run_id": "unit-run",
            "integration_mode": "native-nginx-http-module",
        }
        record = no_crs.normalize_case_record(
            raw, "nginx", cases, [native_event], "native-nginx-http-module"
        )
        self.assertIsNotNone(record)
        self.assertEqual(record["status"], "PASS", record["reason"])

    def test_host_result_without_canonical_event_cannot_pass(self) -> None:
        cases = {
            case["case_id"]: case
            for case in no_crs.catalog_cases(no_crs.load_catalog())
        }
        raw = {
            "case_id": "multiple_headers",
            "status": "PASS",
            "live_executed": True,
            "run_id": "unit-run",
            "integration_mode": "native-nginx-http-module",
            "actual_status": 200,
            "observed_rule_ids": [1100501],
            "transaction_ids": ["unit-tx"],
        }
        record = no_crs.normalize_case_record(
            raw, "nginx", cases, [], "native-nginx-http-module"
        )
        self.assertIsNotNone(record)
        self.assertEqual(record["status"], "FAIL")
        self.assertIn("canonical event is missing expected fields", record["reason"])

    def test_two_headers_require_a_real_chained_rule_match(self) -> None:
        catalog_path = ROOT / "tests/cases/no-crs-baseline/catalog.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        row = next(case for case in catalog["cases"] if case["case_id"] == "multiple_headers")

        self.assertEqual(row.get("runner_case"), "multiple_headers.yaml")
        self.assertEqual(
            row["required_capabilities"],
            ["request_headers", "phase1", "event_jsonl"],
        )
        self.assertEqual(row["expected_rule_id"], 1100501)
        self.assertEqual(row["expected_event_fields"], ["rule_id", "phase"])

        fixture = load_case(catalog_path.parent / row["runner_case"])
        self.assertEqual(fixture["name"], row["case_id"])
        self.assertEqual(fixture["required_capabilities"], row["required_capabilities"])
        self.assertEqual(fixture["request"]["method"], row["request"]["method"])
        self.assertEqual(fixture["request"]["path"], row["request"]["path"])
        self.assertEqual(
            request_headers(fixture),
            {"X-No-Crs-A": "one", "X-No-Crs-B": "two"},
        )
        self.assertEqual(fixture["expect"]["status"], 200)
        self.assertEqual(fixture["expect"]["intervention"], "none")
        self.assertEqual(fixture["expect"]["rule_id"], row["expected_rule_id"])
        self.assertIs(fixture["expect"]["audit_log"]["required"], True)
        self.assertEqual(fixture["expect"]["audit_log"]["rule_id"], 1100501)
        self.assertEqual(
            fixture["expect"]["audit_log"]["message"],
            "no-crs multiple request headers",
        )
        self.assertIn(
            'SecRule REQUEST_HEADERS:X-No-Crs-A "@streq one"', fixture["rules"]
        )
        self.assertIn(
            'SecRule REQUEST_HEADERS:X-No-Crs-B "@streq two"', fixture["rules"]
        )
        self.assertIn("id:1100501,phase:1,pass,log,t:none,chain", fixture["rules"])

        with tempfile.TemporaryDirectory(prefix="multiple-headers-runner-") as temporary:
            output_root = Path(temporary)
            headers_path = output_root / "headers.txt"
            write_headers_file(fixture, headers_path, output_root=output_root)
            self.assertEqual(
                headers_path.read_text(encoding="utf-8"),
                "X-No-Crs-A: one\nX-No-Crs-B: two\n",
            )

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
            self.assertEqual(rendered.count("id:1100501,"), 1)
            self.assertIn("id:1100001,", rendered)
            audit_file = output_root / "audit.log"
            self.assertEqual(
                assert_audit_log(fixture, audit_file, timeout_seconds=0.0),
                [f"audit log file missing or empty: {audit_file}"],
            )

            # Validator negative control only; this is not host runtime evidence.
            audit_file.write_text("unrelated rule and message\n", encoding="utf-8")
            self.assertEqual(
                assert_audit_log(fixture, audit_file, timeout_seconds=0.0),
                [
                    "expected audit log field rule_id to contain '1100501'",
                    "expected audit log field message to contain 'no-crs multiple request headers'",
                ],
            )


if __name__ == "__main__":
    unittest.main()
