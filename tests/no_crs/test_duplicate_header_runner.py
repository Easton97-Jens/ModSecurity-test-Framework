"""Ordered header transport and bound duplicate-header fixture contracts."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/runners"))
import runner_core as runner  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "no_crs_duplicate_header", ROOT / "ci/checks/catalog/no_crs_baseline.py"
)
assert SPEC is not None and SPEC.loader is not None
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)


class OrderedHeaderRepresentationTest(unittest.TestCase):
    def test_preserves_multiplicity_values_order_casing_and_empty_values(self) -> None:
        headers = [
            {"name": "X-Duplicate", "value": "one"},
            {"name": "X-Duplicate", "value": "two"},
            {"name": "x-Duplicate", "value": ""},
        ]
        case = {"request": {"headers": headers}}
        expected = [("X-Duplicate", "one"), ("X-Duplicate", "two"), ("x-Duplicate", "")]
        self.assertEqual(runner.request_header_entries(case), expected)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner.write_headers_file(case, root / "headers", output_root=root)
            self.assertEqual((root / "headers").read_text(),
                             "X-Duplicate: one\nX-Duplicate: two\nx-Duplicate: \n")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            runner.request_headers(case)

    def test_mapping_scalar_compatibility_and_empty_headers(self) -> None:
        headers = {"X-Empty": "", "X-Number": 42, "X-Bool": True, "X-Null": None}
        case = {"request": {"headers": headers}}
        self.assertEqual(runner.request_headers(case), headers)
        self.assertEqual(runner.request_header_entries(case), list(headers.items()))
        for headers in ({}, [], None):
            self.assertEqual(runner.request_header_entries({"request": {"headers": headers}}), [])

    def test_rejects_malformed_shapes_and_unsafe_headers_in_both_forms(self) -> None:
        malformed = ["X: value", ["X"], [["X", "one"]], [{"name": "X"}],
                     [{"value": "one"}], [{"name": "X", "value": "one", "extra": True}],
                     {"X": []}, {"X": {}}, [{"name": "X", "value": []}]]
        for headers in malformed:
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                runner.request_header_entries({"request": {"headers": headers}})
        for name in ("", "bad name", "bad:name", "é", "X\r\nInjected", 123):
            for headers in ({name: "value"}, [{"name": name, "value": "value"}]):
                with self.subTest(headers=headers), self.assertRaises(ValueError):
                    runner.request_header_entries({"request": {"headers": headers}})
        for control in [chr(code) for code in (*range(32), *range(127, 160))]:
            for headers in ({"X": f"a{control}b"}, [{"name": "X", "value": f"a{control}b"}]):
                with self.subTest(control=ord(control)), self.assertRaises(ValueError):
                    runner.request_header_entries({"request": {"headers": headers}})

    def test_multipart_checks_every_ordered_entry(self) -> None:
        case = {"request": {"method": "POST", "path": "/", "multipart": {
            "boundary": "safe-boundary", "parts": [{"name": "field", "value": "one"}]},
            "headers": [{"name": "X", "value": "one"},
                        {"name": "cOnTeNt-TyPe", "value": "text/plain"}]}}
        with self.assertRaisesRegex(ValueError, "Content-Type"):
            runner._validate_request(case, "")
        with self.assertRaisesRegex(ValueError, "Content-Type"):
            runner.request_header_entries(case)
        case["request"]["headers"] = [{"name": "X", "value": "one"}]
        self.assertEqual(runner.request_header_entries(case),
                         [("X", "one"), ("Content-Type", "multipart/form-data; boundary=safe-boundary")])


class DuplicateHeaderFixtureTest(unittest.TestCase):
    def test_parser_materialization_and_count_value_chain(self) -> None:
        path = ROOT / "tests/cases/no-crs-baseline/duplicate_header_names.yaml"
        fixture = runner.load_case(path)
        fallback = runner._load_minimal_yaml(path)
        self.assertEqual(fallback["request"], fixture["request"])
        self.assertEqual(runner.request_header_entries(fixture),
                         [("X-No-Crs-Duplicate", "one"), ("X-No-Crs-Duplicate", "two")])
        self.assertEqual(fixture["request"]["method"], "GET")
        self.assertEqual(fixture["request"]["path"], "/no-crs/headers/duplicate")
        self.assertEqual(fixture["expect"]["status"], 200)
        self.assertEqual(fixture["required_capabilities"], ["request_headers", "phase1", "event_jsonl"])
        self.assertEqual(fixture["expected_event_fields"], ["rule_id", "phase"])
        self.assertIn('SecRule &REQUEST_HEADERS:X-No-Crs-Duplicate "@eq 2"', fixture["rules"])
        self.assertIn('SecRule REQUEST_HEADERS:X-No-Crs-Duplicate "@streq one"', fixture["rules"])
        self.assertIn('SecRule REQUEST_HEADERS:X-No-Crs-Duplicate "@streq two"', fixture["rules"])
        self.assertIn("id:1100504,phase:1,pass,log,t:none,chain", fixture["rules"])
        single = copy.deepcopy(fixture)
        single["request"]["headers"].pop()
        self.assertEqual(len(runner.request_header_entries(single)), 1)
        # The native count predicate prevents the single-header request matching.
        self.assertIn('"@eq 2"', single["rules"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner.write_headers_file(fixture, root / "headers", output_root=root)
            self.assertEqual((root / "headers").read_text(),
                             "X-No-Crs-Duplicate: one\nX-No-Crs-Duplicate: two\n")
            audit = root / "audit"
            audit.write_text('1100504 no-crs duplicate request header names\n')
            self.assertEqual(runner.assert_audit_log(fixture, audit, timeout_seconds=0.0), [])
            audit.write_text('1100501 no-crs multiple request headers\n')
            self.assertEqual(len(runner.assert_audit_log(fixture, audit, timeout_seconds=0.0)), 2)

    def test_catalog_binds_native_rule_and_fixture(self) -> None:
        rows = json.loads((ROOT / "tests/cases/no-crs-baseline/catalog.json").read_text())["cases"]
        row = next(row for row in rows if row["case_id"] == "duplicate_header_names")
        self.assertEqual(row.get("runner_case"), "duplicate_header_names.yaml")
        self.assertEqual(row["expected_rule_id"], 1100504)
        self.assertEqual(row["expected_event_fields"], ["rule_id", "phase"])

    def test_http_success_without_bound_duplicate_native_event_cannot_pass(self) -> None:
        cases = {case["case_id"]: case for case in no_crs.catalog_cases(no_crs.load_catalog())}
        raw = {
            "case_id": "duplicate_header_names", "status": "PASS", "live_executed": True,
            "run_id": "unit-run", "integration_mode": "native-nginx-http-module",
            "actual_status": 200, "observed_rule_ids": [1100504], "transaction_ids": ["unit-tx"],
        }
        # Validator controls only: these objects are never emitted as runtime evidence.
        event = {
            "connector": "nginx", "rule_id": 1100504, "phase": 1,
            "status": "allowed", "transaction_id": "unit-tx", "http_status": 200,
            "run_id": "unit-run", "integration_mode": "native-nginx-http-module",
        }
        for events in ([], [{**event, "rule_id": 1100501}],
                       [{**event, "run_id": "foreign-run"}],
                       [{**event, "transaction_id": "foreign-tx"}]):
            with self.subTest(events=events):
                record = no_crs.normalize_case_record(raw, "nginx", cases, events,
                                                     "native-nginx-http-module")
                self.assertIsNotNone(record)
                self.assertEqual(record["status"], "FAIL", record["reason"])


if __name__ == "__main__":
    unittest.main()
