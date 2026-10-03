from __future__ import annotations

import json
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/runners"))
from runner_core import load_case, request_headers, write_headers_file  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "no_crs_baseline", ROOT / "ci/checks/catalog/no_crs_baseline.py"
)
assert SPEC is not None
assert SPEC.loader is not None
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)


class CaseInsensitiveHeaderRunnerTest(unittest.TestCase):
    def test_selection_requires_deny_capability(self) -> None:
        catalog_path = ROOT / "tests/cases/no-crs-baseline/catalog.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        row = next(case for case in catalog["cases"] if case["case_id"] == "case_insensitive_header_name")
        capabilities = {
            name: {"state": "verified", "reason": "test host capability"}
            for name in no_crs.CAPABILITIES
        }

        self.assertIn("deny", row["required_capabilities"])
        self.assertEqual(
            no_crs.select_catalog_case(row, capabilities)["selection_status"], "SELECTED"
        )
        capabilities["deny"] = {"state": "not_implemented", "reason": "host lacks deny"}
        result = no_crs.select_catalog_case(row, capabilities)
        self.assertEqual(result["selection_status"], "NOT_EXECUTED")
        self.assertEqual(result["required_capability_states"]["deny"], "not_implemented")

    def test_selected_case_has_distinct_materializable_runner(self) -> None:
        catalog_path = ROOT / "tests/cases/no-crs-baseline/catalog.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        row = next(case for case in catalog["cases"] if case["case_id"] == "case_insensitive_header_name")

        self.assertEqual(row["runner_case"], "case_insensitive_header_name.yaml")
        fixture = load_case(catalog_path.parent / row["runner_case"])
        self.assertEqual(fixture["name"], row["case_id"])
        self.assertEqual(fixture["request"]["method"], row["request"]["method"])
        self.assertEqual(fixture["request"]["path"], row["request"]["path"])
        self.assertEqual(request_headers(fixture), {"x-modsec-smoke": "block"})
        self.assertEqual(row["request"]["headers"], [{"name": "x-modsec-smoke", "value": "block"}])
        self.assertEqual(fixture["expect"]["status"], row["expected_status"])
        self.assertEqual(fixture["expect"]["rule_id"], row["expected_rule_id"])
        self.assertEqual(fixture["expect"]["intervention"], "deny")

        with tempfile.TemporaryDirectory(prefix="case-insensitive-header-") as temporary:
            root = Path(temporary)
            headers_path = root / "headers.txt"
            write_headers_file(fixture, headers_path, output_root=root)
            self.assertEqual(headers_path.read_text(encoding="utf-8"), "x-modsec-smoke: block\n")


if __name__ == "__main__":
    unittest.main()
