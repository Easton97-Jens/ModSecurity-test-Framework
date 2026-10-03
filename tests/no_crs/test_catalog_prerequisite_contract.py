from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "no_crs_baseline", ROOT / "ci/checks/catalog/no_crs_baseline.py"
)
assert SPEC is not None
assert SPEC.loader is not None
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)


class CatalogPrerequisiteContractTest(unittest.TestCase):
    PREREQUISITES = {
        "parallel_requests": "parallel_requests",
        "abort_if_supported": "drop",
        "case_insensitive_header_name": "deny",
    }

    @staticmethod
    def catalog() -> dict[str, object]:
        path = ROOT / "tests/cases/no-crs-baseline/catalog.json"
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def case(catalog: dict[str, object], case_id: str) -> dict[str, object]:
        return next(
            case for case in catalog["cases"]
            if case["case_id"] == case_id
        )

    def test_catalog_rejects_each_missing_prerequisite(self) -> None:
        catalog = self.catalog()
        for case_id, capability in self.PREREQUISITES.items():
            with self.subTest(case_id=case_id):
                mutated = copy.deepcopy(catalog)
                case = self.case(mutated, case_id)
                case["required_capabilities"] = [
                    item for item in case["required_capabilities"]
                    if item != capability
                ]
                errors = no_crs.validate_catalog(mutated)
                self.assertTrue(
                    any(case_id in error and capability in error for error in errors),
                    errors,
                )

    def test_selection_requires_each_prerequisite_and_preserves_supported_case(self) -> None:
        catalog = self.catalog()
        for case_id, capability in self.PREREQUISITES.items():
            with self.subTest(case_id=case_id):
                case = self.case(catalog, case_id)
                capabilities = {
                    name: {"state": "verified", "reason": "test host capability"}
                    for name in no_crs.CAPABILITIES
                }
                self.assertEqual(
                    no_crs.select_catalog_case(case, capabilities)["selection_status"],
                    "SELECTED",
                )
                capabilities[capability] = {
                    "state": "not_implemented", "reason": "test host lacks prerequisite"
                }
                selection = no_crs.select_catalog_case(case, capabilities)
                self.assertEqual(selection["selection_status"], "NOT_EXECUTED")
                self.assertEqual(
                    selection["required_capability_states"][capability],
                    "not_implemented",
                )


if __name__ == "__main__":
    unittest.main()
