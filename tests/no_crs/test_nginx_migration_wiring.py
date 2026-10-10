"""Explicitly migrated Required configuration identities retain strict contracts."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ci/lib"))
from nginx_migration_config_contracts import nginx_migration_config_contracts
SPEC = importlib.util.spec_from_file_location("nginx_migration_wiring", ROOT / "ci/checks/catalog/no_crs_baseline.py")
CORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORE)


class MigrationWiringTest(unittest.TestCase):
    def test_three_required_ids_declare_exact_native_config_operation(self):
        cases = {case["case_id"]: case for case in CORE.catalog_cases(CORE.load_catalog())}
        self.assertEqual(len(cases), 166)
        for case_id, invocation in nginx_migration_config_contracts().items():
            with self.subTest(case_id=case_id):
                self.assertEqual(CORE.NGINX_CONFIGTEST_CONTRACTS.get(case_id), invocation)
                self.assertEqual(CORE.config_invocation_for_case(cases[case_id], "nginx"), invocation)
                self.assertEqual(cases[case_id]["phase"], 0)
                self.assertEqual(cases[case_id]["expected_status"], 1)
                self.assertEqual(CORE.config_invocation_contract_errors(cases[case_id]), [])

    def test_migration_requires_same_exact_source_fixture_bytes(self):
        for case_id, leaf in (("phase4_invalid_scope_file", "invalid-content-type-scope.txt"),
                              ("phase4_wildcard_scope_rejected", "wildcard-content-type-scope.txt")):
            with self.subTest(case_id=case_id):
                self.assertEqual(CORE.CONFIGTEST_PATH_FIXTURES.get(case_id), (leaf, "regular"))
                fields = CORE.configtest_artifacts_for_record({"case_id": case_id})
                self.assertEqual(fields.get(leaf), ("fixture_sha256", 512))
