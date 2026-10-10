"""Closed Engine lexical/migration rejections, not invented status/MIME ranges."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ci/lib"))
from nginx_migration_config_contracts import nginx_migration_config_contracts


class NginxMigrationConfigContractsTests(unittest.TestCase):
    def test_invalid_status_is_lexical_engine_rule_error(self):
        contract = nginx_migration_config_contracts()["invalid_status"]
        self.assertEqual(contract["directive"], "modsecurity_rules")
        self.assertIn("status:not-a-number", contract["value"])
        self.assertEqual(contract["expected_exit_code"], 1)
        self.assertEqual(contract["error_class"], "invalid_status")
        self.assertIn("Expecting an action, got:  status:not-a-number", contract["diagnostic_fragments"])

    def test_removed_scope_directive_rejection_is_not_mime_validation(self):
        contracts = nginx_migration_config_contracts()
        for case_id, filename in (("phase4_invalid_scope_file", "invalid-content-type-scope.txt"),
                                  ("phase4_wildcard_scope_rejected", "wildcard-content-type-scope.txt")):
            with self.subTest(case_id=case_id):
                contract = contracts[case_id]
                self.assertEqual(contract["directive"], "modsecurity_phase4_content_types_file")
                self.assertEqual(contract["value"], filename)
                self.assertEqual(contract["operation"], "configtest")
                self.assertEqual(contract["expected_outcome"], "config_rejected")
                self.assertEqual(contract["expected_exit_code"], 1)
                self.assertEqual(contract["error_class"], case_id)
                self.assertEqual(contract["diagnostic_fragments"], ['unknown directive "modsecurity_phase4_content_types_file"'])
                self.assertNotIn("invalid media type", str(contract))

    def test_no_other_configuration_case_is_authorized(self):
        self.assertEqual(set(nginx_migration_config_contracts()), {
            "invalid_status", "phase4_invalid_scope_file", "phase4_wildcard_scope_rejected"})

    def test_contract_calls_do_not_share_mutable_state(self):
        first = nginx_migration_config_contracts()
        first["invalid_status"]["diagnostic_fragments"].append("invented")
        self.assertNotIn("invented", nginx_migration_config_contracts()["invalid_status"]["diagnostic_fragments"])


if __name__ == "__main__":
    unittest.main()
