"""Strict projection of regular removed-API fixture metadata, not runtime proof."""
from modsecurity_connector_tests.test_nginx_configtest_collection import collector
import unittest


class MigrationCollectionTest(unittest.TestCase):
    def test_regular_fixture_digest_survives_only_for_two_closed_cases(self):
        for case_id, leaf in (("phase4_invalid_scope_file", "invalid-content-type-scope.txt"),
                              ("phase4_wildcard_scope_rejected", "wildcard-content-type-scope.txt")):
            receipt = {"operation": "configtest", "case_id": case_id, "fixture_leaf": leaf,
                       "fixture_state": "regular", "fixture_sha256": "1" * 64}
            row = {"case_id": case_id, "configtest_receipt": receipt}
            self.assertEqual(collector.configtest_source_fields(row, 0)["configtest_receipt"], receipt)
            for unrelated in ("invalid_status", "missing_rules_file", "unsafe_event_path"):
                with self.subTest(unrelated=unrelated), self.assertRaises(ValueError):
                    collector.configtest_source_fields({**row, "case_id": unrelated}, 0)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
