"""Closed result counts stay independent from each host's evidence validator."""
from copy import deepcopy
from pathlib import Path
import unittest

from tests.runners import non_nginx_h2_acceptance as registry
from tests.runners import protocol_acceptance_contract as nginx


class NativeH2RegistryTests(unittest.TestCase):
    def test_registered_adapters_exist_without_default_or_nginx_collision(self):
        root = Path(__file__).resolve().parents[2]
        self.assertEqual(len(registry.CASES), 32)
        self.assertEqual(len(nginx.CASES), 25)
        self.assertFalse(set(registry.CASES) & set(nginx.CASES))
        for adapter in {case["adapter"] for case in registry.CASES.values()}:
            self.assertTrue((root / adapter).is_file(), adapter)
        self.assertTrue(all(case["selection"] == "opt_in" for case in registry.CASES.values()))

    def test_missing_duplicate_foreign_zero_and_failed_results_rejected(self):
        rows = [{"case_id": case, "status": "PASS"} for case in registry.CASES]
        self.assertEqual(registry.validate_results(rows)["evaluated"], 32)
        corruptions = [[], rows[:-1], rows + [rows[0]], None, [{"status": "PASS"}]]
        for key, value in (("case_id", "foreign"), ("status", "FAIL"), ("status", "BLOCKED")):
            changed = deepcopy(rows)
            changed[0][key] = value
            corruptions.append(changed)
        for changed in corruptions:
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    registry.validate_results(changed)


if __name__ == "__main__":
    unittest.main()
