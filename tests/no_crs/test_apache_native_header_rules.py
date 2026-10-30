"""Native Apache test setup preserves the portable oracle and audit contract."""
from copy import deepcopy
import hashlib
from pathlib import Path
import unittest

import yaml

from modsecurity_test_framework.runners.apache_native_header_rules import (
    CASE_SHA256, adapt_native_case,
)


CASE = Path(__file__).resolve().parents[1] / "cases/no-crs-baseline/duplicate_header_names.yaml"


class ApacheNativeHeaderRulesTests(unittest.TestCase):
    def setUp(self):
        self.raw = CASE.read_bytes()
        self.case = yaml.safe_load(self.raw)

    def adapt(self, case=None, **changes):
        return adapt_native_case(self.case if case is None else case,
                                 profile=changes.get("profile", "apache-native"),
                                 case_sha256=changes.get("case_sha256", CASE_SHA256))

    def test_native_header_view_keeps_wire_request_and_all_expectations(self):
        original = deepcopy(self.case)
        adapted, receipt = self.adapt()
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), CASE_SHA256)
        self.assertEqual(self.case, original)
        self.assertEqual(CASE.read_bytes(), self.raw)
        self.assertIn('SecRule &REQUEST_HEADERS:X-No-Crs-Duplicate "@eq 1"', adapted["rules"])
        self.assertIn('SecRule REQUEST_HEADERS:X-No-Crs-Duplicate "@streq one, two" "t:none"', adapted["rules"])
        self.assertIn("id:1100504,phase:1,pass,log,t:none,chain", adapted["rules"])
        self.assertIn("SecAuditEngine On", adapted["rules"])
        self.assertNotIn('"@eq 2"', adapted["rules"])
        self.assertIn('"@eq 2"', original["rules"])
        self.assertEqual({key: value for key, value in adapted.items() if key != "rules"},
                         {key: value for key, value in original.items() if key != "rules"})
        self.assertEqual(receipt["unchanged_expectations"],
                         {"http_status": 200, "rule_id": 1100504, "audit_required": True})
        self.assertFalse(receipt["wire_occurrence_count_observable"])
        self.assertIsNone(receipt["runtime_retest"])
        self.assertIsNone(receipt["lifecycle_qualification"])
        adapted["expect"]["status"] = 403
        self.assertEqual(self.case["expect"]["status"], 200)

    def test_altered_original_rule_request_assertion_or_profile_is_rejected(self):
        for profile in (None, "nginx-native", "apache-compatibility"):
            with self.subTest(profile=profile), self.assertRaisesRegex(ValueError, "profile"):
                self.adapt(profile=profile)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.adapt(case_sha256="0" * 64)
        for field, value in (("rules", self.case["rules"].replace("@eq 2", "@eq 1")),
                             ("expected_status", 403), ("expected_rule_id", None)):
            changed = deepcopy(self.case)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.adapt(changed)
        for target, field, value in (("expect", "status", 403), ("expect", "rule_id", None),
                                     ("request", "headers", list(reversed(self.case["request"]["headers"]))),
                                     ("request", "method", "POST")):
            changed = deepcopy(self.case)
            changed[target][field] = value
            with self.subTest(target=target, field=field), self.assertRaises(ValueError):
                self.adapt(changed)
        for field, value in (("required", False), ("rule_id", None), ("message", "other")):
            changed = deepcopy(self.case)
            changed["expect"]["audit_log"][field] = value
            with self.subTest(audit=field), self.assertRaises(ValueError):
                self.adapt(changed)

    def test_other_cases_have_no_adapter_and_keep_independent_original_rules(self):
        original = deepcopy(self.case)
        original["name"] = "allow_without_marker"
        adapted, receipt = self.adapt(original, case_sha256="unrelated")
        self.assertEqual(adapted, original)
        self.assertIsNone(receipt)
        self.assertIsNot(adapted, original)




def load_tests(loader, standard_tests, pattern):
    import os
    if os.environ.get("ON_DEMAND_TESTS") == "1":
        return standard_tests
    return unittest.TestSuite()

if __name__ == "__main__":
    unittest.main()
