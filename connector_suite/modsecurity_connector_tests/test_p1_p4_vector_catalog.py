from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
from pathlib import Path
import re
import unittest


ROOT = connector_root()
RULES = source_path('common/rules/modsecurity_p1_p4_vectors.conf', root=ROOT)
CATALOG = source_path('common/rules/p1_p4_traffic_vectors.json', root=ROOT)


class P1P4VectorCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = RULES.read_text(encoding="utf-8")
        cls.catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        cls.vectors = {vector["id"]: vector for vector in cls.catalog["vectors"]}

    def test_phase_specific_rules_have_stable_unique_ids(self) -> None:
        expected = {
            1101001: ("P1", "REQUEST_HEADERS", 1),
            1102001: ("P2", "REQUEST_BODY", 2),
            1102002: ("P2", "REQUEST_BODY", 2),
            1103001: ("P3", "RESPONSE_HEADERS", 3),
            1103002: ("P3", "RESPONSE_HEADERS", 3),
            1104001: ("P4", "RESPONSE_BODY", 4),
            1104002: ("P4", "RESPONSE_BODY", 4),
            1104003: ("P4", "RESPONSE_BODY", 4),
        }
        found = {}
        for match in re.finditer(
            r"SecRule\s+(?P<variable>[A-Z_]+).*?id:(?P<id>110\d+),phase:(?P<phase>\d)",
            self.rules,
        ):
            rule_id = int(match.group("id"))
            self.assertNotIn(rule_id, found)
            found[rule_id] = (match.group("variable"), int(match.group("phase")))

        self.assertEqual(set(found), set(expected))
        for rule_id, (_, variable, phase) in expected.items():
            with self.subTest(rule_id=rule_id):
                self.assertEqual(found[rule_id], (variable, phase))

    def test_catalog_covers_each_required_vector_and_evidence_field(self) -> None:
        required_ids = {
            "allow_control",
            "p1_only",
            "p2_only",
            "p2_body_limit",
            "p2_empty_body",
            "p2_client_abort",
            "p3_only",
            "p3_redirect",
            "p4_only",
            "p4_safe",
            "p4_strict",
        }
        self.assertEqual(set(self.vectors), required_ids)
        self.assertEqual(
            self.catalog["evidence_contract"]["required_fields"],
            [
                "connector",
                "transaction_id",
                "rule_id",
                "phase",
                "requested_action",
                "actual_host_action",
                "event_time",
                "vector_id",
                "cleanup_status",
            ],
        )
        self.assertEqual(
            self.catalog["phase_semantics"],
            {
                "P1": "request headers",
                "P2": "raw request body",
                "P3": "upstream response headers",
                "P4": "response body",
            },
        )

    def test_p2_vectors_are_real_body_boundary_cases(self) -> None:
        self.assertIn("SecRequestBodyLimit 32", self.rules)
        self.assertIn("SecRequestBodyNoFilesLimit 32", self.rules)
        self.assertIn("SecRequestBodyLimitAction Reject", self.rules)

        p2_only = self.vectors["p2_only"]
        self.assertEqual(p2_only["phase"], "P2")
        self.assertIn("body", p2_only["request"])
        self.assertIn("request body EOS observed", p2_only["expected"]["body_requirements"])
        self.assertIn("no query-only substitute", p2_only["expected"]["body_requirements"])

        body_limit = self.vectors["p2_body_limit"]
        self.assertGreater(body_limit["request"]["headers"]["Content-Length"], 32)
        self.assertEqual(body_limit["expected"]["response_status"], 403)

        empty = self.vectors["p2_empty_body"]
        self.assertEqual(empty["request"]["headers"]["Content-Length"], 0)
        self.assertIn("P2 EOS recorded", empty["expected"]["body_requirements"])

        aborted = self.vectors["p2_client_abort"]
        self.assertTrue(aborted["request"]["client_abort"]["before_request_eos"])
        self.assertIn("no synthetic request EOS", aborted["expected"]["body_requirements"])

    def test_p4_safe_and_strict_remain_distinct(self) -> None:
        safe = self.vectors["p4_safe"]
        strict = self.vectors["p4_strict"]
        self.assertEqual(safe["phase"], strict["phase"])
        self.assertEqual(safe["phase"], "P4")
        self.assertNotEqual(safe["marker"], strict["marker"])
        self.assertNotEqual(safe["rule_id"], strict["rule_id"])
        self.assertEqual(safe["mode"], "safe")
        self.assertEqual(strict["mode"], "strict")
        self.assertEqual(safe["expected"]["requested_rule_action"], "deny,status=451")
        self.assertEqual(safe["expected"]["actual_host_action"], "forward_original_response")
        self.assertEqual(
            strict["expected"]["actual_host_action"],
            "connector_documented_deterministic_strict_action",
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
