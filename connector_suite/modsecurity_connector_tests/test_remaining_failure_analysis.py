from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = connector_root()
GENERATOR_PATH = source_path('ci/evidence/reports/generate-remaining-failure-analysis.py', root=ROOT)
GENERATOR = load_source(GENERATOR_PATH)


class RemainingFailureAnalysisTest(unittest.TestCase):
    def test_category_rollup_keeps_typical_examples_without_discarded_summary_reads(self) -> None:
        category = GENERATOR.FAILURE_CATEGORIES[0]
        with (
            mock.patch.object(GENERATOR, "failure_category", return_value=category),
            mock.patch.object(
                GENERATOR,
                "case_group_summary",
                side_effect=AssertionError("discarded summary reads must not run"),
            ),
            mock.patch.object(GENERATOR, "example_entry", return_value={"case_id": "case-1"}),
        ):
            rows = GENERATOR.category_rollup([{"case_id": "case-1", "connector": "apache"}])

        selected = next(row for row in rows if row["category"] == category)
        self.assertEqual(selected["typical_examples"], [{"case_id": "case-1"}])
        self.assertEqual(selected["count"], 1)

    def test_phase4_detail_category_keeps_precedence_and_action_fallbacks(self) -> None:
        base_context = {
            "hard_abort": False,
            "has_log_evidence": False,
            "classification": "",
            "reason": "",
            "case_id": "case",
            "phase4_log": "",
            "evidence": {"response_body_truncated": False},
            "expected_action": "deny",
            "connector": "apache",
            "known_limitations": "",
        }
        precedence_cases = (
            ({"hard_abort": True, "has_log_evidence": True, "classification": "native"}, "phase4_hard_abort_evidence"),
            ({"classification": "native_semantics"}, "phase4_native_semantics"),
            ({"reason": "log only"}, "phase4_log_only_no_abort"),
            ({"evidence": {"response_body_truncated": True}}, "phase4_truncated_not_accepted"),
        )
        for changes, expected in precedence_cases:
            context = {**base_context, **changes}
            with self.subTest(expected=expected), mock.patch.object(
                GENERATOR,
                "phase4_is_log_only",
                return_value=expected == "phase4_log_only_no_abort",
            ), mock.patch.object(GENERATOR, "phase4_detail_context", return_value=context):
                self.assertEqual(GENERATOR.phase4_detail_category({"runtime_status": "FAIL"}), expected)

        with mock.patch.object(GENERATOR, "phase4_is_connector_gap", return_value=True):
            self.assertEqual(
                GENERATOR.phase4_action_category({"runtime_status": "FAIL"}, base_context),
                "phase4_connector_gap",
            )
        with mock.patch.object(GENERATOR, "phase4_is_connector_gap", return_value=False):
            self.assertEqual(
                GENERATOR.phase4_action_category({"runtime_status": "FAIL"}, base_context),
                "phase4_missing_abort_evidence",
            )
            self.assertEqual(
                GENERATOR.phase4_action_category(
                    {"runtime_status": "FAIL"},
                    {**base_context, "expected_action": "pass"},
                ),
                "phase4_missing_abort_evidence",
            )
            self.assertEqual(
                GENERATOR.phase4_action_category(
                    {"runtime_status": "PASS"},
                    {**base_context, "expected_action": "pass", "has_log_evidence": True},
                ),
                "phase4_no_hard_abort_required",
            )

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
