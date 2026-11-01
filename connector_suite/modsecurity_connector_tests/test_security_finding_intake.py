"""Consistency checks for the source-ID intake; not security verification."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
from pathlib import Path
import unittest

ROOT = connector_root()
INTAKE = source_path('reports/audits/findings/20260929-intake.json', root=ROOT)


class FindingIntakeTests(unittest.TestCase):
    def test_originals_are_preserved_once_and_dedupe_is_complete(self) -> None:
        intake = json.loads(INTAKE.read_text(encoding="utf-8"))
        rows = intake["originals"]
        expected = {
            f"{prefix}{number:02}"
            for prefix, count in (("A", 21), ("B", 27), ("C", 24))
            for number in range(1, count + 1)
        }
        aliases = [row["alias"] for row in rows]
        self.assertEqual(len(aliases), len(set(aliases)))
        self.assertEqual(set(aliases), expected)
        self.assertEqual(len(rows), intake["source_counts"]["original"])
        mapped = {key for row in rows for key in row["work_items"]}
        self.assertEqual(mapped, set(intake["canonical_work_items"]))
        self.assertEqual(len(mapped), intake["source_counts"]["work_items"])
        self.assertEqual(len(mapped), 59)
        self.assertTrue(all(row["source_id"] for row in rows))
        self.assertTrue(all(row["reported_severity"] in
                            {"high", "medium", "low", "informational"} for row in rows))
        by_alias = {row["alias"]: row for row in rows}
        self.assertEqual(by_alias["A08"]["work_items"], ["B01", "B15"])
        self.assertEqual(by_alias["C20"]["work_items"], ["C19"])

    def test_intake_does_not_claim_unperformed_verification(self) -> None:
        intake = json.loads(INTAKE.read_text(encoding="utf-8"))
        self.assertEqual(set(intake["parent_changes"]), {"B09"})
        self.assertEqual(intake["parent_changes"]["B09"]["implementation"],
                         "candidate_patch")
        self.assertEqual(intake["parent_changes"]["B09"]["verification"], "pending")
        self.assertIn("not_changed_in_this_draft", intake["remaining_work_items"])
        self.assertIn("MRTS root cause unchanged", intake["external_work"]["B03"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
