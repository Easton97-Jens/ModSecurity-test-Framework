#!/usr/bin/env python3
"""Regression tests for generated test-matrix report path validation."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = connector_root()
SCRIPT = source_path('ci/checks/documentation/ensure-test-matrix-language-switches.py', root=ROOT)
CHECKER = load_source(SCRIPT)


class EnsureTestMatrixLanguageSwitchesTests(unittest.TestCase):
    def test_regular_in_tree_report_is_selected_and_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative = Path("reports/testing/generated/coverage/report.generated.md")
            report = root / relative
            report.parent.mkdir(parents=True)
            report.write_text("# Report\n\nBody\n", encoding="utf-8")
            report.chmod(0o640)
            with (
                patch.object(CHECKER, "REPOSITORY_ROOT", root),
                patch.object(CHECKER, "GENERATED_TEST_MATRIX_REPORTS", (relative,)),
            ):
                self.assertEqual(report, CHECKER.trusted_report_path(relative))
                self.assertEqual(CHECKER.rewrite_selected_reports(), 1)
            self.assertIn("**Language:** English", report.read_text(encoding="utf-8"))
            self.assertEqual(report.stat().st_mode & 0o777, 0o640)

    def test_switch_rendering_preserves_a_single_current_marker(self) -> None:
        rendered = CHECKER.switched_report_text(
            "# Report\n\n**Language:** stale\n\nBody\n",
            "**Language:** English | [Deutsch](report.de.md)",
            "**Language:**",
        )
        self.assertEqual(
            rendered,
            "# Report\n\n**Language:** English | [Deutsch](report.de.md)\n\nBody\n",
        )

    def test_symlink_report_is_not_selected_or_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "checkout"
            outside = base / "outside.generated.md"
            outside.write_text("# Outside\n", encoding="utf-8")
            relative = Path("reports/testing/generated/coverage/report.generated.md")
            candidate = root / relative
            candidate.parent.mkdir(parents=True)
            candidate.symlink_to(outside)
            with (
                patch.object(CHECKER, "REPOSITORY_ROOT", root),
                patch.object(CHECKER, "GENERATED_TEST_MATRIX_REPORTS", (relative,)),
            ):
                self.assertIsNone(CHECKER.trusted_report_path(relative))
                self.assertEqual(CHECKER.rewrite_selected_reports(), 0)
            self.assertEqual(outside.read_text(encoding="utf-8"), "# Outside\n")

    def test_descriptor_replace_does_not_follow_a_swapped_final_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "checkout"
            outside = base / "outside.generated.md"
            outside.write_text("# Outside\n", encoding="utf-8")
            relative = Path("reports/testing/generated/coverage/report.generated.md")
            candidate = root / relative
            candidate.parent.mkdir(parents=True)
            candidate.symlink_to(outside)
            with patch.object(CHECKER, "REPOSITORY_ROOT", root):
                CHECKER._replace_selected_report(relative, "# Replacement\n", 0o640)
            self.assertEqual(outside.read_text(encoding="utf-8"), "# Outside\n")
            self.assertFalse(candidate.is_symlink())
            self.assertEqual(candidate.read_text(encoding="utf-8"), "# Replacement\n")

    def test_descriptor_replace_rejects_traversal_before_opening_a_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            with patch.object(CHECKER, "REPOSITORY_ROOT", root):
                with self.assertRaises(ValueError):
                    CHECKER._replace_selected_report(Path("../outside.generated.md"), "# Outside\n", 0o640)

    def test_outside_report_is_not_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "checkout"
            outside = base / "outside.generated.md"
            outside.write_text("# Outside\n", encoding="utf-8")
            with (
                patch.object(CHECKER, "REPOSITORY_ROOT", root),
                patch.object(CHECKER, "GENERATED_TEST_MATRIX_REPORTS", (Path("../outside.generated.md"),)),
            ):
                self.assertIsNone(CHECKER.trusted_report_path(Path("../outside.generated.md")))
                self.assertEqual(CHECKER.rewrite_selected_reports(), 0)
            self.assertEqual(outside.read_text(encoding="utf-8"), "# Outside\n")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
