"""Tests for the source-backed logical connector example matrix."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import tempfile
import unittest
from pathlib import Path
from shutil import copytree


ROOT = connector_root()
CHECKER_PATH = source_path('ci/checks/documentation/check-logical-connector-example-matrix.py', root=ROOT)
CHECKER = load_source(CHECKER_PATH)


class LogicalConnectorExampleMatrixTests(unittest.TestCase):
    def test_repository_has_all_profiles_and_variants(self) -> None:
        self.assertEqual(CHECKER.logical_connector_example_errors(ROOT), [])

    def test_missing_companion_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copytree(source_path('examples', root=ROOT), root / "examples")
            (root / "examples/haproxy/spoe-spop/minimal/spoa-agent.conf").unlink()
            errors = CHECKER.logical_connector_example_errors(root)
            matching_errors = [error for error in errors if "haproxy-spoe-spop/minimal" in error]
            self.assertEqual(len(matching_errors), 1)
            self.assertIn("spoa-agent.conf", matching_errors[0])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
