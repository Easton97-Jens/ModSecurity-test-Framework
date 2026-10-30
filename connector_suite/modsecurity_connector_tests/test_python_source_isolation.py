"""Candidate checkout files cannot become Framework or stdlib bootstrap code."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from modsecurity_test_framework.connector_context import connector_root, test_root, load_source, source_path, ContextError


class PythonSourceIsolationTests(unittest.TestCase):
    def test_absent_legacy_source_uses_only_the_reviewed_migration_map(self):
        before = tuple(sys.path)
        logical = "tests/c_source_contract.py"
        self.assertFalse((connector_root() / logical).exists())
        module = load_source(connector_root() / logical)
        self.assertEqual(Path(module.__file__), source_path(logical))
        self.assertTrue(module.__name__.startswith("modsecurity_connector_tests."))
        self.assertEqual(tuple(sys.path), before)
        unreviewed_source = connector_root() / "not-a-reviewed-moved-source.py"
        with self.assertRaises(ContextError):
            load_source(unreviewed_source)

    def environment(self, candidate, *, legacy=False):
        framework = test_root()
        roots = [str(framework), str(framework / "connector_suite")]
        if legacy:
            roots.append(str(candidate))
        return {**os.environ, "PYTHONPATH": os.pathsep.join(roots), "PYTHONSAFEPATH": "1"}

    def test_candidate_standard_library_name_is_not_a_bootstrap_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary)
            (candidate / "json.py").write_text("raise RuntimeError('UNADMITTED_JSON_SOURCE')\n")
            command = [sys.executable, "-P", "-c", "import json; print(json.__file__)"]
            before = subprocess.run(command, cwd=candidate, env=self.environment(candidate, legacy=True),
                                    capture_output=True, text=True)
            self.assertNotEqual(before.returncode, 0)
            self.assertIn("UNADMITTED_JSON_SOURCE", before.stderr)
            after = subprocess.run(command, cwd=candidate, env=self.environment(candidate),
                                   capture_output=True, text=True)
            self.assertEqual(after.returncode, 0, after.stderr)
            self.assertFalse(Path(after.stdout.strip()).is_relative_to(candidate))

    def test_unsafe_current_directory_is_not_a_test_package_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary)
            package = candidate / "modsecurity_connector_ci"
            package.mkdir()
            (package / "__init__.py").write_text("raise RuntimeError('UNADMITTED_TEST_SOURCE')\n")
            code = "import modsecurity_connector_ci; print(modsecurity_connector_ci.__file__)"
            before_env = self.environment(candidate)
            before_env.pop("PYTHONSAFEPATH")
            before = subprocess.run([sys.executable, "-c", code], cwd=candidate, env=before_env,
                                    capture_output=True, text=True)
            self.assertNotEqual(before.returncode, 0)
            self.assertIn("UNADMITTED_TEST_SOURCE", before.stderr)
            after = subprocess.run([sys.executable, "-P", "-c", code], cwd=candidate,
                                   env=self.environment(candidate), capture_output=True, text=True)
            self.assertEqual(after.returncode, 0, after.stderr)
            self.assertTrue(Path(after.stdout.strip()).is_relative_to(test_root()))

    def test_framework_infrastructure_is_a_regular_owned_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary)
            package = candidate / "modsecurity_connector_ci"
            package.mkdir()
            (package / "__init__.py").write_text("raise RuntimeError('FOREIGN_REGULAR_PACKAGE')\n")
            completed = subprocess.run(
                [sys.executable, "-P", "-c", "import modsecurity_connector_ci; print(modsecurity_connector_ci.__file__)"],
                cwd=test_root(), env=self.environment(candidate, legacy=True), capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(Path(completed.stdout.strip()).is_relative_to(test_root()))


def load_tests(loader, standard_tests, pattern):
    return standard_tests if os.environ.get("ON_DEMAND_TESTS") == "1" else unittest.TestSuite()
