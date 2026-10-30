"""Subprocess-only tests for the Python interpreter identity checker."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()
CHECKER_PATH = source_path('ci/checks/common/check-python-interpreter-contract.py', root=ROOT)


class PythonInterpreterContractTest(unittest.TestCase):
    def temporary_root(self) -> tempfile.TemporaryDirectory[str]:
        return tempfile.TemporaryDirectory(prefix="python-interpreter-contract-")

    def checker_environment(self, root: Path) -> dict[str, str]:
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for command in ("python", "python3"):
            os.symlink(sys.executable, bin_dir / command)
        environment = os.environ.copy()
        environment["PATH"] = f"{bin_dir}{os.pathsep}{environment.get('PATH', '')}"
        environment["PYTHONNOUSERSITE"] = "1"
        return environment

    def run_checker(
        self,
        root: Path,
        arguments: list[str],
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER_PATH), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            cwd=root,
        )

    def test_available_host_python_and_expected_path_are_validated_safely(self) -> None:
        with self.temporary_root() as directory:
            root = Path(directory)
            version_file = root / ".python-version"
            version_file.write_text("3.15.6\n", encoding="utf-8")
            completed = self.run_checker(
                root,
                [
                    "--version-file",
                    ".python-version",
                    "--expected-python",
                    sys.executable,
                    "--json",
                ],
                self.checker_environment(root),
            )
        self.assertEqual(completed.returncode, 1)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "violations")
        self.assertTrue(
            any("current sys.version" in violation for violation in payload["violations"]),
            payload,
        )
        self.assertFalse(
            any(
                "--expected-python is" in violation
                or "--expected-python runs" in violation
                for violation in payload["violations"]
            ),
            payload,
        )
        self.assertFalse(
            any(" -m pip --version" in violation for violation in payload["violations"]),
            payload,
        )

    def test_fake_expected_python_path_is_rejected_without_execution(self) -> None:
        with self.temporary_root() as directory:
            root = Path(directory)
            version_file = root / ".python-version"
            version_file.write_text("3.15.6\n", encoding="utf-8")
            completed = self.run_checker(
                root,
                [
                    "--version-file",
                    ".python-version",
                    "--expected-python",
                    str(root / "missing-python"),
                    "--json",
                ],
                self.checker_environment(root),
            )
        self.assertEqual(completed.returncode, 1)
        payload = json.loads(completed.stdout)
        self.assertTrue(
            any("--expected-python is not a regular file" in violation for violation in payload["violations"]),
            payload,
        )

    def test_malformed_candidate_version_is_an_invocation_error(self) -> None:
        with self.temporary_root() as directory:
            root = Path(directory)
            completed = self.run_checker(
                root,
                [
                    "--expected-version",
                    "3.15",
                    "--expected-python",
                    sys.executable,
                    "--json",
                ],
                self.checker_environment(root),
            )
        self.assertEqual(completed.returncode, 2)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "error")
        self.assertIn("exact Python 3.15.N", payload["violations"][0])

    def test_non_ascii_candidate_version_is_an_invocation_error(self) -> None:
        with self.temporary_root() as directory:
            root = Path(directory)
            completed = self.run_checker(
                root,
                [
                    "--expected-version",
                    "3.15.\u0661",
                    "--expected-python",
                    sys.executable,
                    "--json",
                ],
                self.checker_environment(root),
            )
        self.assertEqual(completed.returncode, 2)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "error")
        self.assertIn("exact Python 3.15.N", payload["violations"][0])

    def test_candidate_version_and_version_file_are_mutually_exclusive(self) -> None:
        with self.temporary_root() as directory:
            root = Path(directory)
            version_file = root / ".python-version"
            version_file.write_text("3.15.6\n", encoding="utf-8")
            completed = self.run_checker(
                root,
                [
                    "--version-file",
                    ".python-version",
                    "--expected-version",
                    "3.15.6",
                ],
                self.checker_environment(root),
            )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("not allowed with argument", completed.stderr)

    def test_noncanonical_version_file_is_rejected_before_any_file_read(self) -> None:
        with self.temporary_root() as directory:
            root = Path(directory)
            (root / ".python-version").write_text("3.15.6\n", encoding="utf-8")
            completed = self.run_checker(
                root,
                ["--version-file", "/dev/null", "--json"],
                self.checker_environment(root),
            )

        self.assertEqual(completed.returncode, 2)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "error")
        self.assertIn("literal .python-version", payload["violations"][0])

    def test_foreign_expected_executable_is_not_invoked(self) -> None:
        with self.temporary_root() as directory:
            root = Path(directory)
            (root / ".python-version").write_text("3.15.6\n", encoding="utf-8")
            marker = root / "unexpected-execution"
            foreign = root / "foreign-python"
            foreign.write_text(
                f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n",
                encoding="utf-8",
            )
            foreign.chmod(0o755)
            completed = self.run_checker(
                root,
                [
                    "--version-file",
                    ".python-version",
                    "--expected-python",
                    str(foreign),
                    "--json",
                ],
                self.checker_environment(root),
            )
            marker_was_created = marker.exists()

        self.assertEqual(completed.returncode, 1)
        payload = json.loads(completed.stdout)
        self.assertTrue(
            any("--expected-python is" in violation for violation in payload["violations"]),
            payload,
        )
        self.assertFalse(marker_was_created)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
