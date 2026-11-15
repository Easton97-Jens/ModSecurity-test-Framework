"""Exercise C-standards temporary output with the read-only runner contract."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from modsecurity_test_framework.connector_context import connector_root, source_path, test_root


ROOT = connector_root()
CHECK = source_path("ci/checks/connectors/all/check-remaining-connectors-c-standards.sh", root=ROOT)


class RemainingConnectorsCStandardTempTests(unittest.TestCase):
    def run_check(
        self,
        *,
        runner_temp: str | None,
        tmpdir: str | None,
        compiler_status: int = 0,
    ) -> tuple[subprocess.CompletedProcess[str], list[str], list[str]]:
        with tempfile.TemporaryDirectory(prefix="remaining-c-standard-temp-") as raw:
            root = Path(raw)
            for name in ("runner", "private-tmp"):
                (root / name).mkdir()
            compiler = root / "cc"
            compiler.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$@" >> "$CC_TRACE"\nexit "$CC_STATUS"\n',
                encoding="utf-8",
            )
            compiler.chmod(0o700)
            trace = root / "compiler-arguments"
            environment = os.environ.copy()
            environment.pop("RUNNER_TEMP", None)
            environment.pop("TMPDIR", None)
            for key, value in (("RUNNER_TEMP", runner_temp), ("TMPDIR", tmpdir)):
                if value is not None:
                    environment[key] = str(root / value) if value else ""
            environment.update(
                CC=str(compiler),
                CC_TRACE=str(trace),
                CC_STATUS=str(compiler_status),
                CONNECTOR_C_STD_PROFILE="c17",
                CONNECTOR_ROOT=str(ROOT),
                TEST_ROOT=str(test_root()),
            )
            result = subprocess.run(
                ["/bin/sh", str(CHECK)], cwd=ROOT, env=environment,
                capture_output=True, text=True, check=False,
            )
            arguments = trace.read_text(encoding="utf-8").splitlines() if trace.exists() else []
            output_paths = [
                Path(arguments[index + 1]).relative_to(root).as_posix()
                for index, argument in enumerate(arguments[:-1]) if argument == "-o"
            ]
            retained = [
                path.relative_to(root).as_posix()
                for name in ("runner", "private-tmp") for path in (root / name).iterdir()
            ]
            return result, output_paths, retained

    def assert_success(self, runner_temp: str | None, tmpdir: str | None, parent: str) -> None:
        result, outputs, retained = self.run_check(runner_temp=runner_temp, tmpdir=tmpdir)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS: remaining connectors C standard check (c17)", result.stdout)
        self.assertTrue(outputs)
        self.assertTrue(all(path.startswith(parent + "/") for path in outputs), outputs)
        self.assertEqual(retained, [])

    def test_private_namespace_tmpdir_without_runner_temp(self) -> None:
        self.assert_success(None, "private-tmp", "private-tmp")

    def test_existing_runner_temp_contract_without_tmpdir(self) -> None:
        self.assert_success("runner", None, "runner")

    def test_runner_temp_retains_precedence(self) -> None:
        self.assert_success("runner", "private-tmp", "runner")

    def test_missing_explicit_parents_prevent_compilation(self) -> None:
        result, outputs, retained = self.run_check(runner_temp=None, tmpdir=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outputs, [])
        self.assertEqual(retained, [])

    def test_empty_runner_temp_is_not_replaced_by_tmpdir(self) -> None:
        result, outputs, retained = self.run_check(runner_temp="", tmpdir="private-tmp")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outputs, [])
        self.assertEqual(retained, [])

    def test_nonexistent_runner_temp_is_not_replaced_by_tmpdir(self) -> None:
        result, outputs, retained = self.run_check(runner_temp="missing", tmpdir="private-tmp")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outputs, [])
        self.assertEqual(retained, [])

    def test_compile_failure_remains_failure_and_cleans_private_output(self) -> None:
        result, outputs, retained = self.run_check(
            runner_temp=None, tmpdir="private-tmp", compiler_status=23,
        )
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertTrue(outputs)
        self.assertEqual(retained, [])


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
