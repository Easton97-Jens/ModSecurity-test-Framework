"""Contract coverage for Apache Framework case-output containment."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import os
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()
HARNESS = source_path('connectors/apache/harness/run_apache_smoke.sh', root=ROOT)
LIFECYCLE = source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)


class ApacheSmokeCaseOutputRootTest(unittest.TestCase):
    def test_harness_passes_one_explicit_output_root_to_each_framework_case_writer(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn('APACHE_CASE_OUTPUT_ROOT="${APACHE_CASE_OUTPUT_ROOT:-$BUILD_ROOT}"', source)
        self.assertIn(
            'require_absolute_generated_path "$APACHE_CASE_OUTPUT_ROOT" "APACHE_CASE_OUTPUT_ROOT"',
            source,
        )
        self.assertEqual(source.count('--output-root "$APACHE_CASE_OUTPUT_ROOT"'), 3)

    def test_generated_directories_are_private_owned_and_symlink_free(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn("prepare_runtime_directory() {", source)
        self.assertIn('"$PYTHON_BIN" "$APACHE_PROCESS_GUARD" prepare-directory', source)
        self.assertIn('MSCONNECTOR_APACHE_GUARD_DIRECTORY="$directory"', source)
        self.assertIn('export MSCONNECTOR_APACHE_GUARD_ARTIFACT_ROOT="$RUNTIME_ROOT"', source)
        self.assertIn("--private", source)
        self.assertNotIn("--directory", source)
        self.assertNotIn("--artifact-root", source)
        self.assertNotIn("mkdir -p", source)
        for invocation in (
            'prepare_runtime_directory "$RUNTIME_ROOT" "RUNTIME_ROOT" 1',
            'prepare_runtime_directory "$RUNTIME_ROOT/conf" "Apache runtime conf" 1',
            'prepare_runtime_directory "$RUNTIME_ROOT/logs" "Apache runtime logs" 1',
            'prepare_runtime_directory "$RUNTIME_ROOT/run" "Apache runtime state" 1',
            'prepare_runtime_directory "$RUNTIME_ROOT/modules" "Apache runtime modules" 1',
            'prepare_runtime_directory "$LOG_DIR" "$APACHE_LOG_DIR_LABEL" 1',
        ):
            self.assertIn(invocation, source)

    def test_runtime_directory_helper_rejects_symlink_and_accepts_private_path(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        start = source.index("prepare_runtime_directory() {")
        end = source.index("\n\nprepare_runtime_directory \"$LOG_DIR\"", start)
        helper = source[start:end]
        runner = "set -e\n" + helper + '\nprepare_runtime_directory "$1" "test runtime path" 1\n'
        environment = os.environ.copy()
        environment["PYTHON_BIN"] = sys.executable
        environment["APACHE_PROCESS_GUARD"] = str(
            source_path('connectors/apache/harness/apache_process_guard.py', root=ROOT)
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            symlink = root / "link"
            symlink.symlink_to(outside, target_is_directory=True)
            rejected = subprocess.run(
                ["sh", "-c", runner, "runtime-directory-test", str(symlink / "nested")],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse((outside / "nested").exists())

            accepted = root / "private" / "nested"
            completed = subprocess.run(
                ["sh", "-c", runner, "runtime-directory-test", str(accepted)],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(accepted.is_dir())
            self.assertFalse(accepted.is_symlink())
            self.assertEqual(stat.S_IMODE(accepted.stat().st_mode), 0o700)

    def test_no_crs_lifecycle_keeps_apache_case_outputs_inside_host_runtime(self) -> None:
        source = LIFECYCLE.read_text(encoding="utf-8")
        self.assertIn(
            'APACHE_RUNTIME_LOG_DIR="$HOST_RUNTIME_ROOT/apache-runtime"',
            source,
        )
        self.assertIn('APACHE_CASE_OUTPUT_ROOT="$HOST_RUNTIME_ROOT"', source)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
