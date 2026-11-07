"""Contract coverage for Apache Framework case-output containment."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import json
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
        self.assertEqual(source.count('--output-root "$APACHE_CASE_OUTPUT_ROOT"'), 4)

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

    def context_helper(self) -> str:
        source = HARNESS.read_text(encoding="utf-8")
        start = source.index("preflight_apache_execution_context() {")
        end = source.index("\napache_profile_enabled() {", start)
        return source[start:end]

    def run_context_helper(self, root: Path, python: str) -> subprocess.CompletedProcess[str]:
        runtime, logs = root / "runtime", root / "logs"
        runtime.mkdir(mode=0o700)
        logs.mkdir(mode=0o700)
        environment = dict(os.environ, PYTHON_BIN=python, RUNTIME_ROOT=str(runtime), LOG_DIR=str(logs),
                           HOST_SENTINEL=str(root / "host-started"))
        runner = "set -e\n" + self.context_helper() + '\npreflight_apache_execution_context\nprintf started > "$HOST_SENTINEL"\n'
        return subprocess.run(["sh", "-c", runner], env=environment, capture_output=True, text=True, check=False)

    def test_native_execution_preflight_records_actual_launcher_identity_before_host(self) -> None:
        with tempfile.TemporaryDirectory(prefix="apache-context-pass-") as temporary:
            root = Path(temporary)
            result = self.run_context_helper(root, sys.executable)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"execution-context PASS uid={os.geteuid()} gid={os.getegid()}", result.stdout)
            reports = list((root / "runtime").glob("execution-context-*/status.json"))
            self.assertEqual(len(reports), 1)
            report = json.loads(reports[0].read_text())
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["execution_context"]["observed_worker"]["uid"], list(os.getresuid()))
            self.assertEqual(report["execution_context"]["observed_worker"]["gid"], list(os.getresgid()))
            self.assertTrue((root / "host-started").is_file())
            self.assertNotIn("--worker-", self.context_helper())
            self.assertNotIn("--require-root-master", self.context_helper())
            source = HARNESS.read_text()
            self.assertIn('preflight_apache_execution_context || blocked "Apache launcher execution-context preflight failed; no host started"\nstart_server', source)

    def test_failed_or_nonpass_native_preflight_never_reaches_host_start(self) -> None:
        for native_exit in (77, 0):
            with self.subTest(native_exit=native_exit), tempfile.TemporaryDirectory(prefix="apache-context-fail-") as temporary:
                root = Path(temporary)
                wrapper = root / "native-preflight-control.py"
                wrapper.write_text(
                    "#!" + sys.executable + "\n"
                    "import json, os, pathlib, sys\n"
                    "if '-m' not in sys.argv: os.execv(sys.executable, [sys.executable, *sys.argv[1:]])\n"
                    "pathlib.Path(os.environ['HOST_SENTINEL'] + '.invocation').write_text(json.dumps(sys.argv[1:]))\n"
                    "target = pathlib.Path(sys.argv[sys.argv.index('--output-dir') + 1])\n"
                    "target.mkdir(mode=0o700)\n"
                    "(target / 'status.json').write_text(json.dumps({'status': 'BLOCKED'}))\n"
                    f"raise SystemExit({native_exit})\n"
                )
                wrapper.chmod(0o700)
                result = self.run_context_helper(root, str(wrapper))
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertFalse((root / "host-started").exists())
                invocation = json.loads((root / "host-started.invocation").read_text())
                self.assertIn("--execution-context-only", invocation)
                self.assertNotIn("--worker-user", invocation)
                self.assertNotIn("execution-context PASS", result.stdout)

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
