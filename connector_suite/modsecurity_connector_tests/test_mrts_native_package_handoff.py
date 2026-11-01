"""On-demand checks for the Parent's native MRTS package boundary."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from modsecurity_test_framework.connector_context import source_path

SOURCE = source_path("ci/runtime/lifecycle/run-mrts-native-full.sh")


def function_source(name, next_name):
    source = SOURCE.read_text()
    return source[source.index(name + "() {"):source.index(next_name + "() {")]


class MRTSNativePackageHandoffTests(unittest.TestCase):
    def run_shell(self, script, root):
        environment = dict(os.environ)
        environment["MRTS_NATIVE_ROOT"] = str(root)
        return subprocess.run(["sh", "-u", "-c", script], env=environment,
            cwd=root, text=True, capture_output=True, timeout=15)

    def test_failed_preparation_and_failed_writer_return_error(self):
        with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as temporary:
            root = Path(temporary)
            source = SOURCE.read_text()
            functions = source[source.index("run_native_target() {"):source.index("\nhas_fail=0")]
            script = "\n".join([
                functions,
                "safe_remove_runtime_path() { return 0; }",
                "prepare_mrts_outputs() { return 17; }",
                "write_job_json() { return 9; }",
                "MRTS_JOB_STATUS_BLOCKED=BLOCKED",
                "run_native_target apache2_ubuntu",
            ])
            result = self.run_shell(script, root)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertNotIn("PASS", result.stdout)

    def test_failed_generator_does_not_fall_through_to_materialization(self):
        with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as temporary:
            root = Path(temporary)
            stale = root / "old-output"
            stale.write_text("old output")
            script = "\n".join([
                function_source("prepare_mrts_outputs", "patch_common_ftw_config"),
                "mrts_package_command() { return 17; }",
                "MRTS_NATIVE_PACKAGE_READY=0",
                'MRTS_PACKAGE_ROOT="$MRTS_NATIVE_ROOT/old-output"',
                "MODSECURITY_MRTS_PREPARED=0",
                "prepare_mrts_outputs || exit $?",
                'printf "UNEXPECTED SUCCESS\\n"',
            ])
            result = self.run_shell(script, root)
            self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
            self.assertEqual(stale.read_text(), "old output")
            self.assertNotIn("UNEXPECTED SUCCESS", result.stdout)

    def test_enabled_demo_is_included_in_private_native_selection_and_load(self):
        with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as temporary:
            root = Path(temporary)
            for corpus in ("upstream-config-tests", "feature-demo"):
                directory = root / "shared" / corpus / "ftw"
                directory.mkdir(parents=True)
                (directory / "case.yaml").write_text("private request fixture\n")
                (directory.parent / "mrts.load").write_text("private load fixture\n")
            target = root / "native-target"
            target.mkdir()
            script = "\n".join([
                function_source("materialize_mrts_outputs", "patch_common_ftw_config"),
                'mrts_package_command() { cp -R "$MRTS_NATIVE_ROOT/shared" "$MRTS_TARGET_PACKAGE_ROOT"; }',
                "MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1",
                'materialize_mrts_outputs "$MRTS_NATIVE_ROOT/native-target" 19080',
            ])
            result = self.run_shell(script, root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for corpus in ("upstream-config-tests", "feature-demo"):
                self.assertEqual((target / "selected-ftw" / corpus / "case.yaml").read_text(), "private request fixture\n")
                self.assertIn(str(target / "package" / corpus / "mrts.load"), (target / "mrts.load").read_text())
                self.assertEqual((root / "shared" / corpus / "ftw/case.yaml").read_text(), "private request fixture\n")

    def test_apache_single_case_writer_failure_cannot_print_pass(self):
        source = source_path("connectors/apache/harness/run_apache_smoke.sh").read_text()
        final_assertion = source[source.index("set +e\nhttp_status=$(send_case_request)"):]
        with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as temporary:
            root = Path(temporary)
            script = "\n".join([
                'LOG_DIR="$MRTS_NATIVE_ROOT"',
                "send_case_request() { printf 200; }",
                "apache_profile_enabled() { return 1; }",
                "write_case_result() { return 9; }",
                'fail() { printf "apache_smoke: fail %s\\n" "$*"; exit 1; }',
                'PYTHON_BIN=true CASE_CLI=unused TEST_CASE=mrts-case CASE_NAME=mrts-case',
                'RESPONSE_BODY=unused AUDIT_LOG_FILE=unused APACHE_PHASE4_LOG_FILE=unused STATUS_FILE=unused',
                'OBSERVED_TRANSPORT_HTTP_STATUS=http_status EXPECT_STATUS=200',
                final_assertion,
            ])
            result = self.run_shell(script, root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("Apache case result publication failed", result.stdout)
            self.assertNotIn("apache_smoke: pass", result.stdout)


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
