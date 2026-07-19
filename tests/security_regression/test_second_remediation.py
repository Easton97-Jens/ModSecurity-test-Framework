import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
import types
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load_module(path: str, name: str):
    sys.modules.setdefault("yaml", types.SimpleNamespace(safe_load=lambda text: {}))
    for extra in (ROOT / "ci", ROOT / "tests/runners"):
        if str(extra) not in sys.path:
            sys.path.insert(0, str(extra))
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class SecondRemediationTests(unittest.TestCase):
    def test_non_promotable_and_strict_abort_never_verified_pass(self):
        sys.path.insert(0, str(ROOT / "tests/runners"))
        models = load_module("tests/runners/msconnector_models.py", "msconnector_models_test")
        entries = [
            {"status": "pass", "live_executed": True, "capabilities": ["request-headers"], "runtime_classification": "pending"},
            {"status": "pass", "live_executed": True, "capabilities": ["request-body"], "strict_abort": True},
            {"status": "pass", "live_executed": False, "capabilities": ["args"]},
        ]
        self.assertEqual(models.verified_variables(entries), [])

    def test_with_mrts_and_xml_failures_not_report_only(self):
        queue = load_module("ci/reporting/generate-connector-work-queue.py", "connector_queue_test")
        self.assertFalse(queue.is_with_mrts_detection_only_non_disruptive())
        self.assertEqual(queue.NO_MRTS_NOMATCH_BY_CASE["xml_request_body_malformed_connector_gap"]["work_direction"], "xml_processor")
        self.assertEqual(queue.NO_MRTS_NOMATCH_BY_CASE["xml_request_body_malformed_connector_gap"]["priority"], "P2")

    def test_bounded_run_log_reader_rejects_symlink_escape_and_oversize(self):
        report = load_module("ci/reporting/generate-mrts-native-report.py", "mrts_native_report_test")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "native"
            root.mkdir()
            outside = Path(tmp) / "outside.log"
            outside.write_text("run 1 total tests\n", encoding="utf-8")
            self.assertEqual(report.read_bounded_run_log(outside, [root]), "")
            symlink = root / "escape.log"
            symlink.symlink_to(outside)
            self.assertEqual(report.read_bounded_run_log(symlink, [root]), "")
            huge = root / "huge.log"
            huge.write_bytes(b"x" * (report.MAX_RUN_LOG_BYTES + 1))
            self.assertEqual(report.read_bounded_run_log(huge, [root]), "")
            ok = root / "ok.log"
            ok.write_text("run 1 total tests\npassed in 1s\n", encoding="utf-8")
            self.assertIn("run 1", report.read_bounded_run_log(ok, [root]))

    def test_default_state_home_uses_a_private_temporary_directory(self):
        report = load_module("ci/reporting/generate-mrts-native-report.py", "mrts_native_report_state_home_test")
        with tempfile.TemporaryDirectory() as tmp:
            temporary_root = Path(tmp)
            temporary_root.chmod(0o777)
            for variable_name in ("RUNNER_TEMP", "TMPDIR"):
                with self.subTest(variable_name=variable_name):
                    with mock.patch.dict(os.environ, {variable_name: str(temporary_root)}, clear=True):
                        state_home = report.default_state_home()
                    self.assertTrue(state_home.is_dir())
                    self.assertEqual(state_home.parent, temporary_root)
                    self.assertTrue(state_home.name.startswith(report.DEFAULT_STATE_HOME_PREFIX))
                    self.assertEqual(state_home.stat().st_mode & 0o077, 0)

    def test_native_report_paths_redact_external_and_symlink_escapes(self):
        report = load_module("ci/reporting/generate-mrts-native-report.py", "mrts_native_report_paths_test")
        with tempfile.TemporaryDirectory() as tmp:
            temporary_root = Path(tmp)
            native_root = temporary_root / "native"
            native_root.mkdir()
            inside = native_root / "apache2_ubuntu" / report.RUN_LOG_FILENAME
            inside.parent.mkdir()
            inside.write_text("run 1 total tests\n", encoding="utf-8")
            outside = temporary_root / "outside" / "secret.log"
            outside.parent.mkdir()
            outside.write_text("sensitive", encoding="utf-8")
            escape = native_root / "escape"
            escape.symlink_to(outside.parent, target_is_directory=True)

            self.assertEqual(report.display_native_path(inside, native_root), "$MRTS_NATIVE_ROOT/apache2_ubuntu/run.log")
            self.assertEqual(report.display_native_path(outside, native_root), "<external-path-redacted>")
            self.assertEqual(report.display_native_path(escape / outside.name, native_root), "<external-path-redacted>")
            self.assertEqual(
                report.display_component_value(str(outside), [("BUILD_ROOT", native_root)]),
                "<system-path-redacted>/secret.log",
            )

    def test_native_report_output_root_and_symlink_escape_are_rejected(self):
        report = load_module("ci/reporting/generate-mrts-native-report.py", "mrts_native_report_output_test")
        framework_lib = ROOT / "ci/lib"
        if str(framework_lib) not in sys.path:
            sys.path.insert(0, str(framework_lib))
        with tempfile.TemporaryDirectory() as tmp:
            temporary_root = Path(tmp)
            framework_root = temporary_root / "framework"
            connector_root = temporary_root / "connector"
            native_root = temporary_root / "native"
            outside_root = temporary_root / "outside"
            for root in (framework_root, connector_root, native_root, outside_root):
                root.mkdir()
            base_argv = [
                "generate-mrts-native-report.py",
                "--framework-root",
                str(framework_root),
                "--connector-root",
                str(connector_root),
                "--native-root",
                str(native_root),
            ]
            with mock.patch.object(sys, "argv", base_argv):
                self.assertEqual(report.main(), 0)

            output_directory = connector_root / "reports/testing/generated/canonical"
            expected_outputs = {
                "mrts_native_full.generated.json",
                "mrts_native_full.generated.md",
                "mrts_native_apache.generated.json",
                "mrts_native_apache.generated.md",
                "mrts_native_nginx.generated.json",
                "mrts_native_nginx.generated.md",
                "mrts_native_summary.generated.json",
                "mrts_native_summary.generated.md",
            }
            self.assertEqual({path.name for path in output_directory.iterdir()}, expected_outputs)

            output_directory.chmod(0o777)
            protected_full_report = output_directory / "mrts_native_full.generated.json"
            protected_full_report.unlink()
            outside_file = outside_root / "outside.json"
            outside_file.write_text("unchanged", encoding="utf-8")
            protected_full_report.symlink_to(outside_file)
            report.write_generated_report_file(output_directory, protected_full_report.name, "safe replacement\n")
            self.assertFalse(protected_full_report.is_symlink())
            self.assertEqual(protected_full_report.read_text(encoding="utf-8"), "safe replacement\n")
            self.assertEqual(protected_full_report.stat().st_mode & 0o077, 0)
            self.assertEqual(outside_file.read_text(encoding="utf-8"), "unchanged")

            with mock.patch.object(sys, "argv", [*base_argv, "--output-root", str(outside_root)]):
                with self.assertRaises(ValueError):
                    report.main()
            self.assertFalse((outside_root / "reports").exists())

            protected_output = output_directory / "mrts_native_summary.generated.json"
            protected_output.unlink()
            protected_output.symlink_to(outside_file)
            with mock.patch.object(sys, "argv", base_argv):
                with self.assertRaises(ValueError):
                    report.main()
            self.assertEqual(outside_file.read_text(encoding="utf-8"), "unchanged")

    def test_nginx_overlay_listens_on_loopback_only(self):
        config = (ROOT / "tests/mrts/infra-overlays/nginx-pr24/infra/sites-available/default").read_text(encoding="utf-8")
        self.assertIn("listen 127.0.0.1:80 default_server;", config)
        self.assertIn("listen [::1]:80 default_server;", config)
        self.assertNotIn("listen 80 default_server;", config)
        self.assertNotIn("listen [::]:80 default_server;", config)

    def test_haproxy_stale_summary_not_reused_without_current_exit_code(self):
        snap = load_module("ci/reporting/update-runtime-snapshot.py", "runtime_snapshot_test")
        with tempfile.TemporaryDirectory() as tmp:
            results = Path(tmp) / "results"
            (results / "with-crs").mkdir(parents=True)
            row = snap.haproxy_default_matrix_smoke("make runtime-matrix-haproxy", "not_run", results)
            self.assertEqual(row["status"], "NOT_AVAILABLE")
            self.assertEqual(row["connector"], "haproxy")

    def test_run_one_case_rejects_unverified_pass_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            harness = tmp_path / "harness.sh"
            log = tmp_path / "logs"
            log.mkdir()
            (log / "result.json").write_text(json.dumps({"connector": "haproxy", "status": "pass", "name": "case-a"}), encoding="utf-8")
            harness.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            harness.chmod(0o755)
            script = f'''
CONNECTOR_SMOKE_SCRIPT_DIR={ROOT}/ci
FRAMEWORK_ROOT={ROOT}
CONNECTOR_ROOT={tmp_path}
BUILD_ROOT={tmp_path}/build
SOURCE_ROOT={tmp_path}/src
TMP_ROOT={tmp_path}/build/tmp
LOG_ROOT={tmp_path}/build/logs
RESULTS_DIR={tmp_path}/results
LOG_DIR={log}
RUN_ONE_CASE=1
TEST_CASE=case-a
mkdir -p "$CONNECTOR_ROOT/connectors/haproxy" "$BUILD_ROOT" "$SOURCE_ROOT" "$TMP_ROOT" "$LOG_ROOT" "$RESULTS_DIR"
. {ROOT}/ci/lib/connector-smoke-common.sh
connector_smoke_run haproxy {harness}
'''
            result = subprocess.run(["sh", "-c", script], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_shared_output_path_confinement_rejects_traversal_and_symlink(self):
        utils = load_module("ci/lib/generated_report_utils.py", "generated_report_utils_test")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "out"
            root.mkdir()
            traversal_candidate = "../escape.json"
            with self.assertRaises(ValueError):
                utils.require_under(root, traversal_candidate, "connector output")
            absolute_escape = Path(tmp) / "escape.json"
            with self.assertRaises(ValueError):
                utils.require_under(root, absolute_escape, "phase output")
            outside = Path(tmp) / "outside"
            outside.mkdir()
            link = root / "link"
            link.symlink_to(outside, target_is_directory=True)
            symlink_escape = link / "mrts.json"
            with self.assertRaises(ValueError):
                utils.require_under(root, symlink_escape, "mrts output")

    def test_connector_work_queue_matrix_input_and_output_paths_are_confined(self):
        utils = load_module("ci/lib/generated_report_utils.py", "generated_report_utils_connector_queue_test")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            connector_root = tmp_path / "connector"
            connector_root.mkdir()
            output_root = tmp_path / "output"
            output_root.mkdir()
            outside = tmp_path / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                utils.trusted_root(connector_root / ".." / "connector", "connector root")
            with self.assertRaises(ValueError):
                utils.resolve_full_runtime_matrix_input(connector_root, outside)
            output_dir = utils.generated_report_dir(output_root)
            json_path = utils.connector_work_queue_output_path(output_dir, "json")
            md_path = utils.connector_work_queue_output_path(output_dir, "md")
            self.assertTrue(str(json_path).startswith(str(output_root.resolve())))
            self.assertTrue(str(md_path).startswith(str(output_root.resolve())))
            self.assertEqual(utils.metadata_path_label(utils.resolve_full_runtime_matrix_input(connector_root, None), connector_root, "$CONNECTOR_ROOT"), "$CONNECTOR_ROOT/reports/testing/generated/canonical/full-runtime-matrix.generated.json")

    def test_makefile_haproxy_targets_exist(self):
        result = subprocess.run(["make", "-n", "runtime-matrix-haproxy", "runtime-matrix-haproxy-all", "smoke-haproxy", "prepare-haproxy-runtime"], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-haproxy-runtime-matrix.sh", result.stdout)
        self.assertIn("run-haproxy-smoke.sh", result.stdout)
        self.assertIn("prepare-haproxy-runtime.sh", result.stdout)


if __name__ == "__main__":
    unittest.main()
