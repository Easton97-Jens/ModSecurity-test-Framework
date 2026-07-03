import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
import types
from pathlib import Path

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
        queue = load_module("ci/generate-connector-work-queue.py", "connector_queue_test")
        self.assertFalse(queue.is_with_mrts_detection_only_non_disruptive("with-mrts", "FAIL", 401, 200, "intervention_blocking"))
        self.assertEqual(queue.NO_MRTS_NOMATCH_BY_CASE["xml_request_body_malformed_connector_gap"]["work_direction"], "xml_processor")
        self.assertEqual(queue.NO_MRTS_NOMATCH_BY_CASE["xml_request_body_malformed_connector_gap"]["priority"], "P2")

    def test_bounded_run_log_reader_rejects_symlink_escape_and_oversize(self):
        report = load_module("ci/generate-mrts-native-report.py", "mrts_native_report_test")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "native"
            root.mkdir()
            outside = Path(tmp) / "outside.log"
            outside.write_text("run 1 total tests\n", encoding="utf-8")
            symlink = root / "escape.log"
            symlink.symlink_to(outside)
            self.assertEqual(report.read_bounded_run_log(symlink, [root]), "")
            huge = root / "huge.log"
            huge.write_bytes(b"x" * (report.MAX_RUN_LOG_BYTES + 1))
            self.assertEqual(report.read_bounded_run_log(huge, [root]), "")
            ok = root / "ok.log"
            ok.write_text("run 1 total tests\npassed in 1s\n", encoding="utf-8")
            self.assertIn("run 1", report.read_bounded_run_log(ok, [root]))

    def test_nginx_overlay_listens_on_loopback_only(self):
        config = (ROOT / "tests/mrts/infra-overlays/nginx-pr24/infra/sites-available/default").read_text(encoding="utf-8")
        self.assertIn("listen 127.0.0.1:80 default_server;", config)
        self.assertIn("listen [::1]:80 default_server;", config)
        self.assertNotIn("listen 80 default_server;", config)
        self.assertNotIn("listen [::]:80 default_server;", config)

    def test_haproxy_stale_summary_not_reused_without_current_exit_code(self):
        snap = load_module("ci/update-runtime-snapshot.py", "runtime_snapshot_test")
        with tempfile.TemporaryDirectory() as tmp:
            results = Path(tmp) / "results"
            (results / "with-crs").mkdir(parents=True)
            row = snap.haproxy_default_matrix_smoke({}, "make runtime-matrix-haproxy", "not_run", results)
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
. {ROOT}/ci/connector-smoke-common.sh
connector_smoke_run haproxy {harness}
'''
            result = subprocess.run(["sh", "-c", script], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_shared_output_path_confinement_rejects_traversal_and_symlink(self):
        utils = load_module("ci/generated_report_utils.py", "generated_report_utils_test")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "out"
            root.mkdir()
            with self.assertRaises(ValueError):
                utils.require_under(root, "../escape.json", "connector output")
            with self.assertRaises(ValueError):
                utils.require_under(root, Path(tmp) / "escape.json", "phase output")
            outside = Path(tmp) / "outside"
            outside.mkdir()
            link = root / "link"
            link.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                utils.require_under(root, link / "mrts.json", "mrts output")

    def test_makefile_haproxy_targets_exist(self):
        result = subprocess.run(["make", "-n", "runtime-matrix-haproxy", "runtime-matrix-haproxy-all", "smoke-haproxy", "prepare-haproxy-runtime"], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-haproxy-runtime-matrix.sh", result.stdout)
        self.assertIn("run-haproxy-smoke.sh", result.stdout)
        self.assertIn("prepare-haproxy-runtime.sh", result.stdout)


if __name__ == "__main__":
    unittest.main()
