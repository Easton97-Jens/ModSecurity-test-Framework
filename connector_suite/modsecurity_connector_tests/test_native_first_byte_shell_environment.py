"""First-byte shell orchestration doubles; no native connector executes."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = connector_root()
SCRIPT = source_path('ci/runtime/lifecycle/run-native-first-byte.sh', root=ROOT)


class FirstByteShellEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.parent = self.root / "parent with spaces"
        self.framework = self.root / "framework with spaces"
        upstream = self.framework / "tests/runners/synchronized_upstream.py"
        upstream.parent.mkdir(parents=True)
        upstream.write_text("# Recording fixture only; never invoked.\n")
        wrapper = self.parent / "ci/provisioning/cache/with-runtime-components.sh"
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text('#!/bin/sh\n"$PYTHON" - "$@" <<\'PY\'\n'
                           "import json, os, sys\nfrom pathlib import Path\n"
                           "Path(os.environ['UNIT_WRAPPER']).write_text(json.dumps(sys.argv[1:]))\n"
                           'PY\nexec "$@"\n')
        wrapper.chmod(0o700)
        validator = self.parent / "ci/runtime/common/validate-nginx-harness-paths.py"
        validator.parent.mkdir(parents=True)
        validator.write_text("import json, os, sys\nfrom pathlib import Path\n"
                             "Path(os.environ['UNIT_VALIDATOR']).write_text(json.dumps(sys.argv))\n"
                             "sys.exit(int(os.environ.get('UNIT_VALIDATOR_EXIT', '0')))\n")
        self.env = dict(os.environ, CONNECTOR_ROOT=str(self.parent),
                        FRAMEWORK_ROOT=str(self.framework), PYTHON=os.sys.executable,
                        VERIFIED_RUN_ROOT=str(self.root), BUILD_ROOT=str(self.root / "build"),
                        RESULTS_DIR=str(self.root / "results"), HOST_RUNTIME_ROOT=str(self.root / "host"),
                        NO_CRS_RULES_FILE=str(self.root / "rules with spaces.conf"),
                        FULL_LIFECYCLE_EVIDENCE_OUTPUT=str(self.root / "barrier.json"),
                        SYNCHRONIZED_UPSTREAM_CONTROL_ROOT=str(self.root / "control"),
                        NGINX_DOCROOT_PROJECTION_PARENT=str(self.root / "projections"),
                        NGINX_DOCROOT_PROJECTION_ROOT=str(self.root / "projections/batch-seed"),
                        UNIT_CAPTURE=str(self.root / "capture.json"),
                        UNIT_WRAPPER=str(self.root / "wrapper.json"),
                        UNIT_VALIDATOR=str(self.root / "validator.json"), CDPATH=str(self.framework))

    def harness(self, connector):
        harness = self.parent / f"connectors/{connector}/harness/run_{connector}_smoke.sh"
        harness.parent.mkdir(parents=True)
        harness.write_text('#!/bin/sh\n"$PYTHON" - "$@" <<\'PY\'\n'
                           "import json, os, sys\nfrom pathlib import Path\n"
                           "Path(os.environ['UNIT_CAPTURE']).write_text(json.dumps({'argv': sys.argv[1:], 'env': dict(os.environ)}))\n"
                           'PY\nexit "${UNIT_HARNESS_EXIT:-23}"\n')
        harness.chmod(0o700)
        return harness

    def run_script(self, connector):
        return subprocess.run(["rtk", "proxy", "sh", str(SCRIPT), connector],
                              env=self.env, capture_output=True, text=True, timeout=10)

    def test_recording_apache_boundary_preserves_environment_paths_and_exit(self):
        harness = self.harness("apache")
        result = self.run_script("apache")
        self.assertEqual(result.returncode, 23, result.stderr)
        actual = json.loads((self.root / "capture.json").read_text())
        self.assertEqual(actual["argv"], [])
        env = actual["env"]
        for key in ("CONNECTOR_ROOT", "FRAMEWORK_ROOT", "BUILD_ROOT", "NO_CRS_RULES_FILE",
                    "FULL_LIFECYCLE_EVIDENCE_OUTPUT", "RESULTS_DIR"):
            self.assertEqual(env[key], self.env[key])
        self.assertEqual(env["MODSECURITY_RULE_PREAMBLE_FILE"], self.env["NO_CRS_RULES_FILE"])
        self.assertEqual(env["TEST_CASE"], str(self.framework / "tests/cases/no-crs-baseline/full-lifecycle/phase4_first_byte_before_response_end.yaml"))
        self.assertEqual(env["RUNTIME_COMPONENT_TARGET"], "apache")
        self.assertEqual(env["PORT"], "19280")
        self.assertEqual(env["RUNTIME_ROOT"], str(self.root / "host/first-byte-apache"))
        self.assertEqual(env["LOG_DIR"], str(self.root / "host/apache-first-byte-logs"))
        self.assertEqual(env["SYNCHRONIZED_UPSTREAM_CONTROL_ROOT"], str(self.root / "control"))
        wrapper_args = json.loads((self.root / "wrapper.json").read_text())
        self.assertEqual(wrapper_args[0], "env")
        self.assertEqual(wrapper_args[-1], str(harness))
        self.assertIn("MODSECURITY_RULE_PREAMBLE_FILE=" + self.env["NO_CRS_RULES_FILE"], wrapper_args)
        self.assertFalse((self.root / "results/apache-first-byte-results.jsonl").exists())

    def test_recording_nginx_boundary_retains_safe_mode_and_fresh_projection(self):
        self.harness("nginx")
        result = self.run_script("nginx")
        self.assertEqual(result.returncode, 23, result.stderr)
        actual = json.loads((self.root / "capture.json").read_text())["env"]
        self.assertEqual(actual["RUNTIME_COMPONENT_TARGET"], "nginx")
        self.assertEqual(actual["NGINX_SYNCHRONIZED_PHASE4_MODE"], "safe")
        self.assertEqual(actual["NGINX_PHASE4_LOG_SCOPE"], "server_with_location_override")
        self.assertEqual(actual["NGINX_DOCROOT_PROJECTION"], "1")
        projection = Path(actual["NGINX_DOCROOT_PROJECTION_ROOT"])
        self.assertEqual(projection.parent, Path(self.env["NGINX_DOCROOT_PROJECTION_PARENT"]))
        self.assertRegex(projection.name, r"^nginx-first-byte-[0-9a-f]{32}$")
        self.assertNotEqual(str(projection), self.env["NGINX_DOCROOT_PROJECTION_ROOT"])
        self.assertFalse(projection.exists())
        args = json.loads((self.root / "validator.json").read_text())
        self.assertEqual(args[0], str(self.parent / "ci/runtime/common/validate-nginx-harness-paths.py"))
        self.assertIn(self.env["NGINX_DOCROOT_PROJECTION_ROOT"], args)
        self.assertFalse((self.root / "results/nginx-first-byte-results.jsonl").exists())

    def test_missing_harness_and_upstream_remain_blocked(self):
        self.assertEqual(self.run_script("apache").returncode, 77)
        self.harness("apache")
        (self.framework / "tests/runners/synchronized_upstream.py").unlink()
        self.assertEqual(self.run_script("apache").returncode, 77)
        self.assertFalse((self.root / "capture.json").exists())

    def test_unknown_connector_remains_rejected(self):
        self.assertEqual(self.run_script("future").returncode, 2)
        self.assertFalse((self.root / "capture.json").exists())

    def test_projection_validator_failure_prevents_harness_invocation(self):
        self.harness("nginx")
        self.env["UNIT_VALIDATOR_EXIT"] = "19"
        result = self.run_script("nginx")
        self.assertEqual(result.returncode, 19, result.stderr)
        self.assertFalse((self.root / "capture.json").exists())
        self.assertFalse((self.root / "wrapper.json").exists())

    def test_successful_double_without_log_or_barrier_is_not_evidence(self):
        self.harness("apache")
        self.env["UNIT_HARNESS_EXIT"] = "0"
        result = self.run_script("apache")
        self.assertEqual(result.returncode, 1)
        self.assertIn("without a Phase-4 event", result.stderr)
        log = self.root / "host/apache-first-byte-logs/phase4.log"
        log.parent.mkdir(parents=True)
        log.write_text("unit bytes only, not native evidence\n")
        result = self.run_script("apache")
        self.assertEqual(result.returncode, 1)
        self.assertIn("without barrier evidence", result.stderr)
        self.assertFalse((self.root / "results/apache-first-byte-results.jsonl").exists())

    @unittest.skipUnless(shutil.which("shellcheck"), "ShellCheck is not installed")
    def test_lifecycle_scripts_have_no_warning_level_diagnostics(self):
        paths = [SCRIPT, source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT),
                 source_path('ci/runtime/lifecycle/run-connector-stage.sh', root=ROOT)]
        result = subprocess.run(["rtk", "proxy", "shellcheck", "-S", "warning", *map(str, paths)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
