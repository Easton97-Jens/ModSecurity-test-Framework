"""Extracted shell controls prove wiring only; no native runtime is invoked."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = connector_root()
BASELINE = source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)


class NativeAuthorityWiringTests(unittest.TestCase):
    def setUp(self):
        self.source = BASELINE.read_text()
        start = self.source.index("prepare_nginx_native_authority() {")
        end = self.source.index("\n}\n", start) + 3
        self.function = self.source[start:end]
        self.temp = tempfile.TemporaryDirectory(dir="/var/tmp/codex/ModSecurity-conector/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.parent = self.root / "parent"
        lifecycle = self.parent / "ci/runtime/lifecycle"
        lifecycle.mkdir(parents=True)
        (self.parent / "ci/lib").symlink_to(source_path('ci/lib', root=ROOT), target_is_directory=True)
        producer = lifecycle / "nginx_native_authority.py"
        producer.write_text("import json, os, sys\nfrom pathlib import Path\nPath(os.environ['UNIT_ARGV']).write_text(json.dumps(sys.argv[1:]))\n")
        self.framework = self.root / "framework"
        runners = self.framework / "tests/runners"
        runners.mkdir(parents=True)
        # Unit double for selection only, not a native validator or proof.
        (runners / "nginx_native_operation_bundle.py").write_text("CASE_IDS = frozenset({'single_request_cleanup'})\n")
        catalog = self.framework / "tests/cases/no-crs-baseline/catalog.json"
        catalog.parent.mkdir(parents=True)
        self.catalog = catalog
        self.catalog.write_text(json.dumps({"cases": [{"case_id": "single_request_cleanup", "native_invocations": {"nginx": {"operation": "request_sequence", "contract_case_id": "single_request_cleanup"}}}, {"case_id": "allow_without_marker"}]}))
        self.stage = self.root / "stage"
        self.stage.mkdir(mode=0o700)
        self.env = dict(os.environ, connector="nginx", NO_CRS_ARTIFACT_PROFILE="full_lifecycle", CONNECTOR_ROOT=str(self.parent), FRAMEWORK_ROOT=str(self.framework), PYTHON=str(Path(os.sys.executable)), STAGE_BUILD_ROOT=str(self.stage), NO_CRS_RUN_ID="unit-run97", NO_CRS_SELECTED_CASE_IDS="single_request_cleanup allow_without_marker", NGINX_PREFIX=str(self.root / "prepared-prefix"), UNIT_ARGV=str(self.root / "argv.json"))
        self.env.pop("MRTS_ROOT", None)
        for name in ("INPUT", "BEGIN", "FINISH", "WRITE", "ENGINE_BUDGET"):
            library = self.root / (name + ".so")
            library.write_bytes(b"unit fixture bytes, not compiled runtime proof")
            self.env["NGX_NATIVE_" + name + "_FAULT_LIBRARY"] = str(library)

    def run_control(self, overrides=None):
        env = {**self.env, **(overrides or {})}
        return subprocess.run(["rtk", "proxy", "sh", "-eu", "-c", self.function + '\nprepare_nginx_native_authority\nprintf "enabled=%s authority=%s\\n" "$NGINX_NATIVE_AUTHORITY_ENABLED" "$NGINX_NATIVE_AUTHORITY"'], env=env, capture_output=True, text=True, timeout=15)

    def test_explicit_stage_authority_and_five_original_paths(self):
        result = self.run_control()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads((self.root / "argv.json").read_text())
        values = dict(zip(args[::2], args[1::2], strict=True))
        self.assertEqual(values["--artifact-root"], str(self.stage))
        self.assertEqual(values["--mrts-root"], str(self.framework / "tools/MRTS"))
        self.assertEqual(values["--binary-path"], self.env["NGINX_PREFIX"] + "/sbin/nginx")
        self.assertEqual(values["--module-path"], self.env["NGINX_PREFIX"] + "/modules/ngx_http_modsecurity_module.so")
        self.assertEqual(values["--run-id"], "unit-run97")
        output = Path(values["--output-parent"])
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        self.assertTrue(output.is_relative_to(self.stage))
        self.assertIn("enabled=1", result.stdout)
        for name, flag in (("INPUT", "input"), ("BEGIN", "begin"), ("FINISH", "finish"), ("WRITE", "write"), ("ENGINE_BUDGET", "budget")):
            self.assertEqual(values["--" + flag + "-fault-library"], self.env["NGX_NATIVE_" + name + "_FAULT_LIBRARY"])

    def test_missing_each_library_and_prefix_blocks_without_invocation(self):
        for name in ("INPUT", "BEGIN", "FINISH", "WRITE", "ENGINE_BUDGET"):
            with self.subTest(name=name):
                result = self.run_control({"NGX_NATIVE_" + name + "_FAULT_LIBRARY": ""})
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertFalse((self.root / "argv.json").exists())
        result = self.run_control({"NGINX_PREFIX": ""})
        self.assertEqual(result.returncode, 77, result.stderr)

    def test_explicit_read_only_mrts_root_passes_through_unchanged(self):
        actual_mrts = self.root / "separate-initialized-mrts"
        actual_mrts.mkdir(mode=0o700)
        result = self.run_control({"MRTS_ROOT": str(actual_mrts)})
        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads((self.root / "argv.json").read_text())
        values = dict(zip(args[::2], args[1::2], strict=True))
        self.assertEqual(values["--mrts-root"], str(actual_mrts))
        self.assertEqual(list(actual_mrts.iterdir()), [])

    def test_other_profiles_and_no_native_selection_do_not_promote(self):
        for override in ({"connector": "apache"}, {"NO_CRS_ARTIFACT_PROFILE": "generic"}, {"NO_CRS_SELECTED_CASE_IDS": "allow_without_marker"}):
            with self.subTest(override=override):
                result = self.run_control(override)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("enabled=0", result.stdout)
                self.assertFalse((self.root / "argv.json").exists())

    def test_required_closed_descriptor_cannot_disappear(self):
        self.catalog.write_text(json.dumps({"cases": [{"case_id": "single_request_cleanup"}]}))
        result = self.run_control()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "argv.json").exists())

    def test_reused_authority_parent_rejected(self):
        first = self.run_control()
        self.assertEqual(first.returncode, 0, first.stderr)
        original = (self.root / "argv.json").read_bytes()
        second = self.run_control()
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual((self.root / "argv.json").read_bytes(), original)

    def test_snapshot_prefix_mismatch_does_not_override_authority(self):
        start = self.source.index('if [ "$NGINX_NATIVE_AUTHORITY_ENABLED" -eq 1 ] && \\\n')
        end = self.source.index("\nfi\n", start) + 4
        guard = self.source[start:end]
        for observed, expected in (("/prepared/original", 0), ("/snapshot/other", 1), ("", 1)):
            with self.subTest(observed=observed):
                result = subprocess.run(["rtk", "proxy", "sh", "-eu", "-c", 'stage_rc=0\n' + guard + '\nprintf "stage=%s prefix=%s\\n" "$stage_rc" "$NGINX_NATIVE_AUTHORITY_PREFIX"'], env={**self.env, "NGINX_NATIVE_AUTHORITY_ENABLED": "1", "NGINX_NATIVE_AUTHORITY_PREFIX": "/prepared/original", "NGINX_PREFIX": observed}, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, f"stage={expected} prefix=/prepared/original\n")

    def test_selected_absent_duplicate_or_foreign_descriptor_rejected(self):
        for cases in ([], [{"case_id": "single_request_cleanup"}] * 2, [{"case_id": "allow_without_marker", "native_invocations": {"nginx": {"operation": "request_sequence"}}}]):
            with self.subTest(cases=cases):
                self.catalog.write_text(json.dumps({"cases": cases}))
                result = self.run_control()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "argv.json").exists())

    def test_central_arguments_scope_and_initialization_order(self):
        invoke = self.source.index("\nprepare_nginx_native_authority\n")
        self.assertLess(self.source.index(" init \\\n"), invoke)
        self.assertLess(invoke, self.source.index("started_at="))
        self.assertIn(
            '--allowed-native-operation-root '
            '"$STAGE_BUILD_ROOT/host-runtime/native-operations-$NO_CRS_RUN_ID"',
            self.source,
        )
        self.assertNotIn(
            '--allowed-native-operation-root "$STAGE_BUILD_ROOT"', self.source
        )
        self.assertIn('--native-operation-authority "$NGINX_NATIVE_AUTHORITY"', self.source)
        self.assertIn('"${NGINX_PREFIX:-}" != "$NGINX_NATIVE_AUTHORITY_PREFIX"', self.source)
        self.assertIn('--allowed-source-root "$RAW_DIR"', self.source)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
