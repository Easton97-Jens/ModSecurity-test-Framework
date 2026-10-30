"""Shell boundary checks only; no connector build or native host executes."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = connector_root()
BASELINE = source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=ROOT)


class BaselineShellEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.source = BASELINE.read_text(encoding="utf-8")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def command_block(self, marker, leaf):
        start = self.source.index(marker) + len(marker)
        end_marker = 'sh "$CONNECTOR_ROOT/ci/runtime/lifecycle/' + leaf + '" "$connector"'
        end = self.source.index(end_marker, start) + len(end_marker)
        if leaf == "run-connector-stage.sh":
            end += len(' "$evidence_stage"')
        return self.source[start:end].strip()

    def check_child_boundary(self, block, leaf, expected_args):
        lifecycle = self.root / "parent with spaces/ci/runtime/lifecycle"
        lifecycle.mkdir(parents=True)
        keys = re.findall(r"^\s*([A-Z_]+)=", block, flags=re.MULTILINE)
        self.assertTrue(keys)
        child = lifecycle / leaf
        child.write_text(
            '"$PYTHON" - "$@" <<\'PY\'\n'
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "Path(os.environ['UNIT_CAPTURE']).write_text(json.dumps({'argv': sys.argv[1:], "
            "'env': {key: os.environ.get(key) for key in " + repr(keys) + "}}))\n"
            "PY\nexit 23\n", encoding="utf-8")
        env = dict(os.environ)
        for name in re.findall(r"\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)", block):
            env[name] = "outer " + name
        env.update(CONNECTOR_ROOT=str(lifecycle.parents[2]), PYTHON=os.sys.executable,
                   UNIT_CAPTURE=str(self.root / "capture.json"), connector="nginx",
                   evidence_stage="no_crs_baseline", SHARED_COMPONENT_CACHE="resolved cache",
                   VERIFIED_COMPONENT_CACHE="resolved cache",
                   STAGE_BUILD_ROOT="stage build", BUILD_ROOT="outer BUILD_ROOT",
                   NO_CRS_RULES_FILE="outer rules")
        result = subprocess.run(["rtk", "proxy", "sh", "-c", block +
            '\nrc=$?\nprintf "%s|%s|%s\\n" "$rc" "$BUILD_ROOT" "$NO_CRS_RULES_FILE"'],
            env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = json.loads((self.root / "capture.json").read_text())
        self.assertEqual(actual["argv"], expected_args)
        self.assertEqual(actual["env"]["CONNECTOR_ROOT"], env["CONNECTOR_ROOT"])
        self.assertEqual(actual["env"]["BUILD_ROOT"], "stage build")
        self.assertEqual(actual["env"]["NO_CRS_RULES_FILE"], "outer rules")
        self.assertTrue(all(value is not None for value in actual["env"].values()))
        if leaf == "run-connector-stage.sh":
            self.assertEqual(actual["env"]["RULES_FILE"], "outer rules")
            self.assertEqual(actual["env"]["MSCONNECTOR_RULES_FILE"], "outer rules")
            self.assertEqual(actual["env"]["VERIFIED_COMPONENT_CACHE"], "resolved cache")
            self.assertEqual(actual["env"]["CONNECTOR_COMPONENT_CACHE"], "resolved cache")
        else:
            self.assertEqual(actual["env"]["SKIP_RUNTIME_COMPONENT_PREPARE"], "1")
        self.assertEqual(result.stdout.strip(), "23|outer BUILD_ROOT|outer rules")

    def test_stage_outer_expansions_child_environment_exit_and_parent_scope(self):
        block = self.command_block("set +e\n", "run-connector-stage.sh")
        self.check_child_boundary(block, "run-connector-stage.sh", ["nginx", "no_crs_baseline"])

    def test_first_byte_outer_expansions_child_environment_exit_and_parent_scope(self):
        block = self.command_block("native_first_byte_rc=0\n", "run-native-first-byte.sh")
        self.check_child_boundary(block, "run-native-first-byte.sh", ["nginx"])

    def test_post_snapshot_live_cache_reassertion_without_unused_export(self):
        start = self.source.index("CONNECTOR_COMPONENT_CACHE=$SHARED_COMPONENT_CACHE", self.source.index("runtime_env=$RUNTIME_COMPONENT_ENV_SNAPSHOT"))
        end = self.source.index("RUNTIME_COMPONENT_ENV_SNAPSHOT=$runtime_env", start)
        reset = self.source[start:end]
        self.assertNotIn("VERIFIED_COMPONENT_CACHE", reset)
        env = dict(os.environ, SHARED_COMPONENT_CACHE="actual resolved cache",
                   CONNECTOR_COMPONENT_CACHE="stale snapshot cache")
        env.pop("VERIFIED_COMPONENT_CACHE", None)
        result = subprocess.run(["rtk", "proxy", "sh", "-eu", "-c", reset +
            '\n"' + os.sys.executable + '" -c \'import os; print(os.environ["CONNECTOR_COMPONENT_CACHE"]); print(os.environ.get("VERIFIED_COMPONENT_CACHE", "missing"))\''],
            env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["actual resolved cache", "missing"])

    @unittest.skipUnless(shutil.which("shellcheck"), "ShellCheck is not installed")
    def test_baseline_has_no_shellcheck_warnings(self):
        result = subprocess.run(["rtk", "proxy", "shellcheck", "-S", "warning", str(BASELINE)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
