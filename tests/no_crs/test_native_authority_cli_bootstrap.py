"""Standalone CLI imports use this checkout; fixtures are not runtime evidence."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


FRAMEWORK_ROOT = Path(__file__).resolve().parents[2]
CLI = FRAMEWORK_ROOT / "ci/checks/catalog/no_crs_baseline.py"
PROBE = r'''
import json
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace

cli, root, mode, shadow = sys.argv[1:]
if shadow:
    sys.path.insert(0, shadow)
    sys.path.append(str(Path(cli).resolve().parents[3]))
namespace = runpy.run_path(cli, run_name="cli_bootstrap_probe")
root = Path(root)
expected = {"run_id": "unit-cli", "parent_sha": "a" * 40,
            "framework_sha": "b" * 40, "mrts_sha": "c" * 40}
context = SimpleNamespace(run_dir=root / "retained", manifest={"artifacts": {}})
context.run_dir.mkdir(exist_ok=True)
try:
    if mode == "reader":
        namespace["retained_native_operation_authority"](context.run_dir, expected)
    else:
        namespace["retain_finalize_native_authority"](context, root / "authority.json", expected)
        namespace["retained_native_operation_authority"](
            context.run_dir, expected, manifest=context.manifest)
except namespace["ContractError"] as exc:
    print(str(exc))
    raise SystemExit(3)
from tests.runners import nginx_native_operation_authority as authority
from tests.runners import nginx_native_operation_bundle as bundle
from tests.runners import nginx_native_operation_contract as contract
for module in (authority, bundle, contract):
    assert Path(module.__file__).resolve().is_relative_to(Path(cli).resolve().parents[3])
assert (context.run_dir / namespace["NATIVE_AUTHORITY_FILE_PATH"]).read_bytes() == (root / "authority.json").read_bytes()
print(json.dumps({"retained": True, "readers": "current-checkout"}))
'''


class NativeAuthorityCliBootstrapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native-cli-", dir=os.environ["TMPDIR"])
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cwd = self.root / "unrelated"
        self.cwd.mkdir()
        for name in ("parent", "framework", "artifacts"):
            (self.root / name).mkdir()

    def probe(self, mode="retain", shadow=""):
        return subprocess.run(
            [sys.executable, "-I", "-B", "-c", PROBE, str(CLI), str(self.root), mode, str(shadow)],
            cwd=self.cwd, env={"PATH": os.defpath, "PYTHONNOUSERSITE": "1"},
            text=True, capture_output=True, timeout=30, check=False,
        )

    def write_authority(self):
        document = {
            "schema_version": 1, "connector": "nginx", "run_id": "unit-cli",
            "parent_sha": "a" * 40, "framework_sha": "b" * 40, "mrts_sha": "c" * 40,
            "parent_root": str(self.root / "parent"), "framework_root": str(self.root / "framework"),
            "artifact_root": str(self.root / "artifacts"), "binary_sha256": "d" * 64,
            "module_sha256": "e" * 64, "fault_library_sha256": {},
        }
        path = self.root / "authority.json"
        path.write_text(json.dumps(document) + "\n", encoding="utf-8")
        path.chmod(0o600)

    def test_standalone_finalize_retains_and_offline_reader_loads_authority(self):
        self.write_authority()
        result = self.probe()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('"readers": "current-checkout"', result.stdout)

    def test_missing_authority_fails_closed_in_both_paths(self):
        for mode, message in (("retain", "native authority retention failed"),
                              ("reader", "retained native authority validation failed")):
            with self.subTest(mode=mode):
                result = self.probe(mode)
                self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
                self.assertIn(message, result.stdout)
                self.assertNotIn("ModuleNotFoundError", result.stderr)

    def test_malformed_authority_fails_closed_in_both_paths(self):
        (self.root / "authority.json").write_text("{}", encoding="utf-8")
        retained = self.root / "retained/inventory"
        retained.mkdir(parents=True)
        (retained / "native-operation-authority.json").write_text("{}", encoding="utf-8")
        for mode in ("retain", "reader"):
            with self.subTest(mode=mode):
                result = self.probe(mode)
                self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
                self.assertIn("closed native authority fields required", result.stdout)

    def test_foreign_tests_package_cannot_shadow_current_checkout(self):
        self.write_authority()
        package = self.cwd / "tests"
        package.mkdir()
        (package / "__init__.py").write_text('raise RuntimeError("foreign tests package")\n', encoding="utf-8")
        result = self.probe(shadow=self.cwd)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)


if __name__ == "__main__":
    unittest.main()
