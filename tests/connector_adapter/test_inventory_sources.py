"""Exercise migrated bindings and Go's supported package-private test overlay."""
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

from modsecurity_connector_ci.lib import active_test_inventory as active


class ConnectorInventorySourcesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.product = self.directory / "product"
        self.framework = self.directory / "framework"
        self.output = self.directory / "output"
        self.module = "connectors/envoy/ext_proc"
        self.package = self.product / self.module
        self.package.mkdir(parents=True)
        self.output.mkdir()
        (self.framework / "connector_suite").mkdir(parents=True)
        self.logical = self.module + "/private_test.go"
        self.migrated = "connector_suite/adapters/envoy/ext_proc/private_test.go"
        self.source = self.framework / self.migrated
        self.source.parent.mkdir(parents=True)
        self.source.write_text('package fixture\nimport "testing"\n'
                               'func TestPrivate(t *testing.T) { if hidden() != 7 { t.Fatal("private helper") } }\n')
        (self.package / "go.mod").write_text("module example.test/overlay\n\ngo 1.22\n")
        (self.package / "product.go").write_text("package fixture\nfunc hidden() int { return 7 }\n")
        self.mapping = {self.logical: self.migrated}
        self.map_file = self.framework / "connector_suite/source-map.json"
        self.write_map()
        self.inventory_path = self.product / "inventory.json"
        self.data = {"schema_version": 1, "executions": [{
            "id": "fixture.private", "groups": ["fixture"],
            "sources": [{"path": self.logical, "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest()}],
            "selector": {"kind": "go", "module": self.module, "package": ".", "test": "TestPrivate"},
            "cases": [{"id": "fixture.private.case", "requirement": "Preserve same-package private access.",
                       "profiles": ["fixture"]}],
        }]}
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.dict(os.environ, {
            "CONNECTOR_ROOT": str(self.product), "CONNECTOR_REVISION": "a" * 40,
            "TEST_ROOT": str(self.framework), "CONNECTOR_TEST_PROFILE": "fixture",
            "CONNECTOR_TEST_OUTPUT_ROOT": str(self.output),
            "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOWORK": "off",
            "GOCACHE": str(self.directory / "go-cache"), "CGO_ENABLED": "0",
        }))
        stack.enter_context(patch.object(active, "connector_root", return_value=self.product))
        stack.enter_context(patch.object(active, "validate_checkout", return_value=self.product))
        stack.enter_context(patch.object(active, "test_root", return_value=self.framework))
        stack.enter_context(patch.object(active, "source_path", side_effect=self.resolve))

    def resolve(self, relative, *, root=None):
        name = str(relative)
        if root is not None and root != self.product:
            return root / name
        return self.framework / self.mapping[name] if name in self.mapping else self.product / name

    def write_map(self):
        self.map_file.write_text(json.dumps({"schema_version": 1, "paths": self.mapping}))

    def load(self):
        self.inventory_path.write_text(json.dumps(self.data))
        return active.load_inventory(self.product, self.inventory_path)

    def test_mapped_source_reader_preserves_hash_and_rejects_symlink_or_escape(self):
        original = self.source.read_bytes()
        self.assertEqual(active.read_source(self.product, self.logical), original)
        moved = self.source.with_name("original.go")
        self.source.rename(moved)
        self.source.symlink_to(moved)
        with self.assertRaisesRegex(active.InventoryError, "non-symlink"):
            active.read_source(self.product, self.logical)
        with patch.object(active, "source_path", return_value=self.directory / "outside.go"):
            with self.assertRaisesRegex(active.InventoryError, "escapes"):
                active.read_source(self.product, self.logical)

    def test_changed_source_map_rejects_before_any_test_child(self):
        inventory = self.load()
        self.map_file.write_text(self.map_file.read_text() + " ")
        with patch.object(active.subprocess, "Popen") as child:
            with self.assertRaisesRegex(active.InventoryError, "source map changed"):
                active.run_execution(inventory, inventory.executions[0], self.output, False, True)
        child.assert_not_called()

    def test_unique_python_selector_binds_legacy_source_without_connector_checkout(self):
        root = self.directory / "isolated-fixture"
        content = ("import unittest\nclass FixtureCase(unittest.TestCase):\n"
                   "    def test_true(self): self.assertTrue(True)\n")
        data = {"schema_version": 1, "executions": [{
            "id": "fixture.python", "groups": ["fixture"],
            "sources": [{"path": "tests/fixture_scope.py", "sha256": hashlib.sha256(content.encode()).hexdigest()}],
            "selector": {"kind": "python", "target": "modsecurity_connector_tests.fixture_scope.FixtureCase.test_true"},
            "cases": [{"id": "fixture.python.case", "requirement": "Bind the unique test package to its reviewed source.",
                       "profiles": ["fixture"]}],
        }]}
        inventory_path = root / "inventory.json"
        with patch.dict(os.environ, {"CONNECTOR_ROOT": "", "CONNECTOR_REVISION": "", "TEST_ROOT": ""}):
            for module, relative in (
                    ("modsecurity_connector_tests.fixture_scope", "tests/fixture_scope.py"),
                    ("modsecurity_connector_ci.fixture_scope", "ci/fixture_scope.py"),
                    ("connector_suite.adapters.lighttpd.tests.fixture_scope", "connectors/lighttpd/tests/fixture_scope.py")):
                source = root / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(content)
                data["executions"][0]["sources"][0]["path"] = relative
                data["executions"][0]["selector"]["target"] = module + ".FixtureCase.test_true"
                inventory_path.write_text(json.dumps(data))
                with self.subTest(module=module):
                    inventory = active.load_inventory(root, inventory_path)
                    self.assertEqual(inventory.case_ids, ("fixture.python.case",))
            data["executions"][0]["selector"]["target"] = "foreign_tests.fixture_scope.FixtureCase.test_true"
            inventory_path.write_text(json.dumps(data))
            with self.assertRaisesRegex(active.InventoryError, "exact test-module source binding"):
                active.load_inventory(root, inventory_path)

    def test_native_command_uses_mapped_framework_script_and_product_working_directory(self):
        logical = "ci/checks/security/check-workflow-fixture.sh"
        migrated = "connector_suite/modsecurity_connector_ci/checks/security/check-workflow-fixture.sh"
        script = self.framework / migrated
        script.parent.mkdir(parents=True)
        script.write_text("#!/bin/sh\nexit 0\n")
        self.mapping[logical] = migrated
        self.write_map()
        execution = self.data["executions"][0]
        execution["sources"] = [{"path": logical, "sha256": hashlib.sha256(script.read_bytes()).hexdigest()}]
        execution["selector"] = {"kind": "native", "script": logical, "args": ["safe"]}
        inventory = self.load()
        command, working_directory = active.execution_command(self.product, inventory.executions[0])
        self.assertEqual(command, ["sh", str(script), "safe"])
        self.assertEqual(working_directory, self.product)

    def test_unbound_package_test_is_rejected_during_admission(self):
        second = self.source.with_name("other_test.go")
        second.write_text('package fixture\nimport "testing"\nfunc TestOther(t *testing.T) {}\n')
        self.mapping[self.module + "/other_test.go"] = second.relative_to(self.framework).as_posix()
        self.write_map()
        with self.assertRaisesRegex(active.InventoryError, "every package test-source binding"):
            self.load()

    def test_specialist_overlay_is_explicit_and_never_executes_go(self):
        with patch.object(active, "_run_child") as child:
            for option, environment in ((False, "1"), (True, "0")):
                with patch.dict(os.environ, {"ON_DEMAND_TESTS": environment}):
                    with self.assertRaisesRegex(active.InventoryError, "explicit"):
                        active.create_module_go_overlay(self.product, self.module, self.output, on_demand=option)
            with patch.dict(os.environ, {"ON_DEMAND_TESTS": "1"}):
                overlay = active.create_module_go_overlay(self.product, self.module, self.output, on_demand=True)
        child.assert_not_called()
        self.assertEqual(json.loads(overlay.read_text())["Replace"],
                         {str(self.product / self.logical): str(self.source)})
        receipt = json.loads((overlay.parent / "go-overlay-sources.json").read_text())
        self.assertEqual(receipt["execution"], "not_started")
        self.assertEqual(receipt["sources_sha256"],
                         {self.logical: hashlib.sha256(self.source.read_bytes()).hexdigest()})
        self.assertFalse((self.product / self.logical).exists())

    @unittest.skipUnless(shutil.which("go"), "Go toolchain required for the native overlay proof")
    def test_go_overlay_compiles_private_test_without_writing_product_checkout(self):
        inventory = self.load()
        before = {path.relative_to(self.product): path.read_bytes()
                  for path in self.product.rglob("*") if path.is_file()}
        with redirect_stdout(io.StringIO()):
            result = active.run_execution(inventory, inventory.executions[0], self.output, False, True)
        after = {path.relative_to(self.product): path.read_bytes()
                 for path in self.product.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["case_ids"], ["fixture.private.case"])
        self.assertEqual(len(result["observed"]["leaf_tests"]), 1)
        self.assertEqual(stat.S_IMODE((self.output / "fixture.private.go-overlay.json").stat().st_mode), 0o600)




def load_tests(loader, standard_tests, pattern):
    import os
    if os.environ.get("ON_DEMAND_TESTS") == "1":
        return standard_tests
    return unittest.TestSuite()

if __name__ == "__main__":
    unittest.main()
