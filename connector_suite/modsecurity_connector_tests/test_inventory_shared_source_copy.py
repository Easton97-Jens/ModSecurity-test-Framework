"""A real private proposed tree retains shared source bindings after copying."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root

ROOT = connector_root()


def load_updater():
    name = "shared_source_copy_workflow_updater"
    specification = importlib.util.spec_from_file_location(name, source_path('ci/tools/update-workflow-tools.py', root=ROOT))
    module = importlib.util.module_from_spec(specification)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        specification.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


class SharedSourceCopyTests(unittest.TestCase):
    def test_real_proposed_copy_readmits_shared_sources_and_preserves_original(self):
        updater = load_updater()
        parent = validate_output_root(ROOT, Path(os.environ["I12_TEST_ROOT"]))
        with tempfile.TemporaryDirectory(prefix="shared-copy-", dir=parent) as temporary:
            source, destination = (Path(temporary) / name for name in ("source", "destination"))
            source.mkdir(mode=0o700)
            destination.mkdir(mode=0o700)
            fixed = (updater.ALLOWED_UPDATE_PATHS | updater.PROPOSED_TREE_BASELINE_PATHS
                     | updater.PROPOSED_TREE_ACTIVE_RUNTIME_PATHS)
            for relative in sorted(fixed):
                target = source / relative
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
                target.chmod(0o600)
            fixture_name = "tests/synthetic_shared_copy.py"
            fixture = source / fixture_name
            fixture.write_text("import unittest\nclass Control(unittest.TestCase):\n"
                               "    def test_core(self): self.assertTrue(True)\n"
                               "    def test_offline(self): self.assertTrue(True)\n")
            digest = hashlib.sha256(fixture.read_bytes()).hexdigest()

            def execution(name, groups):
                prefix = "offline." if name == "offline" else ""
                return {"id": prefix + "shared-copy." + name, "groups": groups,
                        "sources": [fixture_name], "expected_subtests": 0,
                        "selector": {"kind": "python", "target":
                                     "tests.synthetic_shared_copy.Control.test_" + name},
                        "cases": [{"id": "shared-copy." + name + ".case",
                                   "requirement": "Admit copied " + name + " source without executing it",
                                   "profiles": ["parent-infrastructure"]}]}

            inventory = {"schema_version": 3, "executions": [execution("core", ["control"])],
                         "offline_unit_exceptions": [execution("offline", ["offline-unit"])],
                         "source_bindings": [{"path": fixture_name, "sha256": digest}]}
            inventory_path = source / "config/testing/active-cases.json"
            inventory_path.write_text(json.dumps(inventory, indent=2) + "\n")
            before = {path.relative_to(source).as_posix(): path.read_bytes()
                      for path in source.rglob("*") if path.is_file()}
            original = updater.admitted_validation_inventory(source)
            updater.copy_update_inputs(source, destination)
            copied = updater.admitted_validation_inventory(destination)
            self.assertEqual(copied.case_ids, original.case_ids)
            self.assertEqual(copied.core_case_ids, original.core_case_ids)
            self.assertEqual(copied.offline_case_ids, original.offline_case_ids)
            self.assertEqual(copied.executions, original.executions)
            self.assertTrue(all(item["sources"] == {fixture_name: digest}
                                for item in copied.executions))
            self.assertEqual((destination / fixture_name).read_bytes(), fixture.read_bytes())
            self.assertEqual((destination / "config/testing/active-cases.json").read_bytes(),
                             inventory_path.read_bytes())
            self.assertEqual({path.relative_to(source).as_posix(): path.read_bytes()
                              for path in source.rglob("*") if path.is_file()}, before)


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
