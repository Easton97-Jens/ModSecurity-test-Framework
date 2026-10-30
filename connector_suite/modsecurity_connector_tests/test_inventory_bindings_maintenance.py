"""Framework-only on-demand maintenance regressions; never read a product tree."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from modsecurity_test_framework.connector_context import test_root

spec = importlib.util.spec_from_file_location("inventory_bindings_maintenance", test_root() /
    "connector_suite/modsecurity_connector_ci/tools/update-inventory-bindings.py")
maintenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(maintenance)


class InventoryBindingsMaintenanceTests(unittest.TestCase):
    def fixture(self, root):
        path = root / maintenance.INVENTORY
        path.parent.mkdir(parents=True)
        (root / "connector_suite/source-map.json").write_text(json.dumps({"schema_version": 1,
            "paths": {"tests/unit.py": "source.py"}, "connector_paths": {}}))
        (root / "source.py").write_text("reviewed source\n")
        value = {"schema_version": 4, "executions": [{"id": "fixture.check", "groups": ["inventory"],
            "sources": ["tests/unit.py", "connectors/model.c"],
            "selector": {"kind": "python", "target": "modsecurity_connector_tests.unit.Tests.test_check"},
            "cases": [{"id": "fixture.check.case", "requirement": "maintenance fixture", "profiles": ["h1"]}]}],
            "offline_unit_exceptions": [], "source_bindings": [{"path": "tests/unit.py", "sha256": "0" * 64}],
            "connector_source_paths": ["connectors/model.c"]}
        path.write_text(json.dumps(value, indent=0) + "\n")
        return path, value

    def test_check_apply_preserves_all_selection_and_product_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path, value = self.fixture(root)
            before = path.read_bytes()
            with mock.patch.object(maintenance, "test_root", return_value=root), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(maintenance.main([]), 1)
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(maintenance.main(["--apply"]), 0)
                self.assertEqual(maintenance.main(["--check"]), 0)
            expected = copy.deepcopy(value)
            expected["source_bindings"][0]["sha256"] = hashlib.sha256((root / "source.py").read_bytes()).hexdigest()
            self.assertEqual(json.loads(path.read_bytes()), expected)
            self.assertLessEqual(path.stat().st_size, maintenance.LIMIT)
            self.assertFalse((root / "connectors").exists())

    def test_legacy_framework_prefix_works_without_product_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path, value = self.fixture(root)
            logical = maintenance.PREFIX + "source.py"
            value["source_bindings"].append({"path": logical, "sha256": "0" * 64})
            value["executions"][0]["sources"].append(logical)
            path.write_text(json.dumps(value))
            original, updated, changes = maintenance.planned(root)
            self.assertEqual(changes, ["tests/unit.py", logical])
            maintenance.atomic_write(root, original, updated)
            self.assertEqual(maintenance.planned(root)[2], [])

    def test_invalid_schema_duplicate_and_escaping_paths_reject_before_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path, value = self.fixture(root)
            variants = []
            duplicate = copy.deepcopy(value); duplicate["source_bindings"] *= 2; variants.append(duplicate)
            schema = copy.deepcopy(value); schema["schema_version"] = 3; variants.append(schema)
            traversal = copy.deepcopy(value); traversal["source_bindings"][0]["path"] = "../escape"; variants.append(traversal)
            unmapped = copy.deepcopy(value); unmapped["source_bindings"][0]["path"] = "connectors/foreign.c"
            unmapped["executions"][0]["sources"][0] = "connectors/foreign.c"; variants.append(unmapped)
            for changed in variants:
                path.write_text(json.dumps(changed)); before = path.read_bytes()
                with self.assertRaises(ValueError): maintenance.planned(root)
                self.assertEqual(path.read_bytes(), before)
            path.write_text(json.dumps(value))
            (root / "connector_suite/source-map.json").write_text(json.dumps({"schema_version": 1,
                "paths": {"tests/unit.py": "../escape"}, "connector_paths": {}}))
            with self.assertRaises(ValueError): maintenance.planned(root)
            path.write_bytes(b'{"schema_version":4,"schema_version":4}')
            with self.assertRaises(ValueError): maintenance.planned(root)
            path.write_bytes(b" " * (maintenance.LIMIT + 1))
            with self.assertRaises(ValueError): maintenance.planned(root)

    def test_symlink_sources_destinations_and_concurrent_replacement_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path, value = self.fixture(root)
            source = root / "source.py"; source.unlink(); source.symlink_to("connector_suite/source-map.json")
            with self.assertRaises(ValueError): maintenance.planned(root)
            source.unlink(); source.write_text("source\n")
            original, updated, _ = maintenance.planned(root)
            path.write_text(json.dumps(value) + "\n")
            with self.assertRaises(ValueError): maintenance.atomic_write(root, original, updated)
            target = root / "target.json"; target.write_bytes(original)
            path.unlink(); path.symlink_to(target)
            with self.assertRaises(ValueError): maintenance.planned(root)
            with self.assertRaises(ValueError): maintenance.atomic_write(root, original, updated)
            self.assertEqual(target.read_bytes(), original)


if os.environ.get("ON_DEMAND_TESTS") != "1":
    InventoryBindingsMaintenanceTests = unittest.skip("explicit specialist selection requires ON_DEMAND_TESTS=1")(InventoryBindingsMaintenanceTests)

if __name__ == "__main__":
    unittest.main()
