"""Schema-4 ownership checks remain executable without a product checkout."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from modsecurity_connector_ci.lib import active_test_inventory as inventory


class InventorySourceDomainsTests(unittest.TestCase):
    def fixture(self, root):
        test = root / "tests/sample.py"
        test.parent.mkdir()
        test.write_text("class Sample:\n    def test_one(self):\n        pass\n")
        product = root / "product.txt"
        product.write_text("version-one\n")
        value = {
            "schema_version": 4,
            "executions": [{"id": "sample.one", "groups": ["sample"],
                            "sources": ["tests/sample.py", "product.txt"],
                            "selector": {"kind": "python", "target": "tests.sample.Sample.test_one"},
                            "cases": [{"id": "sample.one.case", "requirement": "one product scenario",
                                       "profiles": ["sample"]}]}],
            "offline_unit_exceptions": [],
            "source_bindings": [{"path": "tests/sample.py", "sha256": hashlib.sha256(test.read_bytes()).hexdigest()}],
            "connector_source_paths": ["product.txt"],
        }
        target = root / inventory.INVENTORY_PATH
        target.parent.mkdir(parents=True)
        target.write_text(json.dumps(value))
        return value, target, test, product

    def test_new_product_revision_gets_its_own_admitted_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, _, product = self.fixture(root)
            first = inventory.load_inventory(root)
            product.write_text("version-two\n")
            second = inventory.load_inventory(root)
            self.assertEqual(first.digest, second.digest)
            self.assertNotEqual(first.executions[0]["sources"]["product.txt"],
                                second.executions[0]["sources"]["product.txt"])
            self.assertEqual(first.case_ids, second.case_ids)

    def test_product_change_after_admission_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, _, product = self.fixture(root)
            admitted = inventory.load_inventory(root)
            product.write_text("changed after admission\n")
            with self.assertRaisesRegex(inventory.InventoryError, "digest mismatch before execution"):
                inventory._recheck_bindings(admitted)

    def test_changed_framework_test_still_requires_reviewed_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, test, _ = self.fixture(root)
            test.write_text(test.read_text() + "# unexpected collector edit\n")
            with self.assertRaisesRegex(inventory.InventoryError, "reviewed source digest mismatch"):
                inventory.load_inventory(root)

    def test_source_cannot_claim_both_product_and_framework_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value, target, _, _ = self.fixture(root)
            value["connector_source_paths"].append("tests/sample.py")
            target.write_text(json.dumps(value))
            with self.assertRaisesRegex(inventory.InventoryError, "ownership must be unique"):
                inventory.load_inventory(root)


    def test_framework_native_exact_module_binding_is_admitted_and_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value, target, test, _ = self.fixture(root)
            native = "modules/ModSecurity-test-Framework/connector_suite/modsecurity_connector_tests/sample.py"
            physical = root / native
            physical.parent.mkdir(parents=True)
            physical.write_bytes(test.read_bytes())
            value["executions"][0]["selector"]["target"] = "modsecurity_connector_tests.sample.Sample.test_one"
            value["executions"][0]["sources"][0] = native
            value["source_bindings"][0]["path"] = native
            target.write_text(json.dumps(value))
            admitted = inventory.load_inventory(root)
            self.assertIn(native, admitted.executions[0]["sources"])
            physical.write_text("class Sample: pass\n")
            value["source_bindings"][0]["sha256"] = hashlib.sha256(physical.read_bytes()).hexdigest()
            target.write_text(json.dumps(value))
            with self.assertRaisesRegex(inventory.InventoryError, "source-defined test method"):
                inventory.load_inventory(root)

    def test_framework_native_wrong_module_binding_is_rejected(self):
        target = "modsecurity_connector_tests.sample.Sample.test_one"
        wrong = "modules/ModSecurity-test-Framework/connector_suite/modsecurity_connector_tests/other.py"
        with self.assertRaisesRegex(inventory.InventoryError, "exactly one exact"):
            inventory._validate_python_selector({"kind": "python", "target": target}, {wrong: "0" * 64})

    def test_framework_native_and_historical_double_binding_is_rejected(self):
        target = "modsecurity_connector_tests.sample.Sample.test_one"
        native = "modules/ModSecurity-test-Framework/connector_suite/modsecurity_connector_tests/sample.py"
        sources = {"tests/sample.py": "0" * 64, native: "0" * 64}
        with self.assertRaisesRegex(inventory.InventoryError, "exactly one exact"):
            inventory._validate_python_selector({"kind": "python", "target": target}, sources)
        with self.assertRaisesRegex(inventory.InventoryError, "exactly one exact"):
            inventory._python_test_definition({"kind": "python", "target": target},
                                               {name: b"class Sample: pass" for name in sources}, {})


def load_tests(loader, standard_tests, pattern):
    if os.environ.get("ON_DEMAND_TESTS") == "1":
        return standard_tests
    return unittest.TestSuite()
