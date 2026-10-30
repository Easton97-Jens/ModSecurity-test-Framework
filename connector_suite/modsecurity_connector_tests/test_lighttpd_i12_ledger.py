"""Lighttpd inventory integrity and evidence non-promotion regression controls."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import copy
import importlib.util
from pathlib import Path
import os
import tempfile
import unittest


LEDGER = load_source(connector_root() / 'ci/runtime/lifecycle/i12/lighttpd/ledger.py')


class LighttpdLedgerTests(unittest.TestCase):
    def setUp(self):
        # Validator controls only. These records are never persisted as host evidence.
        self.ledger = {"original_ordered_id_sha256": "control-order",
                       "original_selected_contract_sha256": "control-contracts", "rows": []}
        self.oracles = {**self.ledger, "oracle_matrix": []}
        del self.oracles["rows"]
        for route, (cases, oracles) in LEDGER.ROUTES.items():
            for number in range(cases):
                case_id = f"I12::{route}::control-{number}"
                requirement = {"case_id": f"control-{number}"}
                row = {"run_scoped_case_id": case_id, "leg_id": route,
                       "required_leg": route != LEDGER.DIAGNOSTIC,
                       "selected_requirement": requirement,
                       "status": "NOT_EXECUTED_UNQUALIFIED", "execution_observed": None}
                self.ledger["rows"].append(row)
                if number < oracles:
                    self.oracles["oracle_matrix"].append({
                        "run_scoped_case_id": case_id, "leg_id": route,
                        "original_596_member": True,
                        "original_selected_requirement": requirement,
                        "original_source_revision": {"parent": "control-revision"},
                        "original_source_hashes": {"source": "control-source-sha"},
                        "resolved": False, "category": "UNRESOLVED_ORACLE"})

    def reconcile(self, supplemental=None):
        return LEDGER.reconcile(self.ledger, self.oracles, {}, supplemental)

    def test_route_counts_source_bindings_and_independent_diagnostic_membership(self):
        files = self.reconcile()
        self.assertEqual(len(files), 7)
        for route, (cases, oracles) in LEDGER.ROUTES.items():
            case_file = files[f"{route}-cases.json"]
            oracle_file = files[f"{route}-oracles.json"]
            self.assertEqual(len(case_file["rows"]), cases)
            self.assertEqual(len(oracle_file["rows"]), oracles)
            self.assertEqual(case_file["summary"]["unresolved_original_oracles"], oracles)
            self.assertEqual(len(oracle_file["original_source_bindings"]), 1)
            for row in oracle_file["rows"]:
                self.assertIn(row["original_source_binding_sha256"],
                              oracle_file["original_source_bindings"])

    def test_new_capture_pass_cannot_promote_inherited_status_or_resolve_oracle(self):
        before = copy.deepcopy((self.ledger, self.oracles))
        route = "lighttpd-stock-sidecar"
        files = self.reconcile({route: [{"path": "/validator-control/pass.json", "sha256": "control"}]})
        row = files[f"{route}-cases.json"]["rows"][0]
        self.assertEqual(row["status"], "NOT_EXECUTED_UNQUALIFIED")
        self.assertIsNone(row["execution_observed"])
        self.assertFalse(files[f"{route}-oracles.json"]["rows"][0]["resolved"])
        self.assertEqual(before, (self.ledger, self.oracles))

    def test_duplicate_and_missing_ids_rejected(self):
        self.ledger["rows"].append(copy.deepcopy(self.ledger["rows"][0]))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.reconcile()
        self.ledger["rows"].pop()
        self.ledger["rows"].pop()
        with self.assertRaisesRegex(ValueError, "membership count"):
            self.reconcile()

    def test_wrong_route_and_original_requirement_changes_rejected(self):
        self.oracles["oracle_matrix"][0]["leg_id"] = LEDGER.DIAGNOSTIC
        with self.assertRaisesRegex(ValueError, "Wrong route"):
            self.reconcile()
        self.oracles["oracle_matrix"][0]["leg_id"] = "lighttpd-stock-sidecar"
        self.oracles["oracle_matrix"][0]["original_selected_requirement"] = {"case_id": "changed"}
        with self.assertRaisesRegex(ValueError, "Changed original requirement"):
            self.reconcile()

    def test_stock_native_cannot_inherit_body_lifecycle_or_required_route(self):
        row = next(r for r in self.ledger["rows"] if r["leg_id"] == LEDGER.DIAGNOSTIC)
        row["qualification_scope"] = "full_host_lifecycle"
        with self.assertRaisesRegex(ValueError, "body-streaming"):
            self.reconcile()
        del row["qualification_scope"]
        row["required_leg"] = True
        with self.assertRaisesRegex(ValueError, "route confusion"):
            self.reconcile()

    def test_foreign_supplement_and_different_inventory_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-lighttpd"):
            self.reconcile({"nginx-native": []})
        self.oracles["original_ordered_id_sha256"] = "changed"
        with self.assertRaisesRegex(ValueError, "Different original inventory"):
            self.reconcile()

    def test_physical_source_rejects_symlink_parent_and_hardlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            physical = root / "physical"
            physical.mkdir()
            source = physical / "source.json"
            source.write_text("{}")
            (root / "alias").symlink_to(physical, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink components"):
                LEDGER.reference(root / "alias/source.json")
            self.assertEqual(LEDGER.snapshot(source)[0], b"{}")
            os.link(source, physical / "hardlink.json")
            with self.assertRaisesRegex(ValueError, "unshared"):
                LEDGER.reference(source)

    def test_outputs_are_exclusive_and_reject_symlink_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            LEDGER.write_files(output, {"summary.json": {"control": True}})
            original = (output / "summary.json").read_bytes()
            with self.assertRaisesRegex(ValueError, "existing output"):
                LEDGER.write_files(output, {"summary.json": {"control": False}})
            self.assertEqual((output / "summary.json").read_bytes(), original)
            (root / "alias").symlink_to(output, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink components"):
                LEDGER.write_files(root / "alias", {"another.json": {}})



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
