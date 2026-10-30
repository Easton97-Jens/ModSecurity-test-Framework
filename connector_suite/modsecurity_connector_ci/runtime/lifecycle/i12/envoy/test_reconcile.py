"""Synthetic validator controls; these fixtures do not establish host acceptance."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


MODULE = load_source(Path(__file__).with_name('reconcile.py'))
ORACLES = MODULE.ORACLES
HOST = MODULE.CURRENT.HOST_LEDGER


def _private_fixture_root() -> Path:
    from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root

    declared = os.environ.get("I12_TEST_ROOT") or os.environ.get("RUNNER_TEMP")
    if not declared:
        raise RuntimeError("I12_TEST_ROOT or RUNNER_TEMP must name existing private storage")
    return validate_output_root(connector_root(), Path(declared))


def _requirement_row(route: str, number: int, unknown: int) -> dict:
    identity = f"I12::{route}::control-{number}"
    oracle = {"visible_status": 200, "native_result": "allow", "phase": 2,
              "physical_evidence_not_projection": True,
              "unresolved_expected_value_reason": "Control missing oracle" if number < unknown else None}
    config = route == "envoy-ext-authz-request" and 40 <= number < 48
    return {"run_scoped_case_id": identity, "leg_id": route,
                 "required_leg": route != "diagnostic", "status": "PASS" if config else "PLANNED",
                 "execution_observed": config,
                 "selected_requirement": {"run_scoped_case_id": identity,
                                          "case_id": "control-" + str(number),
                                          "origin": "control", "expected_oracle": oracle}}


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="envoy-reconciliation-control-",
                                           dir=_private_fixture_root())
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        rows = []
        groups = [(route, count, unknown) for route, (count, unknown) in MODULE.ROUTES.items()]
        groups += [("control-route-" + str(n), 112 if n < 9 else 114, 48 if n < 9 else 39)
                   for n in range(10)]
        groups += [("diagnostic", 78, 0)]
        for route, count, unknown in groups:
            for n in range(count):
                rows.append(_requirement_row(route, n, unknown))
        self.requirements = {"rows": rows}
        self.selection = {"legs": [{"leg_id": row["leg_id"], "required_leg": row["required_leg"],
                                    "required_cases": [row["selected_requirement"]]} for row in rows],
                          "revisions": {}, "source_hashes": {}}
        ids = [row["run_scoped_case_id"] for row in rows]
        digest = hashlib.sha256(("\n".join(ids) + "\n").encode()).hexdigest()
        contracts = ORACLES.canonical_digest([row["selected_requirement"] for row in rows])
        for module in (ORACLES, HOST.ORACLES):
            for name, value in (("ID_SHA256", digest), ("CONTRACT_SHA256", contracts)):
                patch = mock.patch.object(module, name, value)
                patch.start()
                self.addCleanup(patch.stop)
        independent = self.write("independent.txt", "Independent validator control contract")
        self.records = []
        self.packets = []
        for route in MODULE.ROUTES:
            row = next(row for row in rows if row["leg_id"] == route)
            effective = copy.deepcopy(row["selected_requirement"]["expected_oracle"])
            effective["unresolved_expected_value_reason"] = None
            self.records.append({"run_scoped_case_id": row["run_scoped_case_id"], "leg_id": route,
                                 "reviewed_by": "root", "category": "SOURCE_CONFIRMED_EXPECTATION",
                                 "interpretation": "Synthetic validator control", "scope": route,
                                 "resolved_expectation": effective,
                                 "independent_sources": [{**independent, "kind": "protocol_contract", "revision": "control-v1"}]})
            measurement = self.write(route + ".measurement", "Synthetic measurements; no host run")
            observations = {field: {"value": 1, "evidence": [{**measurement, "role": role}
                            for role in sorted(roles)]} for field, roles in HOST.ROLES.items()}
            packet = {"run_scoped_case_id": row["run_scoped_case_id"], "leg_id": route,
                      "reviewed_by": "root", "execution_kind": "host_http", "execution_observed": True,
                      "run_id": "synthetic-control", "parent_sha": "control-parent", "framework_sha": "control-framework",
                      "mrts_sha": "control-mrts", "effective_config_sha256": "control-config",
                      "oracle_evaluated": True, "oracle_sha256": ORACLES.canonical_digest(effective),
                      "outcome": "PASS", "full_lifecycle_qualified": True, "observations": observations}
            self.packets.append(self.write(route + ".packet.json", packet))
        refs = [self.write("requirements.json", self.requirements), self.write("selection.json", self.selection),
                self.write("records.json", {"records": self.records})]
        for module, name, value in ((MODULE.CURRENT, "HISTORICAL_REQUIREMENTS_SHA256", refs[0]["sha256"]),
                                    (ORACLES, "SELECTION_SHA256", refs[1]["sha256"])):
            patch = mock.patch.object(module, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.oracles = ORACLES.reconcile(self.requirements, self.selection, self.records)
        self.oracles["input_evidence"] = refs
        self.ledger = HOST.build_ledger(self.requirements, self.selection, self.oracles, self.packets)

    def write(self, name, data):
        path = self.root / name
        path.write_text(data if isinstance(data, str) else json.dumps(data))
        return ORACLES.reference(path)

    def reconcile(self):
        return MODULE.reconcile(self.ledger, self.oracles)

    def test_exact_ids_separate_routes_and_inputs_untouched(self):
        before = copy.deepcopy((self.ledger, self.oracles))
        result = self.reconcile()
        self.assertEqual(result["summary"], {"original_ids": 284, "existing_lifecycle_pass": 3,
                         "configuration_only_pass": 8, "unqualified_ids": 273, "original_oracles": 125,
                         "resolved_original_oracles": 3, "open_original_oracles": 122})
        self.assertEqual(result["new_host_runs"], 0)
        expected_ids = [row["run_scoped_case_id"] for row in self.ledger["rows"] if row["leg_id"] in MODULE.ROUTES]
        self.assertEqual([row["run_scoped_case_id"] for row in result["rows"]], expected_ids)
        for route, expected in zip(MODULE.ROUTES, (116, 85, 72)):
            self.assertEqual(result["routes"][route]["unqualified_ids"], expected)
        self.assertEqual(before, (self.ledger, self.oracles))
        self.assertTrue(all(row["physical_evidence"] for row in result["rows"] if row["existing_host_packet"]))

    def test_case_route_and_contract_mutations_rejected(self):
        for field, value in (("leg_id", "envoy-ext-authz-request"),
                             ("run_scoped_case_id", "I12::envoy-ext-proc::invented")):
            with self.subTest(field=field):
                ledger = copy.deepcopy(self.ledger)
                ledger["rows"][0][field] = value
                with self.assertRaises(ValueError):
                    MODULE.reconcile(ledger, self.oracles)
        self.ledger["rows"][0]["selected_requirement"]["expected_oracle"]["phase"] = 4
        with self.assertRaisesRegex(ValueError, "contracts changed"):
            self.reconcile()

    def test_original_oracle_inventory_and_summary_cannot_be_altered(self):
        for key in ("original_596_ordered_ids", "oracle_matrix", "original_ordered_ids"):
            changed = copy.deepcopy(self.oracles)
            changed[key] = changed[key][1:]
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "inventory"):
                MODULE.reconcile(self.ledger, changed)
        self.ledger["summary"]["full_lifecycle_pass"] = 99
        with self.assertRaisesRegex(ValueError, "summary differs"):
            self.reconcile()

    def test_mutually_consistent_false_oracle_counts_rejected(self):
        self.oracles["summary"]["resolved_original_oracles"] += 1
        self.ledger["summary"]["oracle_counts"] = copy.deepcopy(self.oracles["summary"])
        with self.assertRaisesRegex(ValueError, "inventory"):
            self.reconcile()

    def test_physical_packet_hash_and_measurement_hash_required(self):
        Path(self.packets[0]["path"]).write_text("{}")
        with self.assertRaisesRegex(ValueError, "SHA256"):
            self.reconcile()

    def test_changed_physical_measurement_rejected(self):
        (self.root / "envoy-ext-proc.measurement").write_text("Changed after capture")
        with self.assertRaisesRegex(ValueError, "SHA256"):
            self.reconcile()

    def test_sibling_packet_transfer_rejected(self):
        source = next(row for row in self.ledger["rows"] if row["leg_id"] == "envoy-ext-proc")
        target = next(row for row in self.ledger["rows"] if row["leg_id"] == "envoy-ext-authz-response-companion")
        target["current_lifecycle_packet"] = copy.deepcopy(source["current_lifecycle_packet"])
        with self.assertRaisesRegex(ValueError, "sibling route or case"):
            self.reconcile()

    def test_unknown_observation_does_not_become_pass(self):
        path = Path(self.packets[0]["path"])
        packet = json.loads(path.read_text())
        packet["observations"]["native_eos"] = {"value": None, "reason": "Not observed"}
        # Even a freshly rehashed packet cannot manufacture missing EOS.
        self.packets[0] = self.write(path.name, packet)
        with self.assertRaisesRegex(ValueError, "missing observation"):
            HOST.build_ledger(self.requirements, self.selection, self.oracles, self.packets)
        packet["full_lifecycle_qualified"] = False
        self.packets[0] = self.write(path.name, packet)
        self.ledger = HOST.build_ledger(self.requirements, self.selection, self.oracles, self.packets)
        result = self.reconcile()
        self.assertEqual(result["summary"]["existing_lifecycle_pass"], 2)
        self.assertEqual(result["rows"][0]["unknown_observations"], ["native_eos"])

    def test_cli_exclusive_output_preserves_inputs(self):
        ledger = self.write("ledger.json", self.ledger)
        oracles = self.write("oracles.json", self.oracles)
        output = self.root / "result.json"
        argv = ["reconcile", "--ledger", ledger["path"], "--oracles", oracles["path"], "--output", str(output)]
        with mock.patch("sys.argv", argv):
            MODULE.main()
        self.assertEqual(json.loads(output.read_text())["summary"]["original_ids"], 284)
        ORACLES.verify_reference(ledger)
        ORACLES.verify_reference(oracles)
        with mock.patch("sys.argv", argv), self.assertRaises(FileExistsError):
            MODULE.main()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
