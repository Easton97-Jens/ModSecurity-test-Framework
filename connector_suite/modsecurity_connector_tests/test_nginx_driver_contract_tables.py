"""Characterize producer inputs independently; these tests prove no runtime."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest


ROOT = connector_root()
DRIVERS = source_path('ci/runtime/lifecycle', root=ROOT)

FRAMEWORK = Path(os.environ.get("FRAMEWORK_ROOT", source_path('modules/ModSecurity-test-Framework', root=ROOT)))


def load_driver(leaf):
    module = load_source(DRIVERS / leaf)
    return module


CONFIG = load_driver("run-nginx-configtest.py")
SEQUENCE = load_driver("run-nginx-lifecycle-sequences.py")
CONFIG_SNAPSHOT = "7c8ac0a236988ce944635b3cfe98896112ec6cbb4f4b31bad92032ba625463df"
CONFIG_KEYS = ("operation", "directive", "value", "expected_exit_code",
               "expected_outcome", "error_class", "diagnostic_fragments")
EXPECTED_SEQUENCES = [
    ("single_request_cleanup", (200,)),
    ("multiple_sequential_requests", (200, 403, 200)),
    ("keep_alive_requests_if_supported", (200, 403, 200)),
    ("clean_shutdown", (200,)),
    ("keepalive_allow_allow", (200, 200)),
    ("keepalive_allow_deny_allow", (200, 403, 200)),
    ("early_mapping_failure_cleanup", (500,)),
    ("transaction_begin_failure_cleanup", (500,)),
    ("phase4_strict_http1_client_abort", (200,)),
    ("phase4_strict_host_survives", (200, 200)),
    ("phase4_strict_followup_request_succeeds", (200, 200)),
    ("keepalive_after_strict_new_connection", (200, 200)),
    ("keepalive_safe_followup", (200, 200)),
    ("response_short_write_resume", (200,)),
    ("response_write_would_block_resume", (200,)),
    ("transport_keep_alive", (200, 200)),
    ("transport_sequential_requests", (200, 403, 200)),
    ("finish_failure_propagation", (200,)),
    ("engine_timeout_before_commit", (504,)),
    ("engine_timeout_after_commit", (200,)),
    ("transport_http11_content_length", (200,)),
    ("transport_http11_chunked", (200,)),
]


def config_snapshot(table):
    return hashlib.sha256(json.dumps(table, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


class DriverContractTablesTest(unittest.TestCase):
    def test_constructor_creates_independent_input_only_diagnostic_lists(self):
        first = CONFIG.rejection_contract("case", "directive", "value", "diagnostic")
        second = CONFIG.rejection_contract("case", "directive", "value", "diagnostic")
        self.assertEqual(first, second)
        self.assertIsNot(first["diagnostic_fragments"], second["diagnostic_fragments"])
        first["diagnostic_fragments"].append("changed")
        self.assertEqual(second["diagnostic_fragments"], ["diagnostic"])
        self.assertEqual(tuple(second), CONFIG_KEYS)
        self.assertNotIn("status", second)
        self.assertNotIn("observed_exit_code", second)

    def test_all_nine_full_config_contracts_and_key_order_match_frozen_baseline(self):
        self.assertEqual(len(CONFIG.CONFIGTEST_CONTRACTS), 9)
        self.assertEqual(config_snapshot(CONFIG.CONFIGTEST_CONTRACTS), CONFIG_SNAPSHOT)
        for case_id, contract in CONFIG.CONFIGTEST_CONTRACTS.items():
            with self.subTest(case=case_id):
                self.assertEqual(tuple(contract), CONFIG_KEYS)
                self.assertIs(type(contract["expected_exit_code"]), int)
                self.assertIs(type(contract["diagnostic_fragments"]), list)
                self.assertTrue(all(type(value) is str for value in contract["diagnostic_fragments"]))

    def test_all_twenty_two_schedules_and_order_match_frozen_baseline(self):
        self.assertEqual(list(SEQUENCE.SEQUENCES.items()), EXPECTED_SEQUENCES)
        for statuses in SEQUENCE.SEQUENCES.values():
            self.assertIs(type(statuses), tuple)
            self.assertTrue(all(type(status) is int for status in statuses))

    def test_config_snapshot_detects_each_changed_field_and_key_order(self):
        replacements = {"operation": "startup", "directive": "other", "value": "other",
                        "expected_exit_code": True, "expected_outcome": "config_accepted",
                        "error_class": "other", "diagnostic_fragments": ["other"]}
        for case_id in CONFIG.CONFIGTEST_CONTRACTS:
            for key, replacement in replacements.items():
                with self.subTest(case=case_id, field=key):
                    altered = copy.deepcopy(CONFIG.CONFIGTEST_CONTRACTS)
                    altered[case_id][key] = replacement
                    self.assertNotEqual(config_snapshot(altered), CONFIG_SNAPSHOT)
            altered = copy.deepcopy(CONFIG.CONFIGTEST_CONTRACTS)
            altered[case_id] = dict(reversed(list(altered[case_id].items())))
            self.assertNotEqual(config_snapshot(altered), CONFIG_SNAPSHOT)

    def test_sequence_snapshot_detects_changed_case_status_and_order(self):
        for index, (case_id, statuses) in enumerate(EXPECTED_SEQUENCES):
            altered = list(SEQUENCE.SEQUENCES.items())
            altered[index] = (case_id, (999, *statuses[1:]))
            self.assertNotEqual(altered, EXPECTED_SEQUENCES)
            altered[index] = (case_id + "_other", statuses)
            self.assertNotEqual(altered, EXPECTED_SEQUENCES)
        self.assertNotEqual(list(reversed(SEQUENCE.SEQUENCES.items())), EXPECTED_SEQUENCES)

    def test_config_inputs_equal_independent_framework_catalog(self):
        catalog = json.loads((FRAMEWORK / "tests/cases/no-crs-baseline/catalog.json").read_text())
        cases = {case["case_id"]: case for case in catalog["cases"]}
        for case_id, contract in CONFIG.CONFIGTEST_CONTRACTS.items():
            with self.subTest(case=case_id):
                self.assertEqual(contract, cases[case_id]["config_invocations"]["nginx"])

    def test_sequence_inputs_equal_independent_framework_literal_contract(self):
        tree = ast.parse((FRAMEWORK / "tests/runners/nginx_lifecycle_sequence.py").read_text())
        assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == "SEQUENCES"
                                  for target in node.targets))
        expected = ast.literal_eval(assignment.value)
        self.assertEqual(list(SEQUENCE.SEQUENCES.items()), list(expected.items()))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
