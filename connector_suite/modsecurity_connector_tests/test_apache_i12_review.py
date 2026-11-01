"""Keep main/neighbor identity and physical FD differences independent of oracles."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


PATH = connector_root() / "ci/runtime/lifecycle/apache-i12/review.py"
REVIEW = load_source(PATH)


class ReviewTest(unittest.TestCase):
    def setUp(self):
        root = Path(os.environ.get("CODEX_TEST_TMP_ROOT") or os.environ.get("RUNNER_TEMP") or
                    "/var/tmp/codex/ModSecurity-conector/runs/i12-apache-410-20261015/review-tests")
        root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)
        (self.data / "client").mkdir()

    def client(self, token, path, process):
        (self.data / "client" / (token + ".receipt.json")).write_text(json.dumps({"path": path}))
        (self.data / "client" / (token + ".actual-process.json")).write_text(json.dumps(process))

    def test_neighbor_role_wins_when_original_uri_equals_neighbor(self):
        self.client("main", "/no-crs/allow", {"actual_waited_exit_code": 0})
        self.client("neighbor", "/no-crs/allow", {"role": "separate_original_allow_neighbor", "main_client_token": "main"})
        main, neighbors = REVIEW.choose_clients(self.data, "/no-crs/allow")
        self.assertEqual(main[0].name, "main.receipt.json")
        self.assertEqual(len(neighbors), 1)

    def test_unbound_neighbor_token_cannot_transfer(self):
        self.client("main", "/test", {})
        self.client("neighbor", "/no-crs/allow", {"role": "separate_original_allow_neighbor", "main_client_token": "foreign"})
        _, neighbors = REVIEW.choose_clients(self.data, "/test")
        self.assertEqual(neighbors, [])

    def test_ambiguous_main_client_is_rejected(self):
        self.client("first", "/test", {})
        self.client("second", "/test", {})
        with self.assertRaisesRegex(ValueError, "exactly one"):
            REVIEW.choose_clients(self.data, "/test")

    def test_association_uses_method_time_pid_and_typed_scope(self):
        client = {"path": "/test", "method": "POST", "started_ns": 100, "completed_ns": 200}
        host = [{"kind": "host_context_associated", "request_uri": "/test", "request_method": "POST",
                 "monotonic_ns": 150, "pid": 44, "allocation_scope_call": 9}]
        api = [{"pid": 44, "allocation_scope_call": 9, "allocation_scope_kind": "host"},
               {"pid": 99, "allocation_scope_call": 9, "allocation_scope_kind": "host"},
               {"pid": 44, "allocation_scope_call": 9, "allocation_scope_kind": "other"}]
        _, _, selected = REVIEW.associate(host, api, client)
        self.assertEqual(selected, api[:1])
        host[0]["monotonic_ns"] = 99
        with self.assertRaisesRegex(ValueError, "timed host association"):
            REVIEW.associate(host, api, client)

    def test_fd_reuse_is_a_changed_target_not_count_equality(self):
        delta = REVIEW.fd_difference({"3": "socket:[111]", "4": "/task/log"},
                                     {"3": "socket:[222]", "4": "/task/log"})
        self.assertEqual(delta["before_count"], delta["after_count"])
        self.assertEqual(delta["changed"], {"3": {"before": "socket:[111]", "after": "socket:[222]"}})
        self.assertEqual(delta["after_socket_targets"], ["socket:[222]"])

    def test_physical_missing_file_is_not_empty_evidence(self):
        with self.assertRaises(FileNotFoundError):
            REVIEW.reference(self.data / "missing", "backend_process")

    def test_corrected_duplicate_variant_keeps_exact_original_id(self):
        settings = {"original_selected_id": "I12::apache-native::duplicate_header_names"}
        contract = {"original_selected_requirement": {"name": "duplicate_header_names"}}
        self.assertEqual(REVIEW.selected_identity(settings, contract, "duplicate_header_names_apache_core_merged"),
                         "I12::apache-native::duplicate_header_names")
        self.assertEqual(contract["original_selected_requirement"]["name"], "duplicate_header_names")

    def test_variant_cannot_claim_sibling_or_unknown_original(self):
        contract = {"original_selected_requirement": {"name": "duplicate_header_names"}}
        for selected in ("I12::nginx-native::duplicate_header_names", "I12::apache-native::unknown_original"):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                REVIEW.selected_identity({"original_selected_id": selected}, contract,
                                         "duplicate_header_names_apache_core_merged")
        with self.assertRaisesRegex(ValueError, "aliases"):
            REVIEW.selected_identity({"original_selected_id": "I12::apache-native::duplicate_header_names"},
                                     contract, "some_other_execution")

    def test_regular_missing_fixture_contract_keeps_same_selected_id(self):
        self.assertEqual(REVIEW.selected_identity({"original_selected_id": "I12::apache-native::NEED-request-empty"},
                         {"original_selected_requirement": {"case_id": "NEED-request-empty"}}, "NEED-request-empty"),
                         "I12::apache-native::NEED-request-empty")

    def test_declared_phase3_filename_binding_requires_exact_source_hash(self):
        name = "phase3_deny_before_commit"
        settings = {"original_selected_id": "I12::apache-native::" + name,
                    "original_source_path": "/source/" + name + ".yaml",
                    "original_source_sha256": "7de9543c83206019ae7e77f158dd7325e7713d2c31583daeb0e012bba6d67f37"}
        contract = {"original_selected_requirement": {"name": name + "_fixture"}}
        self.assertEqual(REVIEW.selected_identity(settings, contract, name), settings["original_selected_id"])
        settings["original_source_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            REVIEW.selected_identity(settings, contract, name)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
