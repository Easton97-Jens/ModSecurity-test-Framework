"""Selection is dispatch input, never native execution or runtime PASS."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("nginx_selection_core", ROOT / "ci/checks/catalog/no_crs_baseline.py")
CORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORE)


class NativeSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = json.loads((ROOT / "tests/cases/no-crs-baseline/catalog.json").read_text())
        cls.cases = {case["case_id"]: case for case in cls.catalog["cases"]}
        cls.capabilities = {name: {"state": "verified", "reason": "controlled input selection"} for name in CORE.CAPABILITIES}

    def select(self, case_id, connector="nginx"):
        return CORE.select_catalog_case(self.cases[case_id], self.capabilities, "http1", connector)

    def test_all_42_closed_native_descriptors_and_aliases_are_projected(self):
        native = [case for case in self.catalog["cases"] if "native_invocations" in case]
        self.assertEqual(len(native), 42)
        for case in native:
            with self.subTest(case_id=case["case_id"]):
                selected = self.select(case["case_id"])
                self.assertEqual(selected["native_invocation"], case["native_invocations"]["nginx"])
                self.assertEqual(selected["selection_status"], "SELECTED")
                self.assertIsNone(selected["runner_case"])
                self.assertEqual(CORE.selected_case_invocation_errors(selected, case, "nginx"), [])
        for connector in ("apache", "haproxy", "envoy", "lighttpd", None):
            self.assertNotIn("native_invocation", self.select("phase4_body_reject", connector))

    def test_projection_is_independent_and_plan_semantics_rejects_mutation(self):
        case = self.cases["phase4_body_reject"]
        before = deepcopy(case)
        selected = self.select(case["case_id"])
        expected = {"connector": "nginx", "cases": [deepcopy(selected)]}
        plan = deepcopy(expected)
        plan["cases"][0]["native_invocation"]["expected_overrides"]["expected_native_status"] = 500
        self.assertFalse(CORE.plans_have_matching_semantics(plan, expected))
        selected["native_invocation"]["expected_overrides"]["expected_native_status"] = 404
        self.assertEqual(case, before)

    def test_wrong_native_contract_alias_operation_and_unknown_field_fail_projection(self):
        case = self.cases["phase4_end_of_stream_evaluation"]
        for field, value in (("contract_case_id", "phase4_body_reject"), ("source_record_id", "phase4_body_over_limit"),
                             ("operation", "request_sequence"), ("command", "invented-command")):
            changed = deepcopy(case)
            changed["native_invocations"]["nginx"][field] = value
            with self.subTest(field=field), self.assertRaises(CORE.ContractError):
                CORE.select_catalog_case(changed, self.capabilities, "http1", "nginx")

    def test_selected_input_invariant_rejects_all_null_and_foreign_bindings(self):
        case = self.cases["phase4_body_reject"]
        selected = self.select(case["case_id"])
        for field in ("native_invocation", "config_invocation", "runner_case"):
            selected[field] = None
        self.assertTrue(CORE.selected_case_invocation_errors(selected, case, "nginx"))
        for bad in ({}, {"operation": "native_phase4_request", "contract_case_id": "phase4_body_at_limit"}):
            changed = self.select(case["case_id"])
            changed["native_invocation"] = bad
            self.assertTrue(CORE.selected_case_invocation_errors(changed, case, "nginx"))
        self.assertEqual(CORE.selected_case_invocation_errors(selected, case, "apache"), [])
        selected["selection_status"] = "NOT_APPLICABLE"
        self.assertEqual(CORE.selected_case_invocation_errors(selected, case, "nginx"), [])

    def test_real_runner_and_config_are_alternatives_not_fake_yaml(self):
        for case_id in ("allow_without_marker", "valid_rules_file"):
            case = self.cases[case_id]
            self.assertEqual(CORE.selected_case_invocation_errors(self.select(case_id), case, "nginx"), [])
        case = deepcopy(self.cases["allow_without_marker"])
        for runner in ("missing.yaml", "../../../../AGENTS.md", "/etc/passwd"):
            case["runner_case"] = runner
            selected = CORE.select_catalog_case(case, self.capabilities, "http1", "nginx")
            self.assertTrue(CORE.selected_case_invocation_errors(selected, case, "nginx"))

    def test_cli_plan_rejects_selected_case_without_declared_input_not_filtering(self):
        catalog = deepcopy(self.catalog)
        case = next(case for case in catalog["cases"] if case["case_id"] == "allow_without_marker")
        case.pop("runner_case")
        # Preserve all cases; no native/config declaration or reduced plan is invented.
        with self.assertRaisesRegex(CORE.ContractError, "allow_without_marker"):
            CORE.select_cases("nginx", {"connector": "nginx", "capabilities": self.capabilities}, catalog,
                              artifact_profile="full_lifecycle", downstream_protocol="http1")

    def test_advisory_capability_only_plan_cannot_be_a_valid_runtime_manifest(self):
        advisory = {"capabilities": self.capabilities}
        self.assertTrue(CORE.validate_capability_manifest(advisory, "nginx"))
        self.assertTrue(CORE.capability_manifest_header_errors(advisory, "nginx"))

    def test_h2_h3_only_cases_remain_not_applicable_on_http1(self):
        for case in self.catalog["cases"]:
            if case.get("request", {}).get("protocol_profile") in ("h2", "h2c", "h3"):
                self.assertEqual(self.select(case["case_id"])["selection_status"], "NOT_APPLICABLE")

    def test_31_existing_execution_and_derived_contracts_are_explicit_not_fake_runners(self):
        expected = set("deny_response_header_marker_403 phase4_rule_observed phase4_deny_after_commit_log_only phase4_deny_after_commit_abort phase4_event_contains_original_status phase4_event_contains_late_intervention_action event_contains_connector event_contains_transaction_id event_contains_rule_id event_contains_phase event_contains_status event_has_no_request_body_payload event_has_no_response_body_payload allow deny phase1_allow phase1_deny_403 phase1_alternative_status phase1_redirect phase1_transaction_id phase2_request_body_rule phase2_no_payload_event phase3_response_header_rule phase3_original_and_visible_status phase4_deny_after_commit_log_only_safe phase4_deny_after_commit_abort_strict phase4_status_metadata phase4_action_metadata phase4_no_payload_event phase4_no_full_response_buffering phase4_first_byte_before_response_end".split())
        self.assertEqual(set(CORE.NGINX_DERIVED_INVOCATIONS), expected)
        self.assertEqual(CORE.nginx_derived_invocation_graph_errors(CORE.NGINX_DERIVED_INVOCATIONS), [])
        for case_id in expected:
            with self.subTest(case_id=case_id):
                selected = self.select(case_id)
                descriptor = CORE.derived_invocation_for_case(self.cases[case_id], "nginx")
                self.assertEqual(selected["derived_invocation"], descriptor)
                self.assertEqual(set(descriptor), {"operation", "source_case_ids", "mapping"})
                self.assertIsNone(selected["runner_case"])
                self.assertEqual(CORE.selected_case_invocation_errors(selected, self.cases[case_id], "nginx"), [])
                self.assertIsNone(CORE.derived_invocation_for_case(self.cases[case_id], "apache"))

    def test_derived_reuse_is_closed_cycle_free_and_semantically_immutable(self):
        case = self.cases["allow"]
        changed = deepcopy(case)
        changed["request"]["reuses"] = "deny_header_marker_403"
        with self.assertRaises(CORE.ContractError):
            CORE.derived_invocation_for_case(changed, "nginx")
        invented = deepcopy(case)
        invented["case_id"] = "invented_reuse"
        self.assertIsNone(CORE.derived_invocation_for_case(invented, "nginx"))
        cyclic = deepcopy(CORE.NGINX_DERIVED_INVOCATIONS)
        cyclic["allow"]["source_case_ids"] = ["deny"]
        cyclic["deny"]["source_case_ids"] = ["allow"]
        self.assertTrue(CORE.nginx_derived_invocation_graph_errors(cyclic))
        selected = self.select("allow")
        original = deepcopy(selected)
        selected["derived_invocation"]["mapping"] = "invented_mapping"
        self.assertTrue(CORE.selected_case_invocation_errors(selected, case, "nginx"))
        self.assertFalse(CORE.plans_have_matching_semantics({"cases": [selected]}, {"cases": [original]}))

    def test_existing_host_fixture_is_required_and_sources_are_existing_cases(self):
        for descriptor in CORE.NGINX_DERIVED_INVOCATIONS.values():
            self.assertTrue(set(descriptor["source_case_ids"]) <= set(self.cases))
        with patch.object(CORE, "FRAMEWORK_ROOT", ROOT / "absent-closed-fixture-root"):
            with self.assertRaises(CORE.ContractError):
                CORE.derived_invocation_for_case(self.cases["phase4_deny_after_commit_abort"], "nginx")
        with patch.object(CORE, "CATALOG_PATH", ROOT / "absent-closed-fixture-root/catalog.json"):
            with self.assertRaises(CORE.ContractError):
                CORE.derived_invocation_for_case(self.cases["phase4_first_byte_before_response_end"], "nginx")

    def test_runtime_manifest_and_fresh_plan_validation_do_not_accept_advisory_bypass(self):
        capabilities = {name: {"state": "verified" if name in ("request_headers", "phase1") else "not_implemented",
                               "reason": "controlled selection input, not host evidence"} for name in CORE.CAPABILITIES}
        manifest = {"schema_version": 1, "connector": "nginx", "host_name": "nginx",
                    "integration_mode": "native-nginx-http-module", "capabilities": capabilities,
                    "evidence_stages": {stage: {"status": "not_executed", "reason": "controlled input"} for stage in CORE.EVIDENCE_STAGES}}
        self.assertEqual(CORE.validate_capability_manifest(manifest, "nginx"), [])
        plan = CORE.select_cases("nginx", manifest, self.catalog, artifact_profile="full_lifecycle", downstream_protocol="http1")
        CORE.validate_plan_against_capabilities(plan, "nginx", manifest, self.catalog,
                                               "no_crs_baseline", "full_lifecycle", "http1")
        target = next(case for case in plan["cases"] if case["case_id"] == "allow")
        self.assertEqual(target["selection_status"], "SELECTED")
        target.pop("derived_invocation")
        with self.assertRaises(CORE.ContractError):
            CORE.validate_plan_against_capabilities(plan, "nginx", manifest, self.catalog,
                                                   "no_crs_baseline", "full_lifecycle", "http1")


if __name__ == "__main__":
    unittest.main()
