"""Input-plan invariants; these tests never qualify a host execution."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

import yaml


ROOT = connector_root()
CASES = load_source(source_path('ci/runtime/lifecycle/apache-i12/acceptance/cases.py', root=ROOT))


class AcceptanceCasesTest(unittest.TestCase):
    def setUp(self):
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
        selected = os.environ.get("I12_TEST_ROOT") or os.environ["RUNNER_TEMP"]
        temporary_root = validate_output_root(ROOT, Path(selected))
        self.temp = tempfile.TemporaryDirectory(prefix="apache-acceptance-cases-", dir=temporary_root)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.framework = self.root / "framework"
        self.fixture_root = self.framework / "tests/cases/no-crs-baseline"
        self.fixture_root.mkdir(parents=True)
        rules = self.framework / "tests/rules/no-crs-baseline.conf"
        rules.parent.mkdir(parents=True)
        rules.write_text("SecRuleEngine On\n")
        self.sdk = self.root / "transaction.cc"
        self.sdk.write_text("independent SDK source fixture\n")
        self.ledger = json.loads((source_path('reports/audits/apache-i12-20261015/case-ledger.json', root=ROOT)).read_text())
        self.catalog = []
        for row in self.ledger["rows"]:
            requirement = row["selected_requirement"]
            self.catalog.append({"case_id": requirement["case_id"],
                "phase": requirement["expected_oracle"]["phase"],
                "request": {}, "expected_status": requirement["expected_oracle"]["visible_status"],
                "expected_rule_id": requirement["expected_oracle"]["rule_id"]})

    def build(self):
        (self.fixture_root / "catalog.json").write_text(json.dumps({"cases": self.catalog,
            "ruleset": {"path": "tests/rules/no-crs-baseline.conf"}}))
        return CASES.build_plan(self.ledger, self.framework, [], self.sdk, yaml.safe_load)

    def row(self, plan, name):
        return next(r for r in plan["rows"] if r["case_id"] == name)

    def entry(self, name):
        return next(r for r in self.catalog if r["case_id"] == name)

    def test_all155_original_contracts_preserved_no_runtime_promotion(self):
        original = copy.deepcopy(self.ledger)
        result = self.build()
        self.assertEqual((result["host_cases"], result["config_cases"]), (145, 10))
        self.assertEqual([r["original_id"] for r in result["rows"]],
                         [r["run_scoped_case_id"] for r in original["rows"]])
        self.assertEqual([r["original_contract"] for r in result["rows"]],
                         [r["selected_requirement"] for r in original["rows"]])
        self.assertEqual(self.ledger, original)
        self.assertTrue(all(not r["full_lifecycle_qualified"] and r["oracle_reviewed_by"] is None
                            for r in result["rows"]))

    def test_unique_main_request_token_even_aliases(self):
        self.entry("allow")["request"] = {"reuses": "allow_without_marker"}
        self.entry("allow_without_marker")["request"] = {"path": "/original/allow"}
        result = self.build()
        tokens = [r["unique_main_request"]["token"] for r in result["rows"] if r["execution_kind"] == "host_http"]
        self.assertEqual(len(tokens), len(set(tokens)))
        self.assertEqual(self.row(result, "allow")["request"]["path"], "/original/allow")

    def test_p3_principal_marked_neighbor_healthy_unchanged_rule_source(self):
        entry = self.entry("phase3_deny_before_commit")
        entry["runner_case"] = "p3.yaml"
        fixture = {"request": {"method": "GET", "path": "/original/p3"},
            "response": {"headers": {"X-Modsec-Upstream": "block"}, "body": "original bytes"},
            "rules": "SecRuleEngine On\n"}
        (self.fixture_root / "p3.yaml").write_text(yaml.safe_dump(fixture))
        row = self.row(self.build(), "phase3_deny_before_commit")
        self.assertEqual(row["request"]["path"], "/original/p3")
        self.assertTrue(row["backend"]["principal_only"])
        self.assertIn(["X-Modsec-Upstream", "block"], row["backend"]["headers"])
        self.assertEqual(row["rules"], fixture["rules"])
        self.assertEqual(CASES.input_bytes(row["backend"]["body"]), b"original bytes")
        for control in row["controls"]:
            self.assertEqual(control["expected_status"], 200)
            self.assertFalse(any(name == "X-Modsec-Upstream" for name, _ in control["backend_headers"]))

    def test_reject_apache_host_variant_preserves_original_oracle_conflict(self):
        entry = self.entry("phase4_body_reject")
        entry["native_invocations"] = {"nginx": {"expected_overrides": {"expected_rule_id": None}}}
        row = self.row(self.build(), "phase4_body_reject")
        self.assertEqual(row["execution_kind"], "host_http")
        self.assertEqual(row["original_oracle"]["rule_id"], 1100301)
        self.assertEqual(row["limit_variant"]["native_limit_intervention_status"], 403)
        self.assertIsNone(row["limit_variant"]["native_limit_rule_id"])
        self.assertEqual(row["limit_variant"]["wire_bytes"], 17)
        self.assertEqual(row["backend"]["body"]["bytes"], 17)
        self.assertTrue(row["reconciliation_required"])
        self.assertIn("body_limit_outcome", row["required_original_event_fields"])

    def test_process_partial_does_not_claim_transport_truncation(self):
        row = self.row(self.build(), "phase2_truncated")
        self.assertEqual(row["limit_variant"]["native_action"], "ProcessPartial")
        self.assertFalse(row["limit_variant"]["actual_transport_truncation"])
        self.assertEqual(row["request"]["framing"], "content_length")
        transport = self.row(self.build(), "NEED-incomplete-framing")
        self.assertGreater(transport["request"]["declared_content_length"], transport["request"]["body"]["bytes"])
        self.assertEqual(transport["request"]["peer_action"], "shutdown_write_before_body_complete")

    def test_unknown_config_case_rejected_and_config_has_no_request(self):
        with self.assertRaisesRegex(ValueError, "unknown Apache configuration"):
            CASES.config_case("made_up_setting")
        for row in self.build()["rows"]:
            if row["execution_kind"] == "configtest":
                self.assertIsNone(row["config"]["request"])
                self.assertNotIn("request", row)

    def test_mime_variants_and_raw_alias_body_are_materialized(self):
        self.entry("deny_request_body_marker_403")["request"] = {
            "method": "POST", "body_fixture": "original-body-marker"}
        self.entry("phase2_no_payload_event")["request"] = {"reuses": "deny_request_body_marker_403"}
        self.entry("phase4_out_of_scope_content_type")["request"] = {"content_type_variant": "out_of_scope"}
        result = self.build()
        self.assertEqual(CASES.input_bytes(self.row(result, "phase2_no_payload_event")["request"]["body"]), b"original-body-marker")
        self.assertIn(["Content-Type", "image/png"], self.row(result, "phase4_out_of_scope_content_type")["backend"]["headers"])

    def test_actual_nonzero_body_for_null_pointer_fault(self):
        row = self.row(self.build(), "body_size_nonzero_with_null_data")
        self.assertGreater(row["request"]["body"]["bytes"], 0)
        self.assertEqual(row["request"]["method"], "POST")
        self.assertTrue(row["fault"]["must_observe_real_operation"])
        self.assertIsNone(row["fault"]["expected_return"])

    def test_lifecycle_fault_contract_does_not_invent_allocator_oom_requirement(self):
        result = self.build()
        for name, boundary in (("early_mapping_failure_cleanup", "msc_add_request_header"),
                               ("transaction_begin_failure_cleanup", "msc_new_transaction_with_id"),
                               ("finish_failure_propagation", "msc_process_logging")):
            row = self.row(result, name)
            contract = row["controlled_fault_contract"]
            self.assertEqual(row["fault"]["boundary"], boundary)
            self.assertFalse(contract["genuine_allocator_OOM_required"])
            self.assertFalse(contract["elapsed_timeout_budget_required"])
            self.assertFalse(contract["controlled_result_is_actual_sdk_return"])
            self.assertTrue(contract["require_actual_original_result_when_sdk_called"])
            self.assertIsNone(contract["activation_observed"])
            self.assertIsNone(contract["actual_sdk_result"])
            self.assertIn(row["fault"]["operation"], row["driver_seams"])
            self.assertIsNone(row["execution_observed"])
            self.assertIsNone(row["fault"]["expected_return"])
        begin = self.row(result, "transaction_begin_failure_cleanup")["controlled_fault_contract"]
        self.assertEqual(begin["sdk_call_policy"], "not_called_when_injected")
        self.assertIsNone(begin["controlled_effective_result"])

    def test_historical_technical_cases_are_controlled_returns_not_elapsed_timeouts(self):
        for mode, result, boundary, ordinal in (("precommit", 0, "msc_process_request_headers", 1),
                                               ("postcommit", -1, "msc_append_response_body", 2)):
            original = {"name": "technical-" + mode, "uri": "/technical-" + mode, "mode": "safe",
                        "request_limit": 1048576, "request_action": "Reject",
                        "response_limit": 1048576, "response_action": "Reject", "expected": {}, "fault": mode}
            plan = CASES.base_host("E2E-APACHE-TECHNICAL-" + mode.upper(), 0)
            CASES.historical_case(plan, original)
            contract = plan["controlled_fault_contract"]
            self.assertEqual(contract["boundary"], boundary)
            self.assertEqual(contract["controlled_effective_result"], result)
            self.assertEqual(contract["historical_fault_call_ordinal"], ordinal)
            self.assertFalse(contract["historical_sdk_called_on_fault"])
            self.assertFalse(contract["elapsed_timeout_budget_required"])
            self.assertIsNone(contract["activation_observed"])
            self.assertEqual(contract["require_actual_commit_before_fault"], mode == "postcommit")
            self.assertIn("native_" + mode, plan["driver_seams"])

    def test_sink_plans_preserve_first_failure_without_inventing_after16_activation(self):
        result = self.build()
        for name in ("NEED-physical-event-sink-open", "NEED-physical-event-sink-write",
                     "NEED-physical-event-sink-short-write", "NEED-physical-event-sink-flush",
                     "NEED-physical-event-sink-close"):
            row = self.row(result, name)
            self.assertEqual(row["fault"]["activation"], "exact_main_request_id_once")
            self.assertNotIn("after_rule120016", row["fault"]["operation"])
            self.assertLess(row["rules"].index("id:120001,"), row["rules"].index("id:120016,"))
            self.assertIsNone(row["execution_observed"])
        plan = CASES.base_host("E2E-APACHE-INVALID-EVENT-PATH", 0)
        plan["fault"] = CASES.fault("badpath", "physical_event_sink", "original_direct_runner_badpath")
        CASES._configure_historical_sink(plan, "E2E-APACHE-INVALID-EVENT-PATH")
        self.assertIn("without_delaying_first_sink_failure", plan["fault"]["activation"])
        self.assertIn("Source contradicted", plan["historical_planning_assumption"]["disposition"])
        self.assertNotIn("preserve120001_separate_control_and_prove_actual120016_before_sink_failure", plan["driver_seams"])

    def test_body_hash_tampering_and_duplicate_ids_fail(self):
        body = CASES.byte_input(b"real input")
        body["bytes"] += 1
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            CASES.input_bytes(body)
        self.ledger["rows"][1] = copy.deepcopy(self.ledger["rows"][0])
        with self.assertRaisesRegex(ValueError, "155 unique"):
            self.build()

    def test_alias_cycle_and_path_escape_rejected(self):
        self.entry("allow")["request"] = {"reuses": "deny"}
        self.entry("deny")["request"] = {"reuses": "allow"}
        with self.assertRaisesRegex(ValueError, "cyclic"):
            self.build()
        with self.assertRaisesRegex(ValueError, "outside"):
            CASES.fixture_for({"runner_case": "../../../../outside.yaml"}, self.framework, yaml.safe_load)

    def test_changed_original_oracle_and_unknown_id_rejected(self):
        self.ledger["rows"][0]["selected_requirement"]["expected_oracle"]["visible_status"] = 999
        with self.assertRaisesRegex(ValueError, "contracts changed"):
            self.build()
        self.ledger["rows"][0]["run_scoped_case_id"] = "I12::apache-native::invented"
        with self.assertRaisesRegex(ValueError, "ID order changed"):
            self.build()

    def test_original_removed_directive_config_contract_is_not_engine_size_parser(self):
        config = CASES.config_case("invalid_size")
        self.assertEqual(config["directives"], ["modsecurity_phase4_body_limit 1048576"])
        self.assertEqual(config["expected_exit_code"], 1)
        self.assertEqual(CASES.config_case("unknown_config_key")["directives"],
                         ["modsecurity_unknown_config_key on"])
        self.assertIn("status:not-a-number", CASES.config_case("invalid_status")["directives"][0])

    def test_metadata_uri_field_boundaries_do_not_claim_whole_writer_limit(self):
        result = self.build()
        metadata = self.row(result, "event_metadata_truncation")
        self.assertEqual(len(metadata["request"]["path"]), 4096)
        self.assertIn(["X-Modsec-Smoke", "log-only"], metadata["request"]["headers"])
        self.assertIsNone(metadata["fault"])
        self.assertFalse(metadata["driver_seams"])
        boundary = self.row(result, "event_json_limit")
        self.assertEqual(len(boundary["request"]["path"]), 255)
        self.assertEqual(len(boundary["principal_request_variants"][0]["request"]["path"]), 256)
        self.assertIn("actual_total_JSON_serializer_4096byte_boundary_proof", boundary["driver_seams"])
        self.assertFalse(boundary["full_lifecycle_qualified"])

    def test_generated_transaction_id_omits_expression_but_retains_backend_join(self):
        row = self.row(self.build(), "transaction_id_generated_or_fallback")
        self.assertIsNone(row["apache"]["transaction_id_expression"])
        self.assertIn(["X-I12-ID", row["unique_main_request"]["token"]], row["request"]["headers"])
        self.assertEqual(row["transaction_id_variant"]["client_header_role"], "independent_backend_join_only")
        self.assertIsNone(row["transaction_id_variant"]["native_generated_id_observed"])
        self.assertEqual(row["original_oracle"]["rule_id"], 1100502)

    def test_file_inputs_never_claim_unobserved_apr_file_buckets(self):
        result = self.build()
        for name in ("NEED-request-file", "NEED-response-file"):
            row = self.row(result, name)
            provenance = row["file_input_provenance"]
            self.assertFalse(provenance["local_payload_file_is_native_file_bucket"])
            self.assertIsNone(provenance["actual_APR_FILE_bucket_observed"])
            self.assertTrue(row["driver_seams"])
        self.assertEqual(self.row(result, "NEED-response-file")["candidate_expectation"]["backend_requests"], 0)

    def test_above_former_max_contains_tail_marker_with_higher_native_limit(self):
        result = self.build()
        for prefix, marker in (("request", CASES.REQUEST_MARKER), ("response", CASES.RESPONSE_MARKER)):
            row = self.row(result, "NEED-" + prefix + "-above-former-connector-limit")
            target = row["request"] if prefix == "request" else row["backend"]
            data = CASES.input_bytes(target["body"])
            self.assertEqual(len(data), 10 * 1024 * 1024 + 1)
            self.assertTrue(data.endswith(marker))
            self.assertEqual(row["former_limit_proof"]["native_limit_bytes"], 16 * 1024 * 1024)
            self.assertIsNone(row["former_limit_proof"]["source_reviewed_by"])
            self.assertIn("SecResponseBodyLimit 16777216", row["rules"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
