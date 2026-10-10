"""Closed input registrations, not proof of native execution or PASS."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("no_crs_baseline", ROOT / "ci/checks/catalog/no_crs_baseline.py")
no_crs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(no_crs)
RAW = frozenset("invalid_content_length conflicting_content_length duplicate_transfer_encoding content_length_overflow".split())
POINTER = frozenset("body_size_nonzero_with_null_data header_count_nonzero_with_null_headers".split())
PHASE4 = frozenset("phase4_marker_split_across_chunks phase4_end_of_stream_evaluation phase4_deny_after_commit_log_only_minimal phase4_body_at_limit phase4_body_over_limit phase4_body_process_partial phase4_body_reject full_lifecycle_event_metadata_bounded".split())
MIME = frozenset("phase4_in_scope_content_type phase4_content_type_with_charset phase4_out_of_scope_content_type phase4_missing_content_type".split())
SEQUENCE = frozenset("single_request_cleanup multiple_sequential_requests keep_alive_requests_if_supported clean_shutdown early_mapping_failure_cleanup transaction_begin_failure_cleanup finish_failure_propagation phase4_strict_http1_client_abort phase4_strict_host_survives phase4_strict_followup_request_succeeds keepalive_allow_allow keepalive_allow_deny_allow keepalive_safe_followup keepalive_after_strict_new_connection engine_timeout_before_commit engine_timeout_after_commit response_short_write_resume response_write_would_block_resume transport_keep_alive transport_sequential_requests transport_http11_content_length transport_http11_chunked".split())
EVENT = frozenset("event_metadata_truncation event_json_limit".split())
GROUPS = {"native_h1_parser_rejection": RAW, "common_mapper_input_fault": POINTER,
          "native_phase4_request": PHASE4 | MIME, "request_sequence": SEQUENCE,
          "native_event_boundary_request": EVENT}
IDS = frozenset().union(*GROUPS.values())
ALIASES = {"phase4_end_of_stream_evaluation": "phase4_marker_split_across_chunks",
           "full_lifecycle_event_metadata_bounded": "phase4_body_over_limit"}


class NativeInvocationCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = json.loads((ROOT / "tests/cases/no-crs-baseline/catalog.json").read_text())
        cls.schema = json.loads((ROOT / "tests/schemas/no-crs-baseline/case-catalog.schema.json").read_text())
        cls.cases = {case["case_id"]: case for case in cls.catalog["cases"]}

    def schema_errors(self, value):
        return no_crs.json_schema_errors(value, self.schema, root_schema=self.schema, location="catalog")

    def test_exact_42_closed_registrations_bind_existing_case_identity(self):
        self.assertEqual(len(IDS), 42)
        registered = {key for key, case in self.cases.items() if "native_invocations" in case}
        self.assertEqual(registered, IDS)
        for operation, ids in GROUPS.items():
            for case_id in ids:
                with self.subTest(case_id=case_id):
                    invocation = self.cases[case_id]["native_invocations"]
                    self.assertEqual(set(invocation), {"nginx"})
                    descriptor = invocation["nginx"]
                    self.assertEqual(descriptor["operation"], operation)
                    self.assertEqual(descriptor["contract_case_id"], case_id)
                    self.assertEqual(descriptor.get("source_record_id"), ALIASES.get(case_id))

    def test_schema_accepts_complete_catalog(self):
        self.assertEqual(self.schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(self.schema_errors(self.catalog), [])

    def test_schema_rejects_unknown_wrong_case_alias_operation_and_extra_fields(self):
        mutations = (
            ("operation", "invented"), ("operation", "request_sequence"),
            ("contract_case_id", "allow_without_marker"), ("contract_case_id", "phase4_body_at_limit"),
            ("source_record_id", "phase4_body_over_limit"), ("source_record_id", "../foreign"),
            ("unexpected", True), ("contract_case_id", 1),
            ("expected_overrides", {"expected_rule_id": 999}),
        )
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                changed = deepcopy(self.catalog)
                case = next(case for case in changed["cases"] if case["case_id"] == "phase4_marker_split_across_chunks")
                case.setdefault("native_invocations", {"nginx": {"operation": "native_phase4_request", "contract_case_id": case["case_id"]}})["nginx"][key] = value
                self.assertTrue(self.schema_errors(changed))
        for bad in ({}, {"other_connector": {}}, {"nginx": {}}):
            changed = deepcopy(self.catalog)
            changed["cases"][0]["native_invocations"] = bad
            self.assertTrue(self.schema_errors(changed))

    def test_generic_expectations_are_not_migrated_for_other_connectors(self):
        expected = {
            "body_size_nonzero_with_null_data": (500, None, "mapping_error"),
            "header_count_nonzero_with_null_headers": (500, None, "mapping_error"),
            "phase4_body_reject": (None, 1100301, "response_body_reject"),
            "phase4_deny_after_commit_log_only_minimal": (None, 1100301, "late_intervention_log_only_minimal"),
            "finish_failure_propagation": (500, None, "failure_propagated_and_cleaned"),
            "engine_timeout_before_commit": (None, 1100301, "engine_timeout_before_commit"),
            "engine_timeout_after_commit": (None, 1100301, "engine_timeout_after_commit"),
        }
        for case_id, values in expected.items():
            case = self.cases[case_id]
            self.assertEqual(tuple(case[key] for key in ("expected_status", "expected_rule_id", "expected_result")), values)

    def test_required_descriptor_and_alias_cannot_be_removed_or_cross_bound(self):
        for case_id in IDS:
            with self.subTest(case_id=case_id):
                changed = deepcopy(self.catalog)
                case = next(case for case in changed["cases"] if case["case_id"] == case_id)
                case.pop("native_invocations")
                self.assertTrue(self.schema_errors(changed))
        for case_id, alias in ALIASES.items():
            changed = deepcopy(self.catalog)
            case = next(case for case in changed["cases"] if case["case_id"] == case_id)
            case["native_invocations"]["nginx"]["source_record_id"] = case_id
            self.assertTrue(self.schema_errors(changed))

    def test_explicit_nginx_only_migrations_preserve_native_and_wire_distinction(self):
        expected = {
            "body_size_nonzero_with_null_data": {"expected_status": 400, "phase": 1},
            "header_count_nonzero_with_null_headers": {"expected_status": 400},
            "phase4_deny_after_commit_log_only_minimal": {"expected_status": 200, "expected_result": "late_intervention_log_only_safe", "nginx_phase4_mode": "safe"},
            "phase4_body_reject": {"expected_status": 200, "expected_rule_id": None, "expected_native_status": 403, "expected_engine_error_class": "body_limit"},
            "finish_failure_propagation": {"expected_status": 200},
            "clean_shutdown": {"expected_status": 200},
            "engine_timeout_before_commit": {"expected_status": 504, "expected_rule_id": None, "expected_native_status": 504, "expected_engine_error_class": "engine_timeout", "phase": 1},
            "engine_timeout_after_commit": {"expected_status": 200, "expected_rule_id": None, "expected_native_status": 504, "expected_engine_error_class": "engine_timeout"},
            "phase4_out_of_scope_content_type": {"expected_status": 200, "expected_rule_id": None},
            "phase4_missing_content_type": {"expected_status": 200, "expected_rule_id": None},
        }
        actual = {case_id: case["native_invocations"]["nginx"]["expected_overrides"]
                  for case_id, case in self.cases.items()
                  if "expected_overrides" in case.get("native_invocations", {}).get("nginx", {})}
        self.assertEqual(actual, expected)

    def test_actual_nginx_phase_is_closed_without_changing_generic_phase(self):
        for case_id, generic_phase in (("body_size_nonzero_with_null_data", 2),
                                       ("engine_timeout_before_commit", 4)):
            with self.subTest(case_id=case_id):
                case = self.cases[case_id]
                self.assertEqual(case["phase"], generic_phase)
                self.assertEqual(case["native_invocations"]["nginx"]["expected_overrides"]["phase"], 1)
                for invalid in (generic_phase, 0, 5, "1", True, None):
                    changed = deepcopy(self.catalog)
                    target = next(c for c in changed["cases"] if c["case_id"] == case_id)
                    target["native_invocations"]["nginx"]["expected_overrides"]["phase"] = invalid
                    self.assertTrue(self.schema_errors(changed), repr(invalid))
                changed = deepcopy(self.catalog)
                target = next(c for c in changed["cases"] if c["case_id"] == case_id)
                del target["native_invocations"]["nginx"]["expected_overrides"]["phase"]
                self.assertTrue(self.schema_errors(changed))

    def test_available_closed_helpers_support_registered_inputs(self):
        """Missing delegated helpers are disclosed, not replaced by inventions."""
        sys.path.insert(0, str(ROOT / "tests/runners"))
        self.addCleanup(sys.path.remove, str(ROOT / "tests/runners"))
        found = 0
        helpers = (("nginx_phase4_contracts", PHASE4, "RECORD_IDS"),
                   ("nginx_raw_h1", RAW, "RECORD_IDS"),
                   ("nginx_common_input_faults", POINTER, "CONTRACTS"),
                   ("nginx_mime_operations", MIME, "CONTENT_TYPES"),
                   ("nginx_lifecycle_sequence", SEQUENCE, "SEQUENCES"),
                   ("nginx_event_boundary_operations", EVENT, "IDS"))
        for name, ids, registry in helpers:
            path = ROOT / "tests/runners" / (name + ".py")
            if not path.exists():
                continue
            spec = importlib.util.spec_from_file_location(name, path)
            helper = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(helper)
            self.assertEqual(set(getattr(helper, registry)), ids)
            if name in ("nginx_phase4_contracts", "nginx_mime_operations"):
                for case_id in ids:
                    operation = helper.operation(case_id)
                    self.assertEqual(operation["record_id"], case_id)
                    self.assertEqual(operation["operation"], "native_phase4_request")
                    self.assertEqual(operation["source_record_id"], ALIASES.get(case_id, case_id))
            if name == "nginx_event_boundary_operations":
                for case_id in ids:
                    for variant in (("long-query",) if case_id == "event_metadata_truncation" else ("at255", "over256")):
                        self.assertEqual(helper.operation(case_id, variant)["record_id"], case_id)
            found += 1
        self.assertGreater(found, 0)


if __name__ == "__main__":
    unittest.main()
