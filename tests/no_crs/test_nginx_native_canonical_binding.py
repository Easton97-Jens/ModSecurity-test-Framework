"""Controlled source-bound fixtures, never native runtime evidence."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import json
import unittest

from ci.checks.catalog import no_crs_baseline as contract
from tests.no_crs import test_nginx_native_operation_bundle as bundle_tests


class NativeCanonicalBindingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = bundle_tests.NativeBundleRouterTests("test_original_sealed_pointer_layer_not_canonical_pass")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.record["parent_framework_gitlink"] = self.fixture.sources["framework_sha"]
        self.cases = {case["case_id"]: case for case in contract.catalog_cases(contract.load_catalog())}
        self.authority = {"artifact_root": self.fixture.artifact, "sources": self.fixture.sources, "run_id": self.fixture.run_id}

    def normalize(self, raw=None, authority=None):
        return contract.normalize_case_record(
            raw or self.fixture.record, "nginx", self.cases, [], "native-nginx-http-module",
            native_operation_authority=authority or self.authority,
        )

    def test_real_reader_not_exit_zero_proves_controlled_pointer_layer(self):
        original = deepcopy(self.fixture.record)
        record = self.normalize()
        self.assertEqual(record["status"], "PASS", record["reason"])
        self.assertEqual((record["phase"], record["actual_status"], record["expected_status"]), (1, 400, 400))
        self.assertEqual(record["driver_exit_code"], 0)
        self.assertTrue(record["live_executed"])
        self.assertEqual(record["native_operation_receipt"], original["native_operation_receipt"])
        self.assertEqual(self.fixture.record, original)
        self.assertEqual(self.cases[self.fixture.case]["phase"], 2)

    def test_missing_authority_cannot_promote_exit_zero_or_candidate_pass(self):
        for status, expected in (("NOT_EXECUTED", "NOT_EXECUTED"), ("PASS", "FAIL")):
            raw = deepcopy(self.fixture.record)
            raw["status"] = status
            record = contract.normalize_case_record(raw, "nginx", self.cases, [], "native-nginx-http-module")
            self.assertEqual(record["status"], expected)
            self.assertIn("authority", record["reason"])

    def test_wrong_raw_digest_build_source_run_and_child_authority_stay_failure(self):
        original = deepcopy(self.fixture.record)
        for mutation in (lambda raw: raw.update(driver_exit_code=7),
                         lambda raw: raw.update(driver_exit_code=True),
                         lambda raw: raw.update(parent_framework_gitlink="f" * 40),
                         lambda raw: raw.update(parent_framework_gitlink=True),
                         lambda raw: raw.update(run_id="foreign"),
                         lambda raw: raw["native_operation_receipt"].update(bundle_root="../foreign"),
                         lambda raw: raw["native_operation_receipt"]["invocations"][0].update(receipt_sha256="f" * 64)):
            raw = deepcopy(original)
            mutation(raw)
            self.assertNotEqual(self.normalize(raw)["status"], "PASS")
        (self.fixture.output / "native-access.jsonl").write_bytes(b"{}")
        self.assertNotEqual(self.normalize()["status"], "PASS")

    def test_retention_reopens_bytes_seals_copies_and_rejects_duplicate(self):
        output = self.fixture.root / "canonical"
        output.mkdir()
        context = SimpleNamespace(case_by_id=self.cases, connector="nginx", run_dir=output,
                                  native_operation_authority=self.authority,
                                  native_operation_copied_cases=set(), manifest={"artifacts": {}})
        retained = contract.retain_finalize_native_operation_bundle(context, self.fixture.record)
        self.assertEqual(retained["native_operation_receipt"]["bundle_root"],
                         "inventory/native-operations/" + self.fixture.case)
        self.assertEqual(len(context.manifest["artifacts"]), len(self.fixture.validate()["files"]))
        canonical_authority = {"artifact_root": output, "sources": self.fixture.sources, "run_id": self.fixture.run_id}
        record = self.normalize(retained, canonical_authority)
        self.assertEqual(record["status"], "PASS", record["reason"])
        with self.assertRaises(contract.ContractError):
            contract.retain_finalize_native_operation_bundle(context, self.fixture.record)
        missing_authority_context = SimpleNamespace(**{**vars(context), "native_operation_authority": None})
        with self.assertRaises(contract.ContractError):
            contract.retain_finalize_native_operation_bundle(missing_authority_context, self.fixture.record)

    def test_offline_revalidation_rejects_forged_canonical_summary_and_changed_bytes(self):
        record = self.normalize()
        self.assertEqual(contract.native_operation_record_errors(record, self.authority, self.cases[self.fixture.case]), [])
        for field, value in (("actual_status", 200), ("phase", 2), ("observed_rule_ids", [1100001]),
                             ("native_mapping_sha256", "f" * 64), ("observed_event_fields", ["invented"])):
            changed = deepcopy(record)
            changed[field] = value
            self.assertTrue(contract.native_operation_record_errors(changed, self.authority, self.cases[self.fixture.case]))
        (self.fixture.output / "phase1-events.jsonl").write_bytes(b"{}")
        self.assertTrue(contract.native_operation_record_errors(record, self.authority, self.cases[self.fixture.case]))

    def test_schema_keeps_the_source_bound_wrapper_closed(self):
        record = self.normalize()
        schema = contract.load_no_crs_schemas()[contract.CASE_RESULTS_FILE_NAME]
        self.assertEqual(contract.json_schema_errors(record, schema), [])
        for field, value in (("unexpected", True), ("operation", "invented"), ("bundle_root", "../escape")):
            changed = deepcopy(record)
            changed["native_operation_receipt"][field] = value
            self.assertTrue(contract.json_schema_errors(changed, schema))

    def test_native_fact_origins_are_retained_closed_and_offline_reopened(self):
        record = self.normalize()
        self.assertEqual(record["observed_result"], "mapping_error")
        mapping = record["native_evidence_mapping"]
        self.assertEqual(mapping["semantics"]["phase"], 1)
        self.assertEqual(mapping["semantics"]["phase_scope"], "native_event")
        self.assertEqual(mapping["causes"][0]["event"], "protocol_error")
        self.assertTrue(mapping["event_origins"])
        self.assertEqual(mapping["event_origins"][0]["artifact"], "phase1-events.jsonl")
        self.assertEqual(contract.native_operation_record_errors(record, self.authority, self.cases[self.fixture.case]), [])
        schema = contract.load_no_crs_schemas()[contract.CASE_RESULTS_FILE_NAME]
        self.assertEqual(contract.json_schema_errors(record, schema), [])
        changed = deepcopy(record)
        changed["native_evidence_mapping"]["event_origins"][0]["artifact_sha256"] = "f" * 64
        self.assertTrue(contract.native_operation_record_errors(changed, self.authority, self.cases[self.fixture.case]))
        changed = deepcopy(record)
        changed["native_evidence_mapping"]["invented"] = True
        self.assertTrue(contract.json_schema_errors(changed, schema))
        changed = deepcopy(record)
        changed["native_evidence_mapping"]["event_origins"][0]["kind"] = "candidate_claim"
        self.assertTrue(contract.json_schema_errors(changed, schema))

    def test_actual_fail_and_blocked_statuses_are_not_promoted_by_valid_receipt(self):
        for status in ("FAIL", "BLOCKED"):
            raw = deepcopy(self.fixture.record)
            raw["status"] = status
            self.assertEqual(self.normalize(raw)["status"], status)

    def test_full_profile_native_pass_cannot_bypass_original_bundle(self):
        raw = deepcopy(self.fixture.record)
        raw.pop("native_operation_receipt")
        raw.update(status="PASS", observed_result="mapping_error", live_executed=True,
                   actual_status=self.cases[self.fixture.case]["expected_status"])
        context = SimpleNamespace(case_by_id=self.cases, connector="nginx", run_dir=self.fixture.root,
                                  artifact_profile="full_lifecycle", native_operation_authority=self.authority,
                                  manifest={"integration_mode": "native-nginx-http-module"},
                                  event_integration_mode="native-nginx-http-module",
                                  plan={"cases": [{"case_id": self.fixture.case, "selection_status": "SELECTED"}]})
        record, = contract.normalized_finalize_case_records(context, [raw], [])
        self.assertEqual(record["status"], "FAIL")
        self.assertIn("original source-bound operation bundle", record["reason"])

    def test_all12_controlled_phase4_mime_canonical_summaries_use_causal_original_event(self):
        from tests.runners import test_nginx_phase4_operations as phase4_tests
        from tests.no_crs import test_nginx_mime_operations as mime_tests
        from tests.runners import nginx_native_operation_bundle as bundle
        for case_id in sorted(bundle.PHASE4_CASES | bundle.MIME_CASES):
            receipt, raw = (mime_tests.unit_operation(case_id) if case_id in bundle.MIME_CASES else
                            phase4_tests.rejection_fixture() if case_id == "phase4_body_reject" else phase4_tests.fixture(case_id))
            if case_id in {"phase4_out_of_scope_content_type", "phase4_missing_content_type"}:
                # Model the existing native nonintervention completion shape.
                receipt["native_events"][-1].update(requested_action="allow", actual_action="allow",
                                                    transport_result="completed", late_intervention=False)
            if case_id == "phase4_deny_after_commit_log_only_minimal":
                # Controlled Source-shaped fields; not captured runtime and
                # never a mutation of a retained production receipt.
                event = next(row for row in receipt["native_events"] if row["event"] == "phase4_intervention")
                event.update(original_http_status=200, headers_sent=True)
            self.fixture.prepare_case(case_id, receipt["run_id"])
            self.fixture.decorate_phase4(receipt, raw, self.fixture.output)
            self.fixture.write_child(receipt, raw, self.fixture.output, "main", "source-result.json")
            self.fixture.record["parent_framework_gitlink"] = self.fixture.sources["framework_sha"]
            self.authority["run_id"] = self.fixture.run_id
            with self.subTest(case_id=case_id):
                record = self.normalize()
                self.assertEqual(record["status"], "PASS", record["reason"])
                origin = record["native_evidence_mapping"]["semantic_event_origin"]
                events = self.fixture.validate()["events"]
                chosen = events[origin["event_index"]]
                self.assertNotEqual(chosen["event"], "phase4_append")
                self.assertEqual(record["actual_action"], chosen.get("actual_action") or None)
                if case_id == "phase4_deny_after_commit_log_only_minimal":
                    self.assertEqual(record["actual_action"], "log_only")
                    self.assertTrue(record["late_intervention"])
                    self.assertEqual(record["expected_result"], "late_intervention_log_only_safe")
                schema = contract.load_no_crs_schemas()[contract.CASE_RESULTS_FILE_NAME]
                self.assertEqual(contract.json_schema_errors(record, schema), [])
                # Exercise the real aggregate projector as well as the
                # individual case schema; fixtures are not runtime evidence.
                result_schema = contract.load_no_crs_schemas()[contract.RESULT_FILE_NAME]
                facts, _ = contract.status_record_facts([record])
                aggregate = {"phase4_case_results": facts["phase4_case_results"]}
                projection_schema = {"properties": {"phase4_case_results":
                    result_schema["properties"]["phase4_case_results"]},
                    "$defs": result_schema["$defs"]}
                self.assertEqual(contract.json_schema_errors(aggregate, projection_schema), [])
                if case_id in {"phase4_out_of_scope_content_type", "phase4_missing_content_type"}:
                    for field, value in (("actual_action", "deny"), ("case_id", "phase4_body_at_limit"),
                                         ("expected_result", "connection_aborted_strict"),
                                         ("expected_rule_id", 1100301), ("observed_rule_ids", [1100301]),
                                         ("late_intervention", True), ("connection_aborted", True),
                                         ("transport_result", "connection_aborted")):
                        invalid = deepcopy(aggregate)
                        invalid["phase4_case_results"][0][field] = value
                        self.assertTrue(contract.json_schema_errors(invalid, projection_schema), field)
                self.assertEqual(contract.native_operation_record_errors(record, self.authority, self.cases[case_id]), [])
                changed = deepcopy(record)
                changed["actual_action"] = "allow" if chosen.get("actual_action") != "allow" else "deny"
                self.assertTrue(contract.native_operation_record_errors(changed, self.authority, self.cases[case_id]))

    def authority_file(self):
        path = self.fixture.root / "native-operation-authority.json"
        sources = self.fixture.sources
        metadata = {"schema_version": 1, "connector": "nginx", "run_id": self.fixture.run_id,
                    "artifact_root": str(self.fixture.artifact),
                    **{name: str(sources[name]) for name in ("parent_root", "framework_root")},
                    **{name: sources[name] for name in ("parent_sha", "framework_sha", "mrts_sha",
                                                       "binary_sha256", "module_sha256", "fault_library_sha256")}}
        original = json.dumps(metadata, indent=3).encode() + b"\n"
        path.write_bytes(original)
        path.chmod(0o400)
        expected = {name: metadata[name] for name in ("run_id", "parent_sha", "framework_sha", "mrts_sha")}
        return path, original, expected

    def test_authority_retention_preserves_original_bytes_and_independent_tuple(self):
        path, original, expected = self.authority_file()
        output = self.fixture.root / "canonical-authority"
        output.mkdir()
        context = SimpleNamespace(run_dir=output, manifest={"artifacts": {}}, native_operation_authority=None)
        loaded = contract.retain_finalize_native_authority(context, path, expected)
        destination = output / contract.NATIVE_AUTHORITY_FILE_PATH
        self.assertEqual(destination.read_bytes(), original)
        self.assertEqual(loaded["authority_bytes"], original)
        self.assertEqual(contract.retained_native_operation_authority(output, expected)["run_id"], self.fixture.run_id)
        self.assertEqual(contract.retained_native_operation_authority(output, expected, manifest=context.manifest)["run_id"], self.fixture.run_id)
        changed = {**expected, "framework_sha": "f" * 40}
        with self.assertRaises(contract.ContractError):
            contract.retained_native_operation_authority(output, changed)
        destination.write_bytes(b"{}")
        with self.assertRaises(contract.ContractError):
            contract.retained_native_operation_authority(output, expected)


if __name__ == "__main__":
    unittest.main()
