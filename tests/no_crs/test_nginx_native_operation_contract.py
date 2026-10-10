"""Controlled fact fixtures, not native execution or canonical acceptance."""
from copy import deepcopy
import json
import unittest

from tests.no_crs import test_nginx_native_operation_projection as fixtures
from tests.runners import nginx_native_operation_contract as contract


class NativeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.NativeProjectionTests.setUpClass()

    def fixture(self, case_id):
        case, proof = fixtures.NativeProjectionTests().fixture(case_id)
        for name in proof["raw_artifacts"]:
            events = proof["events"]
            if case_id == "event_json_limit":
                tx = proof["transaction_ids"][0 if name == "at" else 1]
                events = [row for row in events if row["transaction_id"] == tx]
            proof["raw_artifacts"][name]["phase1-events.jsonl"] = b"\n".join(json.dumps(row).encode() for row in events)
        return case, proof

    def test_pointer_facts_keep_native_and_visible_status_separate_without_status(self):
        case, proof = self.fixture("body_size_nonzero_with_null_data")
        proof["events"][0]["http_status"] = 400
        proof["raw_artifacts"]["main"]["phase1-events.jsonl"] = b"\n".join(json.dumps(row).encode() for row in proof["events"])
        original = deepcopy((case, proof))
        value = contract.derive_native_operation_contract(case, proof)
        self.assertEqual(value["actual_status"], 400)
        self.assertEqual(value["semanticValues"]["phase"], 1)
        self.assertEqual(value["semanticValues"]["expected_result"], "mapping_error")
        self.assertEqual(value["observed_rule_ids"], [])
        self.assertEqual(value["native_cause"][0]["http_status"], 400)
        self.assertEqual(value["observed_event_fields"], sorted(proof["events"][0]))
        self.assertNotIn("status", value)
        self.assertNotIn("canonical_status", value)
        actual_inputs = (case, proof)
        self.assertEqual(actual_inputs, original)

    def test_event_boundary_truncated_has_actual_line_origin_not_added_event_key(self):
        case, proof = self.fixture("event_metadata_truncation")
        value = contract.derive_native_operation_contract(case, proof)
        self.assertEqual(value["mapped_evidence_fields"]["truncated"], [True])
        origin = value["mapped_evidence_origins"]["truncated"][0]
        self.assertEqual(origin["kind"], "native_event")
        self.assertEqual(origin["source_pointer"], "/events/0/truncated")
        self.assertEqual(len(origin["artifact_sha256"]), 64)
        self.assertEqual(origin["transaction_id"], "unit-tx")
        self.assertEqual(value["observed_event_fields"], sorted(proof["events"][0]))

    def test_cleanup_never_proves_missing_phase1_event_or_required_rule(self):
        for case_id in ("keepalive_allow_allow", "multiple_sequential_requests"):
            case, proof = self.fixture(case_id)
            with self.subTest(case=case_id), self.assertRaises(ValueError):
                contract.derive_native_operation_contract(case, proof)

    def test_actual_event_must_exist_in_original_retained_jsonl(self):
        case, proof = self.fixture("event_metadata_truncation")
        for mutation in ("absent", "wrong_tx", "modified_field"):
            changed = deepcopy(proof)
            if mutation == "absent":
                changed["raw_artifacts"]["main"]["phase1-events.jsonl"] = b""
            elif mutation == "wrong_tx":
                changed["events"][0]["transaction_id"] = "foreign"
            else:
                changed["events"][0]["truncated"] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                contract.derive_native_operation_contract(case, changed)

    def test_unknown_expected_field_and_changed_result_are_not_padded(self):
        case, proof = self.fixture("event_metadata_truncation")
        case["expected_event_fields"].append("imaginary_event_field")
        with self.assertRaises(ValueError):
            contract.derive_native_operation_contract(case, proof)
        case, proof = self.fixture("event_metadata_truncation")
        case["expected_result"] = "clean_shutdown"
        with self.assertRaises(ValueError):
            contract.derive_native_operation_contract(case, proof)

    def test_preconnector_rejection_is_wire_only_without_fake_event_or_rule(self):
        case, proof = self.fixture("invalid_content_length")
        value = contract.derive_native_operation_contract(case, proof)
        self.assertEqual(value["native_events"], [])
        self.assertEqual(value["observed_event_fields"], [])
        self.assertEqual(value["semanticValues"]["phase_scope"], "host_preconnector")
        self.assertEqual(value["semanticValues"]["expected_result"], "rejected_by_host_before_connector_or_connector_rejection")

    def test_unverified_and_wrong_wire_status_fail(self):
        case, proof = self.fixture("header_count_nonzero_with_null_headers")
        for field, value in (("layer_verified", False), ("actual_status", 500), ("actual_status", True)):
            changed = deepcopy(proof)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                contract.derive_native_operation_contract(case, changed)

    def test_closed42_semantics_and_catalog_remain_unchanged(self):
        self.assertEqual(set(contract.CASE_RESULTS), set(fixtures.NativeProjectionTests.cases))
        self.assertEqual(len(contract.CASE_RESULTS), 42)
        catalog = contract.projection.ROOT / "tests/cases/no-crs-baseline/catalog.json"
        self.assertEqual(len(json.loads(catalog.read_text())["cases"]), 166)

    def test_actual_strict_reader_pointer_proof_derives_without_changing_raw(self):
        from tests.no_crs import test_nginx_native_operation_bundle as reader_tests
        fixture = reader_tests.NativeBundleRouterTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        proof = fixture.validate()
        original = deepcopy(proof["raw_artifacts"])
        case = deepcopy(fixtures.NativeProjectionTests.cases[fixture.case])
        value = contract.derive_native_operation_contract(case, proof)
        self.assertEqual(value["actual_status"], 400)
        self.assertEqual(value["native_event_origins"][0]["artifact_sha256"], contract.bundle.digest(original["main"]["phase1-events.jsonl"]))
        self.assertEqual(proof["raw_artifacts"], original)

    def test_strict_reader_phase4_mime_all12_mapping_origins(self):
        from tests.no_crs import test_nginx_native_operation_bundle as reader_tests
        from tests.runners import test_nginx_phase4_operations as phase4_tests
        from tests.no_crs import test_nginx_mime_operations as mime_tests
        fixture = reader_tests.NativeBundleRouterTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for case_id in sorted(contract.bundle.PHASE4_CASES | contract.bundle.MIME_CASES):
            receipt, raw = (mime_tests.unit_operation(case_id) if case_id in contract.bundle.MIME_CASES else
                            phase4_tests.rejection_fixture() if case_id == "phase4_body_reject" else phase4_tests.fixture(case_id))
            if case_id == "phase4_deny_after_commit_log_only_minimal":
                # The existing lightweight fixture omits fields assigned by
                # ngx_http_modsecurity_module.c before the real Common writer.
                # Prove the gap first, then use an explicit Source-shaped unit
                # fixture; this is not captured runtime or a receipt rewrite.
                fixture.prepare_case(case_id, receipt["run_id"])
                fixture.decorate_phase4(receipt, raw, fixture.output)
                fixture.write_child(receipt, raw, fixture.output, "main", "source-result.json")
                case = deepcopy(fixtures.NativeProjectionTests.cases[case_id])
                proof = fixture.validate()
                with self.assertRaisesRegex(ValueError, "original_http_status"):
                    contract.derive_native_operation_contract(case, proof)
                receipt, raw = phase4_tests.fixture(case_id)
                event = next(row for row in receipt["native_events"] if row["event"] == "phase4_intervention")
                event.update(original_http_status=200, headers_sent=True)
                raw["phase4-events.jsonl"] = b"\n".join(fixture.encode(row) for row in receipt["native_events"])
            fixture.prepare_case(case_id, receipt["run_id"])
            fixture.decorate_phase4(receipt, raw, fixture.output)
            fixture.write_child(receipt, raw, fixture.output, "main", "source-result.json")
            proof = fixture.validate()
            case = deepcopy(fixtures.NativeProjectionTests.cases[case_id])
            with self.subTest(case=case_id):
                value = contract.derive_native_operation_contract(case, proof)
                self.assertEqual(set(value["mapped_evidence_fields"]), set(case["expected_event_fields"]))
                self.assertTrue(all(value["mapped_evidence_origins"][field] for field in case["expected_event_fields"]))
                self.assertEqual(value["observed_event_fields"], sorted({key for row in value["selected_native_events"] for key in row}))
                self.assertNotIn("content_type_scope", value["observed_event_fields"])
                summary = value["semantic_native_event"]
                expected_event = "body_limit" if case_id == "phase4_body_reject" else "phase4_completion" if case_id in {
                    "phase4_out_of_scope_content_type", "phase4_missing_content_type"} else "phase4_intervention"
                self.assertEqual(summary["event"], expected_event)
                self.assertIn(summary, proof["events"])
                self.assertEqual(value["semantic_native_event_origin"]["kind"], "native_event")
                if expected_event == "phase4_intervention":
                    self.assertEqual(value["selected_native_events"][0]["event"], "phase4_append")
                    self.assertEqual(summary["actual_action"], "log_only")

    def test_real_phase1_completion_strict_tuple_and_host_identity_are_separate(self):
        case, proof = self.fixture("keepalive_allow_allow")
        event = {**proof["events"][0], "event": "request_headers_complete", "phase": "request_headers", "message_id": "MSCONN_PHASE1_COMPLETE",
                 "requested_action": "allow", "actual_action": "", "http_status": 0, "visible_http_status": 0,
                 "transport_result": "not_observable", "reason": "native_return=1;common_completed=1", "eos_seen": False}
        proof["events"].insert(0, event)
        proof["raw_artifacts"]["main"]["phase1-events.jsonl"] = b"\n".join(json.dumps(row).encode() for row in proof["events"])
        proof["observation"] = {"requests": [{"transport_result": "completed"}, {"transport_result": "completed"}],
                                "native_access": [{"connection": "77", "connection_requests": 1}, {"connection": "77", "connection_requests": 2}]}
        proof["raw_artifacts"]["main"]["sequence-observation.json"] = json.dumps(proof["observation"]).encode()
        proof["files"]["sequence-source.json"] = {"sha256": "a" * 64}
        value = contract.derive_native_operation_contract(case, proof)
        self.assertEqual(value["mapped_evidence_fields"]["connection_reused"], [True])
        self.assertEqual(value["mapped_evidence_origins"]["connection_reused"][0]["kind"], "host_observation")
        self.assertNotIn("connection_reused", value["observed_event_fields"])
        self.assertEqual(value["mapped_evidence_fields"]["event"], ["request_headers_complete"])
        self.assertIs(value["native_events"][0]["eos_seen"], False)
        self.assertEqual(value["mapped_evidence_fields"]["eos_seen"], [True])
        self.assertEqual(value["mapped_evidence_origins"]["eos_seen"][0]["kind"], "host_observation")
        for key, invalid in (("reason", "native_return=0;common_completed=1"), ("phase", "logging"), ("actual_action", "allow"), ("visible_http_status", 200)):
            changed = deepcopy(proof)
            changed["events"][0][key] = invalid
            changed["raw_artifacts"]["main"]["phase1-events.jsonl"] = b"\n".join(json.dumps(row).encode() for row in changed["events"])
            with self.subTest(key=key), self.assertRaises(ValueError):
                contract.derive_native_operation_contract(case, changed)

    def test_host_origins_require_original_observation_and_real_h1_framing(self):
        case, proof = self.fixture("transport_http11_content_length")
        completion = {**proof["events"][0], "phase": "response_body", "event": "phase4_completion", "message_id": "MSCONN_PHASE4_COMPLETE"}
        proof["events"].insert(0, completion)
        proof["raw_artifacts"]["main"]["phase1-events.jsonl"] = b"\n".join(json.dumps(row).encode() for row in proof["events"])
        proof["observation"] = {"protocol": "http1", "requests": [{"transport_result": "completed"}]}
        proof["raw_artifacts"]["main"]["sequence-observation.json"] = json.dumps(proof["observation"]).encode()
        value = contract.derive_native_operation_contract(case, proof)
        self.assertEqual(value["mapped_evidence_fields"]["transfer_encoding"], ["content_length"])
        self.assertEqual(value["mapped_evidence_fields"]["transport_protocol"], ["http1"])
        self.assertNotIn("transfer_encoding", value["observed_event_fields"])
        for mutation in ("h2", "incomplete_wire", "changed_observation"):
            changed = deepcopy(proof)
            if mutation == "h2":
                changed["observation"]["protocol"] = "http2"
                changed["raw_artifacts"]["main"]["sequence-observation.json"] = json.dumps(changed["observation"]).encode()
            elif mutation == "incomplete_wire":
                changed["raw_artifacts"]["main"]["response-wire.bin"] += b"extra"
            else:
                changed["observation"]["requests"][0]["transport_result"] = "connection_aborted"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                contract.derive_native_operation_contract(case, changed)

    @staticmethod
    def write_fixture(case_id):
        short = case_id == "response_short_write_resume"
        observation = {"roles": {"worker_pid": 123}, "native_access": [{"remote_port": 45678}],
                       "native_writes": [
                           {"pid": 123, "fd": 9, "peer_port": 45678, "requested_bytes": 100,
                            "returned_bytes": 7 if short else -1, "errno": 0 if short else 11, "fault_triggered": True},
                           {"pid": 123, "fd": 9, "peer_port": 45678, "requested_bytes": 93 if short else 100,
                            "returned_bytes": 93 if short else 100, "errno": 0, "fault_triggered": False},
                       ]}
        return {"observation": observation, "raw_artifacts": {"main": {
            "sequence-observation.json": json.dumps(observation).encode()}}}

    def test_source_shaped_seven_field_write_rows_keep_fd_and_prove_resume(self):
        for case_id, expected in (("response_short_write_resume", "short_write_resumed"),
                                  ("response_write_would_block_resume", "would_block_resumed")):
            proof = self.write_fixture(case_id)
            original = deepcopy(proof)
            with self.subTest(case=case_id):
                values, origins = contract.mapped_field("write_result", case_id, proof, [])
                self.assertEqual(values, [expected])
                self.assertEqual(origins[0]["artifact_sha256"], contract.bundle.digest(proof["raw_artifacts"]["main"]["sequence-observation.json"]))
                self.assertEqual(proof, original)

    def test_write_fd_exact_type_range_and_closed_source_fields(self):
        case_id = "response_short_write_resume"
        for value in (0, 2**31 - 1):
            proof = self.write_fixture(case_id)
            for row in proof["observation"]["native_writes"]:
                row["fd"] = value
            proof["raw_artifacts"]["main"]["sequence-observation.json"] = json.dumps(proof["observation"]).encode()
            with self.subTest(boundary=value):
                self.assertEqual(contract.mapped_field("write_result", case_id, proof, [])[0], ["short_write_resumed"])
        for value in (True, False, -1, 2**31, 9.0, "9", None):
            proof = self.write_fixture(case_id)
            proof["observation"]["native_writes"][0]["fd"] = value
            proof["raw_artifacts"]["main"]["sequence-observation.json"] = json.dumps(proof["observation"]).encode()
            with self.subTest(fd=value), self.assertRaises(ValueError):
                contract.mapped_field("write_result", case_id, proof, [])

        for mutation in ("missing", "extra"):
            proof = self.write_fixture(case_id)
            if mutation == "missing":
                proof["observation"]["native_writes"][0].pop("fd")
            else:
                proof["observation"]["native_writes"][0]["payload"] = "forbidden"
            proof["raw_artifacts"]["main"]["sequence-observation.json"] = json.dumps(proof["observation"]).encode()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                contract.mapped_field("write_result", case_id, proof, [])

    def test_semantic_native_event_scope_and_original_boundary_variant(self):
        for case_id, wanted in (("invalid_content_length", None), ("clean_shutdown", "transaction_cleanup"),
                                ("body_size_nonzero_with_null_data", "protocol_error"), ("finish_failure_propagation", "invalid_engine_response")):
            case, proof = self.fixture(case_id)
            value = contract.derive_native_operation_contract(case, proof)
            with self.subTest(case=case_id):
                event = value["semantic_native_event"]
                self.assertEqual(event["event"] if event else None, wanted)
                if event:
                    self.assertIn(event, proof["events"])
        case, proof = self.fixture("event_json_limit")
        proof["events"][0]["truncated"] = False
        proof["raw_artifacts"]["at"]["phase1-events.jsonl"] = b"\n".join(json.dumps(row).encode() for row in proof["events"] if row["transaction_id"] == proof["transaction_ids"][0])
        original = deepcopy(proof)
        value = contract.derive_native_operation_contract(case, proof)
        self.assertEqual(value["semantic_native_event"]["transaction_id"], proof["transaction_ids"][1])
        self.assertEqual(value["semantic_native_event_origin"]["invocation"], "over")
        self.assertEqual(proof, original)

    def test_semantic_selection_rejects_foreign_identity_and_conflicting_meaning(self):
        case, proof = self.fixture("event_metadata_truncation")
        for field, value in (("transaction_id", "foreign"), ("rule_id", "1100001"),
                             ("phase", "logging")):
            changed = deepcopy(proof)
            changed["events"][0][field] = value
            changed["raw_artifacts"]["main"]["phase1-events.jsonl"] = json.dumps(changed["events"][0]).encode()
            with self.subTest(field=field), self.assertRaises(ValueError):
                contract.derive_native_operation_contract(case, changed)
        case, proof = self.fixture("event_json_limit")
        next(row for row in proof["events"] if row["event"] == "rule_match" and row["transaction_id"] == proof["transaction_ids"][1])["actual_action"] = "log_only"
        proof["raw_artifacts"]["over"]["phase1-events.jsonl"] = b"\n".join(json.dumps(row).encode() for row in proof["events"] if row["transaction_id"] == proof["transaction_ids"][1])
        with self.assertRaisesRegex(ValueError, "contradictory same-kind"):
            contract.derive_native_operation_contract(case, proof)


if __name__ == "__main__":
    unittest.main()
