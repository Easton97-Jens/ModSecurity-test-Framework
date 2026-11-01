"""Actual immutable selection with synthetic raw/independent-review test evidence."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import copy
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = connector_root()
ACCEPTANCE = load_source(source_path('ci/runtime/lifecycle/i12/nginx/acceptance.py', root=ROOT))
PREFIX = "I12::nginx-native::"


class NginxAcceptanceTests(unittest.TestCase):
    def setUp(self):
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root
        configured = os.environ.get("I12_TEST_ROOT") or os.environ.get("RUNNER_TEMP")
        if not configured:
            raise ValueError("NGINX acceptance tests require a private I12_TEST_ROOT or RUNNER_TEMP")
        scratch = validate_output_root(ROOT, Path(configured))
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.rows = json.loads((source_path('ci/runtime/lifecycle/i12/nginx/evidence-20261015.json', root=ROOT)).read_text())["rows"]
        self.by_id = {row["run_scoped_case_id"]: row for row in self.rows}
        self.bindings = {}

    def reference(self, role, case):
        path = self.path / (case + "-" + role + ".json")
        path.write_text(json.dumps({"synthetic_test_only": role, "case": case}))
        return self.file_reference(path, role)

    def file_reference(self, path, role):
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "role": role}

    def bind(self, case, *, qualified=False):
        case_id = PREFIX + case
        binding = {"run_scoped_case_id": case_id,
                   "selected_requirement_sha256": ACCEPTANCE.CATALOG.CONTRACTS[case_id]["selected_requirement_sha256"],
                   "full_lifecycle_qualified": qualified,
                   "physical_identity": {"run_id": "synthetic-run", "connection_id": "synthetic-connection",
                                         "request_id": case, "physical_request": self.reference("selected_request", case)}}
        if qualified:
            binding["physical_identity"]["transaction_id"] = "synthetic-tx-" + case
            path = self.path / (case + "-packet.json")
            path.write_text(json.dumps({"run_scoped_case_id": case_id, "leg_id": "nginx-native",
                                        "run_id": "synthetic-run", "full_lifecycle_qualified": True,
                                        "outcome": "PASS", "synthetic_test_only": True}))
            binding["lifecycle_packet"] = self.file_reference(path, "lifecycle_packet")
        self.bindings[case_id] = binding
        return binding

    def record(self, case="valid_rules_file"):
        case_id = PREFIX + case
        contract = ACCEPTANCE.CATALOG.CONTRACTS[case_id]
        kind, subtype = contract["contract_kind"], contract["contract_subtype"]
        roles = {"source", *ACCEPTANCE.REQUIRED[subtype].values()}
        binding = None
        if kind in ("lifecycle", "preconnector_http_reject", "special"):
            binding = self.bind(case, qualified=kind == "lifecycle")
            roles.add("selected_request")
        elif case_id in ACCEPTANCE.CATALOG.SELF_ANCHORED_DERIVED_ROOTS:
            binding = self.bind(case, qualified=True)
        if self.by_id[case_id]["selected_requirement"]["expected_oracle"].get("unresolved_expected_value_reason"):
            roles.add("oracle_resolution")
        refs = []
        for role in sorted(roles):
            if role == "lifecycle_packet":
                refs.append(binding["lifecycle_packet"])
            elif role == "selected_request":
                refs.append(binding["physical_identity"]["physical_request"])
            else:
                refs.append(self.reference(role, case))
        values = {name: {"value": True if name in ("native_lifecycle", "source_operation_absent") else "PASS",
                         "evidence_roles": [role]} for name, role in ACCEPTANCE.REQUIRED[subtype].items()}
        if kind == "preconnector_http_reject":
            for name, value in (("allocation_count", 0), ("backend_request_count", 0), ("client_status", 400)):
                values[name]["value"] = value
        result = {"run_scoped_case_id": case_id,
                  "selected_requirement_sha256": contract["selected_requirement_sha256"],
                  "contract_kind": kind, "contract_subtype": subtype,
                  "original_execution_kind": contract["original_execution_kind"],
                  "acceptance_scope": ACCEPTANCE.SCOPES[kind], "status": "PASS",
                  "oracle_resolved": True, "remaining_contract_gaps": [], "evidence_refs": refs,
                  "source_hashes": {ref["path"]: ref["sha256"] for ref in refs if ref["role"] == "source"},
                  "observations": values, "not_applicable_observations": {}}
        if kind in ("configuration", "preconnector_http_reject", "source_not_applicable", "cycle_cleanup"):
            result["not_applicable_observations"] = {name: "synthetic non-native contract" for name in ACCEPTANCE.NATIVE_NA}
        if kind == "source_not_applicable":
            result["not_applicable_observations"].update({name: "no flush operation exists" for name in (
                "selected_request", "client_result", "cleanup_result")})
        return result

    def build(self, *records):
        return ACCEPTANCE.build_acceptance(self.rows, list(records), evidence_root=self.path,
                                           independently_reviewed=self.bindings)

    def packet_outcome(self, record, outcome):
        binding = self.bindings[record["run_scoped_case_id"]]
        path = Path(binding["lifecycle_packet"]["path"])
        packet = json.loads(path.read_text())
        if outcome is None:
            packet.pop("outcome")
        else:
            packet["outcome"] = outcome
        path.write_text(json.dumps(packet))
        reference = self.file_reference(path, "lifecycle_packet")
        binding["lifecycle_packet"] = reference
        record["evidence_refs"] = [reference if ref["role"] == "lifecycle_packet" else ref
                                   for ref in record["evidence_refs"]]

    def test_actual_catalog_exact_partition_order_and_execution_kinds(self):
        result = self.build()
        self.assertEqual(Counter(row["contract_kind"] for row in result["rows"]), {
            "lifecycle": 87, "configuration": 11, "preconnector_http_reject": 4,
            "derived": 31, "source_not_applicable": 1, "cycle_cleanup": 2, "special": 4})
        self.assertEqual([row["run_scoped_case_id"] for row in result["rows"]], list(self.by_id))
        self.assertEqual(result["original_ordered_id_sha256"], ACCEPTANCE.canonical_digest(list(self.by_id)))
        for row in self.rows:
            contract = ACCEPTANCE.CATALOG.CONTRACTS[row["run_scoped_case_id"]]
            self.assertEqual(contract["original_execution_kind"], row["selected_requirement"]["execution_kind"])
            self.assertEqual(contract["selected_requirement_sha256"], row["selected_requirement_sha256"])

    def test_full_original_requirements_and_compact_projection_bind_the_same_catalog(self):
        full = copy.deepcopy(self.rows)
        for row in full:
            requirement = row["selected_requirement"]
            self.assertEqual(requirement.pop("original_source_hashes_count"), 0)
            self.assertEqual(requirement.pop("original_source_hashes_set_sha256"), ACCEPTANCE.canonical_digest({}))
        self.assertEqual(ACCEPTANCE.canonical_digest([row["selected_requirement"] for row in full]),
                         ACCEPTANCE.CATALOG.ORIGINAL_SELECTED_CONTRACT_SHA256)
        self.assertEqual(list(ACCEPTANCE.original_selection(full)), list(self.by_id))

    def test_accepts_each_non_derived_kind_without_mutating_selection(self):
        original = copy.deepcopy(self.rows)
        records = [self.record(case) for case in (
            "valid_rules_file", "NEED-physical-event-sink-open", "invalid_content_length",
            "allow_without_marker", "NEED-physical-event-sink-flush", "clean_shutdown",
            "NEED-physical-event-sink-close", "transaction_begin_failure_cleanup",
            "NEED-missing-eos", "NEED-cancel", "NEED-current-h1-matrix-not-r17")]
        result = self.build(*records)
        self.assertEqual(result["summary"], {"original_ids": 140, "contract_pass": 11, "selected_physical_requests": 6})
        self.assertEqual(original, self.rows)
        self.assertTrue(next(row for row in result["rows"] if row["run_scoped_case_id"] == PREFIX + "allow_without_marker")["full_lifecycle_qualified"])

    def test_rejects_synthetic_arbitrary_selection_reorder_and_changed_execution(self):
        for change in ("order", "count", "id", "execution", "contract"):
            rows = copy.deepcopy(self.rows)
            if change == "order": rows[0], rows[1] = rows[1], rows[0]
            elif change == "count": rows.pop()
            elif change == "id": rows[0]["run_scoped_case_id"] += "-synthetic"
            elif change == "execution": rows[0]["selected_requirement"]["execution_kind"] = "actual_configtest"
            else: rows[0]["selected_requirement"]["expected_oracle"]["visible_status"] = 599
            with self.subTest(change=change), self.assertRaises(ValueError):
                ACCEPTANCE.build_acceptance(rows, [], evidence_root=self.path, independently_reviewed={})

    def test_record_cannot_relabel_exact_catalog_kind_subtype_or_execution(self):
        for field, value in (("contract_kind", "configuration"), ("contract_subtype", "configuration_test"),
                             ("original_execution_kind", "actual_configtest")):
            record = self.record("allow_without_marker")
            record[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "relabel"):
                self.build(record)

    def test_classification_can_be_derived_from_exact_catalog(self):
        record = self.record()
        for field in ("contract_kind", "contract_subtype", "original_execution_kind"):
            del record[field]
        row = next(row for row in self.build(record)["rows"] if row["run_scoped_case_id"] == record["run_scoped_case_id"])
        self.assertEqual(row["contract_kind"], "configuration")

    def test_unknown_and_duplicate_original_record_rejected(self):
        record = self.record()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.build(record, record)
        record["run_scoped_case_id"] += "-alias"
        with self.assertRaisesRegex(ValueError, "unknown"):
            self.build(record)

    def test_forged_lifecycle_boolean_without_independent_packet_rejected(self):
        record = self.record("allow_without_marker")
        record["full_lifecycle_qualified"] = True
        self.bindings[record["run_scoped_case_id"]]["full_lifecycle_qualified"] = False
        del self.bindings[record["run_scoped_case_id"]]["lifecycle_packet"]
        with self.assertRaisesRegex(ValueError, "boolean differs"):
            self.build(record)
        self.bindings[record["run_scoped_case_id"]]["full_lifecycle_qualified"] = True
        with self.assertRaisesRegex(ValueError, "independent lifecycle packet"):
            self.build(record)

    def test_true_flag_for_special_also_requires_bound_packet(self):
        record = self.record("NEED-cancel")
        self.bindings[record["run_scoped_case_id"]]["full_lifecycle_qualified"] = True
        with self.assertRaisesRegex(ValueError, "independent lifecycle packet"):
            self.build(record)

    def test_packet_run_and_independent_physical_run_must_match(self):
        record = self.record("allow_without_marker")
        self.bindings[record["run_scoped_case_id"]]["physical_identity"]["run_id"] = "copied-other-run"
        with self.assertRaisesRegex(ValueError, "packet run differs"):
            self.build(record)

    def test_lifecycle_packet_relabeling_and_replacement_rejected(self):
        record = self.record("allow_without_marker")
        packet = self.bindings[record["run_scoped_case_id"]]["lifecycle_packet"]
        altered = dict(packet, path=self.reference("other-packet", "allow_without_marker")["path"])
        altered["sha256"] = hashlib.sha256(Path(altered["path"]).read_bytes()).hexdigest()
        record["evidence_refs"] = [altered if ref["role"] == "lifecycle_packet" else ref for ref in record["evidence_refs"]]
        with self.assertRaisesRegex(ValueError, "independently reviewed packet"):
            self.build(record)

    def test_copied_raw_request_file_cannot_manufacture_new_physical_binding(self):
        record = self.record("allow_without_marker")
        original = self.bindings[record["run_scoped_case_id"]]["physical_identity"]["physical_request"]
        copy_path = self.path / "copied-request.json"
        copy_path.write_bytes(Path(original["path"]).read_bytes())
        record["evidence_refs"] = [self.file_reference(copy_path, "selected_request") if ref["role"] == "selected_request" else ref for ref in record["evidence_refs"]]
        record["request_id"] = "caller-created-request"
        with self.assertRaisesRegex(ValueError, "identity differs"):
            self.build(record)
        del record["request_id"]
        with self.assertRaisesRegex(ValueError, "independent physical request binding"):
            self.build(record)

    def test_dedup_uses_independent_physical_reference(self):
        one, two = self.record("allow_without_marker"), self.record("deny_header_marker_403")
        physical = self.bindings[one["run_scoped_case_id"]]["physical_identity"]["physical_request"]
        self.bindings[two["run_scoped_case_id"]]["physical_identity"]["physical_request"] = physical
        two["evidence_refs"] = [physical if ref["role"] == "selected_request" else ref
                                for ref in two["evidence_refs"]]
        with self.assertRaisesRegex(ValueError, "multiple original IDs"):
            self.build(one, two)

    def test_dedup_rejects_one_native_transaction_with_different_physical_requests(self):
        one, two = self.record("allow_without_marker"), self.record("deny_header_marker_403")
        self.bindings[two["run_scoped_case_id"]]["physical_identity"]["transaction_id"] = (
            self.bindings[one["run_scoped_case_id"]]["physical_identity"]["transaction_id"])
        with self.assertRaisesRegex(ValueError, "native transaction cannot accept multiple"):
            self.build(one, two)

    def test_historical_lifecycle_binding_requires_no_new_connection_or_request_ids(self):
        record = self.record("allow_without_marker")
        identity = self.bindings[record["run_scoped_case_id"]]["physical_identity"]
        del identity["connection_id"]
        del identity["request_id"]
        self.assertEqual(self.build(record)["summary"]["selected_physical_requests"], 1)
        del identity["transaction_id"]
        with self.assertRaisesRegex(ValueError, "lifecycle transaction_id"):
            self.build(record)

    def test_preconnector_binding_has_no_native_transaction_or_new_identity_fields(self):
        record = self.record("invalid_content_length")
        identity = self.bindings[record["run_scoped_case_id"]]["physical_identity"]
        del identity["connection_id"]
        del identity["request_id"]
        self.assertNotIn("transaction_id", identity)
        self.assertEqual(self.build(record)["summary"]["selected_physical_requests"], 1)

    def test_actual_distinct_requests_on_keepalive_connection_are_not_collapsed(self):
        result = self.build(self.record("allow_without_marker"), self.record("deny_header_marker_403"))
        self.assertEqual(result["summary"]["selected_physical_requests"], 2)

    def test_three_actual_self_anchored_roots_require_reviewed_parent_without_counting(self):
        records = [self.record(case_id.removeprefix(PREFIX)) for case_id in sorted(ACCEPTANCE.CATALOG.SELF_ANCHORED_DERIVED_ROOTS)]
        result = self.build(*records)
        self.assertEqual(result["summary"]["selected_physical_requests"], 0)
        self.assertEqual(result["summary"]["contract_pass"], 3)
        for row in result["rows"]:
            if row["run_scoped_case_id"] in ACCEPTANCE.CATALOG.SELF_ANCHORED_DERIVED_ROOTS:
                self.assertTrue(row["full_lifecycle_qualified"])
                self.assertEqual(row["lifecycle_outcome"], "PASS")
        del self.bindings[records[0]["run_scoped_case_id"]]
        with self.assertRaisesRegex(ValueError, "reviewed parent physical binding"):
            self.build(*records)

    def test_self_anchored_roots_cannot_promote_failed_unqualified_or_packetless_parents(self):
        for case_id in sorted(ACCEPTANCE.CATALOG.SELF_ANCHORED_DERIVED_ROOTS):
            for state in ("qualified-fail", "unqualified-packet", "no-packet"):
                with self.subTest(case_id=case_id, state=state):
                    record = self.record(case_id.removeprefix(PREFIX))
                    binding = self.bindings[case_id]
                    if state == "qualified-fail":
                        self.packet_outcome(record, "FAIL")
                    else:
                        binding["full_lifecycle_qualified"] = False
                        if state == "no-packet":
                            del binding["lifecycle_packet"]
                        else:
                            path = Path(binding["lifecycle_packet"]["path"])
                            packet = json.loads(path.read_text())
                            packet["full_lifecycle_qualified"] = False
                            path.write_text(json.dumps(packet))
                            binding["lifecycle_packet"] = self.file_reference(path, "lifecycle_packet")
                    with self.assertRaisesRegex(ValueError, "self-anchored derived PASS"):
                        self.build(record)
                    record["status"] = "INCOMPLETE"
                    result = self.build(record)
                    self.assertEqual(result["summary"]["contract_pass"], 0)
                    self.assertEqual(result["summary"]["selected_physical_requests"], 0)

    def test_self_anchored_root_cannot_substitute_an_unrelated_successful_parent_packet(self):
        record = self.record("phase4_deny_after_commit_log_only")
        unrelated = self.bind("allow_without_marker", qualified=True)
        self.bindings[record["run_scoped_case_id"]]["lifecycle_packet"] = unrelated["lifecycle_packet"]
        with self.assertRaisesRegex(ValueError, "packet identity or qualification mismatch"):
            self.build(record)

    def test_derived_cannot_change_original_parents_or_count_requests(self):
        for change in ("parents", "request"):
            record = self.record("allow")
            if change == "parents": record["derived_from"] = [PREFIX + "allow"]
            else: record["evidence_refs"].append(self.reference("selected_request", "allow"))
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.build(record)

    def test_derived_requires_accepted_original_parent(self):
        derived = self.record("allow")
        with self.assertRaisesRegex(ValueError, "accepted original parent"):
            self.build(derived)
        result = self.build(derived, self.record("allow_without_marker"))
        self.assertEqual(result["summary"]["contract_pass"], 2)
        self.assertEqual(result["summary"]["selected_physical_requests"], 1)

    def test_source_na_flush_cannot_claim_native_client_cleanup_or_selected_request(self):
        for role in ("client", "cleanup", "selected_request", "lifecycle_packet"):
            record = self.record("NEED-physical-event-sink-flush")
            record["evidence_refs"].append(self.reference(role, "flush-false-proof"))
            with self.subTest(role=role), self.assertRaises(ValueError):
                self.build(record)
        record = self.record("NEED-physical-event-sink-flush")
        del record["not_applicable_observations"]["cleanup_result"]
        with self.assertRaisesRegex(ValueError, "request/client/cleanup N/A"):
            self.build(record)

    def test_config_open_honestly_uses_config_and_sink_open_observers(self):
        record = self.record("NEED-physical-event-sink-open")
        self.assertNotIn("client", {ref["role"] for ref in record["evidence_refs"]})
        self.assertNotIn(record["run_scoped_case_id"], self.bindings)
        del record["observations"]["sink_open_result"]
        with self.assertRaisesRegex(ValueError, "sink_open_result"):
            self.build(record)

    def test_subtype_specific_cycle_and_special_requirements_are_mandatory(self):
        for case in ("clean_shutdown", "NEED-physical-event-sink-close", "NEED-missing-eos", "NEED-cancel",
                     "transaction_begin_failure_cleanup", "NEED-current-h1-matrix-not-r17"):
            record = self.record(case)
            record["observations"].pop(next(iter(record["observations"])))
            with self.subTest(case=case), self.assertRaisesRegex(ValueError, "requires measured"):
                self.build(record)

    def test_sink_close_cycle_cannot_claim_native_eos_or_omit_native_na(self):
        record = self.record("NEED-physical-event-sink-close")
        record["not_applicable_observations"].pop("native_eos")
        record["observations"]["native_eos"] = {"value": True, "evidence_roles": ["source"]}
        with self.assertRaisesRegex(ValueError, "explicit native N/A"):
            self.build(record)
        del record["observations"]["native_eos"]
        with self.assertRaisesRegex(ValueError, "explicit native N/A"):
            self.build(record)

    def test_wrong_allow_evidence_cannot_accept_external_phase4_parent(self):
        parent = PREFIX + "phase4_deny_before_commit"
        for declared_parent in (None, PREFIX + "allow_without_marker", parent):
            record = self.record("phase4_event_contains_original_status")
            allow = self.bind("allow_without_marker", qualified=True)["lifecycle_packet"]
            reference = {**allow, "role": "external_derived_source"}
            if declared_parent is not None:
                reference["source_case_id"] = declared_parent
            record["evidence_refs"].append(reference)
            with self.subTest(declared_parent=declared_parent), self.assertRaisesRegex(ValueError, "external derived"):
                self.build(record)

    def test_exact_reviewed_external_parent_accepts_real_derived_contract(self):
        parent = PREFIX + "phase4_deny_before_commit"
        path = self.path / "reviewed-external-phase4-parent.json"
        path.write_text(json.dumps({"run_scoped_case_id": parent, "outcome": "PASS",
                                    "oracle_evaluated": True, "reviewed_by": "synthetic-reviewer",
                                    "synthetic_test_only": True}))
        external = {**self.file_reference(path, "external_derived_source"), "source_case_id": parent}
        records = {}

        def add(case_id):
            if case_id in records:
                return
            record = self.record(case_id.removeprefix(PREFIX))
            records[case_id] = record
            for source in ACCEPTANCE.CATALOG.CONTRACTS[case_id]["source_case_ids"]:
                if source not in ACCEPTANCE.CATALOG.CONTRACTS:
                    record["evidence_refs"].append(external)
                elif source != case_id:
                    add(source)

        add(PREFIX + "phase4_event_contains_original_status")
        result = self.build(*records.values())
        accepted = next(row for row in result["rows"] if row["run_scoped_case_id"] == PREFIX + "phase4_event_contains_original_status")
        self.assertEqual(accepted["contract_acceptance"], "PASS")
        self.assertEqual(result["summary"]["selected_physical_requests"], 1)
        receipt = json.loads(path.read_text())
        receipt["outcome"] = "FAIL"
        path.write_text(json.dumps(receipt))
        record = records[PREFIX + "phase4_event_contains_original_status"]
        record["evidence_refs"] = [{**self.file_reference(path, "external_derived_source"), "source_case_id": parent}
                                   if ref["role"] == "external_derived_source" else ref
                                   for ref in record["evidence_refs"]]
        selected_records = list(records.values())
        with self.assertRaisesRegex(ValueError, "reviewed PASS"):
            self.build(*selected_records)

    def test_pass_rejects_gaps_unresolved_oracle_scope_and_missing_sources(self):
        for field, value in (("remaining_contract_gaps", ["missing proof"]), ("oracle_resolved", False),
                             ("acceptance_scope", "full_host_lifecycle"), ("source_hashes", {})):
            record = self.record()
            record[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.build(record)

    def test_original_unknown_oracle_requires_hash_bound_review(self):
        record = self.record("NEED-physical-event-sink-flush")
        record["evidence_refs"] = [ref for ref in record["evidence_refs"] if ref["role"] != "oracle_resolution"]
        with self.assertRaisesRegex(ValueError, "resolution evidence"):
            self.build(record)

    def test_preconnector_requires_zero_allocations_backend_client_and_neighbor(self):
        for name, value in (("allocation_count", 1), ("allocation_count", False),
                            ("backend_request_count", 1), ("client_status", 500), ("neighbor_result", "FAIL")):
            record = self.record("invalid_content_length")
            record["observations"][name]["value"] = value
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                self.build(record)

    def test_preconnector_observers_must_be_independent_raw_files(self):
        record = self.record("invalid_content_length")
        client = next(ref for ref in record["evidence_refs"] if ref["role"] == "client")
        record["evidence_refs"] = [{**client, "role": "allocation_observer"} if ref["role"] == "allocation_observer" else ref for ref in record["evidence_refs"]]
        with self.assertRaisesRegex(ValueError, "independent raw evidence"):
            self.build(record)

    def test_hash_binding_and_symlink_escape_protections(self):
        for change in ("raw", "source-map", "symlink", "outside"):
            record = self.record()
            ref = next(ref for ref in record["evidence_refs"] if ref["role"] == "source")
            if change == "raw": Path(ref["path"]).write_text("changed")
            elif change == "source-map": record["source_hashes"][ref["path"]] = "0" * 64
            elif change == "symlink":
                link = self.path / "link.json"
                link.symlink_to(ref["path"])
                ref["path"] = str(link)
            else: ref["path"] = "/etc/passwd"
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.build(record)

    def test_incomplete_keeps_real_independent_lifecycle_result_separate(self):
        record = self.record("allow_without_marker")
        record.update(status="INCOMPLETE", remaining_contract_gaps=["contract gap"])
        row = self.build(record)["rows"][0]
        self.assertEqual(row["contract_acceptance"], "INCOMPLETE")
        self.assertTrue(row["full_lifecycle_qualified"])
        self.assertEqual(row["lifecycle_outcome"], "PASS")

    def test_all_four_historical_qualified_failures_cannot_be_promoted_to_contract_pass(self):
        historical = [row for row in self.rows if row["full_lifecycle_qualified"] and row["new_status"] == "FAIL"]
        self.assertEqual({row["run_scoped_case_id"] for row in historical}, {
            PREFIX + "body_size_nonzero_with_null_data", PREFIX + "engine_timeout_before_commit",
            PREFIX + "engine_timeout_after_commit", PREFIX + "NEED-request-empty"})
        for historical_row in historical:
            case_id = historical_row["run_scoped_case_id"]
            with self.subTest(case_id=case_id):
                record = self.record(case_id.removeprefix(PREFIX))
                self.packet_outcome(record, "FAIL")
                # Qualification proves the independent observation is complete;
                # the actual packet outcome still records an observed failure.
                with self.assertRaisesRegex(ValueError, "packet outcome PASS"):
                    self.build(record)
                record.update(status="FAIL", lifecycle_outcome="FAIL")
                result = self.build(record)
                row = next(row for row in result["rows"] if row["run_scoped_case_id"] == case_id)
                self.assertTrue(row["full_lifecycle_qualified"])
                self.assertEqual(row["lifecycle_outcome"], "FAIL")
                self.assertEqual(row["contract_acceptance"], "FAIL")
                self.assertEqual(result["summary"]["contract_pass"], 0)

    def test_record_binding_and_packet_outcomes_must_agree(self):
        record = self.record("allow_without_marker")
        self.packet_outcome(record, "FAIL")
        binding = self.bindings[record["run_scoped_case_id"]]
        binding["lifecycle_outcome"] = "PASS"
        with self.assertRaisesRegex(ValueError, "outcome differs from hash-bound packet"):
            self.build(record)
        binding["lifecycle_outcome"] = "FAIL"
        record.update(status="FAIL", lifecycle_outcome="PASS")
        with self.assertRaisesRegex(ValueError, "record lifecycle outcome differs"):
            self.build(record)
        record["lifecycle_outcome"] = "FAIL"
        self.assertEqual(self.build(record)["rows"][0]["lifecycle_outcome"], "FAIL")

    def test_lifecycle_outcome_must_be_present_in_the_hash_bound_packet(self):
        record = self.record("allow_without_marker")
        self.packet_outcome(record, None)
        with self.assertRaisesRegex(ValueError, "explicit PASS/FAIL outcome"):
            self.build(record)
        self.packet_outcome(record, "PASS")
        path = Path(self.bindings[record["run_scoped_case_id"]]["lifecycle_packet"]["path"])
        packet = json.loads(path.read_text())
        packet["outcome"] = "FAIL"
        path.write_text(json.dumps(packet))
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            self.build(record)

    def test_preconnector_cannot_invent_lifecycle_outcome_without_packet(self):
        record = self.record("invalid_content_length")
        binding = self.bindings[record["run_scoped_case_id"]]
        binding["lifecycle_outcome"] = "PASS"
        with self.assertRaisesRegex(ValueError, "outcome differs from hash-bound packet"):
            self.build(record)
        del binding["lifecycle_outcome"]
        record["lifecycle_outcome"] = "PASS"
        with self.assertRaisesRegex(ValueError, "record lifecycle outcome differs"):
            self.build(record)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
