"""Synthetic execution-index controls; these never qualify a real host case."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
MODULE_DIRECTORY = tempfile.TemporaryDirectory(
    prefix="lighttpd-current-ledger-module-", dir=os.environ.get("RUNNER_TEMP"))
MODULE_TEMP = Path(MODULE_DIRECTORY.name)
MODULE_EXTERNAL = MODULE_TEMP / "evidence"
MODULE_EXTERNAL.mkdir(mode=0o700)
with mock.patch.dict(os.environ, {"I12_TEST_ROOT": str(MODULE_EXTERNAL)}):
    C = load_source(source_path('ci/runtime/lifecycle/i12/lighttpd/current_ledger.py', root=ROOT))


class CurrentLedgerCoverageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(
            prefix="lighttpd-current-ledger-control-", dir=C.Q.EXTERNAL_ROOT)
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.identity = "I12::lighttpd-stock-sidecar::allow_without_marker"
        self.capture = self.root / "capture.json"
        self.capture.write_text('{"synthetic_capture": true}')
        self.process = self.root / "process.json"
        self.process.write_text('{"synthetic_process": true, "actual_returncode": 0}')
        self.row = {
            "run_scoped_case_id": self.identity,
            "original_row_sha256": C.Q.original_row(self.identity)["original_row_sha256"],
            "status": "PARTIAL_HOST_MEASUREMENTS", "execution_kind": "host_http",
            "execution_observed": True, "remaining_reason": "Synthetic coverage only; Root qualification is missing.",
            "capture_refs": [C.Q.reference(self.capture)],
            "process_producers": [C.Q.reference(self.process, "client_process")],
        }
        self.index = {"schema": "lighttpd-i12-execution-index-v1", "reviewed_by": "root",
                      "independent_review": "Synthetic negative controls, never host proof.", "rows": [self.row]}
        self.path = self.root / "index.json"

    def save(self):
        self.path.write_text(json.dumps(self.index))
        return self.path

    def test_capture_is_executed_but_cannot_become_pass_or_resolve_oracle(self):
        result = C.export([], {"synthetic": True}, self.root / "output", self.save())
        summary = result["lighttpd-stock-sidecar"]
        self.assertEqual(summary["current_executed_original_ids"], 1)
        self.assertEqual(summary["current_unique_http_executions"], 1)
        self.assertEqual(summary["newly_qualified_original_ids"], 0)
        self.assertEqual(summary["newly_resolved_original_oracles"], 0)
        self.assertEqual(summary["current_qualified_verdicts"], {})
        self.assertEqual(summary["current_verdicts"], {"PARTIAL_HOST_MEASUREMENTS": 1})

    def test_worker_pass_unknown_review_and_missing_process_cannot_promote(self):
        original = copy.deepcopy(self.index)
        for mutation in ("PASS", "review", "process", "boolean"):
            self.index = copy.deepcopy(original)
            if mutation == "PASS":
                self.index["rows"][0]["status"] = "PASS"
            elif mutation == "review":
                self.index["reviewed_by"] = "worker"
            elif mutation == "process":
                self.index["rows"][0]["process_producers"] = []
            else:
                self.index["rows"][0]["execution_observed"] = 1
            path = self.save()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                C.execution_inventory(path)

    def test_wrong_original_duplicate_corruption_and_foreign_role_are_rejected(self):
        self.row["original_row_sha256"] = "changed"
        path = self.save()
        with self.assertRaisesRegex(ValueError, "original ID"):
            C.execution_inventory(path)
        self.row["original_row_sha256"] = C.Q.original_row(self.identity)["original_row_sha256"]
        self.index["rows"].append(copy.deepcopy(self.row))
        path = self.save()
        with self.assertRaisesRegex(ValueError, "original ID"):
            C.execution_inventory(path)
        self.index["rows"].pop()
        self.row["process_producers"][0]["role"] = "native_api"
        path = self.save()
        with self.assertRaisesRegex(ValueError, "independent process"):
            C.execution_inventory(path)
        self.row["process_producers"][0]["role"] = "client_process"
        self.capture.write_text("altered")
        path = self.save()
        with self.assertRaisesRegex(ValueError, "SHA256"):
            C.execution_inventory(path)

    def test_copied_receipt_and_reused_request_do_not_inflate_executions(self):
        other = copy.deepcopy(self.row)
        other["run_scoped_case_id"] = "I12::lighttpd-stock-sidecar::deny_header_marker_403"
        other["original_row_sha256"] = C.Q.original_row(other["run_scoped_case_id"])["original_row_sha256"]
        copied = self.root / "copy.json"
        copied.write_bytes(self.process.read_bytes())
        other["process_producers"] = [C.Q.reference(copied, "client_process")]
        self.index["rows"].append(other)
        result = C.export([], {}, self.root / "output", self.save())["lighttpd-stock-sidecar"]
        self.assertEqual(result["current_executed_original_ids"], 2)
        self.assertEqual(result["current_unique_http_executions"], 1)

    def test_receipt_subset_superset_and_transitive_bridge_are_one_execution(self):
        receipts = []
        for number in range(4):
            path = self.root / f"process-{number}.json"
            path.write_text(json.dumps({"synthetic_receipt": number}))
            receipts.append(C.Q.reference(path, "client_process"))
        copied = self.root / "copied-process.json"
        copied.write_bytes(Path(receipts[0]["path"]).read_bytes())
        entries = [
            {"client_producers": [receipts[0]], "original_ids": ["one"]},
            {"client_producers": [receipts[1]], "original_ids": ["two"]},
            {"client_producers": [C.Q.reference(copied)], "original_ids": ["one"]},
            {"client_producers": [receipts[0], receipts[2]], "original_ids": ["three"]},
            {"client_producers": [receipts[1], receipts[2]], "original_ids": ["bridge"]},
            {"client_producers": [receipts[3]], "original_ids": ["independent"]},
        ]
        groups = C.execution_groups(entries)
        self.assertEqual(len(groups), 2)
        joined = next(group for group in groups if "bridge" in group["original_ids"])
        self.assertEqual(set(joined["original_ids"]), {"one", "two", "three", "bridge"})
        self.assertEqual(len(joined["client_producers"]), 4)
        self.assertEqual(joined["unique_execution_count"], 1)

    def test_summary_and_actual_executions_share_overlap_grouping(self):
        second_process = self.root / "second-process.json"
        second_process.write_text('{"synthetic_parser_receipt":true}')
        second_ref = C.Q.reference(second_process, "client_process")
        identities = [self.identity, "I12::lighttpd-stock-sidecar::deny_header_marker_403",
                      "I12::lighttpd-stock-sidecar::log_only"]
        producer_sets = [[self.row["process_producers"][0]], [second_ref],
                         [self.row["process_producers"][0], second_ref]]
        self.index["rows"] = []
        for identity, producers in zip(identities, producer_sets):
            row = copy.deepcopy(self.row)
            row.update(run_scoped_case_id=identity,
                       original_row_sha256=C.Q.original_row(identity)["original_row_sha256"],
                       process_producers=producers)
            self.index["rows"].append(row)
        C.export([], {}, self.root / "grouped-output", self.save())
        result = json.loads((self.root / "grouped-output/lighttpd-stock-sidecar.json").read_text())
        self.assertEqual(result["summary"]["current_unique_http_executions"], 1)
        self.assertEqual(len(result["actual_executions"]), 1)
        self.assertEqual(set(result["actual_executions"][0]["original_ids"]), set(identities))

    def test_fresh_qualifier_status_overrides_no_cached_verdict(self):
        for outcome in ("PASS", "FAIL"):
            qualification = {"full_case_qualified": True, "full_lifecycle_qualified": False,
                             "outcome": outcome}
            C.validate_saved_status({"status": outcome}, qualification)
            with self.subTest(outcome=outcome), self.assertRaisesRegex(ValueError, "Saved status"):
                C.validate_saved_status({"status": "FAIL" if outcome == "PASS" else "PASS"}, qualification)
        incomplete = {"full_lifecycle_qualified": False, "outcome": None}
        with self.assertRaisesRegex(ValueError, "Saved status"):
            C.validate_saved_status({"status": "PASS"}, incomplete)

    def test_real_partial_adapter_result_cannot_reuse_cached_pass(self):
        packet = C.Q.packet_template(self.identity, {
            "run_id": "synthetic-current-result-control", "parent_sha": "synthetic",
            "framework_sha": "synthetic", "mrts_sha": "synthetic",
            "effective_config_sha256": "synthetic"})
        packet["execution_observed"] = True
        packet["observations"]["client_exit"] = {
            "value": 0, "evidence": [C.Q.reference(self.process, "client_process")]}
        packet_path, oracle_path, review_path = [self.root / name for name in
                                               ("packet.json", "oracle.json", "review.json")]
        packet_path.write_text(json.dumps(packet))
        oracle_path.write_text(json.dumps({
            "reviewed_by": "worker", "run_scoped_case_id": self.identity,
            "leg_id": "lighttpd-stock-sidecar", "category": "SOURCE_CONFIRMED_EXPECTATION",
            "interpretation": "Synthetic adapter guard only; no host qualification.",
            "scope": "bounded incomplete synthetic packet",
            "independent_sources": [{**C.Q.reference(self.capture),
                                     "kind": "native_engine_contract", "revision": "synthetic"}]}))
        review_path.write_text(json.dumps({
            "reviewed_by": "root", "run_scoped_case_id": self.identity,
            "packet_sha256": C.Q.reference(packet_path)["sha256"],
            "oracle_record_sha256": C.Q.reference(oracle_path)["sha256"],
            "independent_oracle_review": "Synthetic negative control.",
            "physical_transaction_review": "Synthetic packet remains incomplete.",
            "qualifier_source_sha256": C.Q.loaded_source_digests()}))
        destination = self.root / "partial-result"
        result = C.Q.qualify(packet_path, oracle_path, review_path, destination)
        saved = destination / "qualification.json"
        self.assertEqual(C.current_result(saved)[0]["status"], "PARTIAL_HOST_MEASUREMENTS")
        result["status"] = "PASS"
        saved.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, "Saved status"):
            C.current_result(saved)

    def test_host_start_only_is_not_http_and_blocker_requires_source_evidence(self):
        self.row.update(status="HOST_START_ONLY", execution_observed=False,
                        execution_kind="host_start", process_producers=[])
        result = C.export([], {}, self.root / "output", self.save())["lighttpd-stock-sidecar"]
        self.assertEqual(result["current_executed_original_ids"], 0)
        self.assertEqual(result["current_unique_http_executions"], 0)
        self.row.update(status="ENVIRONMENT_BLOCKED", capture_refs=[])
        path = self.save()
        with self.assertRaisesRegex(ValueError, "concrete evidence"):
            C.execution_inventory(path)

    def test_unsupported_needs_existing_per_id_root_oracle_review(self):
        self.row.update(status="UNSUPPORTED_CAPABILITY", execution_observed=False,
                        execution_kind="host_start", process_producers=[])
        path = self.save()
        with self.assertRaisesRegex(ValueError, "oracle reconciliation"):
            C.execution_inventory(path)
        record = self.root / "oracle.json"
        for owner, identity in (("worker", self.identity), ("root", "another-original")):
            record.write_text(json.dumps({"reviewed_by": owner, "run_scoped_case_id": identity}))
            self.row["oracle_record"] = C.Q.reference(record)
            path = self.save()
            with self.subTest(owner=owner), self.assertRaisesRegex(ValueError, "exact original ID"):
                C.execution_inventory(path)

    def test_export_output_is_confined_and_rejects_traversal_and_symlink_parents(self):
        outside = Path('/opt/i12-current-ledger-output-must-not-be-created')
        with self.assertRaisesRegex(ValueError, "approved"):
            C.export([], {}, outside)
        self.assertFalse(outside.exists())
        traversal = self.root / '..' / self.root.name / 'traversal-output'
        with self.assertRaisesRegex(ValueError, "approved"):
            C.export([], {}, traversal)
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        aliased = alias / 'output'
        with self.assertRaisesRegex(ValueError, "physical parents"):
            C.export([], {}, aliased)
        testing_output = C.Q.REPOSITORY / 'reports/testing/i12-output-guard-control'
        self.assertEqual(C.export_output(testing_output), testing_output)

    def test_diagnostic_http_pass_does_not_claim_required_body_lifecycle(self):
        qualifier = {"full_lifecycle_qualified": True, "execution_observed": True, "outcome": "PASS",
                     "unknown_fields": []}
        result = {"qualifier": qualifier, "status": "PASS",
                  "oracle_review": {"resolved": True, "effective_oracle": {}}}
        packet = {"execution_kind": "host_http", "run_id": "synthetic-control",
                  "parent_sha": "synthetic", "effective_config_sha256": "synthetic"}
        row = {"required_leg": False}
        actual = C.qualified_result(result, packet, [], row, {})
        self.assertTrue(actual["full_case_qualified"])
        self.assertTrue(actual["diagnostic_host_qualified"])
        self.assertFalse(actual["full_lifecycle_qualified"])
        row["required_leg"] = True
        required = C.qualified_result(result, packet, [], row, {})
        self.assertTrue(required["full_lifecycle_qualified"])
        self.assertFalse(required["diagnostic_host_qualified"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
