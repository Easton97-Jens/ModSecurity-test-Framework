"""NGINX evidence identity regressions, using synthetic measurements only."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = connector_root()
LEDGER = load_source(source_path('ci/runtime/lifecycle/i12/nginx/ledger.py', root=ROOT))


class NginxLedgerTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(os.environ.get(
            "I12_NGINX_LEDGER_TEST_ROOT",
            "/var/tmp/codex/ModSecurity-conector/runs/i12-nginx-410-20261015/ledger-tests",
        ))
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.oracle = {"native_result": "allow", "visible_status": 200, "phase": 2,
                       "physical_evidence_not_projection": True,
                       "unresolved_expected_value_reason": None}
        self.baseline = {"rows": [self.row(index) for index in range(140)]}

    def row(self, index):
        identity = f"I12::nginx-native::case-{index}"
        return {"run_scoped_case_id": identity, "leg_id": "nginx-native", "required_leg": True,
                "selected_requirement": {"run_scoped_case_id": identity,
                                         "expected_oracle": copy.deepcopy(self.oracle)},
                "status": "PASS" if index == 0 else "NOT_EXECUTED_UNQUALIFIED",
                "qualification_scope": "historical_configuration_only" if index == 0 else None,
                "partial_observations": {"revision": "original-native-revision", "chunks": [1, 2]},
                "oracle_reconciliation": None}

    def write(self, name, content):
        path = self.path / name
        path.write_text(json.dumps(content))
        return LEDGER.ORACLES.reference(path)

    def packet(self, index, transaction=None, request=None):
        row = self.baseline["rows"][index]
        transaction = transaction or f"tx-{index}"
        request_path = self.path / (request or f"selected-{index}-request.bin")
        request_path.write_bytes(b"GET /synthetic-fixture HTTP/1.1\r\n\r\n")
        request_ref = LEDGER.ORACLES.reference(request_path)
        receipt = self.write(f"client-{index}.json", {
            "selected_id": row["run_scoped_case_id"], "run_id": "synthetic-run", "clients": [{
                "label": "selected", "argv": ["fixture-client", "--request", str(request_path)],
                "observation": {"request_sha256": request_ref["sha256"]}}]})
        raw = self.write(f"raw-{index}.json", {"synthetic_test_measurement": index,
            "transaction_id": transaction, "run": "synthetic-run", "profile": "nginx-native",
            "case": row["run_scoped_case_id"]})
        observations = {}
        for field, roles in LEDGER.SHARED.ROLES.items():
            observations[field] = {"value": "synthetic", "evidence": [
                {**(receipt if field == "client_exit" else raw), "role": role}
                for role in sorted(roles)]}
        observations["native_transaction_id"]["value"] = {"value": transaction}
        packet = {"reviewed_by": "root", "run_scoped_case_id": row["run_scoped_case_id"],
                  "leg_id": "nginx-native", "execution_observed": True,
                  "execution_kind": "host_http", "run_id": "synthetic-run",
                  "parent_sha": "synthetic-parent", "framework_sha": "synthetic-framework",
                  "mrts_sha": "synthetic-mrts", "effective_config_sha256": "synthetic-config",
                  "observations": observations, "oracle_evaluated": True,
                  "oracle_sha256": LEDGER.ORACLES.canonical_digest(self.oracle),
                  "outcome": "PASS", "full_lifecycle_qualified": True}
        return {"packet": self.write(f"packet-{index}.json", packet),
                "request_identity": {"physical_request_path": str(request_path),
                                     "transaction_id": transaction}}

    def mutate_packet(self, record, mutation):
        path = Path(record["packet"]["path"])
        packet = json.loads(path.read_text())
        mutation(packet)
        path.write_text(json.dumps(packet))
        record["packet"] = LEDGER.ORACLES.reference(path)

    def test_preserves_all_original_rows_and_does_not_promote_configuration(self):
        original = copy.deepcopy(self.baseline)
        result = LEDGER.build_ledger(self.baseline, [])
        self.assertEqual(len(result["rows"]), 140)
        self.assertEqual(result["summary"]["full_lifecycle_pass"], 0)
        self.assertEqual([row["baseline"] for row in result["rows"]], original["rows"])
        self.assertEqual(self.baseline, original)

    def test_valid_packet_qualifies_one_original_id(self):
        result = LEDGER.build_ledger(self.baseline, [self.packet(1)])
        self.assertEqual(result["summary"]["new_qualified_original_ids"], 1)
        self.assertEqual(result["summary"]["full_lifecycle_pass"], 1)
        self.assertEqual(result["summary"]["new_selected_physical_host_requests"], 1)
        self.assertEqual(result["rows"][1]["baseline"], self.baseline["rows"][1])

    def test_duplicate_native_transaction_rejected(self):
        packets = [self.packet(1, "same"), self.packet(2, "same")]
        with self.assertRaisesRegex(ValueError, "physical request or run/native"):
            LEDGER.build_ledger(self.baseline, packets)

    def test_historical_qualified_transaction_cannot_qualify_a_different_id(self):
        old = self.packet(1, "historical-tx")
        row = self.baseline["rows"][1]
        row["current_lifecycle_packet"] = LEDGER.SHARED.reviewed_packet(old["packet"], row, self.oracle)
        row["qualification_scope"] = "full_host_lifecycle"
        row["status"] = "PASS"
        packets = [self.packet(2, "historical-tx")]
        with self.assertRaisesRegex(ValueError, "physical request or run/native"):
            LEDGER.build_ledger(self.baseline, packets)

    def test_duplicate_physical_request_path_rejected(self):
        packets = [self.packet(1, request="shared.bin"), self.packet(2, request="shared.bin")]
        with self.assertRaisesRegex(ValueError, "physical request or run/native"):
            LEDGER.build_ledger(self.baseline, packets)

    def test_duplicate_original_id_rejected(self):
        packet = self.packet(1)
        with self.assertRaisesRegex(ValueError, "duplicate original packet ID"):
            LEDGER.build_ledger(self.baseline, [packet, packet])

    def test_packet_sha_corruption_rejected(self):
        packet = self.packet(1)
        Path(packet["packet"]["path"]).write_text("{}")
        with self.assertRaisesRegex(ValueError, "SHA256"):
            LEDGER.build_ledger(self.baseline, [packet])

    def test_unknown_original_id_rejected(self):
        packet = self.packet(1)
        self.mutate_packet(packet, lambda p: p.update(run_scoped_case_id="I12::nginx-native::unknown"))
        with self.assertRaisesRegex(ValueError, "Unknown or duplicate"):
            LEDGER.build_ledger(self.baseline, [packet])

    def test_missing_prescribed_field_rejected(self):
        packet = self.packet(1)
        self.mutate_packet(packet, lambda p: p["observations"].pop("native_eos"))
        with self.assertRaisesRegex(ValueError, "every prescribed observation"):
            LEDGER.build_ledger(self.baseline, [packet])

    def test_unresolved_oracle_cannot_pass(self):
        packet = self.packet(1)
        self.baseline["rows"][1]["selected_requirement"]["expected_oracle"][
            "unresolved_expected_value_reason"] = "No independent expectation"
        self.mutate_packet(packet, lambda p: p.update(oracle_evaluated=False,
                                                     full_lifecycle_qualified=False))
        with self.assertRaisesRegex(ValueError, "unresolved oracle cannot receive a PASS"):
            LEDGER.build_ledger(self.baseline, [packet])

    def test_baseline_requires_exactly_140_unique_ids(self):
        for rows in (self.baseline["rows"][:-1], self.baseline["rows"] + [self.row(141)],
                     self.baseline["rows"][:-1] + [self.baseline["rows"][0]]):
            with self.subTest(size=len(rows)), self.assertRaisesRegex(ValueError, "exactly 140 unique"):
                LEDGER.build_ledger({"rows": rows}, [])

    def test_same_byte_request_alias_is_not_physical_client_identity(self):
        packet = self.packet(1)
        alias = self.path / "alias.bin"
        alias.write_bytes(Path(packet["request_identity"]["physical_request_path"]).read_bytes())
        packet["request_identity"]["physical_request_path"] = str(alias)
        with self.assertRaisesRegex(ValueError, "physical client proof"):
            LEDGER.build_ledger(self.baseline, [packet])

    def test_native_identity_must_match_observation(self):
        packet = self.packet(1)
        packet["request_identity"]["transaction_id"] = "another-transaction"
        with self.assertRaisesRegex(ValueError, "observed native transaction"):
            LEDGER.build_ledger(self.baseline, [packet])

    def test_copied_client_path_and_retagged_id_cannot_change_physical_run(self):
        original = self.packet(1)
        packet = json.loads(Path(original["packet"]["path"]).read_text())
        copied_request = self.path / "copied-request.bin"
        copied_request.write_bytes(Path(original["request_identity"]["physical_request_path"]).read_bytes())
        proof = packet["observations"]["client_exit"]["evidence"][0]
        copied_receipt = json.loads(Path(proof["path"]).read_text())
        copied_receipt["selected_id"] = self.baseline["rows"][2]["run_scoped_case_id"]
        copied_receipt["clients"][0]["argv"][-1] = str(copied_request)
        new_receipt_ref = self.write("copied-client.json", copied_receipt)
        packet["observations"]["client_exit"]["evidence"] = [{**new_receipt_ref, "role": "client_process"}]
        packet["run_scoped_case_id"] = copied_receipt["selected_id"]
        packet["run_id"] = "fabricated-second-run"
        copied = {"packet": self.write("copied-packet.json", packet), "request_identity": {
            "physical_request_path": str(copied_request), "transaction_id": "tx-1"}}
        with self.assertRaisesRegex(ValueError, "actual selected client receipt run"):
            LEDGER.build_ledger(self.baseline, [original, copied])

    def test_physical_native_case_binding_prevents_client_receipt_retag(self):
        packet = self.packet(1)
        raw_packet = json.loads(Path(packet["packet"]["path"]).read_text())
        proof = raw_packet["observations"]["client_exit"]["evidence"][0]
        receipt = json.loads(Path(proof["path"]).read_text())
        receipt["selected_id"] = self.baseline["rows"][2]["run_scoped_case_id"]
        ref = self.write("retagged-receipt.json", receipt)
        raw_packet["run_scoped_case_id"] = receipt["selected_id"]
        raw_packet["observations"]["client_exit"]["evidence"] = [{**ref, "role": "client_process"}]
        packet["packet"] = self.write("retagged-packet.json", raw_packet)
        with self.assertRaisesRegex(ValueError, "native raw run/profile/case"):
            LEDGER.build_ledger(self.baseline, [packet])

    def test_legacy_client_receipt_roles_run_is_validated(self):
        packet = self.packet(1)
        raw_packet = json.loads(Path(packet["packet"]["path"]).read_text())
        proof = raw_packet["observations"]["client_exit"]["evidence"][0]
        receipt = json.loads(Path(proof["path"]).read_text())
        receipt["roles"] = {"run_id": receipt.pop("run_id")}
        proof.update(self.write("legacy-receipt.json", receipt))
        packet["packet"] = self.write("legacy-packet.json", raw_packet)
        result = LEDGER.build_ledger(self.baseline, [packet])
        self.assertEqual(result["summary"]["new_qualified_original_ids"], 1)

    def test_new_source_resolution_preserves_original_unknown_oracle(self):
        packet = self.packet(1)
        row = self.baseline["rows"][1]
        row["selected_requirement"]["expected_oracle"][
            "unresolved_expected_value_reason"] = "original unknown expectation"
        source = self.write("independent-contract.json", {"fixture": "independent native contract"})
        packet["effective_oracle"] = {
            "run_scoped_case_id": row["run_scoped_case_id"], "leg_id": "nginx-native",
            "reviewed_by": "root", "category": "SOURCE_CONFIRMED_EXPECTATION",
            "interpretation": "Synthetic independent expectation for ledger regression",
            "scope": "test-only", "resolved_expectation": self.oracle,
            "independent_sources": [{**source, "kind": "native_engine_contract", "revision": "test-v1"}],
        }
        result = LEDGER.build_ledger(self.baseline, [packet])
        self.assertEqual(result["summary"]["new_source_confirmed_original_oracles"], 1)
        self.assertEqual(result["summary"]["remaining_original_open_oracles"], 0)
        self.assertEqual(result["rows"][1]["selected_requirement"]["expected_oracle"][
            "unresolved_expected_value_reason"], "original unknown expectation")

    def test_naked_oracle_cannot_replace_independent_review(self):
        packet = self.packet(1)
        packet["effective_oracle"] = self.oracle
        with self.assertRaisesRegex(ValueError, "Oracle review must bind"):
            LEDGER.build_ledger(self.baseline, [packet])

    def test_cli_confines_inputs_and_fresh_output_to_protected_run_root(self):
        baseline = self.path / "baseline.json"
        packets = self.path / "packets.json"
        output = self.path / "ledger.json"
        baseline.write_text(json.dumps(self.baseline))
        packets.write_text("[]")
        digest = hashlib.sha256(baseline.read_bytes()).hexdigest()
        environment = patch.dict(os.environ, {"CODEX_RUN_ROOT": str(self.path)})
        with environment, patch.object(LEDGER, "BASELINE_SHA256", digest):
            LEDGER.main(["--baseline", str(baseline), "--packets", str(packets),
                         "--output", str(output)])
        result = json.loads(output.read_text())
        self.assertEqual(result["summary"]["original_ids"], 140)
        self.assertEqual(result["inputs"]["baseline"]["sha256"], digest)

    def test_cli_rejects_escape_links_writable_ancestry_and_existing_output(self):
        baseline = self.path / "baseline.json"
        packets = self.path / "packets.json"
        baseline.write_text(json.dumps(self.baseline))
        packets.write_text("[]")
        digest = hashlib.sha256(baseline.read_bytes()).hexdigest()
        link = self.path / "baseline-link.json"
        link.symlink_to(baseline)
        writable = self.path / "writable"
        writable.mkdir(mode=0o777)
        writable.chmod(0o777)
        writable_packets = writable / "packets.json"
        writable_packets.write_text("[]")
        existing = self.path / "existing.json"
        existing.write_text("sentinel\n")
        outside = self.path.parent / "outside-ledger.json"
        noncanonical = self.path / ".." / self.path.name / "ledger.json"
        environment = patch.dict(os.environ, {"CODEX_RUN_ROOT": str(self.path)})
        with environment, patch.object(LEDGER, "BASELINE_SHA256", digest):
            for candidate_baseline, candidate_packets, candidate_output in (
                    (link, packets, self.path / "from-link.json"),
                    (baseline, writable_packets, self.path / "from-writable.json"),
                    (baseline, packets, existing),
                    (baseline, packets, outside),
                    (baseline, packets, noncanonical)):
                with self.subTest(output=candidate_output), self.assertRaises(ValueError):
                    LEDGER.main(["--baseline", str(candidate_baseline),
                                 "--packets", str(candidate_packets),
                                 "--output", str(candidate_output)])
        self.assertEqual(existing.read_text(), "sentinel\n")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
