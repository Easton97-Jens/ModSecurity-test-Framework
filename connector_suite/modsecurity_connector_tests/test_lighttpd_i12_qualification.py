"""Synthetic negative controls for the lighttpd adapter; never host evidence."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
MODULE_DIRECTORY = tempfile.TemporaryDirectory(
    prefix="lighttpd-qualification-module-", dir=os.environ.get("RUNNER_TEMP"))
MODULE_TEMP = Path(MODULE_DIRECTORY.name)
MODULE_EXTERNAL = MODULE_TEMP / "evidence"
MODULE_EXTERNAL.mkdir(mode=0o700)
with mock.patch.dict(os.environ, {"I12_TEST_ROOT": str(MODULE_EXTERNAL)}):
    Q = load_source(source_path('ci/runtime/lifecycle/i12/lighttpd/qualification.py', root=ROOT))


class LighttpdQualificationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(
            prefix="lighttpd-qualification-control-", dir=Q.EXTERNAL_ROOT)
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.identity = "I12::lighttpd-stock-sidecar::allow_without_marker"
        self.packet = Q.packet_template(self.identity, {
            "run_id": "synthetic-validator-control", "parent_sha": "control-parent",
            "framework_sha": "control-framework", "mrts_sha": "control-mrts",
            "effective_config_sha256": "control-config"})
        self.packet["execution_observed"] = True
        self.source = self.root / "independent-control.txt"
        self.source.write_text("Synthetic independent contract for guard testing only.\n")
        self.record = {
            "run_scoped_case_id": self.identity, "leg_id": "lighttpd-stock-sidecar",
            "reviewed_by": "worker", "category": "SOURCE_CONFIRMED_EXPECTATION",
            "interpretation": "Synthetic guard test, not a runtime or oracle resolution claim.",
            "scope": "adapter negative control",
            "independent_sources": [{**Q.reference(self.source), "kind": "native_engine_contract", "revision": "control"}],
        }
        self.packet_path = self.root / "packet-proposal.json"
        self.record_path = self.root / "oracle-proposal.json"
        self.review_path = self.root / "root-review.json"

    def save(self, review=True):
        self.packet_path.write_text(json.dumps(self.packet))
        self.record_path.write_text(json.dumps(self.record))
        if review:
            self.review_path.write_text(json.dumps({
                "run_scoped_case_id": self.identity, "reviewed_by": "root",
                "packet_sha256": Q.reference(self.packet_path)["sha256"],
                "oracle_record_sha256": Q.reference(self.record_path)["sha256"],
                "qualifier_source_sha256": Q.loaded_source_digests(),
                "independent_oracle_review": "Synthetic authorization control.",
                "physical_transaction_review": "Synthetic incomplete packet: all measurements absent."}))

    def qualify(self):
        return Q.qualify(self.packet_path, self.record_path, self.review_path, self.root / "result")

    def test_exact_original_id_and_all_unknowns_remain_unqualified(self):
        self.save()
        result = self.qualify()
        self.assertEqual(result["status"], "PARTIAL_HOST_MEASUREMENTS")
        self.assertFalse(result["qualifier"]["full_lifecycle_qualified"])
        self.assertEqual(set(result["qualifier"]["unknown_fields"]), set(Q.LEDGER.ROLES))
        self.assertTrue(result["new_evidence_refs"])

    def test_changed_proposal_cannot_reuse_root_approval(self):
        self.save()
        self.packet["outcome"] = "PASS"
        self.save(review=False)
        with self.assertRaisesRegex(ValueError, "Separate Root review"):
            self.qualify()

    def test_validator_snapshot_is_retained_and_midrun_source_change_is_rejected(self):
        frozen = {str(self.source): Q.SOURCES.snapshot(self.source)}
        destination = self.root / "frozen"
        destination.mkdir()
        with mock.patch.dict(Q.LOADED_SOURCES, frozen, clear=True):
            refs = Q.frozen_qualifier_sources(destination)
            self.assertEqual(Path(refs[0]["path"]).read_bytes(), self.source.read_bytes())
            self.assertEqual(Path(refs[0]["path"]).stat().st_mode & 0o777, 0o444)
            self.source.write_text("Different validator after module loading.\n")
            second = self.root / "second-frozen"
            second.mkdir()
            with self.assertRaisesRegex(ValueError, "changed during"):
                Q.frozen_qualifier_sources(second)

    def test_retained_source_substitution_cannot_reuse_root_approval(self):
        self.save()
        result = self.qualify()
        review = json.loads(self.review_path.read_text())
        Q.verify_qualifier_sources(result, review)
        result["qualifier_sources"][0] = {
            **result["qualifier_sources"][0], **Q.reference(self.source),
            "role": "qualification_source"}
        with self.assertRaisesRegex(ValueError, "differs from Root"):
            Q.verify_qualifier_sources(result, review)
        result["qualifier_sources"][0]["original_source_path"] = "unrelated.py"
        with self.assertRaisesRegex(ValueError, "approved identities"):
            Q.verify_qualifier_sources(result, review)

    def test_sibling_oracle_and_missing_observation_cannot_inherit_credit(self):
        self.record["run_scoped_case_id"] = "I12::lighttpd-stock-sidecar::deny_header_marker_403"
        self.save()
        with self.assertRaisesRegex(ValueError, "cannot transfer"):
            self.qualify()
        self.record["run_scoped_case_id"] = self.identity
        del self.packet["observations"]["native_free_calls"]
        self.save()
        with self.assertRaisesRegex(ValueError, "every prescribed observation"):
            self.qualify()

    def test_source_hash_corruption_and_symlink_proposals_are_rejected(self):
        self.save()
        self.source.write_text("Altered contract bytes.\n")
        with self.assertRaisesRegex(ValueError, "SHA256"):
            self.qualify()
        self.packet_path.unlink()
        self.packet_path.symlink_to(self.record_path)
        with self.assertRaisesRegex(ValueError, "symlink components"):
            self.qualify()

    def test_private_scope_and_unshared_files_are_required(self):
        with self.assertRaisesRegex(ValueError, "approved"):
            Q.reference("/etc/hosts")
        with self.assertRaisesRegex(ValueError, "approved"):
            Q.reference(self.root / ".." / self.root.name / self.source.name)
        os.link(self.source, self.root / "hardlink.txt")
        with self.assertRaisesRegex(ValueError, "unshared"):
            Q.reference(self.source)

    def test_existing_storage_parent_cannot_be_shared_writable_or_symlinked(self):
        protected = self.root / "protected"
        protected.mkdir(mode=0o700)
        with mock.patch.object(Q, "Path", return_value=protected):
            self.assertEqual(Q.storage_root(), protected)
            protected.chmod(0o777)
            with self.assertRaisesRegex(ValueError, "without shared write"):
                Q.storage_root()
        protected.chmod(0o700)
        link = self.root / "storage-link"
        link.symlink_to(protected, target_is_directory=True)
        with mock.patch.object(Q, "Path", return_value=link):
            with self.assertRaisesRegex(ValueError, "existing current-user-owned"):
                Q.storage_root()

    def test_import_defers_missing_external_root_until_first_use(self):
        missing = self.root / "does-not-exist"
        spec = importlib.util.spec_from_file_location(
            "lighttpd_adapter_missing_root_control", Path(Q.__file__))
        module = importlib.util.module_from_spec(spec)
        with mock.patch.dict(os.environ, {"I12_TEST_ROOT": str(missing)}):
            spec.loader.exec_module(module)
        self.assertEqual(module.EXTERNAL_ROOT, missing)
        with self.assertRaises(FileNotFoundError):
            module.storage_root()

    def test_non_lighttpd_and_unselected_ids_are_rejected(self):
        for identity in ("I12::traefik-native-uds::allow_without_marker",
                         "I12::lighttpd-stock-sidecar::invented-case"):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                Q.original_row(identity)

    def test_pre_native_source_review_cannot_be_inferred_or_changed(self):
        approval = {"reviewed_by": "worker", "proof": ["synthetic"], "case": self.identity}
        source = self.root / "approval.json"
        source.write_text(json.dumps(approval))
        packet = {"execution_kind": "host_pre_native_rejection", "source_approval": approval,
                  "outcome": None}
        with self.assertRaisesRegex(ValueError, "separate Root"):
            Q.reviewed_proposal(packet, {})
        review = {"pre_native_source_approval": Q.reference(source), "pre_native_outcome": "PASS"}
        result = Q.reviewed_proposal(packet, review)
        self.assertEqual(result["source_approval"]["reviewed_by"], "root")
        self.assertEqual(result["outcome"], "PASS")
        self.assertIsNone(packet["outcome"])
        self.assertIs(Q.packet_validator(packet), Q.LEDGER.reviewed_pre_native_packet)
        source.write_text(json.dumps({**approval, "case": "changed"}))
        with self.assertRaisesRegex(ValueError, "changed after"):
            Q.reviewed_proposal(packet, review)
        with self.assertRaisesRegex(ValueError, "execution-kind"):
            Q.packet_validator({"execution_kind": "invented_http"})



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
