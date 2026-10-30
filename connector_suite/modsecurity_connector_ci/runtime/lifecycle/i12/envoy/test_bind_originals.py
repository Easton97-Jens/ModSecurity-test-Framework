"""Original-ID capture binding controls; all binaries/controllers are inert fixtures."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import types
import unittest
from unittest import mock

if __package__:
    from . import bind_originals as BIND
else:
    import modsecurity_connector_ci.runtime.lifecycle.i12.envoy.bind_originals as BIND


class BaselinePathControls(unittest.TestCase):
    """Inert path controls; the reconciler is substituted, never a host run."""

    def setUp(self):
        if BIND.STORAGE is None or not BIND.STORAGE.is_dir():
            raise RuntimeError("configured external evidence storage is required")
        temp = tempfile.TemporaryDirectory(prefix="envoy-baseline-path-", dir=BIND.STORAGE)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.storage, self.repository, self.archives = (
            self.root / name for name in ("storage", "repository", "archives"))
        self.storage.mkdir()
        self.repository.mkdir()
        self.archives.mkdir()
        for owner, name, value in ((BIND, "STORAGE", self.storage),
                                   (BIND, "ROOT", self.repository),
                                   (BIND.evidence_io, "ARCHIVES", self.archives)):
            patch = mock.patch.object(owner, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.ledger = self.write(self.storage / "ledger.json", {"ledger": "inert"})
        self.oracles = self.write(self.storage / "oracles.json", {"oracles": "inert"})
        self.expected = {"rows": [], "new_host_runs": 0}
        self.baseline = self.write(self.storage / "baseline.json", self.expected | {
            "input_evidence": {"ledger": self.ref(self.ledger), "oracles": self.ref(self.oracles)}})

    def write(self, path, value):
        path.write_text(json.dumps(value))
        return path

    def ref(self, path):
        content = path.read_bytes()
        return {"path": str(path), "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}

    def replace_reference(self, name, ref):
        baseline = json.loads(self.baseline.read_text())
        baseline["input_evidence"][name] = ref
        self.write(self.baseline, baseline)

    def test_storage_baseline_preserves_exact_reconciliation_inputs(self):
        with mock.patch.object(BIND.baseline_producer, "reconcile", return_value=self.expected) as reconcile:
            result = BIND.validate_baseline(self.baseline)
        reconcile.assert_called_once_with({"ledger": "inert"}, {"oracles": "inert"})
        self.assertEqual({key: value for key, value in result.items() if key != "input_evidence"}, self.expected)

    def test_repository_reference_remains_supported(self):
        path = self.write(self.repository / "source.json", {"source": "inert"})
        self.assertEqual(BIND.reference(path), self.ref(path))
        self.assertEqual(BIND.check_reference(self.ref(path)), path)

    def test_archive_reference_remains_supported(self):
        path = self.write(self.archives / "retained.json", {"history": "inert"})
        self.assertEqual(BIND.reference(path), self.ref(path))
        self.assertEqual(BIND.check_reference(self.ref(path)), path)

    def test_relative_reference_is_anchored_to_executed_repository(self):
        path = self.write(self.repository / "relative.json", {"source": "inert"})
        self.assertEqual(BIND.check_reference(self.ref(path) | {"path": path.name}), path)

    def test_legacy_reference_without_optional_size_remains_supported(self):
        ref = self.ref(self.ledger)
        ref.pop("bytes")
        self.assertEqual(BIND.check_reference(ref), self.ledger)

    def test_changed_reference_hash_is_rejected(self):
        ref = self.ref(self.ledger) | {"sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "hash changed"):
            BIND.check_reference(ref)

    def test_changed_reference_size_is_rejected(self):
        ref = self.ref(self.ledger) | {"bytes": 1}
        with self.assertRaisesRegex(ValueError, "hash changed"):
            BIND.check_reference(ref)

    def test_baseline_semantic_mismatch_is_rejected(self):
        with mock.patch.object(BIND.baseline_producer, "reconcile", return_value={"rows": ["changed"]}), \
                self.assertRaisesRegex(ValueError, "Baseline differs"):
            BIND.validate_baseline(self.baseline)

    def reject_outside_baseline_reference(self, name):
        path = self.write(self.root / ("outside-" + name + ".json"), {"outside": "inert"})
        self.replace_reference(name, self.ref(path))
        real_open = os.open

        def checked_open(value, *args, **kwargs):
            self.assertNotEqual(os.fspath(value), path.name, "outside evidence was opened")
            return real_open(value, *args, **kwargs)

        with mock.patch.object(BIND.evidence_io.os, "open", side_effect=checked_open), \
                mock.patch.object(BIND.baseline_producer, "reconcile") as reconcile, \
                self.assertRaisesRegex(ValueError, "outside approved"):
            BIND.validate_baseline(self.baseline)
        reconcile.assert_not_called()

    def test_baseline_ledger_cannot_select_outside_evidence(self):
        self.reject_outside_baseline_reference("ledger")

    def test_baseline_oracles_cannot_select_outside_evidence(self):
        self.reject_outside_baseline_reference("oracles")

    def test_reference_traversal_is_rejected_before_open(self):
        ref = self.ref(self.ledger) | {"path": str(self.storage / ".." / "storage" / self.ledger.name)}
        with mock.patch.object(BIND.evidence_io.os, "open") as opened, \
                self.assertRaisesRegex(ValueError, "without traversal"):
            BIND.check_reference(ref)
        opened.assert_not_called()

    def test_reference_symlink_leaf_is_rejected(self):
        link = self.storage / "ledger-link.json"
        link.symlink_to(self.ledger)
        ref = self.ref(self.ledger) | {"path": str(link)}
        with self.assertRaises(OSError):
            BIND.check_reference(ref)

    def test_reference_symlink_parent_is_rejected(self):
        link = self.storage / "linked-parent"
        link.symlink_to(self.storage, target_is_directory=True)
        ref = self.ref(self.ledger) | {"path": str(link / self.ledger.name)}
        with self.assertRaises(OSError):
            BIND.check_reference(ref)

    def test_private_metadata_is_rejected_before_open(self):
        ref = self.ref(self.ledger) | {"path": str(self.repository / ".git" / "config")}
        with mock.patch.object(BIND.evidence_io.os, "open") as opened, \
                self.assertRaisesRegex(ValueError, "private configuration"):
            BIND.check_reference(ref)
        opened.assert_not_called()


class OriginalBindingControls(unittest.TestCase):
    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        return path

    def setUp(self):
        external = BIND.STORAGE
        temp = tempfile.TemporaryDirectory(prefix="envoy-original-binding-control-",
                                           dir=external if external is not None and external.is_dir() else None)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        patch = mock.patch.object(BIND, "STORAGE", self.root)
        patch.start()
        self.addCleanup(patch.stop)
        self.parent = "f" * 40
        self.identity = "I12::envoy-ext-authz-request::NEED-complete-sample"
        self.original = {"native_result": None, "visible_status": None,
                         "unresolved_expected_value_reason": "Synthetic control"}
        self.baseline = {"rows": [{"run_scoped_case_id": self.identity, "leg_id": "envoy-ext-authz-request",
                                   "original_oracle": copy.deepcopy(self.original)}]}
        self.baseline_path = self.write(self.root / "baseline.json", self.baseline)
        self.source = self.root / "old-run/host-source"
        original_source = self.root / "build/source"
        archive = original_source.parent / "native-build/source-archive.stdout"
        archive.parent.mkdir(parents=True)
        members = {"ci/runtime/lifecycle/i12/manifest.json": json.dumps({"delivery_product_baseline": self.parent}).encode(),
                   "unit.c": b"original", "connectors/envoy/ext_proc/go.mod": b"module inert-control"}
        with tarfile.open(archive, "w") as stream:
            for name, body in members.items():
                member = tarfile.TarInfo(name)
                member.size = len(body)
                stream.addfile(member, io.BytesIO(body))
        capture = {"exact_written_sha256": {"unit.c": hashlib.sha256(b"captured").hexdigest()}}
        self.proof = {"build_ready": True, "actual_source_commit": self.parent,
                      "source_copy": str(original_source), "capture_application": capture,
                      "checks": [{"label": "source-archive", "exit_code": 0,
                                  "argv": ["git", "archive", "--format=tar", self.parent],
                                  "stdout_sha256": BIND.host.sha(archive)}],
                      "binaries": {"build/a": hashlib.sha256(b"a").hexdigest()},
                      "module_inputs": {"go.mod": hashlib.sha256(members["connectors/envoy/ext_proc/go.mod"]).hexdigest()}}
        for name, body in members.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"captured" if name == "unit.c" else body)
        self.write(self.source / ".i12-disposable-source-copy.json",
                   {"format": "i12-disposable-source-copy-v1", "path": str(original_source),
                    "disposable": True, "parent_sha": self.parent})
        self.write(self.source / "i12-source-application-receipt.json", json.dumps(capture, indent=2) + "\n")
        source_binding = BIND.host.seal_tree(self.source) | {"target": "/mnt/src"}
        self.artifacts = self.root / "old-run/host-artifacts"
        self.write(self.artifacts / "a", "a")
        self.write(self.artifacts / "envoy", "inert-host")
        artifacts_binding = BIND.host.seal_tree(self.artifacts) | {"target": "/mnt/artifacts"}
        patch = mock.patch.object(BIND.host, "HOST_SHA", BIND.host.sha(self.artifacts / "envoy"))
        patch.start()
        self.addCleanup(patch.stop)
        self.fixture = self.root / "old-run/host-fixtures/ext-authz-request-streaming"
        self.shape = {"case_id": "I12-ENVOY-HOST::ext-authz-request-streaming", "parent_sha": self.parent,
                      "leg": "envoy-ext-authz-request", "request_hex": "616263", "response_hex": "646566",
                      "request_parts": 3, "request_mime": "text/plain; charset=utf-8", "target_backend": True,
                      "expected_status": 999, "host_request_buffer_max_bytes": 33,
                      "expected_source_oracle_proposal_only": {"visible_status": 999}}
        self.write(self.fixture / "shape.json", self.shape)
        for name in ("native.rules", "native.conf", "envoy.yaml", "client.py", "backend.py", "driver.py"):
            self.write(self.fixture / name, "# inert synthetic input " + name)
        wrapper = self.write(self.fixture / "cc-wrapper.sh", "# inert executable control")
        wrapper.chmod(0o700)
        self.write(self.fixture / "actual-build-provenance-v1.json", self.proof)
        fixture_binding = BIND.host.seal_tree(self.fixture) | {"target": "/mnt/fixtures"}
        self.spec = {"mode": "nonroot", "timeout_seconds": 120, "setup_timeout_seconds": 120,
                     "resource_limits": copy.deepcopy(BIND.LIMITS),
                     "argv": ["/usr/local/bin/python3", "-P", "/mnt/fixtures/driver.py"],
                     "bindings": [source_binding, artifacts_binding, fixture_binding],
                     "environment": {"CONNECTOR_ROOT": "/mnt/src"}}
        self.spec_path = self.write(self.fixture.parent / (self.fixture.name + "-admission.json"), self.spec)
        source_ref = BIND.reference(self.source / "unit.c")
        self.row = {"run_scoped_case_id": self.identity, "route": "envoy-ext-authz-request",
                    "category": "SOURCE_SEMANTICS_CONFIRMED", "original_oracle": self.original,
                    "lifecycle_qualified": False, "source_refs": [source_ref],
                    "effective_oracle": {"native_result": "allow", "visible_status": 200, "phase": 2},
                    "fixture_binding": {"origin": "new_task_fixture_binding", "run_scoped_case_id": self.identity,
                                        "physical_inputs": [BIND.reference(self.fixture / "shape.json")]}}
        self.review_path = self.write(self.root / "review.json", {"rows": [self.row]})
        self.historical = self.root / "historical"
        self.controller = self.write(self.historical / "isolation/private-runtime-v5.py",
                                     "import json\nfrom pathlib import Path\nRUN = Path('" + str(self.historical) + "')\n"
                                     "def read_spec(path):\n"
                                     "    spec = json.loads(path.read_text())\n"
                                     "    assert all(Path(b['source']).is_relative_to(RUN) for b in spec['bindings'])\n"
                                     "    return spec\n")
        self.admission = self.write(self.historical / "isolation/candidate-admission-v5.py", "# inert admission")
        for name, value in (("OLD_CONTROLLER_SHA", BIND.host.sha(self.controller)),
                            ("ADMISSION_SHA", BIND.host.sha(self.admission))):
            patch = mock.patch.object(BIND.host, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.run = self.root / "fresh-run"
        self.write(self.run / ".codex-storage-budget.json", {"status": "registered", "run_root": str(self.run)})
        self.args = types.SimpleNamespace(run_root=self.run, historical=self.historical,
                                         baseline=self.baseline_path, oracle_review=[self.review_path])

    def selected(self):
        self.write(self.review_path, {"rows": [self.row]})
        return BIND.selected_reviews([self.review_path], self.baseline, BIND.reference(self.baseline_path))

    def prepare(self):
        with mock.patch.object(BIND, "validate_baseline", return_value=self.baseline), \
             mock.patch.object(BIND.host, "controller_source", side_effect=lambda text, old, new: text.replace(str(old), str(new))):
            return BIND.prepare(self.args)

    def test_retake_preserves_stimulus_seals_and_exact_original_identity(self):
        result = self.prepare()
        self.assertFalse(result["host_launched"])
        self.assertEqual(result["new_lifecycle_pass"], 0)
        case = result["scenarios"][0]
        spec = json.loads(Path(case["spec"]).read_text())
        fixture = Path(next(item for item in spec["bindings"] if item["target"] == "/mnt/fixtures")["source"])
        shape = json.loads((fixture / "shape.json").read_text())
        self.assertEqual(shape["case_id"], "I12-ENVOY-HOST::" + case["label"])
        self.assertEqual(shape["original_case_ids"], [self.identity])
        self.assertEqual(shape["original_case_ids"], case["original_case_ids"])
        self.assertEqual(shape["oracle_review_sha256"], case["oracle_review_sha256"])
        self.assertEqual(shape["expected_status"], 200)
        self.assertNotIn("host_request_buffer_max_bytes", shape)
        self.assertNotIn("expected_source_oracle_proposal_only", shape)
        for field in ("request_hex", "response_hex", "request_parts", "request_mime", "target_backend"):
            self.assertEqual(shape[field], self.shape[field])
        for name in ("native.rules", "native.conf", "envoy.yaml", "client.py", "backend.py", "driver.py"):
            self.assertEqual((fixture / name).read_bytes(), (self.fixture / name).read_bytes())
        self.assertTrue((fixture / "cc-wrapper.sh").stat().st_mode & 0o111)
        self.assertFalse((fixture / "shape.json").stat().st_mode & 0o222)
        for copied, original in zip(spec["bindings"][:2], self.spec["bindings"][:2]):
            self.assertTrue(Path(copied["source"]).is_relative_to(self.run))
            self.assertTrue(Path(copied["ledger"]).is_relative_to(self.run))
            self.assertEqual(copied["target"], original["target"])
            self.assertEqual(copied["ledger_sha256"], original["ledger_sha256"])
            BIND.verify_binding(copied)
        self.assertTrue(all(Path(item["source"]).is_relative_to(self.run) for item in spec["bindings"]))
        self.assertEqual({k: v for k, v in spec.items() if k != "bindings"},
                         {k: v for k, v in self.spec.items() if k != "bindings"})
        self.assertEqual(json.loads((self.fixture / "shape.json").read_text()), self.shape)
        self.assertEqual(case["qualification"], "unreviewed_capture_input")

    def test_unknown_original_or_missing_binding_identity_or_route_substitution_rejected(self):
        for field, value in (("run_scoped_case_id", "I12::envoy-ext-authz-request::invented"),
                             ("route", "envoy-ext-proc"), ("original_oracle", {"visible_status": 200})):
            original = copy.deepcopy(self.row)
            self.row[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.selected()
            self.row = original
        self.row["fixture_binding"].pop("run_scoped_case_id")
        with self.assertRaisesRegex(ValueError, "exact original identity"):
            self.selected()

    def test_changed_reviewed_fixture_hash_and_lifecycle_promotion_rejected(self):
        self.row["fixture_binding"]["physical_inputs"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "hash changed"):
            self.selected()
        self.row["fixture_binding"]["physical_inputs"][0] = BIND.reference(self.fixture / "shape.json")
        self.row["lifecycle_qualified"] = True
        with self.assertRaisesRegex(ValueError, "cannot qualify"):
            self.selected()

    def test_companion_file_schema_and_duplicate_original_ids(self):
        row = copy.deepcopy(self.row)
        row["fixture_binding"] = {"origin": "new_task_fixture_binding", "original_id": self.identity,
                                  "files": [BIND.reference(self.fixture / "shape.json")]}
        self.write(self.review_path, {"records": [row]})
        selected, _ = BIND.selected_reviews([self.review_path], self.baseline, BIND.reference(self.baseline_path))
        self.assertEqual(len(selected), 1)
        self.write(self.review_path, {"records": [row, row]})
        baseline_ref = BIND.reference(self.baseline_path)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            BIND.selected_reviews([self.review_path], self.baseline, baseline_ref)

    def test_extra_unreviewed_source_file_is_not_hidden_by_capture_overlay_hashes(self):
        self.source.chmod(0o700)
        self.write(self.source / "unexpected.c", "unreviewed")
        self.source.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "complete inventory"):
            self.prepare()

    def test_resealed_extra_source_still_fails_independent_archive_inventory(self):
        self.source.chmod(0o700)
        self.write(self.source / "unreviewed-but-resealed.c", "not part of build archive")
        ledger = Path(self.spec["bindings"][0]["ledger"])
        ledger.chmod(0o600)
        self.spec["bindings"][0] = BIND.host.seal_tree(self.source) | {"target": "/mnt/src"}
        self.write(self.spec_path, self.spec)
        with self.assertRaisesRegex(ValueError, "build-source inventory mismatch"):
            self.prepare()
        self.assertEqual([path.name for path in self.run.iterdir()], [".codex-storage-budget.json"])

    def test_host_image_or_privilege_boundary_substitution_rejected(self):
        self.spec["mode"] = "root"
        self.write(self.spec_path, self.spec)
        with self.assertRaisesRegex(ValueError, "privilege boundary"):
            self.prepare()
        self.spec["mode"] = "nonroot"
        self.write(self.spec_path, self.spec)
        with mock.patch.object(BIND.host, "HOST_SHA", "0" * 64), self.assertRaisesRegex(ValueError, "Envoy image"):
            self.prepare()

    def test_fresh_registration_and_parent_revision_required(self):
        self.write(self.run / "prior.json", {})
        with self.assertRaisesRegex(ValueError, "Fresh registered"):
            self.prepare()
        (self.run / "prior.json").unlink()
        self.write(self.run / ".codex-storage-budget.json", {"status": "registered", "run_root": "/wrong"})
        with self.assertRaisesRegex(ValueError, "registration identity"):
            self.prepare()
        with self.assertRaisesRegex(ValueError, "Parent"):
            BIND.verified_admission(self.fixture / "shape.json", "not-a-parent", {})

    def test_explicit_comparison_oracle_changes_only_expected_result(self):
        row = {"effective_oracle": {"visible_status": 403,
                                    "process_partial_comparison": {"visible_status": 200}}}
        shape = {"case_id": "I12-ENVOY-HOST::ext-authz-request-request-partial", "expected_status": 999}
        self.assertEqual(BIND.fixture_oracle(row, shape), {"visible_status": 200})
        self.assertEqual(shape["expected_status"], 999)
        self.assertEqual(row["effective_oracle"]["visible_status"], 403)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
