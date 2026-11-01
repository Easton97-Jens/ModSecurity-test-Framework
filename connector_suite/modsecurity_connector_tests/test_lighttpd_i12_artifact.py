"""Evidence packages reject lost, changed and unsafe producer/archive bytes."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import subprocess
import sys
import unittest
from unittest import mock


REPO = connector_root()
MODULE_DIRECTORY = tempfile.TemporaryDirectory(
    prefix="lighttpd-artifact-module-", dir=os.environ.get("RUNNER_TEMP"))
MODULE_TEMP = Path(MODULE_DIRECTORY.name)
MODULE_EXTERNAL = MODULE_TEMP / "evidence"
MODULE_EXTERNAL.mkdir(mode=0o700)
with mock.patch.dict(os.environ, {"I12_TEST_ROOT": str(MODULE_EXTERNAL)}):
    A = load_source(REPO / 'ci/runtime/lifecycle/i12/lighttpd/artifact.py')


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(
            prefix="i12-artifact-test-", dir=A.Q.EXTERNAL_ROOT)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.payload = self.root / "physical-client.bin"
        self.payload.write_bytes(b"test-only HTTP body\x00\r\n")
        self.receipt = self.root / "physical-client.json"
        self.receipt.write_text(json.dumps({"original_id": "synthetic-negative-control",
                                            "body": A.Q.reference(self.payload)}))
        self.seed = self.root / "selection.json"
        self.write_seed()

    def write_seed(self, **updates):
        seed = {"schema": "lighttpd-i12-artifact-selection-v1", "reviewed_by": "root",
                "publication_review": "Synthetic test-only local fixture; never host evidence.",
                "revision_binding": {"parent_sha": "test-only"},
                "follow_json_references": True, "files": [A.Q.reference(self.receipt)]}
        seed.update(updates)
        self.seed.write_text(json.dumps(seed))

    def package(self):
        return A.build(self.seed, self.root / "package")

    def test_download_copy_verifies_original_producers_without_extraction(self):
        first = self.package()
        copied = self.root / "retrieved.tar.gz"
        copied.write_bytes(Path(first["archive"]["path"]).read_bytes())
        result = A.verify(copied, first["archive"]["sha256"])
        self.assertTrue(result["verified"])
        self.assertTrue(result["raw_complete"])
        self.assertEqual(result["objects"], 3)
        self.assertFalse((self.root / "physical-client.bin/extracted").exists())

    def test_changed_or_missing_raw_reference_cannot_be_packaged(self):
        self.payload.write_bytes(b"different from the independent receipt")
        with self.assertRaisesRegex(ValueError, "differ"):
            self.package()
        self.payload.unlink()
        with self.assertRaises(FileNotFoundError):
            A.build(self.seed, self.root / "missing-package")

    def test_symlink_hardlink_and_file_budget_are_enforced(self):
        alias = self.root / "alias"
        alias.symlink_to(self.payload)
        self.write_seed(files=[{"path": str(alias), "sha256": hashlib.sha256(self.payload.read_bytes()).hexdigest()}])
        with self.assertRaisesRegex(ValueError, "physical"):
            self.package()
        alias.unlink()
        os.link(self.payload, alias)
        self.write_seed(files=[{"path": str(self.payload), "sha256": hashlib.sha256(self.payload.read_bytes()).hexdigest()}])
        with self.assertRaisesRegex(ValueError, "unshared"):
            A.build(self.seed, self.root / "hardlink-package")
        alias.unlink()
        with self.assertRaisesRegex(ValueError, "per-file budget"):
            A.build(self.seed, self.root / "budget-package", maximum=1)

    def test_explicit_missing_history_remains_incomplete(self):
        missing = A.Q.reference(self.payload)
        self.payload.unlink()
        self.write_seed(unavailable_references=[{**missing, "reason": "Synthetic historical raw intentionally unavailable"}])
        result = self.package()
        self.assertFalse(result["verification"]["raw_complete"])
        self.assertEqual(result["unavailable_references"], 1)

    def test_opaque_attestation_does_not_expand_nested_references(self):
        self.payload.unlink()
        self.write_seed(files=[{**A.Q.reference(self.receipt),
                                "follow_json_references": False}])
        result = self.package()
        self.assertTrue(result["verification"]["raw_complete"])
        self.assertEqual(result["objects"], 2)

    def test_exact_immutable_snapshot_resolves_changed_original_path(self):
        original = A.Q.reference(self.payload)
        snapshot = self.root / "historical-source.snapshot"
        snapshot.write_bytes(self.payload.read_bytes())
        self.payload.write_bytes(b"new source revision")
        self.write_seed(files=[original], immutable_snapshots=[A.Q.reference(snapshot)])
        result = self.package()
        manifest = json.loads(Path(result["manifest"]["path"]).read_text())
        self.assertEqual(len(manifest["immutable_snapshot_resolutions"]), 1)
        self.assertEqual(manifest["immutable_snapshot_resolutions"][0]["reference"]["path"],
                         str(self.payload))

    def test_wrong_immutable_snapshot_cannot_hide_changed_original(self):
        original = A.Q.reference(self.payload)
        snapshot = self.root / "unrelated.snapshot"
        snapshot.write_bytes(b"different historical bytes")
        self.payload.write_bytes(b"new source revision")
        self.write_seed(files=[original], immutable_snapshots=[A.Q.reference(snapshot)])
        with self.assertRaisesRegex(ValueError, "differ"):
            self.package()

    def test_immutable_snapshot_preload_obeys_total_budget(self):
        original = A.Q.reference(self.payload)
        snapshot = self.root / "historical-source.snapshot"
        snapshot.write_bytes(self.payload.read_bytes())
        self.payload.write_bytes(b"new source revision")
        self.write_seed(files=[original], immutable_snapshots=[A.Q.reference(snapshot)])
        total_maximum = len(snapshot.read_bytes()) - 1
        with self.assertRaisesRegex(ValueError, "total-byte budget"):
            A.build(self.seed, self.root / "snapshot-budget-package",
                    maximum=1024, total_maximum=total_maximum)

    def test_snapshot_fallback_rejects_forbidden_and_symlinked_missing_paths(self):
        snapshot = A.Q.reference(self.payload)
        cases = [
            ("foreign", Path("/etc/i12-lighttpd-historical-missing"), "approved roots"),
            ("traversal", self.root / "missing" / ".." / "target", "traversal"),
        ]
        dangling = self.root / "dangling-parent"
        dangling.symlink_to(self.root / "absent-target", target_is_directory=True)
        cases.append(("dangling", dangling / "target", "symlink components"))
        for label, path, diagnostic in cases:
            with self.subTest(label=label):
                original = {"path": str(path), "sha256": snapshot["sha256"],
                            "bytes": snapshot["bytes"]}
                self.write_seed(files=[original], immutable_snapshots=[snapshot])
                with self.assertRaisesRegex(ValueError, diagnostic):
                    A.build(self.seed, self.root / (label + "-package"))

    def test_opaque_duplicate_cannot_suppress_requested_reference_closure(self):
        opaque = {**A.Q.reference(self.receipt), "follow_json_references": False}
        recursive = {**A.Q.reference(self.receipt), "follow_json_references": True}
        self.write_seed(files=[recursive, opaque])
        result = self.package()
        self.assertEqual(result["objects"], 3)

    def test_recursive_roots_leave_foreign_nested_reference_out_of_scope(self):
        self.write_seed(recursive_reference_roots=[str(self.root / "different-root")])
        result = self.package()
        manifest = json.loads(Path(result["manifest"]["path"]).read_text())
        self.assertEqual(result["objects"], 2)
        self.assertEqual(len(manifest["out_of_scope_references"]), 1)

    def malicious_archive(self, members):
        target = self.root / "malicious.tar.gz"
        with tarfile.open(target, "w:gz") as archive:
            for info, data in members:
                archive.addfile(info, io.BytesIO(data))
        return target, A.Q.reference(target)["sha256"]

    def test_traversal_links_and_duplicate_archive_members_fail(self):
        for kind in ("traversal", "link", "duplicate"):
            with self.subTest(kind=kind):
                info = tarfile.TarInfo("../outside" if kind == "traversal" else "objects/" + "a" * 64)
                info.size = 0
                if kind == "link":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "/etc/passwd"
                if kind == "duplicate":
                    info.name = "manifest.json"
                    info.size = 2
                    entries = [(info, b"{}"), (info, b"{}")]
                else:
                    entries = [(info, b"")]
                target, digest = self.malicious_archive(entries)
                with self.assertRaises(ValueError):
                    A.verify(target, digest)
        self.assertFalse((self.root.parent / "outside").exists())

    def test_changed_retrieved_archive_and_lost_object_fail(self):
        result = self.package()
        target = Path(result["archive"]["path"])
        target.write_bytes(target.read_bytes() + b"unexpected download bytes")
        with self.assertRaisesRegex(ValueError, "Retrieved archive"):
            A.verify(target, result["archive"]["sha256"])
        manifest = Path(result["manifest"]["path"]).read_bytes()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        path, digest = self.malicious_archive([(info, manifest)])
        with self.assertRaisesRegex(ValueError, "objects differ"):
            A.verify(path, digest)

    def test_verify_cli_rejects_external_traversal_and_parent_symlink_inputs(self):
        result = self.package()
        actual = Path(result["archive"]["path"])
        alias = self.root / "alias"
        alias.symlink_to(actual.parent, target_is_directory=True)
        cases = ((Path("/etc/hostname"), "approved evidence roots"),
                 (actual.parent / ".." / actual.parent.name / actual.name, "without traversal"),
                 (alias / actual.name, "without symlink components"))
        for path, diagnostic in cases:
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, diagnostic):
                    A.verify(path, result["archive"]["sha256"])
                process = subprocess.run(
                    ["rtk", "proxy", sys.executable, str(Path(A.__file__)), "verify",
                     "--archive", str(path), "--expected-sha256", result["archive"]["sha256"]],
                    capture_output=True, text=True, timeout=15,
                    env={**os.environ, "I12_TEST_ROOT": str(A.Q.EXTERNAL_ROOT)})
                self.assertNotEqual(process.returncode, 0)
                self.assertIn(diagnostic, process.stderr)
                self.assertEqual(process.stdout, "")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
