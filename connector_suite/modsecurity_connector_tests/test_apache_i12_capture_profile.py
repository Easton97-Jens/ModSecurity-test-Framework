"""Apache-only capture closure and unchanged shared disposable apply contract."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


SOURCE = connector_root() / "ci/runtime/lifecycle/apache-i12/acceptance/capture_profile.py"
CAPTURE = load_source(SOURCE)
SHARED = CAPTURE.SHARED


class ApacheCaptureProfileTests(unittest.TestCase):
    def setUp(self):
        storage = Path("/var/tmp/codex/ModSecurity-conector/apache-capture-profile-tests")
        storage.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=storage)
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "registry"
        self.repository = self.base / "repository"
        self.root.mkdir()
        self.repository.mkdir()
        self.original = b"original\n"
        self.replacement = b"observed\n"
        self.patch = b"--- a/payload\n+++ b/payload\n@@ -1 +1 @@\n-original\n+observed\n"
        self.fixture = b"capture\n"
        (self.root / "base.txt").write_bytes(self.original)
        (self.root / "delta.patch").write_bytes(self.patch)
        (self.root / "fixture.txt").write_bytes(self.fixture)
        (self.repository / "unused.txt").write_bytes(b"stale unrelated bytes\n")
        self.before = SHARED.digest(self.original)
        self.after = SHARED.digest(self.replacement)
        self.capture = SHARED.digest(self.fixture)
        self.unrelated = SHARED.digest(b"expected unrelated bytes\n")
        self.manifest = {
            "delivery_product_baseline": "1" * 40,
            "authorized_storage_root": str(self.base),
            "objects": {
                self.before: {"kind": "text", "file": "base.txt"},
                self.after: {"kind": "delta", "base": self.before, "patch": "delta.patch",
                             "patch_sha256": SHARED.digest(self.patch)},
                self.capture: {"kind": "text", "file": "fixture.txt"},
                self.unrelated: {"kind": "repository", "path": "unused.txt"},
            },
            "profiles": {
                "apache-current": {
                    "required_source_identity_format": "i12-disposable-source-copy-v2",
                    "source_targets": {"product.txt": {"before_sha256": self.before,
                                                       "sha256": self.after, "mode": 420}},
                    "capture_files": {"fixture.txt": {"sha256": self.capture, "mode": 493}},
                },
                "traefik": {"source_targets": {"unused.txt": {"sha256": self.unrelated}},
                            "capture_files": {}},
            },
        }
        self.save_manifest()

    def save_manifest(self):
        (self.root / "manifest.json").write_text(json.dumps(self.manifest))

    def registry(self):
        return CAPTURE.ApacheRegistry(self.root, self.repository)

    def export(self, name="export", data=None, mode=420):
        target = self.base / name
        target.mkdir()
        content = self.original if data is None else data
        (target / "product.txt").write_bytes(content)
        (target / "product.txt").chmod(mode)
        snapshot = {"format": "i12-source-export-manifest-v1", "source_revision": "2" * 40,
                    "git_tree": "3" * 40, "files": {
                        "product.txt": {"mode": mode, "sha256": SHARED.digest(content)}}, "gitlinks": {}}
        inventory = json.dumps(snapshot).encode()
        (target / SHARED.SNAPSHOT).write_bytes(inventory)
        marker = {"format": "i12-disposable-source-copy-v2", "path": str(target), "disposable": True,
                  "source_revision": "2" * 40, "snapshot_manifest": SHARED.SNAPSHOT,
                  "snapshot_manifest_sha256": SHARED.digest(inventory)}
        (target / SHARED.MARKER).write_text(json.dumps(marker))
        return target

    def apply(self, target):
        return CAPTURE.apply_apache(target, root=self.root, repository=self.repository)

    def test_transitive_delta_base_is_verified_and_unrelated_stale_object_is_excluded(self):
        result = self.registry().verify()
        self.assertEqual(result["verified_object_sha256"], sorted([self.before, self.after, self.capture]))
        self.assertFalse(result["global_manifest_verified"])
        self.assertFalse(result["runtime_qualified"])
        self.assertEqual(result["profiles"], 1)
        shared_registry = SHARED.Registry(self.root, self.repository)
        with self.assertRaisesRegex(ValueError, "Source byte hash mismatch"):
            shared_registry.verify()

    def test_selected_object_tamper_is_rejected_before_writes(self):
        (self.root / "fixture.txt").write_bytes(b"tampered\n")
        target = self.export()
        with self.assertRaisesRegex(ValueError, "Source byte hash mismatch"):
            self.apply(target)
        self.assertEqual((target / "product.txt").read_bytes(), self.original)
        self.assertFalse((target / SHARED.RECEIPT).exists())
        self.assertFalse((target / ".i12-capture").exists())

    def test_delta_base_tamper_is_rejected(self):
        (self.root / "base.txt").write_bytes(b"tampered base\n")
        registry = self.registry()
        with self.assertRaisesRegex(ValueError, "Source byte hash mismatch"):
            registry.verify()

    def test_delta_patch_tamper_is_rejected(self):
        (self.root / "delta.patch").write_bytes(self.patch + b"extra\n")
        registry = self.registry()
        with self.assertRaisesRegex(ValueError, "Source delta hash mismatch"):
            registry.verify()

    def test_missing_transitive_object_is_rejected(self):
        del self.manifest["objects"][self.before]
        self.save_manifest()
        registry = self.registry()
        with self.assertRaises(KeyError):
            registry.verify()

    def test_missing_selected_file_is_rejected(self):
        (self.root / "fixture.txt").unlink()
        registry = self.registry()
        with self.assertRaises(OSError):
            registry.verify()

    def test_cached_content_does_not_hide_later_tamper(self):
        registry = self.registry()
        registry.verify()
        (self.root / "base.txt").write_bytes(b"tampered\n")
        with self.assertRaisesRegex(ValueError, "Source byte hash mismatch"):
            registry.verify()

    def test_cycle_in_selected_closure_is_rejected(self):
        self.manifest["objects"][self.after]["base"] = self.after
        self.save_manifest()
        registry = self.registry()
        with self.assertRaisesRegex(ValueError, "Cyclic source delta"):
            registry.verify()

    def test_profile_cannot_be_selected_by_cli(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            CAPTURE.main(["verify", "--profile", "traefik"])
        self.assertEqual(caught.exception.code, 2)

    def test_v2_requirement_cannot_be_removed(self):
        self.manifest["profiles"]["apache-current"].pop("required_source_identity_format")
        self.save_manifest()
        registry = self.registry()
        with self.assertRaisesRegex(ValueError, "complete v2 export identity"):
            registry.verify()

    def test_shared_apply_bytes_modes_and_receipt_are_unchanged(self):
        # Make the complete synthetic manifest valid so both verifiers admit it.
        (self.repository / "unused.txt").write_bytes(b"expected unrelated bytes\n")
        apache_target, shared_target = self.export("apache"), self.export("shared")
        result = self.apply(apache_target)
        expected = SHARED.apply(SHARED.Registry(self.root, self.repository), "apache-current", shared_target)
        receipt = result["application_receipt"]
        self.assertEqual(receipt, json.loads((apache_target / SHARED.RECEIPT).read_text()))
        self.assertEqual({k: v for k, v in receipt.items() if k != "source_copy"},
                         {k: v for k, v in expected.items() if k != "source_copy"})
        for name, content, mode in (("product.txt", self.replacement, 420),
                                    (".i12-capture/apache-current/fixture.txt", self.fixture, 493)):
            self.assertEqual((apache_target / name).read_bytes(), content)
            self.assertEqual((apache_target / name).stat().st_mode & 0o777, mode)
        self.assertFalse(result["capture_verification"]["global_manifest_verified"])

    def test_unexpected_export_file_is_rejected(self):
        target = self.export()
        (target / "unlisted").write_text("unlisted")
        with self.assertRaisesRegex(ValueError, "Unexpected export object"):
            self.apply(target)

    def test_export_inventory_mode_tamper_is_rejected(self):
        target = self.export()
        (target / "product.txt").chmod(0o755)
        with self.assertRaisesRegex(ValueError, "Export source mode differs"):
            self.apply(target)

    def test_wrong_source_base_is_rejected_with_valid_inventory(self):
        target = self.export(data=b"different complete export\n")
        with self.assertRaisesRegex(ValueError, "Source-copy base differs"):
            self.apply(target)

    def test_invalid_selected_write_mode_retains_shared_rejection(self):
        self.manifest["profiles"]["apache-current"]["capture_files"]["fixture.txt"]["mode"] = 511
        self.save_manifest()
        target = self.export()
        with self.assertRaisesRegex(ValueError, "Invalid source-copy write"):
            self.apply(target)
        self.assertEqual((target / "product.txt").read_bytes(), self.original)

    def test_repeated_application_is_rejected(self):
        target = self.export()
        self.apply(target)
        with self.assertRaises(ValueError):
            self.apply(target)

    def test_current_apache_closure_resolves_despite_unrelated_stale_repository_object(self):
        registry = CAPTURE.ApacheRegistry()
        result = registry.verify()
        selected = set(result["verified_object_sha256"])
        self.assertGreaterEqual(len(selected), 23)
        self.assertEqual(result["profile"], "apache-current")
        # This integration check verifies the current checked-in Apache closure;
        # the synthetic stale Traefik regression above establishes the failure
        # distinction without pinning an unrelated connector's changing bytes.
        for identity in selected:
            self.assertEqual(SHARED.digest(registry.content(identity)), identity)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
