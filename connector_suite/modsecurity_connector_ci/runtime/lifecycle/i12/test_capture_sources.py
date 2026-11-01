"""Focused ownership/base/patch negative controls; no capture programs run."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import difflib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import copy
import subprocess
import tarfile
import unittest

CAPTURE = load_source(Path(__file__).with_name('capture_sources.py'))
def _private_fixture_root() -> Path:
    from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root

    declared = os.environ.get("I12_TEST_ROOT") or os.environ.get("RUNNER_TEMP")
    if not declared:
        raise RuntimeError("I12_TEST_ROOT or RUNNER_TEMP must name existing private storage")
    return validate_output_root(connector_root(), Path(declared))


class CaptureSourceControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="unit-", dir=_private_fixture_root())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle, self.repo, self.copy = (self.root / name for name in ("bundle", "repository", "copy"))
        for directory in (self.bundle, self.repo, self.copy):
            directory.mkdir()
        self.original = b"int module(void) {\n    return 0;\n}\n"
        self.observed = b"int module(void) {\n    record_actual_call();\n    return 0;\n}\n"
        (self.repo / "module.c").write_bytes(self.original)
        (self.copy / "module.c").write_bytes(self.original)
        before, after = map(CAPTURE.digest, (self.original, self.observed))
        patch = "".join(difflib.unified_diff(self.original.decode().splitlines(keepends=True), self.observed.decode().splitlines(keepends=True), fromfile="a/payload", tofile="b/payload")).encode()
        (self.bundle / "capture.patch").write_bytes(patch)
        client = b"raise RuntimeError('capture source must not execute')\n"
        (self.bundle / "client.py.lines.json").write_text(json.dumps(client.decode().splitlines(keepends=True)))
        identity = CAPTURE.digest(client)
        self.manifest = {"delivery_product_baseline": "8" * 40, "authorized_storage_root": str(self.root),
            "objects": {before: {"kind": "repository", "path": "module.c"},
                after: {"kind": "delta", "base": before, "patch": "capture.patch", "patch_sha256": CAPTURE.digest(patch)},
                identity: {"kind": "text_lines", "file": "client.py.lines.json"}},
            "profiles": {"selected": {"source_targets": {"module.c": {"before_sha256": before, "sha256": after}},
                "capture_files": {"client.py": {"sha256": identity}}}}}
        self.save_manifest()
        self.marker()

    def save_manifest(self):
        (self.bundle / "manifest.json").write_text(json.dumps(self.manifest))

    def marker(self):
        (self.copy / CAPTURE.MARKER).write_text(json.dumps({"format": "i12-disposable-source-copy-v1", "path": str(self.copy), "disposable": True, "parent_sha": "8" * 40}))

    def apply(self):
        return CAPTURE.apply(CAPTURE.Registry(self.bundle, self.repo), "selected", self.copy)

    def assert_refused_unchanged(self):
        before = (self.copy / "module.c").read_bytes()
        with self.assertRaises((ValueError, OSError)):
            self.apply()
        self.assertEqual((self.copy / "module.c").read_bytes(), before)
        self.assertFalse((self.copy / ".i12-capture").exists())

    def test_exact_application_and_no_capture_execution(self):
        result = self.apply()
        self.assertEqual((self.copy / "module.c").read_bytes(), self.observed)
        self.assertEqual((self.copy / ".i12-capture/selected/client.py").read_bytes(),
                         b"raise RuntimeError('capture source must not execute')\n")
        self.assertFalse(result["runtime_qualified"])

    def test_existing_receipt_refused_before_source_writes(self):
        receipt = self.copy / "i12-source-application-receipt.json"
        original = b'{"retained_original_receipt": true}\n'
        receipt.write_bytes(original)
        self.assert_refused_unchanged()
        self.assertEqual(receipt.read_bytes(), original)

    def test_hardlinked_receipt_refused_before_source_or_foreign_writes(self):
        foreign = self.root / "foreign-evidence.json"
        original = b'{"retained_foreign_evidence": true}\n'
        foreign.write_bytes(original)
        receipt = self.copy / "i12-source-application-receipt.json"
        os.link(foreign, receipt)
        self.assert_refused_unchanged()
        self.assertEqual(foreign.read_bytes(), original)
        self.assertEqual(receipt.read_bytes(), original)

    def test_receipt_directory_refused_before_source_writes(self):
        receipt = self.copy / "i12-source-application-receipt.json"
        receipt.mkdir()
        retained = receipt / "retained.txt"
        original = b"existing directory contents\n"
        retained.write_bytes(original)
        self.assert_refused_unchanged()
        self.assertTrue(receipt.is_dir())
        self.assertEqual(retained.read_bytes(), original)

    def test_marker_missing_or_wrong_identity(self):
        (self.copy / CAPTURE.MARKER).unlink()
        self.assert_refused_unchanged()
        self.marker()
        value = json.loads((self.copy / CAPTURE.MARKER).read_text())
        value["path"] = str(self.repo)
        (self.copy / CAPTURE.MARKER).write_text(json.dumps(value))
        self.assert_refused_unchanged()

    def test_root_or_nested_git_refused(self):
        for relative in (".git", "nested/.git"):
            path = self.copy / relative
            path.parent.mkdir(exist_ok=True)
            path.write_text("gitdir: protected-checkout")
            self.assert_refused_unchanged()
            path.unlink()

    def test_symlink_in_copy_refused(self):
        (self.copy / "alias").symlink_to(self.repo, target_is_directory=True)
        self.assert_refused_unchanged()

    def test_hardlinked_product_file_refused(self):
        (self.copy / "module.c").unlink()
        os.link(self.repo / "module.c", self.copy / "module.c")
        self.assert_refused_unchanged()
        self.assertEqual((self.repo / "module.c").read_bytes(), self.original)

    def test_later_bad_base_refused_before_first_write(self):
        self.manifest["profiles"]["selected"]["source_targets"]["unexpected.c"] = {"before_sha256": "0" * 64, "sha256": CAPTURE.digest(self.observed)}
        (self.copy / "unexpected.c").write_text("wrong source")
        self.save_manifest()
        self.assert_refused_unchanged()

    def test_modified_delta_refused(self):
        (self.bundle / "capture.patch").write_text("not the sealed delta")
        self.assert_refused_unchanged()

    def test_context_patch_has_no_fuzz(self):
        modified = self.original.replace(b"return 0", b"return 1")
        patch = (self.bundle / "capture.patch").read_bytes()
        with self.assertRaises(ValueError):
            CAPTURE.exact_patch(modified, patch)

    def test_zero_context_patch_matches_standard_offsets(self):
        patch = "".join(difflib.unified_diff(self.original.decode().splitlines(keepends=True), self.observed.decode().splitlines(keepends=True), fromfile="a/payload", tofile="b/payload", n=0)).encode()
        self.assertEqual(CAPTURE.exact_patch(self.original, patch), self.observed)

    def test_lossless_source_lines_preserve_original_whitespace(self):
        original = b"# retained original line \n"
        identity = CAPTURE.digest(original)
        (self.bundle / "original.lines.json").write_text(json.dumps(original.decode().splitlines(keepends=True)))
        self.manifest["objects"][identity] = {"kind": "text_lines", "file": "original.lines.json"}
        self.save_manifest()
        self.assertEqual(CAPTURE.Registry(self.bundle, self.repo).content(identity), original)

    def test_escape_path_refused(self):
        self.manifest["profiles"]["selected"]["capture_files"] = {"../escaped.py": next(iter(self.manifest["profiles"]["selected"]["capture_files"].values()))}
        self.save_manifest()
        self.assert_refused_unchanged()
        self.assertFalse((self.copy / "escaped.py").exists())

    def test_non_directory_capture_parent_refused_before_product_write(self):
        (self.copy / ".i12-capture").write_text("existing user file")
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual((self.copy / "module.c").read_bytes(), self.original)


class ArchiveStorageControls(unittest.TestCase):
    def test_executable_source_objects_require_inert_line_storage(self):
        with tempfile.TemporaryDirectory(prefix="archive-data-", dir=_private_fixture_root()) as temporary:
            root = Path(temporary)
            identity = "0" * 64
            (root / "manifest.json").write_text(json.dumps({"objects": {
                identity: {"kind": "text", "file": "client.py"}}}))
            registry = CAPTURE.Registry(root, root)
            with self.assertRaisesRegex(ValueError, "inert lossless text-line data"):
                registry.content(identity)


class CurrentSourceCopyControls(CaptureSourceControls):
    def setUp(self):
        super().setUp()
        # Binary and executable files outside the capture target must also bind.
        self.extra = self.copy / "fixture.bin"
        self.extra.write_bytes(b"\0exact export bytes\xff")
        self.extra.chmod(493)
        self.revision = "a" * 40
        self.snapshot = {"format": "i12-source-export-manifest-v1",
            "source_revision": self.revision, "git_tree": "b" * 40,
            "files": {"module.c": {"mode": 420, "sha256": CAPTURE.digest(self.original)},
                      "fixture.bin": {"mode": 493, "sha256": CAPTURE.digest(self.extra.read_bytes())}},
            "gitlinks": {"modules/example": "c" * 40}}
        (self.copy / "modules/example").mkdir(parents=True)
        self.freeze()

    def freeze(self):
        data = json.dumps(self.snapshot).encode()
        (self.copy / CAPTURE.SNAPSHOT).write_bytes(data)
        marker = {"format": "i12-disposable-source-copy-v2", "path": str(self.copy),
            "disposable": True, "source_revision": self.revision,
            "snapshot_manifest": CAPTURE.SNAPSHOT,
            "snapshot_manifest_sha256": CAPTURE.digest(data)}
        (self.copy / CAPTURE.MARKER).write_text(json.dumps(marker))

    def test_exact_application_and_no_capture_execution(self):
        result = self.apply()
        self.assertEqual((self.copy / "module.c").read_bytes(), self.observed)
        self.assertEqual(result["source_revision"], self.revision)
        self.assertEqual(result["delivery_product_baseline"], "8" * 40)
        self.assertEqual(result["source_git_tree"], "b" * 40)
        self.assertEqual(result["snapshot_file_count"], 2)
        self.assertEqual(result["snapshot_gitlinks"], self.snapshot["gitlinks"])
        self.assertEqual(result["snapshot_manifest_sha256"], CAPTURE.digest((self.copy / CAPTURE.SNAPSHOT).read_bytes()))
        self.assertFalse(result["runtime_qualified"])

    def test_bad_revision_format_refused(self):
        for revision in ("a" * 39, "A" * 40, "g" * 40, 40, None):
            with self.subTest(revision=revision):
                self.revision = revision
                self.snapshot["source_revision"] = revision
                self.freeze()
                self.assert_refused_unchanged()

    def test_snapshot_revision_mismatch_refused(self):
        self.snapshot["source_revision"] = "d" * 40
        self.freeze()
        self.assert_refused_unchanged()

    def test_snapshot_hash_tampering_refused(self):
        with (self.copy / CAPTURE.SNAPSHOT).open("a") as output:
            output.write(" ")
        self.assert_refused_unchanged()

    def test_marker_schema_and_manifest_pointer_refused(self):
        self.freeze()
        original = json.loads((self.copy / CAPTURE.MARKER).read_text())
        variants = ({**original, "extra": True}, {**original, "disposable": 1},
                    {**original, "snapshot_manifest": "../manifest.json"},
                    {**original, "snapshot_manifest_sha256": "F" * 64})
        for marker in variants:
            with self.subTest(marker=marker):
                (self.copy / CAPTURE.MARKER).write_text(json.dumps(marker))
                self.assert_refused_unchanged()

    def test_snapshot_schema_and_duplicate_fields_refused(self):
        self.snapshot["extra"] = True
        self.freeze()
        self.assert_refused_unchanged()
        del self.snapshot["extra"]
        self.freeze()
        marker = json.loads((self.copy / CAPTURE.MARKER).read_text())
        data = json.dumps(self.snapshot).replace('"git_tree":', '"git_tree": "e' + 'e' * 39 + '", "git_tree":').encode()
        (self.copy / CAPTURE.SNAPSHOT).write_bytes(data)
        marker["snapshot_manifest_sha256"] = CAPTURE.digest(data)
        (self.copy / CAPTURE.MARKER).write_text(json.dumps(marker))
        self.assert_refused_unchanged()

    def test_marker_duplicate_fields_refused(self):
        data = (self.copy / CAPTURE.MARKER).read_text()
        (self.copy / CAPTURE.MARKER).write_text(data.replace('"disposable":', '"disposable": false, "disposable":'))
        self.assert_refused_unchanged()

    def test_unselected_export_hash_and_mode_tampering_refused(self):
        original = self.extra.read_bytes()
        self.extra.write_bytes(b"different")
        self.assert_refused_unchanged()
        self.extra.write_bytes(original)
        self.extra.chmod(420)
        self.assert_refused_unchanged()

    def test_missing_unselected_export_file_refused(self):
        self.extra.unlink()
        self.assert_refused_unchanged()

    def test_extra_export_file_and_directory_refused(self):
        extra = self.copy / "unlisted.txt"
        extra.write_bytes(b"unlisted")
        self.assert_refused_unchanged()
        extra.unlink()
        extra.mkdir()
        self.assert_refused_unchanged()

    def test_unselected_hardlink_refused(self):
        self.extra.unlink()
        os.link(self.repo / "module.c", self.extra)
        self.assert_refused_unchanged()
        self.assertEqual((self.repo / "module.c").read_bytes(), self.original)

    def test_unselected_symlink_refused(self):
        self.extra.unlink()
        self.extra.symlink_to(self.repo / "module.c")
        self.assert_refused_unchanged()

    def test_fifo_object_refused_without_reading(self):
        os.mkfifo(self.copy / "unexpected.pipe")
        self.assert_refused_unchanged()

    def test_gitlink_content_and_nested_inventory_refused(self):
        (self.copy / "modules/example/foreign").write_text("not Parent export")
        self.assert_refused_unchanged()
        (self.copy / "modules/example/foreign").unlink()
        self.snapshot["gitlinks"]["modules/example/nested"] = "d" * 40
        self.freeze()
        self.assert_refused_unchanged()

    def test_inventory_invalid_entries_refused(self):
        original = dict(self.snapshot["files"]["fixture.bin"])
        for entry in ({**original, "mode": 511}, {**original, "mode": True},
                      {**original, "sha256": "A" * 64}, {**original, "extra": True}):
            with self.subTest(entry=entry):
                self.snapshot["files"]["fixture.bin"] = entry
                self.freeze()
                self.assert_refused_unchanged()

    def test_missing_gitlink_directory_is_allowed_but_contents_are_not(self):
        (self.copy / "modules/example").rmdir()
        (self.copy / "modules").rmdir()
        result = self.apply()
        self.assertEqual(result["snapshot_gitlinks"], self.snapshot["gitlinks"])

    def test_inventory_path_escape_and_git_metadata_refused(self):
        original = self.snapshot["files"].pop("fixture.bin")
        for name in ("../fixture.bin", "nested/.git/config", "/absolute.c"):
            with self.subTest(name=name):
                self.snapshot["files"][name] = original
                self.freeze()
                self.assert_refused_unchanged()
                del self.snapshot["files"][name]

    def test_wrong_tree_identity_and_reserved_inventory_object_refused(self):
        self.snapshot["git_tree"] = "b" * 39
        self.freeze()
        self.assert_refused_unchanged()
        self.snapshot["git_tree"] = "b" * 40
        self.snapshot["files"][CAPTURE.MARKER] = {"mode": 420, "sha256": "0" * 64}
        self.freeze()
        self.assert_refused_unchanged()

    def test_reviewed_current_base_requires_complete_v2(self):
        current = b"int module(void) { return 2; }\n"
        entry = self.manifest['profiles']['selected']['source_targets']['module.c']
        entry['current_before_sha256'] = CAPTURE.digest(current)
        self.save_manifest()
        (self.copy / 'module.c').write_bytes(current)
        self.snapshot['files']['module.c']['sha256'] = CAPTURE.digest(current)
        self.freeze()
        result = self.apply()
        self.assertEqual(result['actual_before_sha256']['module.c'], CAPTURE.digest(current))
        self.assertEqual((self.copy / 'module.c').read_bytes(), self.observed)

    def test_current_base_rejected_for_legacy_marker(self):
        current = b"int module(void) { return 2; }\n"
        self.manifest['profiles']['selected']['source_targets']['module.c']['current_before_sha256'] = CAPTURE.digest(current)
        self.save_manifest()
        (self.copy / 'module.c').write_bytes(current)
        (self.copy / CAPTURE.SNAPSHOT).unlink()
        self.marker()
        self.assert_refused_unchanged()

    def test_current_base_with_unselected_tampering_rejected(self):
        current = b"int module(void) { return 2; }\n"
        self.manifest['profiles']['selected']['source_targets']['module.c']['current_before_sha256'] = CAPTURE.digest(current)
        self.save_manifest()
        (self.copy / 'module.c').write_bytes(current)
        self.snapshot['files']['module.c']['sha256'] = CAPTURE.digest(current)
        self.freeze()
        self.extra.write_bytes(b'tampered unrelated file')
        self.assert_refused_unchanged()

    def test_selected_base_checked_even_with_valid_complete_export(self):
        changed = b"different but frozen source\n"
        (self.copy / "module.c").write_bytes(changed)
        self.snapshot["files"]["module.c"]["sha256"] = CAPTURE.digest(changed)
        self.freeze()
        self.assert_refused_unchanged()


class CurrentApacheProfileControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="apache-export-contract-", dir=_private_fixture_root())
        cls.addClassCleanup(temporary.cleanup)
        cls.work = Path(temporary.name)
        cls.revision = subprocess.run(["git", "rev-parse", "HEAD"],
            cwd=CAPTURE.REPOSITORY, check=True, capture_output=True, text=True).stdout.strip()
        cls.tree = subprocess.run(["git", "rev-parse", "HEAD^{tree}"],
            cwd=CAPTURE.REPOSITORY, check=True, capture_output=True, text=True).stdout.strip()
        cls.archive = cls.work / "committed-parent.tar"
        subprocess.run(["git", "archive", "--format=tar", "--output", str(cls.archive), "HEAD"],
            cwd=CAPTURE.REPOSITORY, check=True, capture_output=True)
        listing = subprocess.run(["git", "ls-tree", "-rz", "HEAD"],
            cwd=CAPTURE.REPOSITORY, check=True, capture_output=True).stdout
        cls.files, cls.gitlinks = {}, {}
        for row in listing.split(b"\0"):
            if not row:
                continue
            metadata, name = row.split(b"\t", 1)
            mode, kind, identity = metadata.decode().split()
            name = name.decode()
            if mode == "160000":
                cls.gitlinks[name] = identity
            else:
                if kind != "blob" or mode not in ("100644", "100755"):
                    raise ValueError("Committed Parent export is not a regular-file-only source inventory")
                cls.files[name] = 493 if mode == "100755" else 420

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="copy-", dir=self.work)
        self.addCleanup(temporary.cleanup)
        self.target = Path(temporary.name)
        with tarfile.open(self.archive) as archive:
            archive.extractall(self.target, filter="data")
        for name, mode in self.files.items():
            (self.target / name).chmod(mode)
        self.inventory = {"format": "i12-source-export-manifest-v1", "source_revision": self.revision,
            "git_tree": self.tree, "files": {name: {"mode": mode,
                "sha256": CAPTURE.digest((self.target / name).read_bytes())} for name, mode in self.files.items()},
            "gitlinks": self.gitlinks}
        self.freeze()

    def freeze(self):
        data = json.dumps(self.inventory).encode()
        (self.target / CAPTURE.SNAPSHOT).write_bytes(data)
        (self.target / CAPTURE.MARKER).write_text(json.dumps({
            "format": "i12-disposable-source-copy-v2", "path": str(self.target), "disposable": True,
            "source_revision": self.revision, "snapshot_manifest": CAPTURE.SNAPSHOT,
            "snapshot_manifest_sha256": CAPTURE.digest(data)}))

    def registry(self):
        registry = CAPTURE.Registry()
        # Only the test-owned storage authorization is relocated for CI. Object,
        # source-profile, identity, and hash validation remain the real contract.
        registry.manifest["authorized_storage_root"] = str(self.work)
        return registry

    def test_current_full_git_export_applies_without_baseline_identity_substitution(self):
        registry = self.registry()
        result = CAPTURE.apply(registry, "apache-current", self.target)
        self.assertEqual(result["source_revision"], self.revision)
        self.assertEqual(result["source_git_tree"], self.tree)
        self.assertEqual(result["snapshot_file_count"], len(self.files))
        self.assertEqual(result["delivery_product_baseline"], registry.manifest["delivery_product_baseline"])
        for name, entry in registry.manifest["profiles"]["apache-current"]["source_targets"].items():
            self.assertEqual(CAPTURE.digest((self.target / name).read_bytes()), entry["sha256"])
        self.assertTrue((self.target / ".i12-capture/apache-current").is_dir())
        self.assertFalse(result["runtime_qualified"])

    def test_current_profile_only_rebinds_native_before_bytes(self):
        registry = self.registry()
        current = copy.deepcopy(registry.manifest["profiles"]["apache-current"])
        historical = registry.manifest["profiles"]["apache"]
        self.assertEqual(current.pop("required_source_identity_format"), "i12-disposable-source-copy-v2")
        provenance = current["provenance"].pop("current_source_application")
        self.assertEqual(provenance["runtime_profile"], "apache-native")
        for name in ("native-lifecycle-observer.c", "native-lifecycle-observer.h"):
            path = "ci/runtime/lifecycle/" + name
            self.assertEqual(current["source_targets"][path]["before_sha256"],
                registry.manifest["shared_observer_repository"][name])
            current["source_targets"][path]["before_sha256"] = historical["source_targets"][path]["before_sha256"]
        self.assertEqual(current, historical)

    def test_historical_profile_still_rejects_current_native_before_bytes(self):
        original = (self.target / "connectors/apache/src/mod_security3.c").read_bytes()
        registry = self.registry()
        with self.assertRaisesRegex(ValueError, "Source-copy base differs"):
            CAPTURE.apply(registry, "apache", self.target)
        self.assertEqual((self.target / "connectors/apache/src/mod_security3.c").read_bytes(), original)
        self.assertFalse((self.target / ".i12-capture").exists())

    def test_v1_marker_cannot_label_current_profile_with_historical_baseline(self):
        registry = self.registry()
        (self.target / CAPTURE.MARKER).write_text(json.dumps({"format": "i12-disposable-source-copy-v1",
            "path": str(self.target), "disposable": True, "parent_sha": registry.manifest["delivery_product_baseline"]}))
        with self.assertRaisesRegex(ValueError, "declared source identity format"):
            CAPTURE.apply(registry, "apache-current", self.target)
        self.assertFalse((self.target / ".i12-capture").exists())

    def test_complete_frozen_inventory_does_not_override_current_before_pin(self):
        name = "ci/runtime/lifecycle/native-lifecycle-observer.c"
        (self.target / name).write_bytes(b"changed but completely inventoried\n")
        self.inventory["files"][name]["sha256"] = CAPTURE.digest((self.target / name).read_bytes())
        self.freeze()
        registry = self.registry()
        with self.assertRaisesRegex(ValueError, "Source-copy base differs"):
            CAPTURE.apply(registry, "apache-current", self.target)
        self.assertFalse((self.target / ".i12-capture").exists())

    def test_unknown_required_identity_format_rejected_by_registry(self):
        registry = self.registry()
        registry.manifest["profiles"]["apache-current"]["required_source_identity_format"] = "unrecognized-v99"
        with self.assertRaisesRegex(ValueError, "Unknown required source identity format"):
            registry.verify()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
