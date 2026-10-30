"""Offline real archive/export admission; controlled Git bytes, no Git process."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = connector_root()
BUILD = "ci/runtime/lifecycle/i12/nginx/build_capture.py"
CAPTURE = "ci/runtime/lifecycle/i12/capture_sources.py"


def load(name, relative):
    module = load_source(ROOT / relative)
    return module


class ExportAdmissionTests(unittest.TestCase):
    def setUp(self):
        parent = os.environ.get("I12_TEST_ROOT") or os.environ.get("RUNNER_TEMP")
        if not parent:
            raise RuntimeError("an explicit external test root is required")
        self.temporary = tempfile.TemporaryDirectory(prefix="nginx-export-offline-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.environment = mock.patch.dict(os.environ, {"CODEX_TEMP_ROOT": str(self.root)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.build = load("offline_actual_nginx_export", BUILD)
        self.capture = load("offline_actual_capture_sources", CAPTURE)
        self.target = self.root / "export"
        self.target.mkdir(mode=0o700)
        self.revision, self.tree, self.gitlink = "a" * 40, "b" * 40, "c" * 40
        self.payloads = {
            "common/src/status.c": (source_path('common/src/status.c', root=ROOT)).read_bytes(),
            "tools/current-script.py": (source_path('ci/tools/new-change-record.py', root=ROOT)).read_bytes(),
        }
        self.source_before = {p: hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in (ROOT / BUILD, ROOT / CAPTURE, source_path('common/src/status.c', root=ROOT),
                                        source_path('ci/tools/new-change-record.py', root=ROOT))}
        self.addCleanup(self.assert_source_unchanged)
        self.inventory_mode = None
        self.archive_mode = None
        self.calls = []

    def assert_source_unchanged(self):
        self.assertEqual(self.source_before, {p: hashlib.sha256(p.read_bytes()).hexdigest()
                                            for p in self.source_before})

    def inventory(self):
        rows = []
        for name, data in self.payloads.items():
            oid = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data,
                               usedforsecurity=False).hexdigest()
            mode = "100755" if name.startswith("tools/") else "100644"
            rows.append(f"{mode} blob {oid}\t{name}".encode())
        if self.inventory_mode == "duplicate":
            rows.append(rows[0])
        if self.inventory_mode == "collision":
            rows.append(b"100644 blob " + b"d" * 40 + b"\tcommon")
        rows.append(f"160000 commit {self.gitlink}\tmodules/fixture".encode())
        return b"\0".join(rows) + b"\0"

    def archive(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for index, (name, original) in enumerate(self.payloads.items()):
                if self.archive_mode == "missing" and index == 1:
                    continue
                data = original + b"mutated" if self.archive_mode == "blob" and index == 0 else original
                member = tarfile.TarInfo("../escaped" if self.archive_mode == "traversal" and index == 0 else name)
                member.mode = 0o755 if name.startswith("tools/") or self.archive_mode == "mode" else 0o644
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return buffer.getvalue()

    def git_bytes(self, *argv):
        self.calls.append(argv)
        if argv == ("rev-parse", self.revision + "^{tree}"):
            return self.tree.encode() + b"\n"
        if argv == ("ls-tree", "-rz", "--full-tree", self.revision):
            return self.inventory()
        if argv == ("-c", "tar.umask=0022", "archive", "--format=tar", self.revision):
            return self.archive()
        raise AssertionError("unapproved external command boundary")

    def export(self):
        return self.build.export_current(self.git_bytes, self.target, self.revision, self.capture)

    def reject(self, message):
        with self.assertRaisesRegex(ValueError, message):
            self.export()
        self.assertFalse((self.target / self.capture.MARKER).exists())

    def test_exact_export_seals_real_sha_lineage_and_private_snapshot(self):
        result = self.export()
        self.assertEqual(Path(self.build.__file__), ROOT / BUILD)
        self.assertEqual(result["source_revision"], self.revision)
        self.assertEqual(result["source_git_tree"], self.tree)
        self.assertEqual(result["snapshot_file_count"], 2)
        self.assertEqual(result["snapshot_gitlinks"], {"modules/fixture": self.gitlink})
        raw = (self.target / self.capture.SNAPSHOT).read_bytes()
        snapshot = json.loads(raw)
        marker = json.loads((self.target / self.capture.MARKER).read_text())
        self.assertEqual(marker["snapshot_manifest_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["snapshot_manifest_sha256"], marker["snapshot_manifest_sha256"])
        for name, data in self.payloads.items():
            path = self.target / name
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(snapshot["files"][name]["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(path.stat().st_mode & 0o777, 0o755 if name.startswith("tools/") else 0o644)
        self.assertTrue((self.target / "modules/fixture").is_dir())
        self.assertEqual(len(self.calls), 3)

    def test_archive_blob_mismatch_cannot_publish_identity(self):
        self.archive_mode = "blob"
        self.reject("archive blob differs")

    def test_archive_mode_mismatch_cannot_publish_identity(self):
        self.archive_mode = "mode"
        self.reject("archive Git mode differs")

    def test_archive_traversal_cannot_escape_or_publish_identity(self):
        self.archive_mode = "traversal"
        self.reject("unsafe Git export path")
        self.assertFalse((self.root / "escaped").exists())

    def test_duplicate_inventory_cannot_publish_identity(self):
        self.inventory_mode = "duplicate"
        self.reject("duplicate Git inventory path")

    def test_inventory_parent_collision_cannot_publish_identity(self):
        self.inventory_mode = "collision"
        self.reject("Git inventory path collision")

    def test_missing_archive_member_cannot_publish_identity(self):
        self.archive_mode = "missing"
        self.reject("missing archive files")


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
