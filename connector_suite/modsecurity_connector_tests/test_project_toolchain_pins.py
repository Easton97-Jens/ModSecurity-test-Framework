"""Security and drift contracts for centrally managed toolchain projections."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
from concurrent.futures import ThreadPoolExecutor
import threading
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from modsecurity_connector_tests.version_updater_test_support import load_updater, write_project_pins

ROOT = connector_root()
UPDATER = load_updater("central_python_updater", source_path('scripts/update-python-version.py', root=ROOT))
SYNC = load_source(source_path('ci/tools/sync-project-versions.py', root=ROOT))
CORE = load_source(source_path('scripts/version_updater_common.py', root=ROOT), fresh=False)


class ProjectToolchainPinsTests(unittest.TestCase):
    def fixture(self, root):
        lock = write_project_pins(root)
        (root / ".python-version").write_text("3.15.7\n")
        (root / ".go-version").write_text("1.27.1\n")
        return lock

    def update(self, root):
        UPDATER.atomic_update_version(root, UPDATER.parse_stable_version("3.15.7"), UPDATER.parse_stable_version("3.15.8"))

    def test_update_only_selected_field_preserves_other_pins(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self.fixture(root)
            before = json.loads(lock.read_bytes())
            self.update(root)
            after = json.loads(lock.read_bytes())
            self.assertEqual(after.pop("python_version"), "3.15.8")
            before.pop("python_version")
            self.assertEqual(after, before)
            self.assertEqual((root / ".python-version").read_text(), "3.15.8\n")
            self.assertEqual(SYNC.synchronize(root), [])

    def test_one_lock_edit_syncs_both_views(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            write_project_pins(root, python_version="3.15.8", go_version="1.28.0")
            self.assertEqual(SYNC.synchronize(root), [".python-version", ".go-version"])
            self.assertEqual(SYNC.synchronize(root, sync=True), [".python-version", ".go-version"])
            self.assertEqual(SYNC.synchronize(root), [])
            self.assertEqual(SYNC.synchronize(root, sync=True), [])

    def test_stale_view_rejected_before_release_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            (root / ".python-version").write_text("3.15.6\n")
            opener = mock.Mock()
            status = UPDATER.main(["--check"], root=root, opener=opener)
            self.assertEqual(status, 1)
            opener.open.assert_not_called()

    def test_invalid_lock_fails_without_mutating_views(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self.fixture(root)
            for data in (b"{}", b"{", b"{}" * 4097,
                         b"{\"schema_version\":1,\"schema_version\":1}"):
                with self.subTest(data=data[:80]):
                    lock.write_bytes(data)
                    with self.assertRaises(CORE.UpdaterError):
                        SYNC.synchronize(root, sync=True)
                    self.assertEqual((root / ".python-version").read_text(), "3.15.7\n")

    def test_unsafe_second_view_preflight_prevents_first_view_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self.fixture(root)
            write_project_pins(root, python_version="3.15.8", go_version="1.28.0")
            before = lock.read_bytes()
            outside = root / "outside"
            outside.write_text("1.27.1\n")
            (root / ".go-version").unlink()
            (root / ".go-version").symlink_to(outside)
            with self.assertRaises(CORE.UpdaterError):
                SYNC.synchronize(root, sync=True)
            self.assertEqual(lock.read_bytes(), before)
            self.assertEqual((root / ".python-version").read_text(), "3.15.7\n")
            self.assertEqual(outside.read_text(), "1.27.1\n")

    def test_hardlinked_lock_and_symlink_directory_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self.fixture(root)
            os.link(lock, root / "alias")
            with self.assertRaises(CORE.UpdaterError):
                self.update(root)
            (root / "alias").unlink()
            tooling = root / "ci/tooling"
            tooling.rename(root / "outside-tooling")
            tooling.symlink_to(root / "outside-tooling", target_is_directory=True)
            with self.assertRaises(CORE.UpdaterError):
                self.update(root)

    def test_failed_central_replacement_rolls_back_view(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self.fixture(root)
            original = lock.read_bytes()
            real_replace = os.replace
            def replace(source, target):
                if target == lock:
                    raise OSError("injected replacement failure")
                return real_replace(source, target)
            with mock.patch.object(CORE.os, "replace", side_effect=replace):
                with self.assertRaises(CORE.UpdaterError):
                    self.update(root)
            self.assertEqual(lock.read_bytes(), original)
            self.assertEqual((root / ".python-version").read_text(), "3.15.7\n")
            self.assertEqual(list(root.rglob(".project-version-*")), [])

    def test_concurrent_lock_replacement_does_not_overwrite_new_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self.fixture(root)
            real_replace = os.replace
            def replace(source, target):
                real_replace(source, target)
                if target == root / ".python-version":
                    replacement = root / "replacement"
                    replacement.write_bytes(lock.read_bytes().replace(b"1.27.1", b"1.28.0"))
                    real_replace(replacement, lock)
            with mock.patch.object(CORE.os, "replace", side_effect=replace):
                with self.assertRaises(CORE.UpdaterError):
                    self.update(root)
            self.assertEqual(json.loads(lock.read_bytes())["go_version"], "1.28.0")
            self.assertEqual((root / ".python-version").read_text(), "3.15.7\n")

    def test_directory_fsync_failure_rolls_back_recorded_replacements(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self.fixture(root)
            original = lock.read_bytes()
            real_fsync = CORE._fsync_directory
            calls = 0
            def fsync(path):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected central-directory fsync failure")
                real_fsync(path)
            with mock.patch.object(CORE, "_fsync_directory", side_effect=fsync):
                with self.assertRaises(CORE.UpdaterError):
                    self.update(root)
            self.assertEqual(lock.read_bytes(), original)
            self.assertEqual((root / ".python-version").read_text(), "3.15.7\n")
            self.assertEqual(SYNC.synchronize(root), [])

    def test_cooperating_python_and_go_writers_preserve_both_updates(self):
        go = load_updater("central_go_updater", source_path('scripts/update-go-version.py', root=ROOT))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self.fixture(root)
            barrier = threading.Barrier(2)
            def python_update():
                barrier.wait(timeout=10)
                self.update(root)
            def go_update():
                barrier.wait(timeout=10)
                go.atomic_update_version(root, go.parse_stable_version("1.27.1"), go.parse_stable_version("1.28.0"))
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(python_update), executor.submit(go_update)]
                for future in futures:
                    future.result(timeout=20)
            pins = json.loads(lock.read_bytes())
            self.assertEqual(pins["python_version"], "3.15.8")
            self.assertEqual(pins["go_version"], "1.28.0")
            self.assertEqual(SYNC.synchronize(root), [])

    def test_failed_update_preserves_concurrent_in_place_view_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self.fixture(root)
            real_replace = os.replace
            def replace(source, target):
                real_replace(source, target)
                if target == root / ".python-version":
                    target.write_text("3.15.9\n")
                    replacement = root / "replacement"
                    replacement.write_bytes(lock.read_bytes().replace(b"1.27.1", b"1.28.0"))
                    real_replace(replacement, lock)
            with mock.patch.object(CORE.os, "replace", side_effect=replace):
                with self.assertRaises(CORE.UpdaterError):
                    self.update(root)
            self.assertEqual((root / ".python-version").read_text(), "3.15.9\n")
            self.assertEqual(json.loads(lock.read_bytes())["go_version"], "1.28.0")

    def test_go_publisher_guard_precedes_new_and_reused_branch_paths(self):
        workflow = (source_path('.github/workflows/update-go-version.yml', root=ROOT)).read_text()
        guard = workflow.index("python3 ci/tools/sync-project-versions.py --verify-update go")
        split = workflow.index("existing_pr=", guard)
        self.assertLess(guard, split)
        self.assertEqual(workflow.count("sync-project-versions.py --verify-update go"), 1)

    def test_publisher_rejects_another_field_even_with_consistent_views(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self.fixture(root)
            previous = lock.read_bytes()
            write_project_pins(root, python_version="3.15.8", go_version="1.28.0")
            SYNC.synchronize(root, sync=True)
            with self.assertRaises(CORE.UpdaterError):
                SYNC.verify_toolchain_update(root, "python", previous)

    def test_unknown_lock_key_and_foreign_revision_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self.fixture(root)
            previous = lock.read_bytes()
            pins = json.loads(previous)
            pins["unexpected"] = "3.15.8"
            lock.write_text(json.dumps(pins))
            with self.assertRaises(CORE.UpdaterError):
                SYNC.synchronize(root, sync=True)
            pins.pop("unexpected")
            pins["framework_sha"] = "a" * 40
            lock.write_text(json.dumps(pins))
            with self.assertRaises(CORE.UpdaterError):
                SYNC.verify_toolchain_update(root, "python", previous)

    def test_hardlinked_generated_view_preflight_rejects_update(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self.fixture(root)
            before = lock.read_bytes()
            os.link(root / ".python-version", root / "outside-view")
            with self.assertRaises(CORE.UpdaterError):
                self.update(root)
            self.assertEqual(lock.read_bytes(), before)
            self.assertEqual((root / "outside-view").read_text(), "3.15.7\n")

    def test_publisher_accepts_only_python_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self.fixture(root)
            previous = lock.read_bytes()
            self.update(root)
            SYNC.verify_toolchain_update(root, "python", previous)
            with self.assertRaises(CORE.UpdaterError):
                SYNC.verify_toolchain_update(root, "go", previous)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
