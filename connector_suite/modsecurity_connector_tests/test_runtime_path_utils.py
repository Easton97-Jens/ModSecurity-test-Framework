"""Real permission-boundary regressions for descriptor runtime traversal."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import fcntl
import os
from pathlib import Path
import pwd
import stat
import sys
import tempfile
import traceback
import unittest
from unittest import mock


ROOT = connector_root()

import modsecurity_connector_ci.lib.runtime_path_utils as PATHS


class RuntimePathUtilsTest(unittest.TestCase):
    def nonroot_identity(self) -> tuple[int, int]:
        if os.geteuid() != 0:
            return os.geteuid(), os.getegid()
        try:
            account = pwd.getpwnam("nobody")
        except KeyError:
            self.skipTest("existing non-root identity unavailable")
        return account.pw_uid, account.pw_gid

    def run_nonroot(self, uid: int, gid: int, exercise) -> None:
        read_descriptor, write_descriptor = os.pipe()
        process = os.fork()
        if process == 0:
            os.close(read_descriptor)
            try:
                if os.geteuid() == 0:
                    os.setgroups([])
                    os.setgid(gid)
                    os.setuid(uid)
                if os.geteuid() == 0:
                    raise AssertionError("permission test must execute without root")
                exercise()
            except BaseException:
                os.write(write_descriptor, traceback.format_exc().encode()[:8192])
                os._exit(1)
            os._exit(0)
        os.close(write_descriptor)
        try:
            evidence = os.read(read_descriptor, 8192).decode()
            _, status = os.waitpid(process, 0)
        finally:
            os.close(read_descriptor)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0, evidence)

    def fixture(self, parent: Path, uid: int, gid: int) -> tuple[Path, Path]:
        os.chmod(parent, 0o755)
        job = parent / "root-owned-job"
        job.mkdir(mode=0o711)
        # A regular non-root CI account also reproduces execute-only traversal.
        leaf = job / "runner-root"
        leaf.mkdir(mode=0o700)
        if os.geteuid() == 0:
            os.chown(leaf, uid, gid)
        os.chmod(job, 0o711 if os.geteuid() == 0 else 0o111)
        return job, leaf

    def test_execute_only_ancestors_preserve_readable_private_leaf(self) -> None:
        uid, gid = self.nonroot_identity()
        with tempfile.TemporaryDirectory(prefix="runtime-execute-ancestor-") as temporary:
            job, leaf = self.fixture(Path(temporary), uid, gid)

            def exercise() -> None:
                with self.assertRaises(PermissionError):
                    os.open(job, os.O_RDONLY | os.O_DIRECTORY)
                self.assertEqual(PATHS.ensure_safe_runtime_directory(leaf), leaf)
                child = leaf / "generated"
                self.assertEqual(PATHS.ensure_safe_runtime_directory(child), child)
                with PATHS.open_private_runtime_root(leaf) as handle:
                    self.assertFalse(fcntl.fcntl(handle.descriptor, fcntl.F_GETFL) & os.O_PATH)
                    self.assertIn("generated", os.listdir(handle.descriptor))
                    handle.create_text("receipt.txt", "live\n")
                    self.assertEqual(handle.read_text("receipt.txt"), "live\n")

            self.run_nonroot(uid, gid, exercise)
            self.assertEqual(stat.S_IMODE(job.stat().st_mode), 0o711 if os.geteuid() == 0 else 0o111)
            self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((leaf / "receipt.txt").stat().st_mode), 0o600)
            os.chmod(job, 0o711)

    def test_execute_only_traversal_keeps_unsafe_ancestor_rejections(self) -> None:
        uid, gid = self.nonroot_identity()
        with tempfile.TemporaryDirectory(prefix="runtime-unsafe-ancestor-") as temporary:
            job, leaf = self.fixture(Path(temporary), uid, gid)
            os.chmod(job, 0o777)
            linked = Path(temporary) / "linked-job"
            linked.symlink_to(job, target_is_directory=True)

            def exercise() -> None:
                for path in (leaf, linked / leaf.name):
                    for opener in (PATHS.ensure_safe_runtime_directory, PATHS.open_private_runtime_root):
                        with self.assertRaises(ValueError):
                            opener(path)

            self.run_nonroot(uid, gid, exercise)

    def test_execute_only_leaf_is_not_accepted_as_readable_runtime_root(self) -> None:
        uid, gid = self.nonroot_identity()
        with tempfile.TemporaryDirectory(prefix="runtime-unreadable-leaf-") as temporary:
            job, leaf = self.fixture(Path(temporary), uid, gid)
            os.chmod(leaf, 0o100)

            def exercise() -> None:
                for opener in (PATHS.ensure_safe_runtime_directory, PATHS.open_private_runtime_root):
                    with self.assertRaises(ValueError):
                        opener(leaf)

            self.run_nonroot(uid, gid, exercise)
            os.chmod(job, 0o711)
            os.chmod(leaf, 0o700)

    def test_missing_path_descriptor_support_fails_closed(self) -> None:
        with mock.patch.object(PATHS.os, "O_PATH", None):
            with self.assertRaisesRegex(ValueError, "require O_PATH"):
                PATHS._open_runtime_root_descriptor()



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
