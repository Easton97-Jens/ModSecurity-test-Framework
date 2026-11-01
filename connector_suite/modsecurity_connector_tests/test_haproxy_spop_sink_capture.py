"""Focused admission and receipt controls for the native SPOP capture helper."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock


ROOT = connector_root()
CAPTURE = load_source(source_path('connectors/haproxy/harness/i12_spop_sink_capture.py', root=ROOT))


class SpopCaptureBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(
            prefix="spop-capture-boundary-", dir=os.environ.get("TMPDIR"))
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.authorized = self.parent / "codex" / "ModSecurity-conector"
        fixed_parent = mock.patch.object(CAPTURE, "fixed_runtime_temp_parent", return_value=self.parent)
        fixed_parent.start()
        self.addCleanup(fixed_parent.stop)

    def test_fresh_nested_output_and_receipts_are_private_with_permissive_umask(self):
        output = self.authorized / "nested" / "capture"
        previous_umask = os.umask(0)
        try:
            with CAPTURE.prepare_output(output) as directory:
                self.assertEqual(directory.identity, (output.stat().st_dev, output.stat().st_ino))
                CAPTURE.retain_command_output(directory, "text.stdout", "captured\n")
                CAPTURE.retain_command_output(directory, "bytes.stderr", b"\xff\x00")
                directory.create_text("commands.json", "[]\n")
                directory.replace_text("commands.json", '[{"exit": 0}]\n')
        finally:
            os.umask(previous_umask)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        for name in ("text.stdout", "bytes.stderr", "commands.json"):
            self.assertEqual(stat.S_IMODE((output / name).stat().st_mode), 0o600)
        self.assertEqual((output / "text.stdout").read_bytes(), b"captured\n")
        self.assertEqual((output / "bytes.stderr").read_bytes(), b"\xff\x00")
        self.assertEqual(json.loads((output / "commands.json").read_text()), [{"exit": 0}])

    def test_outside_sibling_relative_traversal_and_root_paths_are_rejected(self):
        for path in (self.parent / "outside", self.parent / "codex/ModSecurity-conector-sibling/run",
                     Path("relative/run"), self.authorized / ".." / "escape", self.authorized):
            with self.subTest(path=path):
                with self.assertRaises(ValueError), CAPTURE.prepare_output(path):
                    self.fail("invalid output was admitted")
        self.assertFalse(self.authorized.exists())

    def test_existing_output_is_never_reused(self):
        output = self.authorized / "capture"
        with CAPTURE.prepare_output(output) as directory:
            directory.create_text("original.txt", "preserved\n")
        with self.assertRaises(FileExistsError), CAPTURE.prepare_output(output):
            self.fail("existing output was reused")
        self.assertEqual((output / "original.txt").read_text(), "preserved\n")

    def test_writable_parent_is_rejected_before_output_creation(self):
        self.authorized.mkdir(parents=True)
        self.authorized.chmod(0o777)
        output = self.authorized / "capture"
        with self.assertRaises(ValueError), CAPTURE.prepare_output(output):
            self.fail("unsafe parent was admitted")
        self.assertFalse(output.exists())

    def test_symlinked_parent_cannot_redirect_output(self):
        self.authorized.mkdir(parents=True)
        outside = self.parent / "outside"
        outside.mkdir()
        (self.authorized / "linked").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError), CAPTURE.prepare_output(self.authorized / "linked/capture"):
            self.fail("symlinked parent was admitted")
        self.assertEqual(list(outside.iterdir()), [])

    def test_final_leaf_creation_race_fails_exclusively(self):
        output = self.authorized / "capture"
        original_mkdir = os.mkdir

        def race(path, mode=0o777, *, dir_fd=None):
            if path == output.name and mode == 0o700 and dir_fd is not None:
                original_mkdir(path, mode, dir_fd=dir_fd)
            return original_mkdir(path, mode, dir_fd=dir_fd)

        with mock.patch.object(CAPTURE.os, "mkdir", side_effect=race):
            with self.assertRaises(FileExistsError), CAPTURE.prepare_output(output):
                self.fail("racing leaf was reused")
        self.assertEqual(list(output.iterdir()), [])

    def test_replaced_output_and_symlinked_receipts_fail_closed(self):
        output = self.authorized / "capture"
        outside = self.parent / "outside.txt"
        outside.write_text("preserved\n")
        with CAPTURE.prepare_output(output) as directory:
            (output / "linked.txt").symlink_to(outside)
            with self.assertRaises(FileExistsError):
                directory.create_text("linked.txt", "unsafe\n")
            with self.assertRaises(ValueError):
                directory.replace_text("linked.txt", "unsafe\n")
            output.rename(output.with_name("original"))
            output.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "path was replaced"):
                directory.create_text("redirected.txt", "unsafe\n")
        self.assertFalse((output / "redirected.txt").exists())
        self.assertEqual(outside.read_text(), "preserved\n")

    def test_capture_retains_cumulative_commands_artifacts_and_unqualified_receipt(self):
        output = self.authorized / "capture"
        fake_module = ModuleType("modsecurity_connector_tests.test_haproxy_spop_event_sink_failures")

        class Fixture:
            @classmethod
            def setUpClass(cls):
                cls.directory = output / "fixture"
                cls.directory.mkdir(mode=0o700)
                binary = cls.directory / "native"
                binary.write_bytes(b"native-artifact")
                binary.chmod(0o755)
                subprocess.run(["cc", "fixture.c"], capture_output=True, text=True)
                subprocess.run(["native", "control"], capture_output=True, text=True)

            @classmethod
            def doClassCleanups(cls):
                pass

        fake_module.HaproxySpopEventSinkFailureTests = Fixture
        result = SimpleNamespace(testsRun=1, failures=[], errors=[], wasSuccessful=lambda: True)

        def run_suite(_suite):
            Fixture.doClassCleanups()
            return result

        with (CAPTURE.prepare_output(output) as directory,
              mock.patch.dict("sys.modules", {fake_module.__name__: fake_module}),
              mock.patch.dict(os.environ),
              mock.patch.object(CAPTURE.sys, "path", list(CAPTURE.sys.path)),
              mock.patch.object(CAPTURE.subprocess, "run", return_value=subprocess.CompletedProcess(
                  [], 0, "physical stdout\n", "physical stderr\n")),
              mock.patch.object(CAPTURE.unittest.defaultTestLoader, "loadTestsFromTestCase", return_value=object()),
              mock.patch.object(CAPTURE.unittest, "TextTestRunner") as runner):
            runner.return_value.run.side_effect = run_suite
            self.assertEqual(CAPTURE.capture(output, directory), 0)
            self.assertEqual(os.environ["RUNNER_TEMP"], str(output))
        commands = json.loads((output / "commands.json").read_text())
        self.assertEqual([row["argv"] for row in commands],
                         [["rtk", "proxy", "cc", "fixture.c"], ["rtk", "proxy", "native", "control"]])
        self.assertEqual([row["exit"] for row in commands], [0, 0])
        receipt = json.loads((output / "receipt.json").read_text())
        self.assertFalse(receipt["full_lifecycle_pass"])
        self.assertEqual((receipt["tests_run"], receipt["failures"], receipt["errors"]), (1, 0, 0))
        self.assertIn("native-artifacts/native", receipt["files"])
        self.assertEqual(stat.S_IMODE((output / "native-artifacts/native").stat().st_mode), 0o755)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
