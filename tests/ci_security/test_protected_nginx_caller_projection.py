"""Standalone Framework caller generator checks; no Parent Git context."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from modsecurity_test_framework import protected_nginx_caller as PROJECTION

FRAMEWORK = Path(__file__).resolve().parents[2]


class ProtectedCallerGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (FRAMEWORK / PROJECTION.SOURCE).read_bytes()
        cls.revision = subprocess.check_output(
            ["git", "--no-replace-objects", "-C", str(FRAMEWORK), "rev-parse", "HEAD"],
            text=True,
            timeout=30,
        ).strip()

    def test_generator_cli_materializes_checks_and_preserves_invalid_target(self):
        revision = self.revision
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = parent / PROJECTION.TARGET
            target.parent.mkdir(parents=True)
            target.write_bytes(b"previous projection\n")
            target.chmod(0o640)
            command = [
                sys.executable,
                str(FRAMEWORK / "ci/tools/generate-protected-nginx-caller.py"),
                "--parent-root",
                str(parent),
                "--framework-revision",
                revision,
            ]
            result = subprocess.run([*command, "--sync"], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                target.read_bytes(), PROJECTION.render(self.source, revision)
            )
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)
            self.assertEqual(
                subprocess.run([*command, "--check"], capture_output=True).returncode, 0
            )
            before = target.read_bytes()
            self.assertEqual(
                subprocess.run(
                    [*command, "--sync", "--framework-revision", "master"],
                    capture_output=True,
                ).returncode,
                77,
            )
            self.assertEqual(target.read_bytes(), before)
            target.unlink()
            foreign = parent / "foreign"
            foreign.write_bytes(b"preserve")
            target.symlink_to(foreign)
            self.assertEqual(
                subprocess.run([*command, "--sync"], capture_output=True).returncode, 77
            )
            self.assertEqual(foreign.read_bytes(), b"preserve")

    def test_generator_refuses_unreviewed_source_or_symbolic_revision(self):
        with self.assertRaises(PROJECTION.CallerProjectionError):
            PROJECTION.render(
                self.source.replace(b"contents: read", b"contents: write"), "b" * 40
            )
        with self.assertRaises(PROJECTION.CallerProjectionError):
            PROJECTION.render(self.source, "master")


if __name__ == "__main__":
    unittest.main()
