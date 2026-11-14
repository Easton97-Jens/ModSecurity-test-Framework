"""Behavioral controls for two MAIN-scope POSIX redirection parser inputs."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = (
    ROOT / "ci/fixtures/sonar-shell-readwrite-adjacent.sh",
    ROOT / "ci/fixtures/sonar-shell-readwrite-spaced.sh",
)


class ShellReadwriteRedirectionTest(unittest.TestCase):
    def test_adjacent_and_spaced_redirections_preserve_io_and_close_fd(self) -> None:
        descriptors_before = set(os.listdir("/proc/self/fd"))
        with tempfile.TemporaryDirectory(prefix="shell-readwrite-") as directory:
            for interpreter in ("/bin/sh", "/bin/bash"):
                for index, fixture in enumerate(FIXTURES):
                    with self.subTest(interpreter=interpreter, fixture=fixture.name):
                        output = Path(directory) / f"{Path(interpreter).name}-{index}"
                        output.touch()
                        result = subprocess.run(
                            [interpreter, str(fixture), str(output)],
                            cwd=ROOT,
                            check=False,
                            capture_output=True,
                            timeout=10,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout, b"")
                        self.assertEqual(result.stderr, b"")
                        self.assertEqual(output.read_bytes(), b"probe\n")
        self.assertEqual(set(os.listdir("/proc/self/fd")), descriptors_before)


if __name__ == "__main__":
    unittest.main()
