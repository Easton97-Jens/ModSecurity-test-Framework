from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "ci/tools/sync-canonical-python-pins.py"
SPEC = importlib.util.spec_from_file_location("canonical_python_pins", TOOL)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load tool module: {TOOL}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


COMMON = """\
CI_CANONICAL_PYTHON_VERSION="3.14.6"
CI_CANONICAL_PYYAML_VERSION="6.0.3"
CI_CANONICAL_PYYAML_SHA256="c458b6d084f9b935061bc36216e8a69a7e293a2f1e68bf956dcd9e6cbcd143f5"
"""
REQUIREMENTS = """\
# generated view; authority is ci/lib/common.sh
PyYAML==6.0.3 \\
    --hash=sha256:c458b6d084f9b935061bc36216e8a69a7e293a2f1e68bf956dcd9e6cbcd143f5
"""


class CanonicalPythonPinsTest(unittest.TestCase):
    def make_root(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "ci/lib").mkdir(parents=True)
        (root / "ci/lib/common.sh").write_text(COMMON, encoding="utf-8")
        (root / ".python-version").write_text("3.14.6\n", encoding="utf-8")
        (root / "requirements-ci.lock").write_text(REQUIREMENTS, encoding="utf-8")
        return root

    def run_tool(
        self, root: Path, mode: str, *, common: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, str(TOOL), mode, "--root", str(root)]
        if common is not None:
            command.extend(("--common", str(common)))
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_check_passes_and_does_not_write(self) -> None:
        root = self.make_root()
        before = (root / "requirements-ci.lock").read_bytes()
        result = self.run_tool(root, "--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, (root / "requirements-ci.lock").read_bytes())

    def test_write_repairs_views_and_is_idempotent(self) -> None:
        root = self.make_root()
        (root / ".python-version").write_text("3.14.5\n", encoding="utf-8")
        (root / "requirements-ci.lock").write_text(
            REQUIREMENTS.replace("6.0.3", "6.0.2").replace(
                "c458b6d084f9b935061bc36216e8a69a7e293a2f1e68bf956dcd9e6cbcd143f5",
                "0" * 64,
            ),
            encoding="utf-8",
        )
        result = self.run_tool(root, "--write")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((root / ".python-version").read_text(), "3.14.6\n")
        self.assertIn("PyYAML==6.0.3", (root / "requirements-ci.lock").read_text())
        first = (root / "requirements-ci.lock").stat().st_mtime_ns
        result = self.run_tool(root, "--write")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(first, (root / "requirements-ci.lock").stat().st_mtime_ns)

    def test_malformed_canonical_digest_is_rejected(self) -> None:
        root = self.make_root()
        (root / "ci/lib/common.sh").write_text(
            COMMON.replace("c458", "C458"), encoding="utf-8"
        )
        result = self.run_tool(root, "--check")
        self.assertEqual(result.returncode, 2)
        self.assertIn("64 lowercase hex", result.stderr)

    def test_duplicate_canonical_assignment_is_rejected(self) -> None:
        root = self.make_root()
        (root / "ci/lib/common.sh").write_text(
            COMMON + "CI_CANONICAL_PYTHON_VERSION=3.14.6\n", encoding="utf-8"
        )
        result = self.run_tool(root, "--check")
        self.assertEqual(result.returncode, 2)
        self.assertIn("duplicate", result.stderr)

    def test_symlinked_common_source_is_rejected_before_read(self) -> None:
        root = self.make_root()
        outside = Path(tempfile.mkdtemp()) / "common.sh"
        outside.write_text(COMMON, encoding="utf-8")
        (root / "ci/lib/common.sh").unlink()
        (root / "ci/lib/common.sh").symlink_to(outside)
        result = self.run_tool(root, "--check")
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)

    def test_common_override_outside_root_is_rejected(self) -> None:
        root = self.make_root()
        outside = Path(tempfile.mkdtemp()) / "common.sh"
        outside.write_text(COMMON, encoding="utf-8")
        result = self.run_tool(root, "--check", common=outside)
        self.assertEqual(result.returncode, 2)
        self.assertIn("below", result.stderr)

    def test_common_override_lexical_traversal_is_rejected_before_read(self) -> None:
        root = self.make_root()
        outside = root.parent / f"{root.name}-outside-common.sh"
        self.addCleanup(outside.unlink, missing_ok=True)
        outside.write_text(COMMON, encoding="utf-8")
        result = self.run_tool(root, "--check", common=root / ".." / outside.name)
        self.assertEqual(result.returncode, 2)
        self.assertIn("below", result.stderr)

    def test_non_ascii_versions_are_rejected(self) -> None:
        root = self.make_root()
        common = root / "ci/lib/common.sh"
        common.write_text(
            COMMON.replace('CI_CANONICAL_PYTHON_VERSION="3.14.6"', 'CI_CANONICAL_PYTHON_VERSION="١.14.6"'),
            encoding="utf-8",
        )
        result = self.run_tool(root, "--check")
        self.assertEqual(result.returncode, 2)
        self.assertIn("malformed", result.stderr)

        common.write_text(
            COMMON.replace('CI_CANONICAL_PYYAML_VERSION="6.0.3"', 'CI_CANONICAL_PYYAML_VERSION="٦.0.3"'),
            encoding="utf-8",
        )
        result = self.run_tool(root, "--check")
        self.assertEqual(result.returncode, 2)
        self.assertIn("malformed", result.stderr)

        common.write_text(COMMON, encoding="utf-8")
        (root / ".python-version").write_text("٣.14.6\n", encoding="utf-8")
        result = self.run_tool(root, "--check")
        self.assertEqual(result.returncode, 2)
        self.assertIn("stable version", result.stderr)

    def test_symlinked_generated_view_is_rejected_without_following_it(self) -> None:
        root = self.make_root()
        outside = Path(tempfile.mkdtemp()) / "python-version"
        outside.write_text("3.14.5\n", encoding="utf-8")
        (root / ".python-version").unlink()
        (root / ".python-version").symlink_to(outside)
        result = self.run_tool(root, "--write")
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)
        self.assertEqual(outside.read_text(encoding="utf-8"), "3.14.5\n")

    def test_symlinked_generated_parent_is_rejected(self) -> None:
        root = self.make_root()
        outside = Path(tempfile.mkdtemp())
        generated = root / "generated"
        generated.symlink_to(outside, target_is_directory=True)
        # Exercise the path-boundary helper directly for a nested output path;
        # the production views remain at the repository root.
        with self.assertRaises(MODULE.PinError):
            MODULE.path_in_root(generated / "view", root, "generated view")


if __name__ == "__main__":
    unittest.main()
