"""Security controls for the standalone case-matrix report writer."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "ci" / "reporting" / "write-case-matrix.py"


def load_module():
    specification = importlib.util.spec_from_file_location("write_case_matrix", SCRIPT_PATH)
    if specification is None or specification.loader is None:
        raise RuntimeError("could not load write-case-matrix.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class WriteCaseMatrixSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.environment = os.environ.copy()

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self.environment)

    def test_writes_only_below_a_private_build_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "build"
            root.mkdir(mode=0o700)
            self.module.FRAMEWORK_ROOT = Path(temporary) / "framework"
            self.module.CONNECTOR_ROOT = Path(temporary) / "connector"
            os.environ["BUILD_ROOT"] = str(root)

            self.assertEqual(0, self.module.main(["write-case-matrix.py"]))
            output = root / "case-matrix.md"
            self.assertTrue(output.is_file())
            self.assertFalse(output.is_symlink())

    def test_rejects_external_and_symlink_escaped_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "build"
            root.mkdir(mode=0o700)
            outside = Path(temporary) / "outside.md"
            outside.write_text("outside", encoding="utf-8")
            escaped = root / "escaped.md"
            escaped.symlink_to(outside)
            self.module.FRAMEWORK_ROOT = Path(temporary) / "framework"
            self.module.CONNECTOR_ROOT = Path(temporary) / "connector"
            os.environ["BUILD_ROOT"] = str(root)

            self.assertEqual(2, self.module.main(["write-case-matrix.py", str(outside)]))
            self.assertEqual(2, self.module.main(["write-case-matrix.py", "", str(escaped)]))
            self.assertEqual("outside", outside.read_text(encoding="utf-8"))

    def test_requires_an_explicit_private_root(self) -> None:
        os.environ.pop("BUILD_ROOT", None)
        os.environ.pop("VERIFIED_RUN_ROOT", None)
        self.assertEqual(2, self.module.main(["write-case-matrix.py"]))
