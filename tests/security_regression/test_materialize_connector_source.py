"""Regression coverage for source-tree materialization boundaries."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MATERIALIZER_PATH = ROOT / "ci" / "provisioning" / "materialize-connector-source.py"


def load_materializer():
    specification = importlib.util.spec_from_file_location(
        "materialize_connector_source_test", MATERIALIZER_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("could not load materialize-connector-source.py")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


class MaterializeConnectorSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.materializer = load_materializer()

    def test_copies_a_regular_file_within_the_source_tree(self) -> None:
        with tempfile.TemporaryDirectory(prefix="materialize-source-") as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            destination.mkdir()
            (source / "safe.txt").write_text("regular fixture\n", encoding="utf-8")

            entries = self.materializer.copy_tree_files(
                source, destination, Path("."), "fixture", "", "", "", "test"
            )

            self.assertEqual(
                (destination / "safe.txt").read_text(encoding="utf-8"),
                "regular fixture\n",
            )
            self.assertEqual(entries["safe.txt"].path, "safe.txt")

    def test_rejects_file_and_directory_symlinks_before_copying(self) -> None:
        with tempfile.TemporaryDirectory(prefix="materialize-source-") as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            (outside / "target.txt").write_text("fixture target\n", encoding="utf-8")

            for name, target, directory in (
                ("linked-file.txt", outside / "target.txt", False),
                ("linked-directory", outside, True),
            ):
                with self.subTest(name=name):
                    source = root / f"source-{name}"
                    destination = root / f"destination-{name}"
                    source.mkdir()
                    destination.mkdir()
                    (source / name).symlink_to(target, target_is_directory=directory)

                    with self.assertRaisesRegex(ValueError, "unsupported symlink"):
                        self.materializer.copy_tree_files(
                            source,
                            destination,
                            Path("."),
                            "fixture",
                            "",
                            "",
                            "",
                            "test",
                        )

                    self.assertFalse((destination / name).exists())


if __name__ == "__main__":
    unittest.main()
