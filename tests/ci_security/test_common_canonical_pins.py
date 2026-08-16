"""Path-integrity tests for the canonical CI pin reader."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "ci/tools/common_canonical_pins.py"
SPEC = importlib.util.spec_from_file_location("common_canonical_pins_test_target", TOOL)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load canonical pin reader")
PINS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PINS)


class CommonCanonicalPinsPathTest(unittest.TestCase):
    def write_common(self, root: Path) -> None:
        common = root / "ci/lib/common.sh"
        common.parent.mkdir(parents=True)
        common.write_text(
            'CI_ACTION_CHECKOUT_REPOSITORY="actions/checkout"\n'
            'CI_ACTION_CHECKOUT_VERSION="v4.2.2"\n',
            encoding="utf-8",
        )

    def test_real_common_path_is_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_common(root)

            self.assertEqual(
                PINS.load_canonical_ci_pins(root),
                {
                    "CI_ACTION_CHECKOUT_REPOSITORY": "actions/checkout",
                    "CI_ACTION_CHECKOUT_VERSION": "v4.2.2",
                },
            )

    def test_symlinked_ci_lib_cannot_redirect_pin_reads_outside_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "framework"
            outside = parent / "outside"
            (outside / "lib").mkdir(parents=True)
            (outside / "lib/common.sh").write_text(
                'CI_ACTION_CHECKOUT_REPOSITORY="attacker/checkout"\n',
                encoding="utf-8",
            )
            (root / "ci").mkdir(parents=True)
            (root / "ci/lib").symlink_to(outside / "lib", target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "may not contain symlinks"):
                PINS.load_canonical_ci_pins(root)


if __name__ == "__main__":
    unittest.main()
