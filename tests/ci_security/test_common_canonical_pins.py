"""Path-integrity tests for the canonical CI pin reader."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
import runpy


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


class DiagnosticSourceProvenanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.checker = runpy.run_path(str(ROOT / "ci/tools/check-common-versions.py"))

    def test_dedicated_source_owner_and_namespace_identity_are_distinct(self) -> None:
        checker = self.checker
        _lines, entries = checker["parse_common"](ROOT / "ci/lib/common.sh")
        names = set(checker["CI_DIAGNOSTIC_SOURCE_VARIABLES"])
        owners = [
            item
            for item in checker["COMPONENT_DEFINITIONS"]
            if names.intersection(item.variables)
        ]
        self.assertEqual(len(owners), 1)
        self.assertEqual(set(owners[0].variables), names)
        self.assertEqual(owners[0].update_policy, "manual_review")
        self.assertEqual(checker["_canonical_value_errors"](entries), [])
        values = checker["_canonical_pin_values"](ROOT / "ci/lib/common.sh")
        self.assertNotIn("CI_SONAR_DIAGNOSTIC_REPOSITORY", values)
        self.assertIn("CI_SONAR_DIAGNOSTIC_COMMIT", values)
        self.assertIn("CI_SONAR_DIAGNOSTIC_SOURCE_REFERENCE", values)
        self.assertIn("CI_ACTION_CHECKOUT_REPOSITORY", values)

    def test_source_tuple_corruption_and_unregistered_fields_fail(self) -> None:
        checker = self.checker
        source = (ROOT / "ci/lib/common.sh").read_text(encoding="utf-8")
        for old, new in (
            ("865e4ec4fd0a745d1d125b3f43b3dd8d56b3ca7a", "a" * 40),
            (".github/actions/sonar-private", ".github/actions/other-node"),
        ):
            with self.subTest(old=old):
                lines = source.replace(old, new).splitlines()
                entries = checker["parse_common_lines"](lines)
                self.assertTrue(checker["canonical_contract_errors"](lines, entries))
        lines = source.splitlines() + ['CI_SONAR_DIAGNOSTIC_VERSION="v1.0.0"']
        entries = checker["parse_common_lines"](lines)
        self.assertTrue(checker["canonical_contract_errors"](lines, entries))

    def test_namespace_mentions_do_not_hide_executable_or_ordinary_pins(self) -> None:
        checker = self.checker
        values = checker["_canonical_pin_values"](ROOT / "ci/lib/common.sh")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            common = root / "ci/lib/common.sh"
            common.parent.mkdir(parents=True)
            common.write_bytes((ROOT / "ci/lib/common.sh").read_bytes())
            consumer = root / "ci/consumer.py"
            consumer.write_text(
                "project = 'Easton97-Jens/ModSecurity-test-Framework'\n",
                encoding="utf-8",
            )
            self.assertEqual(checker["active_consumer_pin_literals"](common, root), [])
            for name in (
                "CI_SONAR_DIAGNOSTIC_SOURCE_REFERENCE",
                "CI_SONAR_DIAGNOSTIC_COMMIT",
                "CI_ACTION_CHECKOUT_REPOSITORY",
            ):
                with self.subTest(name=name):
                    consumer.write_text(
                        "value = " + repr(values[name]) + "\n", encoding="utf-8"
                    )
                    self.assertTrue(
                        checker["active_consumer_pin_literals"](common, root)
                    )


if __name__ == "__main__":
    unittest.main()
