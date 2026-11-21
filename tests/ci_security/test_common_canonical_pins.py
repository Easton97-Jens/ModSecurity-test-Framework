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
            ("9ae8ecc4f686e9cc70413e5494bc098a24eb18d7", "a" * 40),
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


GO_TOOL_LINES = (
    'CI_GO_TOOL_STATICCHECK_MODULE="honnef.co/go/tools"\n'
    'CI_GO_TOOL_STATICCHECK_PACKAGE="honnef.co/go/tools/cmd/staticcheck"\n'
    'CI_GO_TOOL_STATICCHECK_VERSION="v0.8.2"\n'
    'CI_GO_TOOL_STATICCHECK_MODULE_SUM="h1:+jPbCzuYxYrcoOvCecYUFDj+XJQRmzIhJmlbpps21Zk="\n'
)


class CanonicalGoToolPinsTest(unittest.TestCase):
    def load(self, text: str) -> dict[str, dict[str, str]]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            common = root / "ci/lib/common.sh"
            common.parent.mkdir(parents=True)
            common.write_text(text, encoding="utf-8")
            return PINS.load_canonical_go_tools(root)

    def test_complete_group_is_returned_by_executable(self) -> None:
        self.assertEqual(
            self.load(GO_TOOL_LINES),
            {
                "staticcheck": {
                    "module": "honnef.co/go/tools",
                    "package": "honnef.co/go/tools/cmd/staticcheck",
                    "version": "v0.8.2",
                    "module_sum": "h1:+jPbCzuYxYrcoOvCecYUFDj+XJQRmzIhJmlbpps21Zk=",
                    "executable": "staticcheck",
                }
            },
        )

    def test_incomplete_group_fails_closed(self) -> None:
        text = "".join(
            line + "\n"
            for line in GO_TOOL_LINES.splitlines()
            if "_MODULE_SUM=" not in line
        )
        with self.assertRaisesRegex(
            ValueError, "incomplete or invalid Go tool pin group STATICCHECK"
        ):
            self.load(text)

    def test_range_version_and_foreign_package_are_rejected(self) -> None:
        for old, new in (
            ('"v0.8.2"', '">=v0.8"'),
            ("honnef.co/go/tools/cmd", "example.com/other/cmd"),
        ):
            with (
                self.subTest(new=new),
                self.assertRaisesRegex(ValueError, "invalid Go tool pin group"),
            ):
                self.load(GO_TOOL_LINES.replace(old, new))

    def test_shell_expressions_and_duplicates_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsafe Go tool pin expression"):
            self.load(GO_TOOL_LINES.replace('"v0.8.2"', '"$(curl example)"'))
        with self.assertRaisesRegex(ValueError, "duplicate Go tool pin"):
            self.load(GO_TOOL_LINES + 'CI_GO_TOOL_STATICCHECK_VERSION="v0.8.2"\n')

    def test_group_must_name_its_executable(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not name its executable"):
            self.load(
                GO_TOOL_LINES.replace("CI_GO_TOOL_STATICCHECK_", "CI_GO_TOOL_LINTER_")
            )

    def test_repository_common_pins_both_go_tools(self) -> None:
        tools = PINS.load_canonical_go_tools(ROOT)
        self.assertEqual(sorted(tools), ["govulncheck", "staticcheck"])


class CanonicalGoToolInventoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.checker = runpy.run_path(str(ROOT / "ci/tools/check-common-versions.py"))

    def inventory_errors(self, text: str) -> list[str]:
        entries = self.checker["parse_common_lines"](text.splitlines())
        _names, errors = self.checker["canonical_ci_group_inventory"](entries)
        return errors

    def test_complete_go_tool_group_is_owned_and_valid(self) -> None:
        self.assertEqual(self.inventory_errors(GO_TOOL_LINES), [])
        entries = self.checker["parse_common_lines"](GO_TOOL_LINES.splitlines())
        self.assertEqual(self.checker["unassigned_provenance_variables"](entries), [])

    def test_incomplete_go_tool_group_is_reported(self) -> None:
        text = "".join(
            line + "\n"
            for line in GO_TOOL_LINES.splitlines()
            if "_PACKAGE=" not in line
        )
        self.assertIn(
            "incomplete go tool group STATICCHECK; missing: PACKAGE",
            self.inventory_errors(text),
        )
