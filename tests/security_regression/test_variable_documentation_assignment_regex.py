from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "ci/checks/documentation/check-variable-documentation.py"


def load_variable_documentation_checker():
    spec = importlib.util.spec_from_file_location("variable_documentation_assignment_regex", CHECKER)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load variable documentation checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class VariableDocumentationAssignmentRegexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.checker = load_variable_documentation_checker()

    def test_ascii_variable_assignments_and_ascii_prefix_control(self) -> None:
        for assignment in ("VARIABLE=value", "VARIABLE ?= value", "VARIABLE:=value"):
            with self.subTest(assignment=assignment):
                self.assertEqual(self.checker.ASSIGNMENT_RE.findall(assignment), ["VARIABLE"])
        self.assertEqual(self.checker.ASSIGNMENT_RE.findall("xVARIABLE=value"), [])

    def test_non_ascii_adjacency_remains_a_variable_boundary(self) -> None:
        self.assertEqual(self.checker.ASSIGNMENT_RE.findall("éVARIABLE=value"), ["VARIABLE"])

    def test_unicode_whitespace_before_assignment_operator_remains_valid(self) -> None:
        self.assertEqual(self.checker.ASSIGNMENT_RE.findall("VARIABLE\u00a0= value"), ["VARIABLE"])

    def test_agent_include_cannot_exempt_an_arbitrary_reader_facing_document(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            (temporary_root / "AGENTS.md").write_text("@arbitrary-reader-facing.md\n", encoding="utf-8")
            arbitrary = temporary_root / "arbitrary-reader-facing.md"
            arbitrary.write_text("Reader-facing content\n", encoding="utf-8")
            with mock.patch.object(self.checker, "ROOT", temporary_root):
                self.assertFalse(self.checker.is_local_agent_configuration_path(arbitrary))


if __name__ == "__main__":
    unittest.main()
