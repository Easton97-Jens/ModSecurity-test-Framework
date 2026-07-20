from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
