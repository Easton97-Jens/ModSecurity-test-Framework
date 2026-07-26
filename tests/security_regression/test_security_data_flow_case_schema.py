"""Regression controls for connector-neutral security/data-flow descriptors."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
RUNNER_DIRECTORY = ROOT / "tests" / "runners"
if str(RUNNER_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIRECTORY))

import case_cli  # noqa: E402
from runner_core import discover_case_files, is_runtime_materializable, load_case, validate_case  # noqa: E402


class SecurityDataFlowCaseSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cases = tuple(sorted((ROOT / "tests" / "cases" / "security-data-flow").rglob("*.yaml")))

    def test_connector_neutral_descriptors_are_explicitly_non_materializable(self) -> None:
        self.assertEqual(len(self.cases), 15)
        for path in self.cases:
            case = load_case(path)
            self.assertFalse(is_runtime_materializable(case), path)
            self.assertTrue(case["former_xfail"], path)
            self.assertFalse(case["capabilities"]["runtime_verified"], path)

    def test_force_all_discovery_skips_non_materializable_descriptors(self) -> None:
        with mock.patch.dict(os.environ, {"FORCE_ALL_CASES": "1"}, clear=False):
            selected = discover_case_files(ROOT, "apache", "all", framework_root=ROOT)

        self.assertTrue(selected)
        self.assertTrue(set(self.cases).isdisjoint(selected))

    def test_missing_rules_requires_explicit_non_materializable_contract(self) -> None:
        case = dict(load_case(self.cases[0]))
        case.pop("runtime_materializable")

        with self.assertRaisesRegex(ValueError, "case requires rules"):
            validate_case(case)

    def test_non_materializable_contract_cannot_reclassify_an_active_case(self) -> None:
        case = dict(load_case(self.cases[0]))
        case["status"] = "active"

        with self.assertRaisesRegex(ValueError, "requires status=connector-gap"):
            validate_case(case)

    def test_direct_materialization_rejects_non_materializable_descriptor(self) -> None:
        with self.assertRaisesRegex(ValueError, "explicitly non-materializable"):
            case_cli.materialize(argparse.Namespace(case=self.cases[0]))
