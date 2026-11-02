from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import re
from typing import Any
import unittest

from ci.tools.common_canonical_pins import load_canonical_ci_pins


WorkflowContractErrors = Callable[[Path, str, Any], list[str]]


def assert_canonical_action_pin(
    test_case: unittest.TestCase,
    root: Path,
    uses: object,
    suffix: str,
    repository: str,
) -> None:
    """Require the fixed Action identity and its independent canonical commit."""
    values = load_canonical_ci_pins(root)
    test_case.assertEqual(values.get(f"CI_ACTION_{suffix}_REPOSITORY"), repository)
    commit = values.get(f"CI_ACTION_{suffix}_COMMIT", "")
    test_case.assertIsNotNone(re.fullmatch(r"[0-9a-f]{40}", commit))
    test_case.assertEqual(uses, f"{repository}@{commit}")


def assert_rejects_unsafe_workflow_controls(
    test_case: unittest.TestCase,
    workflow_contract_errors: WorkflowContractErrors,
) -> None:
    data = {
        "permissions": "write-all",
        "concurrency": {"group": "", "cancel-in-progress": "true"},
        "jobs": {
            "check": {
                "timeout-minutes": True,
                "env": {"GITHUB_TOKEN": "${{ github.token }}"},
            }
        },
    }
    errors = workflow_contract_errors(Path("unsafe-controls.yml"), "", data)
    test_case.assertTrue(
        any("permissions must be a mapping" in error for error in errors)
    )
    test_case.assertTrue(any("non-empty group" in error for error in errors))
    test_case.assertTrue(any("cancel-in-progress" in error for error in errors))
    test_case.assertTrue(
        any("positive integer timeout-minutes" in error for error in errors)
    )
    test_case.assertTrue(
        any("must not expose GITHUB_TOKEN" in error for error in errors)
    )
