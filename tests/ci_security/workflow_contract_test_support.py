from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any
import unittest


WorkflowContractErrors = Callable[[Path, str, Any], list[str]]


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
