"""Regression coverage for the Connector GitHub Actions security contract.

The historical test depended on a non-existent standalone checker.  This
suite keeps the security regression intent by exercising the checked-in
Connector contract (`make check-ci-security-contract`) and the constrained
workflow-tool updater's exact allowlist and YAML defenses.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest

from modsecurity_connector_tests import test_ci_security_workflows as native_contract


ROOT = connector_root()
UPDATER_PATH = source_path('ci/tools/update-workflow-tools.py', root=ROOT)
WORKFLOW_PATH = source_path('.github/workflows/update-workflow-tools.yml', root=ROOT)


def load_updater():
    module = load_source(UPDATER_PATH)
    return module


UPDATER = load_updater()


class WorkflowSecurityContractTests(unittest.TestCase):
    def test_current_connector_workflows_meet_the_native_contract(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "-v",
                "modsecurity_connector_tests.test_ci_security_workflows",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            encoding="utf-8",
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_parent_allowlist_exactly_covers_every_current_workflow(self) -> None:
        _path, lock, _digest = UPDATER.load_lock(ROOT)
        actual_workflows = {
            str(path.relative_to(ROOT))
            for path in (source_path('.github/workflows', root=ROOT)).glob("*.yml")
        }
        references = UPDATER.locked_action_workflow_references(ROOT, lock)
        referenced_workflows = set().union(*references.values())
        self.assertTrue(referenced_workflows.issubset(actual_workflows))
        self.assertEqual(set(UPDATER.WORKFLOW_UPDATE_PATHS), actual_workflows)
        UPDATER.ensure_locked_action_workflow_coverage(ROOT, lock)

    def test_update_workflow_preserves_the_separated_security_boundary(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        jobs = native_contract.job_blocks(workflow)
        self.assertEqual(set(jobs), {"resolver", "validator", "publisher", "outcome"})
        self.assertEqual(
            native_contract.job_permissions(jobs["resolver"]), {"contents": "read"}
        )
        self.assertEqual(
            native_contract.job_permissions(jobs["validator"]), {"contents": "read"}
        )
        self.assertEqual(
            native_contract.job_permissions(jobs["publisher"]), {"contents": "read"}
        )
        self.assertEqual(native_contract.job_permissions(jobs["outcome"]), {})
        self.assertIn("persist-credentials: false", jobs["resolver"])
        self.assertIn("persist-credentials: false", jobs["validator"])
        self.assertIn("persist-credentials: false", jobs["publisher"])
        self.assertIn("--expected-candidate-sha256", workflow)
        self.assertIn("draft: true", workflow)
        self.assertIn("verify-scope --root . --staged", workflow)

    def test_yaml_indirection_is_rejected_in_both_updater_and_native_contract(self) -> None:
        unsafe = "defaults: &unsafe {value: true}\njob: {<<: *unsafe}\n"
        self.assertTrue(UPDATER.yaml_safety_errors(unsafe))
        self.assertTrue(native_contract.yaml_security_errors(unsafe))
        checked_paths = [
            source_path('ci/tooling/security-tools.lock.yml', root=ROOT),
            *sorted((source_path('.github/workflows', root=ROOT)).glob("*.yml")),
        ]
        for path in checked_paths:
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(UPDATER.yaml_safety_errors(text), [])
                self.assertEqual(native_contract.yaml_security_errors(text), [])

    def test_no_legacy_missing_checker_or_fetcher_is_reintroduced(self) -> None:
        updater = UPDATER_PATH.read_text(encoding="utf-8")
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn('with_name("fetch_security_tool.py")', updater)
        self.assertIn("check-ci-security-contract", updater)
        self.assertIn("run: make check-ci-security-contract", workflow)
        for absent_path in (
            "ci/checks/security/check-ci-security-contract.py",
            "ci/checks/security/check-github-actions-workflows.py",
            "ci/checks/security/check-workflow-action-pins.py",
            "ci/tools/fetch-security-tool.py",
        ):
            with self.subTest(absent_path=absent_path):
                self.assertNotIn(absent_path, updater)
                self.assertNotIn(absent_path, workflow)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
