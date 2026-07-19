"""Regression coverage for the Framework GitHub Actions security contract."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "ci/checks/security/check-github-actions-workflows.py"
FIXTURES = ROOT / "tests/fixtures/workflow_security_contract"


class WorkflowSecurityContractTests(unittest.TestCase):
    def fixture_path(self, name: str) -> Path:
        directory = FIXTURES / name
        return directory if directory.is_dir() else directory.with_suffix(".yml")

    def run_checker(
        self, workflow_root: Path, check: str = "all", working_directory: Path = ROOT
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                "--workflow-root",
                str(workflow_root),
                "--check",
                check,
            ],
            cwd=working_directory,
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_framework_workflows_meet_full_contract(self) -> None:
        result = self.run_checker(ROOT / ".github/workflows")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_safe_fixtures_meet_full_contract(self) -> None:
        for name in ("safe_read_only_pr", "safe_trusted_writer"):
            with self.subTest(name=name):
                result = self.run_checker(FIXTURES / name)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_validator_recurses_into_nested_workflow_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            workflow_root = Path(temporary_root)
            nested_directory = workflow_root / "nested"
            nested_directory.mkdir()
            (nested_directory / "workflow.yaml").write_text(
                """\
name: nested workflow
on: pull_request
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
""",
                encoding="utf-8",
            )
            result = self.run_checker(
                workflow_root, check="pins", working_directory=workflow_root
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("immutable full SHA", result.stderr)

    def test_validator_rejects_workflow_roots_outside_the_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            workflow = Path(temporary_root) / "workflow.yml"
            workflow.write_text("name: external\n", encoding="utf-8")
            result = self.run_checker(workflow, check="pins")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no .yml or .yaml workflow files found", result.stderr)

    def test_validator_does_not_follow_a_workflow_symlink_outside_repository(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as repository,
            tempfile.TemporaryDirectory() as external,
        ):
            repository_root = Path(repository)
            external_workflow = Path(external) / "workflow.yml"
            external_workflow.write_text("name: external\n", encoding="utf-8")
            (repository_root / "escaped.yml").symlink_to(external_workflow)
            result = self.run_checker(
                repository_root, check="pins", working_directory=repository_root
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no .yml or .yaml workflow files found", result.stderr)

    def test_pin_validator_rejects_mutable_tags_in_both_extensions(self) -> None:
        cases = {
            "unsafe_mutable_tag": "immutable full SHA",
            "unsafe_yaml_mutable_tag": "immutable full SHA",
            "unsafe_dynamic_uses": "immutable full SHA",
            "unsafe_spaced_uses": "immutable full SHA",
            "unsafe_quoted_uses": "immutable full SHA",
            "unsafe_flow_uses": "flow-style YAML collections",
            "unsafe_flow_sequence_uses": "flow-style YAML collections",
            "unsafe_nested_flow_uses": "flow-style YAML collections",
            "unsafe_block_scalar_uses": "must not use YAML block scalars",
            "unsafe_explicit_key_uses": "explicit mapping keys",
            "unsafe_tagged_key_uses": "YAML tags, anchors, aliases, and merge keys",
            "unsafe_tagged_flow_sequence_uses": "YAML tags, anchors, aliases, and merge keys",
            "unsafe_escaped_key_uses": "escaped double-quoted mapping keys",
            "unsafe_document_start_tagged_flow": "YAML document markers",
            "unsafe_bom_document_start_tagged_flow": "YAML document markers",
        }
        for name, expected_message in cases.items():
            with self.subTest(name=name):
                result = self.run_checker(self.fixture_path(name), check="pins")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_message, result.stderr)

    def test_permission_and_trust_boundary_validator_rejects_unsafe_fixtures(
        self,
    ) -> None:
        cases = {
            "unsafe_pull_request_target": "pull_request_target",
            "unsafe_pr_write_permission": "write permission",
            "unsafe_top_level_write_permission": "top-level permissions",
            "unsafe_checkout_credentials": "persist-credentials",
            "unsafe_job_token_scope": "job-level GITHUB_TOKEN",
            "unsafe_pr_submodules": "submodules",
            "unsafe_pr_dynamic_submodules": "submodules",
            "unsafe_pr_secret": "secrets",
            "unsafe_pr_secret_bracket": "secrets",
            "unsafe_pr_reusable_secrets": "reusable-workflow secrets",
            "unsafe_workflow_token_scope": "workflow-level GITHUB_TOKEN",
            "unsafe_renamed_workflow_token": "workflow-level env must not expose github.token",
            "unsafe_duplicate_key": "duplicate key",
            "unsafe_yaml_anchor": "anchors",
            "unsafe_missing_version_comment": "release comment",
        }
        for name, expected_message in cases.items():
            with self.subTest(name=name):
                check = (
                    "pins"
                    if name == "unsafe_missing_version_comment"
                    else "permissions"
                )
                result = self.run_checker(self.fixture_path(name), check=check)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_message, result.stderr)
