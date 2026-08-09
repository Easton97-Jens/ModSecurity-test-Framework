from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

from tests.ci_security.workflow_contract_test_support import (
    assert_rejects_unsafe_workflow_controls,
)


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "ci/checks/security/check-ci-security-contract.py"
FETCHER_PATH = ROOT / "ci/tools/fetch-security-tool.py"
LOCK_PATH = ROOT / "ci/tooling/security-tools.lock.yml"


def load_checker():
    spec = importlib.util.spec_from_file_location("ci_security_contract", CHECKER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CHECKER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


def load_fetcher():
    spec = importlib.util.spec_from_file_location("security_tool_fetcher", FETCHER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {FETCHER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FETCHER = load_fetcher()


class CiSecurityContractTest(unittest.TestCase):
    def test_current_workflows_meet_the_contract(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CHECKER_PATH), "--root", str(ROOT)],
            check=False,
            capture_output=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_setup_python_version_file_parsing_accepts_reviewed_values_and_rejects_long_input(
        self,
    ) -> None:
        setup_python = CHECKER.SETUP_PYTHON_REFERENCE
        safe_text = (
            f"uses: {setup_python}\n"
            'python-version-file: ".python-version" # canonical\n'
            "check-latest: false\n"
            f"uses: {setup_python}\n"
            'python-version-file: "${{ runner.temp }}/framework-python-3.14-candidate"\n'
            "check-latest: false\n"
        )
        self.assertEqual(
            CHECKER.setup_python_errors(
                Path(CHECKER.PYTHON_VERSION_MAINTENANCE_WORKFLOW), safe_text
            ),
            [],
        )

        long_untrusted_value = "untrusted" * 5_000
        untrusted_text = (
            f"uses: {setup_python}\n"
            f"python-version-file: {long_untrusted_value} # comment\n"
            "check-latest: false\n"
        )
        errors = CHECKER.setup_python_errors(Path("untrusted.yml"), untrusted_text)
        self.assertTrue(
            any("every setup-python use" in error for error in errors),
            "\n".join(errors),
        )

    def test_lock_has_complete_action_and_tool_provenance(self) -> None:
        actions, tools, errors = CHECKER.load_lock(LOCK_PATH)
        self.assertFalse(errors, "\n".join(errors))
        self.assertIn("actions/checkout", actions)
        self.assertIn("actionlint", tools)
        self.assertIn("pyright", tools)

    def test_safe_fixture_has_no_trust_boundary_error(self) -> None:
        fixture = ROOT / "tests/fixtures/ci-security/safe.yml"
        self.assertEqual(
            CHECKER.trust_boundary_errors(fixture, fixture.read_text()), []
        )

    def test_unsafe_fixture_is_rejected_for_trigger_and_interpolation(self) -> None:
        fixture = ROOT / "tests/fixtures/ci-security/unsafe.yml"
        errors = CHECKER.trust_boundary_errors(fixture, fixture.read_text())
        self.assertTrue(any("pull_request_target" in error for error in errors))
        self.assertTrue(
            any("interpolate PR title or body" in error for error in errors)
        )

    def test_inline_pull_request_target_fixture_is_rejected(self) -> None:
        fixture = ROOT / "tests/fixtures/ci-security/unsafe-inline.yml"
        errors = CHECKER.trust_boundary_errors(fixture, fixture.read_text())
        self.assertTrue(any("pull_request_target" in error for error in errors))

    def test_pull_request_target_matching_preserves_identifier_boundaries(self) -> None:
        harmless = "on: pull_request_target_fixture\n"
        self.assertEqual(
            CHECKER.trust_boundary_errors(ROOT / "harmless.yml", harmless), []
        )
        quoted_trigger = "on: 'pull_request_target'\n"
        errors = CHECKER.trust_boundary_errors(
            ROOT / "quoted-trigger.yml", quoted_trigger
        )
        self.assertTrue(
            any("pull_request_target is forbidden" in error for error in errors)
        )

    def test_github_context_detection_rejects_bracket_and_bare_forms(self) -> None:
        for expression in ("${{ github['token'] }}", "${{ github }}"):
            with self.subTest(expression=expression):
                self.assertTrue(CHECKER.contains_sensitive_reference(expression))

    def test_yaml_workflow_and_quoted_mutable_action_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workflow_dir = root / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            workflow = workflow_dir / "quoted-action.yaml"
            workflow.write_text(
                textwrap.dedent(
                    """\
                    name: quoted action fixture
                    on: pull_request
                    permissions: {}
                    concurrency:
                      group: quoted-action-fixture
                      cancel-in-progress: true
                    jobs:
                      check:
                        runs-on: ubuntu-latest
                        timeout-minutes: 5
                        steps:
                          - uses: "actions/checkout@v7" # v7.0.0
                            with:
                              persist-credentials: false
                              submodules: false
                    """
                ),
                encoding="utf-8",
            )
            errors = CHECKER.validate(root, LOCK_PATH)
        self.assertTrue(any("quoted-action.yaml" in error for error in errors))
        self.assertTrue(any("full immutable commit SHA" in error for error in errors))

    def test_parsed_action_lock_validation_rejects_yaml_spelling_bypasses(
        self,
    ) -> None:
        actions, _tools, lock_errors = CHECKER.load_lock(LOCK_PATH)
        self.assertFalse(lock_errors, "\n".join(lock_errors))
        locked_sha = actions["actions/checkout"]["immutable_commit"]
        different_sha = "0" * 40 if locked_sha != "0" * 40 else "1" * 40

        fixtures = {
            "quoted-key.yml": f"""\
jobs:
  publisher:
    steps:
      - "uses": actions/checkout@{different_sha} # v7.0.1
""",
            "flow-mapping.yml": f"""\
jobs:
  publisher:
    steps:
      - {{name: Checkout, uses: actions/checkout@{different_sha}}}
""",
        }
        for name, text in fixtures.items():
            with self.subTest(name=name):
                data = CHECKER.yaml.safe_load(text)
                errors = CHECKER.parsed_action_lock_errors(Path(name), data, actions)
                self.assertTrue(
                    any(
                        "SHA differs from the reviewed lock" in error
                        for error in errors
                    ),
                    "\n".join(errors),
                )

        current_data = CHECKER.load_yaml(
            ROOT / ".github/workflows/update-workflow-tools.yml"
        )
        self.assertEqual(
            CHECKER.parsed_action_lock_errors(
                ROOT / ".github/workflows/update-workflow-tools.yml",
                current_data,
                actions,
            ),
            [],
        )

    def test_contract_rejects_scalar_permissions_and_invalid_controls(self) -> None:
        assert_rejects_unsafe_workflow_controls(self, CHECKER.workflow_contract_errors)

    def test_contract_rejects_unlocked_container_reference(self) -> None:
        actions, _tools, errors = CHECKER.load_lock(LOCK_PATH)
        self.assertFalse(errors, "\n".join(errors))
        errors = CHECKER.pin_errors(
            Path("container.yml"),
            "uses: docker://example.invalid/security-tool:latest\n",
            actions,
        )
        self.assertTrue(any("locked GitHub Action" in error for error in errors))

    def test_malformed_action_lock_fails_closed_without_a_checker_crash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workflow_dir = root / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            action_sha = "0" * 40
            (workflow_dir / "checkout.yml").write_text(
                textwrap.dedent(
                    """\
                    name: malformed action lock fixture
                    on: pull_request
                    permissions: {}
                    concurrency:
                      group: malformed-action-lock
                      cancel-in-progress: true
                    jobs:
                      check:
                        runs-on: ubuntu-latest
                        timeout-minutes: 5
                        steps:
                          - uses: actions/checkout@ACTION_SHA # v5.0.0
                            with:
                              persist-credentials: false
                              submodules: false
                    """
                ).replace("ACTION_SHA", action_sha),
                encoding="utf-8",
            )
            lock = root / "security-tools.lock.yml"
            lock.write_text("actions:\n  actions/checkout: invalid\ntools: {}\n")
            errors = CHECKER.validate(root, lock)

        self.assertTrue(any("must be a mapping" in error for error in errors))
        self.assertTrue(
            any("absent from the action lock" in error for error in errors),
            "\n".join(errors),
        )

    def test_cli_root_and_lock_paths_fail_closed_before_lock_loading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            missing_root = temporary_root / "missing"
            missing_root_result = subprocess.run(
                [sys.executable, str(CHECKER_PATH), "--root", str(missing_root)],
                check=False,
                capture_output=True,
                encoding="utf-8",
            )
            self.assertEqual(missing_root_result.returncode, 1)
            self.assertIn(
                "--root must resolve to an existing directory",
                missing_root_result.stdout,
            )

            root = temporary_root / "framework"
            root.mkdir()
            lock_directory = root / "not-a-lock-file"
            lock_directory.mkdir()
            lock_directory_result = subprocess.run(
                [
                    sys.executable,
                    str(CHECKER_PATH),
                    "--root",
                    str(root),
                    "--lock",
                    str(lock_directory),
                ],
                check=False,
                capture_output=True,
                encoding="utf-8",
            )
            self.assertEqual(lock_directory_result.returncode, 1)
            self.assertIn(
                "--lock must resolve to a regular file",
                lock_directory_result.stdout,
            )

    def test_tool_lock_schema_and_fetcher_reject_path_escape(self) -> None:
        _actions, tools, errors = CHECKER.load_lock(LOCK_PATH)
        self.assertFalse(errors, "\n".join(errors))
        malformed = dict(tools["actionlint"])
        malformed["asset"] = "../escape.tar.gz"
        schema_errors = CHECKER.record_errors(
            LOCK_PATH, "tool", "actionlint", malformed
        )
        self.assertTrue(
            any("unsafe release asset name" in error for error in schema_errors)
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            lock = Path(temporary_directory) / "lock.yml"
            lock.write_text(
                "tools:\n"
                "  ../escape:\n"
                "    name: ../escape\n"
                "    version: v1\n"
                "    immutable_commit: 0000000000000000000000000000000000000000\n"
                "    upstream_release: https://github.com/example/tool/releases/tag/v1\n"
                "    asset: tool.tar.gz\n"
                "    asset_url: https://github.com/example/tool/releases/download/v1/tool.tar.gz\n"
                "    sha256: 0000000000000000000000000000000000000000000000000000000000000000\n"
                "    archive_type: tar.gz\n"
                "    layout: executable\n"
                "    archive_member: tool\n"
                "    executable: tool\n"
                "    license: MIT\n"
                "    purpose: fixture\n"
                "    platform: fixture\n"
                "    update_procedure: fixture\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                FETCHER.ToolError, "contained within the Framework root"
            ):
                FETCHER.read_tool_record(lock, "../escape")

    def test_unallowlisted_github_token_reference_is_rejected(self) -> None:
        errors = CHECKER.trust_boundary_errors(
            ROOT / "untrusted-token.yml", "token: ${{ github.token }}\n"
        )
        self.assertTrue(any("token reference" in error for error in errors))

    def test_workflow_tool_updater_rejects_secret_or_token_expressions_in_read_jobs(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/update-workflow-tools.yml").read_text(
            encoding="utf-8"
        )
        unsafe = workflow.replace(
            "    steps:\n",
            '    env: { UPDATER_TOKEN: "${{ secrets.UPDATER_TOKEN }}" }\n    steps:\n',
            1,
        )
        errors = CHECKER.workflow_tool_updater_errors(
            ROOT / ".github/workflows/update-workflow-tools.yml",
            unsafe,
            CHECKER.yaml.safe_load(unsafe),
        )
        self.assertTrue(
            any(
                "resolver must not contain secrets or token expressions" in error
                for error in errors
            ),
            "\n".join(errors),
        )

    def test_workflow_tool_updater_semantically_rejects_quoted_inline_write_permissions(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/update-workflow-tools.yml").read_text(
            encoding="utf-8"
        )
        unsafe = workflow.replace(
            "    permissions:\n      contents: read",
            "    permissions: {'contents': 'read', actions: 'write'}",
            1,
        )
        errors = CHECKER.workflow_tool_updater_errors(
            ROOT / ".github/workflows/update-workflow-tools.yml",
            unsafe,
            CHECKER.yaml.safe_load(unsafe),
        )
        self.assertTrue(
            any(
                "resolver must declare exactly {contents: read}" in error
                for error in errors
            ),
            "\n".join(errors),
        )

    def test_workflow_tool_updater_rejects_extra_jobs_and_nonexact_publisher_permissions(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/update-workflow-tools.yml").read_text(
            encoding="utf-8"
        )
        unsafe = workflow.replace(
            "    timeout-minutes: 25\n    permissions:\n      contents: read\n    steps:",
            "    timeout-minutes: 25\n    permissions:\n      contents: read\n"
            "      actions: write\n    steps:",
            1,
        ) + (
            "\n  unexpected_writer:\n"
            "    runs-on: ubuntu-latest\n"
            "    permissions: {contents: write}\n"
            "    steps: []\n"
        )
        errors = CHECKER.workflow_tool_updater_errors(
            ROOT / ".github/workflows/update-workflow-tools.yml",
            unsafe,
            CHECKER.yaml.safe_load(unsafe),
        )
        self.assertTrue(
            any(
                "must define exactly resolver, validator, publisher, and outcome jobs"
                in error
                for error in errors
            ),
            "\n".join(errors),
        )
        self.assertTrue(
            any("publisher must declare exactly" in error for error in errors),
            "\n".join(errors),
        )

    def test_workflow_tool_updater_semantically_enforces_job_ordering(self) -> None:
        workflow = (ROOT / ".github/workflows/update-workflow-tools.yml").read_text(
            encoding="utf-8"
        )
        unsafe = workflow.replace("    needs: resolver", "    needs: [] # resolver", 1)
        errors = CHECKER.workflow_tool_updater_errors(
            ROOT / ".github/workflows/update-workflow-tools.yml",
            unsafe,
            CHECKER.yaml.safe_load(unsafe),
        )
        self.assertTrue(
            any("validator must need exactly resolver" in error for error in errors),
            "\n".join(errors),
        )

    def test_workflow_tool_updater_requires_a_default_branch_publisher_gate(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/update-workflow-tools.yml").read_text(
            encoding="utf-8"
        )
        unsafe = workflow.replace(
            "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
            "github.ref == 'refs/heads/unsafe'",
            1,
        )
        errors = CHECKER.workflow_tool_updater_errors(
            ROOT / ".github/workflows/update-workflow-tools.yml",
            unsafe,
            CHECKER.yaml.safe_load(unsafe),
        )
        self.assertTrue(
            any(
                "publisher must be gated to the default branch and resolver has_updates"
                in error
                for error in errors
            ),
            "\n".join(errors),
        )

    def test_workflow_tool_updater_allows_only_reviewed_schedule_and_dispatch_triggers(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/update-workflow-tools.yml").read_text(
            encoding="utf-8"
        )
        unsafe = workflow.replace(
            "  schedule:\n",
            "  push:\n    branches: [main]\n  schedule:\n",
            1,
        )
        errors = CHECKER.workflow_tool_updater_errors(
            ROOT / ".github/workflows/update-workflow-tools.yml",
            unsafe,
            CHECKER.yaml.safe_load(unsafe),
        )
        self.assertTrue(
            any("updater triggers must be exactly" in error for error in errors),
            "\n".join(errors),
        )

    def test_submodule_updater_uses_the_reviewed_framework_profile(self) -> None:
        workflow = (ROOT / ".github/workflows/update-submodules.yml").read_text(
            encoding="utf-8"
        )
        errors = CHECKER.submodule_updater_errors(
            ROOT / ".github/workflows/update-submodules.yml",
            workflow,
            CHECKER.yaml.safe_load(workflow),
        )
        self.assertEqual(errors, [], "\n".join(errors))

    def test_submodule_updater_rejects_mrts_ref_token_and_force_push_bypasses(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/update-submodules.yml").read_text(
            encoding="utf-8"
        )
        variants = {
            "wrong-mrts-default-branch": workflow.replace(
                "SUBMODULE_REF: refs/heads/main",
                "SUBMODULE_REF: refs/heads/master",
                1,
            ),
            "reader-token": workflow.replace(
                "      - name: Resolve the official MRTS commit",
                "      - name: Resolve the official MRTS commit\n"
                "        env:\n"
                "          GH_TOKEN: ${{ github.token }}",
                1,
            ),
            "force-push": workflow.replace(
                'git push origin "HEAD:refs/heads/$UPDATE_BRANCH"',
                'git push --force-with-lease origin "HEAD:refs/heads/$UPDATE_BRANCH"',
                1,
            ),
            "persisted-validator-credentials": workflow.replace(
                "persist-credentials: false",
                "persist-credentials: true",
                2,
            ),
            "recursive-validator-checkout": workflow.replace(
                "submodules: false",
                "submodules: recursive",
                2,
            ),
        }
        for name, unsafe in variants.items():
            with self.subTest(name=name):
                errors = CHECKER.submodule_updater_errors(
                    ROOT / ".github/workflows/update-submodules.yml",
                    unsafe,
                    CHECKER.yaml.safe_load(unsafe),
                )
                self.assertTrue(errors, "expected reviewed-profile rejection")

    def test_submodule_updater_rejects_extra_publisher_code_and_token_steps(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/update-submodules.yml").read_text(
            encoding="utf-8"
        )
        variants = {
            "extra-run-command": workflow.replace(
                "      - name: Revalidate the official MRTS revision\n"
                "        run: |\n"
                "          set -euo pipefail\n",
                "      - name: Revalidate the official MRTS revision\n"
                "        run: |\n"
                "          set -euo pipefail\n"
                "          git config core.hooksPath /tmp/hooks\n",
                1,
            ),
            "extra-token-step": workflow.replace(
                "      - name: Revalidate the official MRTS revision",
                "      - name: Exfiltrate publisher token\n"
                "        env:\n"
                "          TOKEN: ${{ github.token }}\n"
                "        run: printf '%s' \"$TOKEN\"\n\n"
                "      - name: Revalidate the official MRTS revision",
                1,
            ),
        }
        for name, unsafe in variants.items():
            with self.subTest(name=name):
                errors = CHECKER.submodule_updater_errors(
                    ROOT / ".github/workflows/update-submodules.yml",
                    unsafe,
                    CHECKER.yaml.safe_load(unsafe),
                )
                self.assertTrue(
                    any("exactly match" in error for error in errors),
                    "\n".join(errors),
                )

    def test_workflow_tool_updater_publisher_profile_rejects_pr_aliases_and_comments(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/update-workflow-tools.yml").read_text(
            encoding="utf-8"
        )
        variants = {
            "remove-existing-pr-uniqueness": workflow.replace(
                "pullRequests.length !== 1", "false", 1
            ),
            "duplicate-direct-pr-create": workflow.replace(
                "            await github.rest.pulls.create({",
                "            await github.rest.pulls.create({ owner: context.repo.owner });\n"
                "            await github.rest.pulls.create({",
                1,
            ),
            "bracket-pr-create-alias": workflow.replace(
                "github.rest.pulls.create(", 'github.rest.pulls["create"](', 1
            ),
            "bracket-auto-merge-alias": workflow.replace(
                "            await github.rest.pulls.create({",
                '            await github.rest.pulls["merge"]({ owner: context.repo.owner });\n'
                "            await github.rest.pulls.create({",
                1,
            ),
            "commented-draft": workflow.replace("draft: true,", "# draft: true,", 1),
        }
        for name, unsafe in variants.items():
            with self.subTest(name=name):
                errors = CHECKER.workflow_tool_updater_errors(
                    ROOT / ".github/workflows/update-workflow-tools.yml",
                    unsafe,
                    CHECKER.yaml.safe_load(unsafe),
                )
                self.assertTrue(
                    any("publisher github-script body" in error for error in errors),
                    "\n".join(errors),
                )

    def test_workflow_tool_updater_publisher_profile_rejects_push_and_validation_bypasses(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/update-workflow-tools.yml").read_text(
            encoding="utf-8"
        )
        existing_branch_command = (
            "              python3 ci/tools/update-workflow-tools.py verify-existing-branch --root . \\\n"
            '                --base "origin/$DEFAULT_BRANCH" \\\n'
            '                --head "origin/$UPDATE_BRANCH"\n'
        )
        update_branch = (
            '          UPDATE_BRANCH="automation/update-framework-workflow-tools"'
        )
        first_assignment, commit_assignment = workflow.split(update_branch, 1)
        variants = {
            "commented-existing-branch-proof": workflow.replace(
                existing_branch_command,
                "              # verify-existing-branch --root .\n",
                1,
            ),
            "commented-tool-asset-verification": workflow.replace(
                "--verify-tool-assets",
                "--no-verify-tool-assets",
            ),
            "command-prefixed-force-push": workflow.replace(
                '          git push origin "HEAD:refs/heads/$UPDATE_BRANCH"',
                '          command git push --force origin "HEAD:refs/heads/$UPDATE_BRANCH"',
                1,
            ),
            "env-prefixed-force-push": workflow.replace(
                '          git push origin "HEAD:refs/heads/$UPDATE_BRANCH"',
                "          env X=1 git push -f origin +HEAD:refs/heads/$UPDATE_BRANCH",
                1,
            ),
            "git-config-default-branch-push": workflow.replace(
                '          git push origin "HEAD:refs/heads/$UPDATE_BRANCH"',
                "          git -c protocol.version=2 push origin "
                '"HEAD:refs/heads/${{ github.event.repository.default_branch }}"',
                1,
            ),
            "commit-default-branch-reassignment": first_assignment
            + update_branch
            + commit_assignment.replace(
                update_branch,
                '          UPDATE_BRANCH="${{ github.event.repository.default_branch }}"',
                1,
            ),
            "fresh-branch-starts-from-stale-checkout-head": workflow.replace(
                '              git switch --create "$UPDATE_BRANCH" "origin/$DEFAULT_BRANCH"',
                '              git switch --create "$UPDATE_BRANCH"',
                1,
            ),
            "publisher-environment-injection": workflow.replace(
                "          PUBLISH_TOKEN: ${{ steps.publisher_app_token.outputs.token }}\n        run: |",
                "          PUBLISH_TOKEN: ${{ steps.publisher_app_token.outputs.token }}\n"
                "          BASH_ENV: /tmp/untrusted\n        run: |",
                1,
            ),
        }
        for name, unsafe in variants.items():
            with self.subTest(name=name):
                errors = CHECKER.workflow_tool_updater_errors(
                    ROOT / ".github/workflows/update-workflow-tools.yml",
                    unsafe,
                    CHECKER.yaml.safe_load(unsafe),
                )
                self.assertTrue(
                    any(
                        "publisher" in error and "reviewed" in error for error in errors
                    ),
                    "\n".join(errors),
                )

    def test_workflow_tool_updater_publisher_uses_only_the_reviewed_app_token(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/update-workflow-tools.yml").read_text(
            encoding="utf-8"
        )
        variants = {
            "legacy-github-script-token": workflow.replace(
                "github-token: ${{ steps.publisher_app_token.outputs.token }}",
                "github-token: ${{ github.token }}",
                1,
            ),
            "legacy-git-publish-token": workflow.replace(
                "PUBLISH_TOKEN: ${{ steps.publisher_app_token.outputs.token }}",
                "PUBLISH_TOKEN: ${{ github.token }}",
                1,
            ),
            "unreviewed-app-permission": workflow.replace(
                "          permission-workflows: write",
                "          permission-workflows: read",
                1,
            ),
            "unreviewed-app-repository-scope": workflow.replace(
                "          repositories: ${{ github.repository }}",
                "          repositories: another-repository",
                1,
            ),
        }
        for name, unsafe in variants.items():
            with self.subTest(name=name):
                errors = CHECKER.workflow_tool_updater_errors(
                    ROOT / ".github/workflows/update-workflow-tools.yml",
                    unsafe,
                    CHECKER.yaml.safe_load(unsafe),
                )
                self.assertTrue(
                    any(
                        "reviewed" in error or "GitHub App token" in error
                        for error in errors
                    ),
                    "\n".join(errors),
                )

    def test_workflow_tool_updater_rejects_identity_binding_and_outcome_regressions(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/update-workflow-tools.yml").read_text(
            encoding="utf-8"
        )
        variants = {
            "missing-resolver-digest": workflow.replace(
                "      candidate_sha256: ${{ steps.resolve.outputs.candidate_sha256 }}\n",
                "",
                1,
            ),
            "validator-without-resolver-digest": workflow.replace(
                "--expected-candidate-sha256",
                "--resolver-candidate-sha256",
                2,
            ),
            "publisher-without-required-update": workflow.replace(
                "            --require-updates --verify-tool-assets \\\n",
                "            --verify-tool-assets \\\n",
                1,
            ),
            "masked-app-configuration-failure": workflow.replace(
                'if [ -z "$WORKFLOW_UPDATER_APP_CLIENT_ID" ]; then',
                "if false; then",
                1,
            ),
            "missing-app-preflight": workflow.replace(
                "Verify workflow publisher GitHub App configuration",
                "Bypass workflow publisher GitHub App configuration",
                1,
            ),
            "credential-cleanup-mask": workflow.replace(
                "trap 'git config --local --unset-all credential.helper' EXIT",
                "trap 'git config --local --unset-all credential.helper || true' EXIT",
                1,
            ),
            "outcome-not-always": workflow.replace(
                "if: ${{ always() }}", "if: ${{ success() }}", 1
            ),
            "outcome-write-permission": workflow.replace(
                "    permissions: {}\n    env:\n      RESOLVER_RESULT:",
                "    permissions:\n      contents: write\n    env:\n      RESOLVER_RESULT:",
                1,
            ),
            "outcome-token-exposure": workflow.replace(
                "    env:\n      RESOLVER_RESULT:",
                "    env:\n      UNSAFE_TOKEN: ${{ secrets.UNSAFE_TOKEN }}\n"
                "      RESOLVER_RESULT:",
                1,
            ),
        }
        for name, unsafe in variants.items():
            with self.subTest(name=name):
                errors = CHECKER.workflow_tool_updater_errors(
                    ROOT / ".github/workflows/update-workflow-tools.yml",
                    unsafe,
                    CHECKER.yaml.safe_load(unsafe),
                )
                self.assertTrue(errors, "expected fail-closed updater rejection")

    def test_python_version_publisher_rejects_app_token_scope_and_outcome_regressions(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/check-python-version.yml").read_text(
            encoding="utf-8"
        )
        variants = {
            "workflow-level-reader-permission": workflow.replace(
                "permissions: {}\n\nconcurrency:",
                "permissions:\n  contents: read\n\nconcurrency:",
                1,
            ),
            "missing-reader-job-permission": workflow.replace(
                "  resolve:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n"
                "    permissions:\n      contents: read\n",
                "  resolve:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n",
                1,
            ),
            "native-token-fallback": workflow.replace(
                "token: ${{ steps.publisher_app_token.outputs.token }}",
                "token: ${{ github.token }}",
                1,
            ),
            "broadened-app-scope": workflow.replace(
                "          permission-pull-requests: write\n",
                "          permission-pull-requests: write\n"
                "          permission-workflows: write\n",
                1,
            ),
            "missing-app-preflight": workflow.replace(
                "Verify CPython publisher GitHub App configuration",
                "Bypass CPython publisher GitHub App configuration",
                1,
            ),
            "unconstrained-branch": workflow.replace(
                'UPDATE_BRANCH="automation/update-framework-python-314"',
                'UPDATE_BRANCH="master"',
                1,
            ),
            "missing-draft-marker": workflow.replace(
                "<!-- framework-python-314-updater -->",
                "<!-- unsafe-python-updater -->",
                1,
            ),
            "expanded-publish-path": workflow.replace(
                "            .python-version\n",
                "            .python-version\n            .github/workflows/check-python-version.yml\n",
                1,
            ),
            "outcome-not-always": workflow.replace(
                "if: ${{ always() }}", "if: ${{ success() }}", 1
            ),
            "outcome-write-permission": workflow.replace(
                "    permissions: {}\n    env:\n      RESOLVER_RESULT:",
                "    permissions:\n      contents: write\n    env:\n      RESOLVER_RESULT:",
                1,
            ),
            "publisher-error-reported-green": workflow.replace(
                '                echo "::error::CPython update was not fully validated and published" >&2\n'
                "                exit 1\n",
                '                echo "::error::CPython update was not fully validated and published" >&2\n'
                "                exit 0\n",
                1,
            ),
        }
        for name, unsafe in variants.items():
            with self.subTest(name=name):
                errors = CHECKER.workflow_contract_errors(
                    ROOT / ".github/workflows/check-python-version.yml",
                    unsafe,
                    CHECKER.yaml.safe_load(unsafe),
                )
                self.assertTrue(errors, "expected fail-closed CPython rejection")

    def test_common_version_publisher_rejects_privilege_and_scope_regressions(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/check-common-versions.yml").read_text(
            encoding="utf-8"
        )

        def replace_last(text: str, old: str, new: str) -> str:
            prefix, separator, suffix = text.rpartition(old)
            self.assertTrue(separator, old)
            return prefix + new + suffix

        variants = {
            "reader-write-permission": workflow.replace(
                "  resolve:\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n"
                "    permissions:\n      contents: read",
                "  resolve:\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n"
                "    permissions:\n      contents: write",
                1,
            ),
            "reader-token-exposure": workflow.replace(
                "      - name: Resolve an ephemeral common.sh candidate\n        id: resolve\n",
                "      - name: Resolve an ephemeral common.sh candidate\n"
                "        env:\n"
                "          GITHUB_TOKEN: ${{ github.token }}\n"
                "        id: resolve\n",
                1,
            ),
            "stale-default-checkout": workflow.replace(
                "          ref: ${{ github.event.repository.default_branch }}",
                "          ref: main",
                1,
            ),
            "native-github-token-publisher": workflow.replace(
                "          token: ${{ steps.publisher_app_token.outputs.token }}",
                "          token: ${{ github.token }}",
                1,
            ),
            "native-secret-github-token-publisher": workflow.replace(
                "          token: ${{ steps.publisher_app_token.outputs.token }}",
                "          token: ${{ secrets.GITHUB_TOKEN }}",
                1,
            ),
            "missing-app-token-action": workflow.replace(
                "uses: actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
                "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                1,
            ),
            "wrong-app-client-id-variable": workflow.replace(
                "client-id: ${{ vars.WORKFLOW_UPDATER_APP_CLIENT_ID }}",
                "client-id: ${{ vars.UNSAFE_APP_CLIENT_ID }}",
                1,
            ),
            "wrong-app-private-key-secret": workflow.replace(
                "private-key: ${{ secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY }}",
                "private-key: ${{ secrets.UNSAFE_APP_PRIVATE_KEY }}",
                1,
            ),
            "app-configuration-uses-secret-directly-in-if": workflow.replace(
                "env.WORKFLOW_UPDATER_APP_PRIVATE_KEY_CONFIGURED != 'true'",
                "secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY == ''",
                1,
            ),
            "app-configuration-flag-is-forged": workflow.replace(
                "${{ secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY != '' }}",
                "true",
                1,
            ),
            "wrong-app-owner-scope": workflow.replace(
                "owner: ${{ github.repository_owner }}",
                "owner: another-owner",
                1,
            ),
            "broad-app-repository-scope": workflow.replace(
                "repositories: ${{ github.repository }}",
                'repositories: "*"',
                1,
            ),
            "foreign-app-repository-scope": workflow.replace(
                "repositories: ${{ github.repository }}",
                "repositories: another-repository",
                1,
            ),
            "app-token-workflows-write": workflow.replace(
                "          permission-pull-requests: write\n",
                "          permission-pull-requests: write\n"
                "          permission-workflows: write\n",
                1,
            ),
            "app-token-missing-contents-write": workflow.replace(
                "          permission-contents: write\n",
                "",
                1,
            ),
            "app-token-missing-pull-requests-write": workflow.replace(
                "          permission-pull-requests: write\n",
                "",
                1,
            ),
            "maintenance-branch-changed": workflow.replace(
                "          branch: automation/update-framework-common-versions",
                "          branch: automation/unreviewed-common-versions",
                1,
            ),
            "pull-request-not-draft": workflow.replace(
                "          draft: true",
                "          draft: false",
                1,
            ),
            "maintenance-marker-removed": workflow.replace(
                "<!-- framework-common-version-updater -->",
                "<!-- removed -->",
            ),
            "publisher-path-expansion": workflow.replace(
                "          add-paths: |\n            ci/lib/common.sh\n",
                "          add-paths: |\n            ci/lib/common.sh\n"
                "            .github/workflows/check-common-versions.yml\n",
                1,
            ),
            "broad-git-add-dot": workflow.replace(
                "          git diff --check\n",
                "          git diff --check\n          git add .\n",
                1,
            ),
            "broad-git-add-all": workflow.replace(
                "          git diff --check\n",
                "          git diff --check\n          git add -A\n",
                1,
            ),
            "direct-default-branch-push": workflow.replace(
                "          git diff --check\n",
                "          git diff --check\n"
                '          git push origin "HEAD:refs/heads/${{ github.event.repository.default_branch }}"\n',
                1,
            ),
            "force-push": workflow.replace(
                "          git diff --check\n",
                "          git diff --check\n"
                "          git push --force origin HEAD:refs/heads/automation/update-framework-common-versions\n",
                1,
            ),
            "missing-publisher-candidate-sha-comparison": replace_last(
                workflow,
                '          test "$candidate_sha256" = "$CANDIDATE_SHA256"\n',
                "",
            ),
            "missing-candidate-validator-candidate-sha-comparison": workflow.replace(
                '          if hashlib.sha256(candidate).hexdigest() != os.environ["CANDIDATE_SHA256"]:\n'
                '              raise SystemExit("candidate validator candidate SHA-256 mismatch")\n',
                "",
                1,
            ),
            "short-publisher-candidate-sha": replace_last(
                workflow,
                '          test "${#candidate_sha256}" -eq 64\n',
                "",
            ),
            "candidate-from-resolver-artifact": workflow.replace(
                "          python3 ci/tools/check-common-versions.py --common-sh ci/lib/common.sh \\\n",
                '          cp "$RUNNER_TEMP/resolver-common.sh" ci/lib/common.sh\n',
                1,
            ),
            "resolver-omits-explicit-reviewed-provenance-mode": workflow.replace(
                "--update --defer-reviewed-provenance --json",
                "--update --json",
                1,
            ),
            "resolver-manual-review-output-is-removed": workflow.replace(
                "      manual_review_required: ${{ steps.resolve.outputs.manual_review_required }}\n",
                "",
                1,
            ),
            "candidate-manual-pin-proof-is-unbound": workflow.replace(
                "      MANUAL_REVIEW_PINS_SHA256: ${{ needs.resolve.outputs.manual_review_pins_sha256 }}\n",
                "",
                1,
            ),
            "publisher-untrusted-branch": workflow.replace(
                "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
                "github.ref == 'refs/heads/untrusted'",
                1,
            ),
            "publisher-runs-without-update": replace_last(
                workflow,
                "needs.resolve.outputs.update_available == 'true'",
                "needs.resolve.outputs.update_available == 'false'",
            ),
            "unsafe-existing-pr-is-accepted": workflow.replace(
                "              pull.title !== title ||\n",
                "              false ||\n",
                1,
            ),
            "matching-pr-head-sha-is-not-verified": workflow.replace(
                "              pull.head?.sha !== branchSha ||\n",
                "",
                1,
            ),
            "matching-pr-base-repository-is-not-verified": workflow.replace(
                "              pull.base?.repo?.full_name !== repositoryName ||\n",
                "",
                1,
            ),
            "fork-branch-collision-is-counted": workflow.replace(
                "            const matchingPulls = openPulls.filter(\n"
                "              (pull) =>\n"
                "                pull.head?.repo?.full_name === repositoryName &&\n"
                "                pull.head?.ref === branch,\n"
                "            );\n",
                "            const matchingPulls = openPulls.filter((pull) => pull.head?.ref === branch);\n",
                1,
            ),
            "trusted-base-sha-is-template-interpolated": workflow.replace(
                "process.env.TRUSTED_BASE_SHA",
                '"${{ steps.candidate_revalidation.outputs.trusted_base_sha }}"',
                1,
            ),
            "app-token-passed-to-unreviewed-step": workflow.replace(
                "      - name: Create or update Draft pull request",
                "      - name: Unreviewed App-token consumer\n"
                "        run: echo '${{ steps.publisher_app_token.outputs.token }}'\n\n"
                "      - name: Create or update Draft pull request",
                1,
            ),
            "publisher-draft-output-removed": workflow.replace(
                "      draft_pull_request_url: ${{ steps.draft_pull_request.outputs.pull-request-url }}\n",
                "",
                1,
            ),
            "result-does-not-always-run": workflow.replace(
                "    if: ${{ always() }}\n",
                "    if: ${{ success() }}\n",
                1,
            ),
            "result-write-permission": workflow.replace(
                "    timeout-minutes: 5\n    permissions:\n      contents: read\n",
                "    timeout-minutes: 5\n    permissions:\n      contents: write\n",
                1,
            ),
            "result-token-exposure": workflow.replace(
                "      UPDATE_AVAILABLE: ${{ needs.resolve.outputs.update_available }}\n",
                "      UPDATE_AVAILABLE: ${{ needs.resolve.outputs.update_available }}\n"
                "      GITHUB_TOKEN: ${{ github.token }}\n",
                1,
            ),
            "result-accepts-empty-resolver-output": workflow.replace(
                "            no_updates:false:false)\n",
                "            ''|no_updates:false:false)\n",
                1,
            ),
            "result-accepts-unknown-resolver-output": workflow.replace(
                "            no_updates:false:false)\n",
                "            unknown|no_updates:false:false)\n",
                1,
            ),
            "result-masks-manual-review-only": workflow.replace(
                "            manual_review_only:false:true)\n",
                "            no_updates:false:false)\n",
                1,
            ),
            "result-runs-validator-for-no-update": workflow.replace(
                'test "$VALIDATOR_RESULT" = "skipped"',
                'test "$VALIDATOR_RESULT" = "success"',
                1,
            ),
            "result-runs-publisher-for-no-update": workflow.replace(
                'test "$PUBLISHER_RESULT" = "skipped"',
                'test "$PUBLISHER_RESULT" = "success"',
                1,
            ),
            "result-masks-publisher-failure": workflow.replace(
                'test "$PUBLISHER_RESULT" = "success"',
                'test "$PUBLISHER_RESULT" = "skipped"',
                1,
            ),
        }
        for name, unsafe in variants.items():
            with self.subTest(name=name):
                self.assertNotEqual(workflow, unsafe)
                errors = CHECKER.workflow_contract_errors(
                    ROOT / ".github/workflows/check-common-versions.yml",
                    unsafe,
                    CHECKER.yaml.safe_load(unsafe),
                )
                self.assertTrue(
                    errors,
                    "\n".join(errors),
                )

    def test_common_version_result_job_reports_safe_terminal_states(self) -> None:
        workflow_path = ROOT / ".github/workflows/check-common-versions.yml"
        workflow = CHECKER.yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        result_run = workflow["jobs"]["result"]["steps"][0]["run"]

        terminal_defaults = {
            "MAINTENANCE_OUTCOME": "fatal",
            "UPDATE_AVAILABLE": "",
            "CANDIDATE_SHA256": "",
            "MANUAL_REVIEW_REQUIRED": "",
            "MANUAL_REVIEW_COMPONENTS_B64": "",
            "MANUAL_REVIEW_PINS_SHA256": "",
            "RESOLVER_RESULT": "failure",
            "VALIDATOR_RESULT": "skipped",
            "PUBLISHER_RESULT": "skipped",
            "DRAFT_PULL_REQUEST_NUMBER": "",
            "DRAFT_PULL_REQUEST_URL": "",
        }
        manual_components_b64 = "WyJNb2RTZWN1cml0eSB2MyJd"
        cases = (
            (
                "no-update",
                {
                    **terminal_defaults,
                    "RESOLVER_RESULT": "success",
                    "MAINTENANCE_OUTCOME": "no_updates",
                    "UPDATE_AVAILABLE": "false",
                    "MANUAL_REVIEW_REQUIRED": "false",
                    "MANUAL_REVIEW_COMPONENTS_B64": "W10=",
                    "VALIDATOR_RESULT": "skipped",
                    "PUBLISHER_RESULT": "skipped",
                },
                0,
                (
                    "No reviewed common.sh version updates are currently available.",
                    "Derzeit sind keine geprüften common.sh-Versionsaktualisierungen verfügbar.",
                    "Es wurde kein Branch, Commit oder Pull Request erstellt oder verändert.",
                ),
            ),
            (
                "manual-review-only",
                {
                    **terminal_defaults,
                    "RESOLVER_RESULT": "success",
                    "MAINTENANCE_OUTCOME": "manual_review_only",
                    "UPDATE_AVAILABLE": "false",
                    "MANUAL_REVIEW_REQUIRED": "true",
                    "MANUAL_REVIEW_COMPONENTS_B64": manual_components_b64,
                    "MANUAL_REVIEW_PINS_SHA256": "a" * 64,
                },
                0,
                (
                    "A reviewed manual common.sh provenance decision is required.",
                    "Eine geprüfte manuelle common.sh-Provenance-Entscheidung ist erforderlich.",
                    "No automatic candidate, branch, commit, or pull request was created or modified.",
                ),
            ),
            (
                "published-update-with-url",
                {
                    **terminal_defaults,
                    "RESOLVER_RESULT": "success",
                    "MAINTENANCE_OUTCOME": "safe_updates",
                    "UPDATE_AVAILABLE": "true",
                    "CANDIDATE_SHA256": "a" * 64,
                    "MANUAL_REVIEW_REQUIRED": "false",
                    "MANUAL_REVIEW_COMPONENTS_B64": "W10=",
                    "VALIDATOR_RESULT": "success",
                    "PUBLISHER_RESULT": "success",
                    "DRAFT_PULL_REQUEST_NUMBER": "42",
                    "DRAFT_PULL_REQUEST_URL": "https://example.test/owner/repo/pull/42",
                },
                0,
                (
                    "A reviewed common.sh version update was validated and published",
                    "Draft pull request: https://example.test/owner/repo/pull/42",
                    "Draft-Pull-Request: https://example.test/owner/repo/pull/42",
                ),
            ),
            (
                "published-update-with-manual-review",
                {
                    **terminal_defaults,
                    "RESOLVER_RESULT": "success",
                    "MAINTENANCE_OUTCOME": "safe_updates_with_manual_review",
                    "UPDATE_AVAILABLE": "true",
                    "CANDIDATE_SHA256": "b" * 64,
                    "MANUAL_REVIEW_REQUIRED": "true",
                    "MANUAL_REVIEW_COMPONENTS_B64": manual_components_b64,
                    "MANUAL_REVIEW_PINS_SHA256": "c" * 64,
                    "VALIDATOR_RESULT": "success",
                    "PUBLISHER_RESULT": "success",
                },
                0,
                (
                    "A separate manual provenance review remains required",
                    "Eine getrennte manuelle Provenance-Prüfung bleibt erforderlich",
                    "Draft pull request: created or updated; the action did not report a URL or number.",
                    "Draft-Pull-Request: erstellt oder aktualisiert; die Action hat keine URL oder Nummer gemeldet.",
                ),
            ),
            (
                "published-update-without-action-output",
                {
                    **terminal_defaults,
                    "RESOLVER_RESULT": "success",
                    "MAINTENANCE_OUTCOME": "safe_updates",
                    "UPDATE_AVAILABLE": "true",
                    "CANDIDATE_SHA256": "a" * 64,
                    "MANUAL_REVIEW_REQUIRED": "false",
                    "MANUAL_REVIEW_COMPONENTS_B64": "W10=",
                    "VALIDATOR_RESULT": "success",
                    "PUBLISHER_RESULT": "success",
                },
                0,
                (
                    "Draft pull request: created or updated; the action did not report a URL or number.",
                    "Draft-Pull-Request: erstellt oder aktualisiert; die Action hat keine URL oder Nummer gemeldet.",
                ),
            ),
            (
                "unknown-maintenance-outcome",
                {
                    **terminal_defaults,
                    "RESOLVER_RESULT": "success",
                    "MAINTENANCE_OUTCOME": "unknown",
                    "UPDATE_AVAILABLE": "unknown",
                },
                1,
                (),
            ),
            (
                "no-update-with-executed-publisher",
                {
                    **terminal_defaults,
                    "RESOLVER_RESULT": "success",
                    "MAINTENANCE_OUTCOME": "no_updates",
                    "UPDATE_AVAILABLE": "false",
                    "MANUAL_REVIEW_REQUIRED": "false",
                    "MANUAL_REVIEW_COMPONENTS_B64": "W10=",
                    "VALIDATOR_RESULT": "skipped",
                    "PUBLISHER_RESULT": "success",
                },
                1,
                (),
            ),
            (
                "available-update-with-failed-validator",
                {
                    **terminal_defaults,
                    "RESOLVER_RESULT": "success",
                    "MAINTENANCE_OUTCOME": "safe_updates",
                    "UPDATE_AVAILABLE": "true",
                    "CANDIDATE_SHA256": "a" * 64,
                    "MANUAL_REVIEW_REQUIRED": "false",
                    "MANUAL_REVIEW_COMPONENTS_B64": "W10=",
                    "VALIDATOR_RESULT": "failure",
                    "PUBLISHER_RESULT": "skipped",
                },
                1,
                (),
            ),
            (
                "manual-outcome-with-false-review-flag",
                {
                    **terminal_defaults,
                    "RESOLVER_RESULT": "success",
                    "MAINTENANCE_OUTCOME": "manual_review_only",
                    "UPDATE_AVAILABLE": "false",
                    "MANUAL_REVIEW_REQUIRED": "false",
                    "MANUAL_REVIEW_COMPONENTS_B64": manual_components_b64,
                    "MANUAL_REVIEW_PINS_SHA256": "a" * 64,
                },
                1,
                (),
            ),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            summary_path = Path(temporary_directory) / "github-step-summary.md"
            for name, values, expected_return_code, expected_fragments in cases:
                with self.subTest(name=name):
                    summary_path.unlink(missing_ok=True)
                    result = subprocess.run(
                        ["bash", "-c", result_run],
                        check=False,
                        capture_output=True,
                        encoding="utf-8",
                        env={
                            **os.environ,
                            **values,
                            "GITHUB_STEP_SUMMARY": str(summary_path),
                        },
                    )
                    self.assertEqual(
                        result.returncode,
                        expected_return_code,
                        result.stdout + result.stderr,
                    )
                    summary = (
                        summary_path.read_text(encoding="utf-8")
                        if expected_return_code == 0
                        else ""
                    )
                    for fragment in expected_fragments:
                        self.assertIn(fragment, summary)

    def test_static_lock_provenance_binds_release_asset_and_version_tuples(
        self,
    ) -> None:
        actions, tools, errors = CHECKER.load_lock(LOCK_PATH)
        self.assertFalse(errors, "\n".join(errors))

        mismatched_action = dict(actions["actions/checkout"])
        mismatched_action["upstream_release"] = (
            "https://github.com/example/checkout/releases/tag/v7.0.1"
        )
        action_errors = CHECKER.record_errors(
            LOCK_PATH, "action", "actions/checkout", mismatched_action
        )
        self.assertTrue(
            any("owner/repository must match" in error for error in action_errors),
            "\n".join(action_errors),
        )

        mismatched_tool = dict(tools["actionlint"])
        mismatched_tool["asset_url"] = (
            "https://github.com/example/actionlint/releases/download/"
            "v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz"
        )
        tool_errors = CHECKER.record_errors(
            LOCK_PATH, "tool", "actionlint", mismatched_tool
        )
        self.assertTrue(
            any("owner/repository/tag must match" in error for error in tool_errors),
            "\n".join(tool_errors),
        )

        unsafe_codeql = dict(actions["github/codeql-action"])
        unsafe_codeql["release_resolution"] = "latest-release"
        codeql_errors = CHECKER.record_errors(
            LOCK_PATH, "action", "github/codeql-action", unsafe_codeql
        )
        self.assertTrue(
            any("same-major-release" in error for error in codeql_errors),
            "\n".join(codeql_errors),
        )

        non_ascii_codeql = dict(actions["github/codeql-action"])
        non_ascii_codeql["version"] = "v٤.37.1"
        non_ascii_errors = CHECKER.common_record_errors(
            LOCK_PATH, "action", "github/codeql-action", non_ascii_codeql
        )
        self.assertTrue(
            any("v<major>.<minor>.<patch>" in error for error in non_ascii_errors),
            "\n".join(non_ascii_errors),
        )

    def test_crs_version_pinning_uses_a_safe_runtime_temp_file(self) -> None:
        script = (ROOT / "ci/checks/catalog/check-crs-version-pinning.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('assert_safe_runtime_path "$TMP_ROOT"', script)
        self.assertIn('mktemp "$TMP_ROOT/crs-version-pinning.XXXXXX"', script)
        self.assertIn('mktemp "$TMP_ROOT/crs-version-pinning-paths.XXXXXX"', script)
        self.assertIn("find ci -type f -name '*.sh' -print0", script)
        self.assertIn('xargs -0 -r -n 1 sh "$SCRIPT_PATH" --check-path', script)
        self.assertNotIn("crs-version-pinning.$$", script)

    def test_archive_member_validation_rejects_path_escape(self) -> None:
        self.assertTrue(FETCHER.is_safe_archive_member("package/index.js"))
        self.assertTrue(FETCHER.is_safe_path_component("actionlint"))
        self.assertFalse(FETCHER.is_safe_path_component("package/actionlint"))
        self.assertFalse(FETCHER.is_safe_archive_member("../escape"))
        self.assertFalse(FETCHER.is_safe_archive_member("/absolute"))


if __name__ == "__main__":
    unittest.main()
