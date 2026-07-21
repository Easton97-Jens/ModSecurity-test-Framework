from __future__ import annotations

import importlib.util
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
            "      pull-requests: write",
            "      pull-requests: write\n      issues: read",
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
                "must define exactly resolver, validator, and publisher jobs" in error
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
            '                --base "origin/${{ github.event.repository.default_branch }}" \\\n'
            '                --head "origin/$UPDATE_BRANCH"\n'
        )
        publisher_validation = (
            '          python3 ci/tools/update-workflow-tools.py validate --root . --candidate "$CANDIDATE" \\\n'
            "            --verify-tool-assets \\\n"
            '            --output-dir "$RUNNER_TEMP/framework-workflow-tool-publisher-validation"\n'
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
                publisher_validation,
                '          python3 ci/tools/update-workflow-tools.py validate --root . --candidate "$CANDIDATE" \\\n'
                "            # --verify-tool-assets\n"
                '            --output-dir "$RUNNER_TEMP/framework-workflow-tool-publisher-validation"\n',
                1,
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
                "          PUBLISH_TOKEN: ${{ github.token }}\n        run: |",
                "          PUBLISH_TOKEN: ${{ github.token }}\n"
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

    def test_common_version_checker_rejects_delivery_and_stale_base_regressions(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/check-common-versions.yml").read_text(
            encoding="utf-8"
        )
        variants = {
            "write-permission": workflow.replace(
                "    permissions:\n      contents: read\n    steps:",
                "    permissions:\n      contents: write\n    steps:",
                1,
            ),
            "token-exposure": workflow.replace(
                "      - name: Validate an ephemeral common.sh candidate\n        run: |",
                "      - name: Validate an ephemeral common.sh candidate\n"
                "        env:\n          GITHUB_TOKEN: ${{ github.token }}\n        run: |",
                1,
            ),
            "stale-default-checkout": workflow.replace(
                "          ref: ${{ github.event.repository.default_branch }}",
                "          ref: main",
                1,
            ),
            "direct-push": workflow.replace(
                "      - name: Syntax and ShellCheck",
                "      - name: Publish candidate\n"
                "        run: git push origin HEAD\n\n"
                "      - name: Syntax and ShellCheck",
                1,
            ),
            "third-party-pr-action": workflow.replace(
                "      - name: Syntax and ShellCheck",
                "      - name: Create pull request\n"
                "        uses: peter-evans/create-pull-request@5f6978faf089d4d20b00c7766989d076bb2fc7f1\n\n"
                "      - name: Syntax and ShellCheck",
                1,
            ),
            "source-checkout-write": workflow.replace(
                '          cp ci/lib/common.sh "$BUILD_ROOT/common.sh"\n',
                "",
                1,
            ),
        }
        for name, unsafe in variants.items():
            with self.subTest(name=name):
                errors = CHECKER.workflow_contract_errors(
                    ROOT / ".github/workflows/check-common-versions.yml",
                    unsafe,
                    CHECKER.yaml.safe_load(unsafe),
                )
                self.assertTrue(
                    any(
                        "common-version" in error or "write" in error
                        for error in errors
                    ),
                    "\n".join(errors),
                )

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
