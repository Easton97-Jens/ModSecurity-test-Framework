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

    def test_shared_ci_dependency_installer_is_hash_bound_and_required(self) -> None:
        self.assertEqual(CHECKER.ci_dependency_installer_errors(ROOT), [])

        workflow_path = ROOT / ".github/workflows/ci-security-quality.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        unsafe = workflow.replace(
            "run: bash ci/tools/install-hash-locked-ci-dependencies.sh",
            "run: true",
            1,
        )
        self.assertNotEqual(unsafe, workflow)
        errors = CHECKER.workflow_contract_errors(
            workflow_path, unsafe, CHECKER.yaml.safe_load(unsafe)
        )
        self.assertTrue(
            any("must invoke only the reviewed helper" in error for error in errors),
            "\n".join(errors),
        )

        osv_path = ROOT / ".github/workflows/ci-security-osv.yml"
        osv = osv_path.read_text(encoding="utf-8")
        trusted_base_bootstrap = """run: |
          set -euo pipefail
          python3 -m pip install --disable-pip-version-check --no-input --only-binary=:all: \\
            --require-hashes -r requirements-ci.lock
          python3 -m pip check"""
        unsafe_osv = osv.replace(
            trusted_base_bootstrap,
            f"run: {CHECKER.CI_DEPENDENCY_INSTALLER_COMMAND}",
            1,
        )
        self.assertNotEqual(unsafe_osv, osv)
        errors = CHECKER.osv_scanner_evidence_errors(
            osv_path, unsafe_osv, CHECKER.yaml.safe_load(unsafe_osv)
        )
        self.assertTrue(
            any("trusted-base job must retain" in error for error in errors),
            "\n".join(errors),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            installer = root / CHECKER.CI_DEPENDENCY_INSTALLER
            installer.parent.mkdir(parents=True)
            installer.write_text("#!/usr/bin/env bash\necho unsafe\n", encoding="utf-8")
            errors = CHECKER.ci_dependency_installer_errors(root)
        self.assertTrue(
            any("approved SHA-256" in error for error in errors), "\n".join(errors)
        )

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
            ROOT / ".github/workflows/check-common-versions.yml"
        )
        self.assertEqual(
            CHECKER.parsed_action_lock_errors(
                ROOT / ".github/workflows/check-common-versions.yml",
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

    def test_consolidated_workflow_rejects_reader_token_permission_trigger_and_topology_bypasses(
        self,
    ) -> None:
        workflow_path = ROOT / ".github/workflows/check-common-versions.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        variants = {
            "reader-secret": workflow.replace(
                "      - name: Snapshot trusted workflow-tool validation inputs\n",
                "      - name: Snapshot trusted workflow-tool validation inputs\n"
                "        env:\n"
                "          UNSAFE_TOKEN: ${{ secrets.UNSAFE_TOKEN }}\n",
                1,
            ),
            "reader-write-permission": workflow.replace(
                "  candidate:\n    needs: canonical-maintenance\n",
                "  candidate:\n    needs: canonical-maintenance\n",
                1,
            ).replace(
                "    permissions:\n      contents: read\n    outputs:\n      validated:",
                "    permissions:\n      contents: write\n    outputs:\n      validated:",
                1,
            ),
            "unexpected-writer": workflow
            + (
                "\n  unexpected_writer:\n"
                "    runs-on: ubuntu-latest\n"
                "    permissions: {contents: write}\n"
                "    steps: []\n"
            ),
            "unsafe-publisher-gate": workflow.replace(
                "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
                "github.ref == 'refs/heads/unsafe'",
                1,
            ),
            "unsafe-trigger": workflow.replace(
                "  schedule:\n",
                "  push:\n    branches: [master]\n  schedule:\n",
                1,
            ),
        }
        for name, unsafe in variants.items():
            with self.subTest(name=name):
                self.assertNotEqual(unsafe, workflow)
                errors = CHECKER.workflow_contract_errors(
                    workflow_path, unsafe, CHECKER.yaml.safe_load(unsafe)
                )
                self.assertTrue(errors, "\n".join(errors))

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

    def test_submodule_updater_rejects_fork_head_pr_identity_bypasses(self) -> None:
        workflow_path = ROOT / ".github/workflows/update-submodules.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        variants = {
            "omits-head-repository-fields": workflow.replace(
                "headRefName,headRepository,headRepositoryOwner",
                "headRefName",
                1,
            ),
            "accepts-any-head-repository": workflow.replace(
                '(.headRepositoryOwner.login // "") + "/" + (.headRepository.name // "") == $repository',
                "true",
                1,
            ),
            "omits-head-branch-check": workflow.replace(
                ".headRefName == $branch and\n",
                "",
                1,
            ),
        }
        for name, unsafe in variants.items():
            with self.subTest(name=name):
                errors = CHECKER.submodule_updater_errors(
                    workflow_path, unsafe, CHECKER.yaml.safe_load(unsafe)
                )
                self.assertTrue(
                    any(
                        "first-party head repository and branch" in error
                        for error in errors
                    ),
                    "\n".join(errors),
                )

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

    def test_consolidated_workflow_rejects_candidate_binding_and_publisher_bypasses(
        self,
    ) -> None:
        workflow_path = ROOT / ".github/workflows/check-common-versions.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        variants = {
            "missing-publisher-candidate-binding": workflow.replace(
                '--expected-candidate-sha256 "$WORKFLOW_TOOL_CANDIDATE_SHA256" \\\n',
                "",
                1,
            ),
            "missing-asset-verification": workflow.replace(
                "--verify-tool-assets", "--skip-tool-assets", 1
            ),
            "missing-proposed-tree-validation": workflow.replace(
                "--validate-proposed-tree", "--skip-proposed-tree", 1
            ),
            "native-github-token": workflow.replace(
                "github-token: ${{ steps.publisher_app_token.outputs.token }}",
                "github-token: ${{ github.token }}",
                1,
            ),
            "unreviewed-app-permission": workflow.replace(
                "          permission-workflows: write",
                "          permission-workflows: read",
                1,
            ),
            "unreviewed-app-repository-scope": workflow.replace(
                "          repositories: ${{ github.event.repository.name }}",
                "          repositories: another-repository",
                1,
            ),
            "existing-pr-uniqueness-bypass": workflow.replace(
                "pullRequests.length !== 1", "false", 1
            ),
            "existing-branch-scope-bypass": workflow.replace(
                'comparison.data.status !== "ahead"', "false", 1
            ),
            "outcome-not-always": workflow.replace(
                "if: ${{ always() }}", "if: ${{ success() }}", 1
            ),
        }
        for name, unsafe in variants.items():
            with self.subTest(name=name):
                self.assertNotEqual(unsafe, workflow)
                errors = CHECKER.workflow_contract_errors(
                    workflow_path, unsafe, CHECKER.yaml.safe_load(unsafe)
                )
                self.assertTrue(errors, "\n".join(errors))

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
                "            ci/lib/common.sh\n            .python-version\n",
                "            ci/lib/common.sh\n            .python-version\n"
                "            .github/workflows/check-python-version.yml\n",
                1,
            ),
            "publisher-omits-generated-view-write": workflow.replace(
                "          python3 ci/tools/sync-canonical-python-pins.py --write --root .\n",
                "",
                1,
            ),
            "publisher-allows-generated-view-only": workflow.replace(
                "          expected_paths=$'.python-version\\nci/lib/common.sh'\n",
                "          expected_paths='.python-version'\n",
                1,
            ),
            "publisher-allows-unbounded-common-source": workflow.replace(
                '          if git_diff("--numstat") != "1\\t1\\tci/lib/common.sh\\n":\n',
                "              if False:\n",
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

    def test_python_version_publisher_rejects_untrusted_base_lifecycle_regressions(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/check-python-version.yml").read_text(
            encoding="utf-8"
        )
        variants = {
            "missing-explicit-pr-base": workflow.replace(
                "          base: master\n", "", 1
            ),
            "pr-base-equals-maintenance-branch": workflow.replace(
                "          base: master\n",
                "          base: automation/update-framework-python-314\n",
                1,
            ),
            "pr-branch-equals-base": workflow.replace(
                "          branch: automation/update-framework-python-314\n",
                "          branch: master\n",
                1,
            ),
            "existing-branch-is-not-detached": workflow.replace(
                '              git switch --detach "origin/$UPDATE_BRANCH"\n',
                '              git switch --create "$UPDATE_BRANCH" --track "origin/$UPDATE_BRANCH"\n',
                1,
            ),
            "new-update-precreates-maintenance-branch": workflow.replace(
                "            false)\n              ;;\n",
                "            false)\n"
                '              git switch --create "$UPDATE_BRANCH" "origin/$DEFAULT_BRANCH"\n'
                "              ;;\n",
                1,
            ),
            "missing-trusted-master-switch": workflow.replace(
                "          git switch --force-create master origin/master\n", "", 1
            ),
            "master-is-not-reset-to-trusted-origin": workflow.replace(
                "          git reset --hard origin/master\n",
                "          git reset --hard HEAD\n",
                1,
            ),
            "missing-clean-base-tree-check": workflow.replace(
                '          test -z "$(git status --porcelain)"\n\n'
                "      - name: Independently revalidate and apply the candidate\n",
                "      - name: Independently revalidate and apply the candidate\n",
                1,
            ),
            "candidate-does-not-prove-master": workflow.replace(
                '          test "$(git branch --show-current)" = "master"\n'
                '          test -z "$(git status --porcelain)"\n'
                "          python3 ci/tools/update-python-version.py --check",
                '          test -z "$(git status --porcelain)"\n'
                "          python3 ci/tools/update-python-version.py --check",
                1,
            ),
            "candidate-diff-is-not-bound-to-master": workflow.replace(
                '          changed_paths="$(git diff --name-only origin/master)"\n',
                '          changed_paths="$(git diff --name-only "origin/$DEFAULT_BRANCH")"\n',
                1,
            ),
            "candidate-does-not-prove-master-after-update": workflow.replace(
                "          git diff --check origin/master\n"
                '          test "$(git branch --show-current)" = "master"\n',
                "          git diff --check origin/master\n",
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
                if name == "pr-base-equals-maintenance-branch":
                    self.assertTrue(
                        any(
                            "distinct base and maintenance branches" in error
                            for error in errors
                        ),
                        "\n".join(errors),
                    )

    def test_unified_common_maintenance_rejects_security_boundary_mutations(
        self,
    ) -> None:
        workflow_path = ROOT / ".github/workflows/check-common-versions.yml"
        workflow = workflow_path.read_text(encoding="utf-8")

        def replace_job_field(
            text: str, job: str, next_job: str, old: str, new: str
        ) -> str:
            start = text.index(f"\n  {job}:\n")
            end = text.index(f"\n  {next_job}:\n", start + 1)
            section = text[start:end]
            self.assertIn(old, section)
            return text[:start] + section.replace(old, new, 1) + text[end:]

        mutations = {
            "legacy_job": workflow.replace(
                "jobs:\n",
                "jobs:\n  legacy-resolve:\n    if: ${{ false }}\n    runs-on: ubuntu-latest\n    timeout-minutes: 1\n    permissions:\n      contents: read\n    steps: []\n",
                1,
            ),
            "candidate_write": replace_job_field(
                workflow,
                "candidate",
                "publish",
                "      contents: read",
                "      contents: write",
            ),
            "missing_plan_binding": workflow.replace(
                (
                    '            --expected-plan-sha256 "$PLAN_SHA256" \\\n'
                    "            --validate-only"
                ),
                "            --validate-only",
                1,
            ),
            "artifact-name-is-not-caller-bound": workflow.replace(
                "canonical-maintenance-plan-${{ github.run_id }}-${{ github.run_attempt }}",
                "canonical-maintenance-plan-unbound",
                1,
            ),
            "artifact-attempt-is-not-bound": workflow.replace(
                "canonical-maintenance-plan-${{ github.run_id }}-${{ github.run_attempt }}",
                "canonical-maintenance-plan-${{ github.run_id }}",
                1,
            ),
            "downstream-artifact-path-is-expanded": workflow.replace(
                "path: ${{ runner.temp }}",
                "path: ${{ runner.temp }}/untrusted-plan-location",
                1,
            ),
            "downstream-artifact-action-is-replaced": workflow.replace(
                "actions/download-artifact@",
                "actions/checkout@",
                1,
            ),
            "extra_read_token": workflow.replace(
                "          GITHUB_TOKEN: ${{ github.token }}\n",
                "          GITHUB_TOKEN: ${{ github.token }}\n          EXTRA_TOKEN: ${{ github.token }}\n",
                1,
            ),
            "issue_uses_publisher_app": workflow.replace(
                "MAINTENANCE_ISSUE_APP_PRIVATE_KEY",
                "WORKFLOW_UPDATER_APP_PRIVATE_KEY",
                1,
            ),
            "publisher_uses_default_token": workflow.replace(
                "          token: ${{ steps.publisher_app_token.outputs.token }}",
                "          token: ${{ github.token }}",
                1,
            ),
            "generated_path_expanded": workflow.replace(
                "            ci/lib/common.sh\n",
                "            ci/lib/common.sh\n            unsafe/generated.txt\n",
                1,
            ),
            "result_not_always": workflow.replace(
                "    if: ${{ always() }}\n",
                "    if: ${{ success() }}\n",
                1,
            ),
        }
        for name, mutated in mutations.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutated, workflow)
                errors = CHECKER.workflow_contract_errors(
                    workflow_path, mutated, CHECKER.yaml.safe_load(mutated)
                )
                self.assertTrue(errors, name)

    def test_unified_common_maintenance_rejects_unprepared_resolvers(self) -> None:
        workflow_path = ROOT / ".github/workflows/check-common-versions.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        setup = (
            "          python3 -m pip install --disable-pip-version-check --no-input --only-binary=:all: \\\n"
            "            --require-hashes -r requirements-ci.lock\n"
            "          python3 -m pip check\n"
        )

        def replace_in_job(
            text: str, job: str, next_job: str, old: str, new: str
        ) -> str:
            start = text.index(f"\n  {job}:\n")
            end = text.index(f"\n  {next_job}:\n", start)
            section = text[start:end]
            self.assertIn(old, section)
            return text[:start] + section.replace(old, new, 1) + text[end:]

        next_jobs = {
            "canonical-maintenance": "reconcile-trusted",
            "candidate": "publish",
            "publish": "result",
        }
        snapshot_step_marker = (
            "      - name: Snapshot trusted workflow-tool validation inputs\n"
        )
        updater_snapshot = (
            "          python3 ci/tools/update-workflow-tools.py "
            "snapshot-validation-inputs \\\n"
            "            --root . \\\n"
            '            --output-dir "$RUNNER_TEMP/canonical-workflow-tool-base"\n'
        )
        premature_updater_step = (
            "      - name: Invoke workflow-tool updater prematurely\n"
            "        run: |\n"
            "          set -euo pipefail\n" + updater_snapshot
        )
        for job, next_job in next_jobs.items():
            variants = {
                "omits-hash-locked-install": replace_in_job(
                    workflow,
                    job,
                    next_job,
                    setup,
                    setup.replace("--require-hashes", "--no-deps"),
                ),
                "omits-pip-check": replace_in_job(
                    workflow,
                    job,
                    next_job,
                    setup,
                    setup.replace("          python3 -m pip check\n", ""),
                ),
                "comments-out-bootstrap": replace_in_job(
                    workflow,
                    job,
                    next_job,
                    setup,
                    setup.replace(
                        "          python3 -m pip install",
                        "          # python3 -m pip install",
                        1,
                    ).replace(
                        "          python3 -m pip check\n",
                        "          # python3 -m pip check\n",
                        1,
                    ),
                ),
                "echoes-bootstrap": replace_in_job(
                    workflow,
                    job,
                    next_job,
                    setup,
                    "          printf '%s\\n' 'python3 -m pip install --require-hashes -r requirements-ci.lock'\n"
                    "          printf '%s\\n' 'python3 -m pip check'\n",
                ),
            }
            expected_errors: dict[str, tuple[str, ...]] = {
                "omits-hash-locked-install": (),
                "omits-pip-check": (),
                "comments-out-bootstrap": (),
                "echoes-bootstrap": (),
            }
            if job in {"candidate", "publish"}:
                variants["invokes-updater-before-bootstrap"] = replace_in_job(
                    workflow,
                    job,
                    next_job,
                    setup + updater_snapshot,
                    updater_snapshot + setup,
                )
                variants["invokes-updater-before-snapshot"] = replace_in_job(
                    workflow,
                    job,
                    next_job,
                    snapshot_step_marker,
                    premature_updater_step + snapshot_step_marker,
                )
                expected_errors.update(
                    {
                        "comments-out-bootstrap": (
                            "snapshot must bootstrap hash-locked CI requirements",
                        ),
                        "invokes-updater-before-bootstrap": (
                            "snapshot must bootstrap hash-locked CI requirements",
                        ),
                        "invokes-updater-before-snapshot": (
                            "must not invoke the workflow-tool updater before its locked bootstrap",
                        ),
                    }
                )
            for mutation, mutated in variants.items():
                with self.subTest(job=job, mutation=mutation):
                    errors = CHECKER.workflow_contract_errors(
                        workflow_path, mutated, CHECKER.yaml.safe_load(mutated)
                    )
                    self.assertTrue(errors, "\n".join(errors))
                    for expected in expected_errors[mutation]:
                        self.assertTrue(
                            any(expected in error for error in errors),
                            "\n".join(errors),
                        )

    def test_unified_common_maintenance_rejects_resolvers_outside_reviewed_runs(
        self,
    ) -> None:
        workflow_path = ROOT / ".github/workflows/check-common-versions.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        resolver = (
            "          python3 ci/tools/resolve-canonical-maintenance.py "
            "--root . --check\n"
        )
        foreign_step_markers = {
            "canonical-maintenance": (
                "          python3 ci/tools/reconcile-common-version-review-issues.py "
                '--plan "$RUNNER_TEMP/canonical-maintenance-plan.json" --validate-only\n'
            ),
            "reconcile-trusted": (
                '          [[ -n "$ISSUE_APP_CLIENT_ID" && -n "$ISSUE_APP_PRIVATE_KEY" ]] '
                "|| { echo 'review-issue App configuration is required' >&2; exit 1; }\n"
            ),
            "candidate": (
                "          allowed='^(.github/workflows/[^/]+\\.yml|ci/lib/common\\.sh|"
                "ci/provisioning/runtime-(components\\.manifest|component-lock)\\.json|"
                "ci/tooling/security-tools\\.lock\\.yml|\\.python-version|"
                "requirements-ci\\.lock|docs/(reference/variables|"
                "github-actions-workflow-security)(\\.de)?\\.md|tests/schemas/"
                "five-connectors-with-crs-no-mrts/(normalized-event|manifest|receipt)"
                "\\.schema\\.json|tests/cases/security/crs/"
                "crs_sqli_anomaly_block\\.yaml)$'\n"
            ),
            "publish": (
                '          [[ -n "$PUBLISHER_CLIENT_ID" && -n "$PUBLISHER_PRIVATE_KEY" ]] '
                "|| { echo 'publisher App configuration is required' >&2; exit 1; }\n"
            ),
            "result": '          cat >> "$GITHUB_STEP_SUMMARY" <<EOF\n',
        }
        for job, marker in foreign_step_markers.items():
            with self.subTest(job=job):
                self.assertIn(marker, workflow)
                mutated = workflow.replace(marker, resolver + marker, 1)
                errors = CHECKER.workflow_contract_errors(
                    workflow_path, mutated, CHECKER.yaml.safe_load(mutated)
                )
                self.assertTrue(errors, "\n".join(errors))

    def test_unified_common_maintenance_rejects_publisher_token_permission_mutations(
        self,
    ) -> None:
        workflow_path = ROOT / ".github/workflows/check-common-versions.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        variants = {
            "publisher-missing-workflows-permission": workflow.replace(
                "          permission-workflows: write\n", "", 1
            ),
            "publisher-extra-actions-permission": workflow.replace(
                "          permission-workflows: write\n",
                "          permission-workflows: write\n"
                "          permission-actions: write\n",
                1,
            ),
        }
        for name, mutated in variants.items():
            with self.subTest(name=name):
                self.assertNotEqual(workflow, mutated)
                errors = CHECKER.workflow_contract_errors(
                    workflow_path, mutated, CHECKER.yaml.safe_load(mutated)
                )
                self.assertTrue(errors, "\n".join(errors))

    def _legacy_common_version_publisher_rejects_privilege_and_scope_regressions(
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
            "dispatch-component-input-removed": workflow.replace(
                "    inputs:\n"
                "      component:\n"
                '        description: "Optional exact common-version component name to resolve"\n'
                "        required: false\n"
                "        type: string\n"
                '        default: ""\n',
                "",
                1,
            ),
            "dispatch-component-is-interpolated-into-shell": workflow.replace(
                "        env:\n"
                "          REQUESTED_COMPONENT: ${{ inputs.component }}\n",
                "",
                1,
            ),
            "dispatch-component-is-not-passed-as-an-argv-element": workflow.replace(
                '            component_args+=(--component "$REQUESTED_COMPONENT")\n',
                '            component_args+=("$REQUESTED_COMPONENT")\n',
                1,
            ),
            "publisher-dispatch-component-is-not-bound": workflow.replace(
                "          TOOLS_DIR: ${{ runner.temp }}/framework-ci-security-tools\n"
                "          REQUESTED_COMPONENT: ${{ inputs.component }}\n",
                "          TOOLS_DIR: ${{ runner.temp }}/framework-ci-security-tools\n",
                1,
            ),
            "publisher-dispatch-component-is-not-passed-as-an-argv-element": workflow.replace(
                '            "${component_args[@]}" > "$RUNNER_TEMP/common-version-check.stdout.json"\n',
                '            "$REQUESTED_COMPONENT" > "$RUNNER_TEMP/common-version-check.stdout.json"\n',
                1,
            ),
            "candidate-validator-omits-atomic-provenance-regression": workflow.replace(
                "            tests.security_regression.test_common_version_atomic_provenance \\\n",
                "",
                1,
            ),
            "publisher-omits-atomic-provenance-regression": replace_last(
                workflow,
                "            tests.security_regression.test_common_version_atomic_provenance \\\n",
                "",
            ),
            "resolver-exit-is-not-captured": workflow.replace(
                " || resolver_exit=$?\n",
                "\n",
                1,
            ),
            "resolver-markdown-summary-is-not-preserved": workflow.replace(
                '          cp "$BUILD_ROOT/results/common-version-check/summary.md" \\\n',
                "          # summary.md preservation removed\n",
                1,
            ),
            "resolver-failure-annotation-loses-component-and-reason": workflow.replace(
                "::error title=Common-version resolver failed for {command_component}::{command_reason}",
                "::error::Common-version resolver failed",
                1,
            ),
            "reader-write-permission": workflow.replace(
                "  resolve:\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n"
                "    permissions:\n      contents: read",
                "  resolve:\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n"
                "    permissions:\n      contents: write",
                1,
            ),
            "reader-token-exposure": workflow.replace(
                "      - name: Resolve an ephemeral common.sh candidate\n"
                "        id: resolve\n"
                "        env:\n"
                "          REQUESTED_COMPONENT: ${{ inputs.component }}\n",
                "      - name: Resolve an ephemeral common.sh candidate\n"
                "        id: resolve\n"
                "        env:\n"
                "          REQUESTED_COMPONENT: ${{ inputs.component }}\n"
                "          GITHUB_TOKEN: ${{ github.token }}\n",
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

    def test_unified_common_maintenance_rejects_result_boundary_mutations(self) -> None:
        workflow_path = ROOT / ".github/workflows/check-common-versions.yml"
        workflow = workflow_path.read_text(encoding="utf-8")

        def replace_result_field(text: str, old: str, new: str) -> str:
            start = text.index("\n  result:\n")
            section = text[start:]
            self.assertIn(old, section)
            return text[:start] + section.replace(old, new, 1)

        mutations = {
            "result_writes": replace_result_field(
                workflow,
                "      contents: read",
                "      contents: write",
            ),
            "result_not_always": replace_result_field(
                workflow,
                "    if: ${{ always() }}",
                "    if: ${{ success() }}",
            ),
            "result_secret": workflow.replace(
                "          FATAL: ${{ needs.canonical-maintenance.outputs.fatal }}\n",
                "          FATAL: ${{ needs.canonical-maintenance.outputs.fatal }}\n          SECRET: ${{ secrets.UNSAFE }}\n",
                1,
            ),
        }
        for name, mutated in mutations.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutated, workflow)
                errors = CHECKER.workflow_contract_errors(
                    workflow_path, mutated, CHECKER.yaml.safe_load(mutated)
                )
                self.assertTrue(errors, name)

    def _legacy_common_version_result_job_reports_safe_terminal_states(self) -> None:
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

    def test_action_release_resolution_keeps_valid_and_invalid_paths_distinct(
        self,
    ) -> None:
        actions, _tools, errors = CHECKER.load_lock(LOCK_PATH)
        self.assertFalse(errors, "\n".join(errors))

        valid = actions["actions/checkout"]
        self.assertEqual(
            CHECKER.action_release_resolution_errors(
                LOCK_PATH, "actions/checkout", valid
            ),
            [],
        )

        invalid = dict(valid)
        invalid["release_resolution"] = "unsupported"
        invalid_errors = CHECKER.action_release_resolution_errors(
            LOCK_PATH, "actions/checkout", invalid
        )
        self.assertTrue(
            any("unsupported release resolution" in error for error in invalid_errors),
            "\n".join(invalid_errors),
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
