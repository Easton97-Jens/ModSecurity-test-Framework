from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


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
        errors = CHECKER.workflow_contract_errors(Path("unsafe-controls.yml"), "", data)
        self.assertTrue(
            any("permissions must be a mapping" in error for error in errors)
        )
        self.assertTrue(any("non-empty group" in error for error in errors))
        self.assertTrue(any("cancel-in-progress" in error for error in errors))
        self.assertTrue(
            any("positive integer timeout-minutes" in error for error in errors)
        )
        self.assertTrue(
            any("must not expose GITHUB_TOKEN" in error for error in errors)
        )

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

    def test_crs_version_pinning_uses_a_safe_runtime_temp_file(self) -> None:
        script = (ROOT / "ci/checks/catalog/check-crs-version-pinning.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('assert_safe_runtime_path "$TMP_ROOT"', script)
        self.assertIn('mktemp "$TMP_ROOT/crs-version-pinning.XXXXXX"', script)
        self.assertIn('mktemp "$TMP_ROOT/crs-version-pinning-paths.XXXXXX"', script)
        self.assertIn("find ci -type f -name '*.sh' -print0", script)
        self.assertIn('xargs -0 -r -n 1 sh "$SCRIPT_PATH" --check-path', script)
        self.assertNotIn("/tmp/crs-version-pinning", script)

    def test_archive_member_validation_rejects_path_escape(self) -> None:
        self.assertTrue(FETCHER.is_safe_archive_member("package/index.js"))
        self.assertTrue(FETCHER.is_safe_path_component("actionlint"))
        self.assertFalse(FETCHER.is_safe_path_component("package/actionlint"))
        self.assertFalse(FETCHER.is_safe_archive_member("../escape"))
        self.assertFalse(FETCHER.is_safe_archive_member("/absolute"))


if __name__ == "__main__":
    unittest.main()
