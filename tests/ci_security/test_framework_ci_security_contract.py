from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from tests.ci_security.workflow_contract_test_support import (
    assert_rejects_unsafe_workflow_controls,
)


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "ci/checks/security/check-ci-security-contract.py"
FETCHER_PATH = ROOT / "ci/tools/fetch-security-tool.py"
LOCK_PATH = ROOT / "ci/tooling/security-tools.lock.yml"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load_module("framework_ci_security_contract", CHECKER_PATH)
FETCHER = load_module("framework_security_tool_fetcher", FETCHER_PATH)


class FrameworkCiSecurityContractTest(unittest.TestCase):
    def test_current_workflows_and_lock_pass(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CHECKER_PATH), "--root", str(ROOT)],
            check=False,
            capture_output=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        actions, tools, errors = CHECKER.load_lock(LOCK_PATH)
        self.assertFalse(errors, "\n".join(errors))
        self.assertIn("actions/checkout", actions)
        self.assertIn("actionlint", tools)
        self.assertIn("shellcheck", tools)
        self.assertIn("osv-scanner", tools)
        self.assertIn("actions/upload-artifact", actions)

    def test_cli_lock_path_is_confined_to_the_framework_root(self) -> None:
        legitimate = subprocess.run(
            [
                sys.executable,
                str(CHECKER_PATH),
                "--root",
                str(ROOT),
                "--lock",
                "ci/tooling/security-tools.lock.yml",
            ],
            check=False,
            capture_output=True,
            encoding="utf-8",
        )
        self.assertEqual(
            legitimate.returncode, 0, legitimate.stdout + legitimate.stderr
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            root = temporary_root / "framework"
            root.mkdir()
            outside_lock = temporary_root / "outside-lock.yml"
            outside_lock.write_text("actions: {}\ntools: {}\n", encoding="utf-8")
            symlinked_lock = root / "linked-lock.yml"
            symlinked_lock.symlink_to(outside_lock)

            for unsafe_lock in (outside_lock, Path("linked-lock.yml")):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(CHECKER_PATH),
                        "--root",
                        str(root),
                        "--lock",
                        str(unsafe_lock),
                    ],
                    check=False,
                    capture_output=True,
                    encoding="utf-8",
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn("must resolve inside --root", result.stdout)

    def test_uses_parser_preserves_quotes_and_rejects_malformed_quotes(self) -> None:
        sha = "0" * 40
        self.assertEqual(
            CHECKER.uses_reference_and_comment(
                f'  - uses: "actions/checkout@{sha}" # v5.0.0'
            ),
            (f"actions/checkout@{sha}", "v5.0.0"),
        )
        actions, _tools, lock_errors = CHECKER.load_lock(LOCK_PATH)
        self.assertFalse(lock_errors, "\n".join(lock_errors))
        malformed_errors = CHECKER.pin_errors(
            Path("malformed.yml"),
            f'uses: "actions/checkout@{sha} # v5.0.0',
            actions,
        )
        self.assertTrue(
            any("locked GitHub Action" in error for error in malformed_errors)
        )

    def test_osv_and_scorecard_evidence_contracts_reject_regressions(self) -> None:
        osv_path = ROOT / ".github/workflows/ci-security-osv.yml"
        osv_text = osv_path.read_text(encoding="utf-8")
        self.assertEqual(CHECKER.scanner_evidence_errors(osv_path, osv_text), [])
        relaxed_osv = osv_text.replace(
            "--format json", "--format json --allow-no-lockfiles", 1
        ).replace("retention-days: 1", "retention-days: 2", 1)
        osv_errors = CHECKER.scanner_evidence_errors(osv_path, relaxed_osv)
        self.assertTrue(any("allow-no-lockfiles" in error for error in osv_errors))
        self.assertTrue(any("retention-days: 1" in error for error in osv_errors))
        ungated_scheduled_osv = osv_text.replace(
            "if: always() && steps.scan_current_osv.outputs.evidence_valid == 'true'",
            "if: always()",
            1,
        )
        scheduled_errors = CHECKER.scanner_evidence_errors(
            osv_path, ungated_scheduled_osv
        )
        self.assertTrue(
            any(
                "steps.scan_current_osv.outputs.evidence_valid" in error
                for error in scheduled_errors
            )
        )

        scorecard_path = ROOT / ".github/workflows/ci-security-scorecard.yml"
        scorecard_text = scorecard_path.read_text(encoding="utf-8")
        self.assertEqual(
            CHECKER.scanner_evidence_errors(scorecard_path, scorecard_text), []
        )
        pr_upload = scorecard_text.replace(
            "\n  current-revision-advisory:",
            "\n      - uses: actions/upload-artifact@0000000000000000000000000000000000000000 # v5.0.0"
            "\n\n  current-revision-advisory:",
            1,
        )
        scorecard_errors = CHECKER.scanner_evidence_errors(
            scorecard_path,
            pr_upload.replace("retention-days: 1", "retention-days: 2", 1),
        )
        self.assertTrue(any("artifact-free" in error for error in scorecard_errors))
        self.assertTrue(any("retention-days: 1" in error for error in scorecard_errors))

    def test_safe_and_unsafe_trust_boundary_fixtures(self) -> None:
        safe = ROOT / "tests/fixtures/ci-security/safe.yml"
        unsafe = ROOT / "tests/fixtures/ci-security/unsafe.yml"
        unsafe_inline = ROOT / "tests/fixtures/ci-security/unsafe-inline.yml"
        self.assertEqual(CHECKER.trust_boundary_errors(safe, safe.read_text()), [])
        unsafe_errors = CHECKER.trust_boundary_errors(unsafe, unsafe.read_text())
        self.assertTrue(any("pull_request_target" in error for error in unsafe_errors))
        self.assertTrue(any("interpolate PR" in error for error in unsafe_errors))
        inline_errors = CHECKER.trust_boundary_errors(
            unsafe_inline, unsafe_inline.read_text()
        )
        self.assertTrue(any("pull_request_target" in error for error in inline_errors))

    def test_yaml_workflow_and_quoted_mutable_action_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workflow_dir = root / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "quoted-action.yaml").write_text(
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

    def test_contract_rejects_broad_controls_and_unlocked_container(self) -> None:
        assert_rejects_unsafe_workflow_controls(self, CHECKER.workflow_contract_errors)
        actions, _tools, lock_errors = CHECKER.load_lock(LOCK_PATH)
        self.assertFalse(lock_errors, "\n".join(lock_errors))
        container_errors = CHECKER.pin_errors(
            Path("container.yml"),
            "uses: docker://example.invalid/security-tool:latest\n",
            actions,
        )
        self.assertTrue(
            any("locked GitHub Action" in error for error in container_errors)
        )

    def test_python_and_downloader_provisioning_are_fail_closed(self) -> None:
        errors = CHECKER.python_provisioning_errors(
            Path("incomplete-provisioning.yml"),
            textwrap.dedent(
                """\
                uses: actions/setup-python@0000000000000000000000000000000000000000
                with:
                  python-version: "3.12"
                run: python3 ci/tools/fetch-security-tool.py --tool fixture
                """
            ),
        )
        self.assertTrue(any("exact reviewed CPython" in error for error in errors))
        self.assertTrue(any("check-latest" in error for error in errors))
        self.assertTrue(any("hash-locked" in error for error in errors))

    def test_token_references_and_tool_paths_are_fail_closed(self) -> None:
        token_errors = CHECKER.trust_boundary_errors(
            ROOT / "untrusted-token.yml", "token: ${{ github.token }}\n"
        )
        self.assertTrue(any("token reference" in error for error in token_errors))
        _actions, tools, lock_errors = CHECKER.load_lock(LOCK_PATH)
        self.assertFalse(lock_errors, "\n".join(lock_errors))
        malformed = dict(tools["actionlint"])
        malformed["asset"] = "../escape.tar.gz"
        schema_errors = CHECKER.record_errors(
            LOCK_PATH, "tool", "actionlint", malformed
        )
        self.assertTrue(
            any("unsafe release asset name" in error for error in schema_errors)
        )
        raw_tool = dict(tools["osv-scanner"])
        raw_tool["archive_member"] = "not-permitted"
        raw_schema_errors = CHECKER.record_errors(
            LOCK_PATH, "tool", "osv-scanner", raw_tool
        )
        self.assertTrue(
            any("raw assets must not declare" in error for error in raw_schema_errors)
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
            with patch.object(FETCHER, "confined_lock_path", return_value=lock):
                with self.assertRaisesRegex(FETCHER.ToolError, "safe output path"):
                    FETCHER.read_tool_record(lock, "../escape")
        self.assertTrue(FETCHER.is_safe_archive_member("package/index.js"))
        self.assertTrue(FETCHER.is_safe_path_component("actionlint"))
        self.assertFalse(FETCHER.is_safe_path_component("package/actionlint"))
        self.assertFalse(FETCHER.is_safe_archive_member("../escape"))

    def test_fetcher_requires_a_runner_temp_child_without_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            outside = root / "outside"
            outside.mkdir()
            escape = runner_temp / "escape"
            escape.symlink_to(outside, target_is_directory=True)
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                self.assertEqual(
                    FETCHER.runner_owned_output_dir(runner_temp / "tools"),
                    runner_temp / "tools",
                )
                with self.assertRaisesRegex(FETCHER.ToolError, "strict child"):
                    FETCHER.runner_owned_output_dir(runner_temp)
                with self.assertRaisesRegex(FETCHER.ToolError, "strict child"):
                    FETCHER.runner_owned_output_dir(outside / "tools")
                with self.assertRaisesRegex(FETCHER.ToolError, "symlink"):
                    FETCHER.runner_owned_output_dir(escape / "tools")


if __name__ == "__main__":
    unittest.main()
