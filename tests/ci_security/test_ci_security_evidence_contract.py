from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "ci/checks/security/check-ci-security-evidence-contract.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load_module("framework_ci_security_evidence_contract", CHECKER_PATH)


class FrameworkCiSecurityEvidenceContractTest(unittest.TestCase):
    @staticmethod
    def scorecard_command() -> str:
        return (
            '"$TOOLS_DIR/scorecard" --local . --format json '
            '--output "$SCORECARD_RESULTS"'
        )

    def test_current_workflows_pass_the_semantic_evidence_contract(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CHECKER_PATH), "--root", str(ROOT)],
            check=False,
            capture_output=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_shell_comment_cannot_satisfy_missing_osv_input_contract(self) -> None:
        path = ROOT / ".github/workflows/ci-security-osv.yml"
        mutated = path.read_text(encoding="utf-8").replace(
            "write_osv_input requirements-dev.txt requirements-dev.txt",
            "write_osv_input requirements-other.txt requirements-other.txt "
            "# write_osv_input requirements-dev.txt requirements-dev.txt",
            1,
        )
        errors = CHECKER.workflow_errors(path, CHECKER.yaml.safe_load(mutated))
        self.assertTrue(
            any(
                "requirements-dev.txt requirements-dev.txt" in error for error in errors
            ),
            "\n".join(errors),
        )

    def test_control_branch_cannot_satisfy_scorecard_scan_contract(self) -> None:
        path = ROOT / ".github/workflows/ci-security-scorecard.yml"
        command = self.scorecard_command()
        for header in (
            "if false; then",
            "if true; then",
            "if false\n          then",
        ):
            with self.subTest(header=header):
                mutated = path.read_text(encoding="utf-8").replace(
                    command,
                    f"{header}\n            {command}\n          fi",
                    1,
                )
                errors = CHECKER.workflow_errors(path, CHECKER.yaml.safe_load(mutated))
                self.assertTrue(
                    any(command in error for error in errors), "\n".join(errors)
                )

    def test_uninvoked_function_cannot_satisfy_scorecard_scan_contract(self) -> None:
        path = ROOT / ".github/workflows/ci-security-scorecard.yml"
        command = self.scorecard_command()
        for definition in (
            "unused_scorecard_scan() {",
            "function unused_scorecard_scan {",
            "unused_scorecard_scan()\n          {",
            "function unused_scorecard_scan\n          {",
        ):
            with self.subTest(definition=definition):
                mutated = path.read_text(encoding="utf-8").replace(
                    command,
                    "echo 'Scorecard scan intentionally omitted'\n"
                    f"          {definition}\n"
                    f"            {command}\n"
                    "          }",
                    1,
                )
                errors = CHECKER.workflow_errors(path, CHECKER.yaml.safe_load(mutated))
                self.assertTrue(
                    any(command in error for error in errors), "\n".join(errors)
                )

    def test_assignment_only_cannot_invoke_a_scorecard_helper(self) -> None:
        path = ROOT / ".github/workflows/ci-security-scorecard.yml"
        command = self.scorecard_command()
        for assignment in (
            "unused_scorecard_scan=disabled",
            "unused_scorecard_scan[0]=disabled",
            'unused_scorecard_scan["mode"]=disabled',
        ):
            with self.subTest(assignment=assignment):
                assignment_only = path.read_text(encoding="utf-8").replace(
                    command,
                    "unused_scorecard_scan() {\n"
                    f"            {command}\n"
                    "          }\n"
                    f"          {assignment}",
                    1,
                )
                assignment_errors = CHECKER.workflow_errors(
                    path, CHECKER.yaml.safe_load(assignment_only)
                )
                self.assertTrue(
                    any(command in error for error in assignment_errors),
                    "\n".join(assignment_errors),
                )

        assignment_prefixed_call = path.read_text(encoding="utf-8").replace(
            command,
            "unused_scorecard_scan() {\n"
            f"            {command}\n"
            "          }\n"
            "          SCAN_MODE=local unused_scorecard_scan",
            1,
        )
        call_errors = CHECKER.workflow_errors(
            path, CHECKER.yaml.safe_load(assignment_prefixed_call)
        )
        self.assertFalse(call_errors, "\n".join(call_errors))

    def test_exec_command_terminates_scorecard_reachability(self) -> None:
        path = ROOT / ".github/workflows/ci-security-scorecard.yml"
        command = self.scorecard_command()
        terminated = path.read_text(encoding="utf-8").replace(
            command, f"exec /usr/bin/true\n          {command}", 1
        )
        terminated_errors = CHECKER.workflow_errors(
            path, CHECKER.yaml.safe_load(terminated)
        )
        self.assertTrue(
            any(command in error for error in terminated_errors),
            "\n".join(terminated_errors),
        )

        json_check = (
            "python3 ci/checks/security/check-json-result.py "
            '--input "$SCORECARD_RESULTS" --max-bytes 1048576'
        )
        after_commands = path.read_text(encoding="utf-8").replace(
            json_check, f"{json_check}\n          exec /usr/bin/true", 1
        )
        after_errors = CHECKER.workflow_errors(
            path, CHECKER.yaml.safe_load(after_commands)
        )
        self.assertFalse(after_errors, "\n".join(after_errors))

        redirect_only = path.read_text(encoding="utf-8").replace(
            command, f'exec > "$SCORECARD_RESULTS"\n          {command}', 1
        )
        redirect_errors = CHECKER.workflow_errors(
            path, CHECKER.yaml.safe_load(redirect_only)
        )
        self.assertFalse(redirect_errors, "\n".join(redirect_errors))

    def test_pr_osv_base_without_ci_lock_uses_an_empty_optional_input(self) -> None:
        path = ROOT / ".github/workflows/ci-security-osv.yml"
        workflow = CHECKER.load_yaml(path)
        pull_request = workflow["jobs"]["pull-request-head"]
        step = next(
            item for item in pull_request["steps"] if item.get("id") == "compare_osv"
        )
        run = step["run"]
        prelude, marker, _remainder = run.partition(
            'prepare_osv_inputs "$BASE_SHA" "$RESULTS_DIR/base-inputs"'
        )
        self.assertTrue(marker)

        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)

            def run_git(*arguments: str) -> str:
                result = subprocess.run(
                    ["git", *arguments],
                    cwd=repository,
                    check=True,
                    capture_output=True,
                    encoding="utf-8",
                )
                return result.stdout.strip()

            run_git("init", "-q")
            run_git("config", "user.email", "ci-security@example.invalid")
            run_git("config", "user.name", "CI Security Test")
            (repository / "requirements-dev.txt").write_text(
                "example-dev==1.0\n", encoding="utf-8"
            )
            run_git("add", "requirements-dev.txt")
            run_git("commit", "-qm", "base without ci lock")
            base_sha = run_git("rev-parse", "HEAD")
            (repository / "requirements-ci.lock").write_text(
                "example-ci==1.0\n", encoding="utf-8"
            )
            run_git("add", "requirements-ci.lock")
            run_git("commit", "-qm", "head with ci lock")
            head_sha = run_git("rev-parse", "HEAD")
            results_directory = repository / "results"
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    "\n".join(
                        (
                            prelude,
                            'prepare_osv_inputs "$BASE_SHA" "$RESULTS_DIR/base-inputs"',
                            'test -s "$RESULTS_DIR/base-inputs/requirements-dev.txt"',
                            'test ! -s "$RESULTS_DIR/base-inputs/requirements-ci.txt"',
                        )
                    ),
                ],
                cwd=repository,
                check=False,
                capture_output=True,
                encoding="utf-8",
                env={
                    **os.environ,
                    "BASE_SHA": base_sha,
                    "HEAD_SHA": head_sha,
                    "RESULTS_DIR": str(results_directory),
                    "TOOLS_DIR": str(repository / "tools"),
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_reachable_osv_helpers_satisfy_nested_command_contract(self) -> None:
        path = ROOT / ".github/workflows/ci-security-osv.yml"
        workflow = CHECKER.load_yaml(path)
        errors = CHECKER.osv_errors(path, workflow)
        self.assertFalse(errors, "\n".join(errors))

    def test_codeql_checkout_and_gitleaks_redaction_are_fail_closed(self) -> None:
        codeql_path = ROOT / ".github/workflows/ci-security-codeql-pr.yml"
        codeql = codeql_path.read_text(encoding="utf-8").replace(
            "${{ github.event.pull_request.head.sha }}",
            "${{ github.sha }}",
            1,
        )
        codeql_errors = CHECKER.workflow_errors(
            codeql_path, CHECKER.yaml.safe_load(codeql)
        )
        self.assertTrue(
            any("checkout must use ref" in error for error in codeql_errors)
        )

        secrets_path = ROOT / ".github/workflows/ci-security-secrets.yml"
        secrets = secrets_path.read_text(encoding="utf-8").replace(
            "--redact=100", "--redact=0", 1
        )
        secrets_errors = CHECKER.workflow_errors(
            secrets_path, CHECKER.yaml.safe_load(secrets)
        )
        self.assertTrue(any("--redact=100" in error for error in secrets_errors))

    def test_codeql_security_events_write_is_trusted_only(self) -> None:
        pull_request_path = ROOT / ".github/workflows/ci-security-codeql-pr.yml"
        pull_request = pull_request_path.read_text(encoding="utf-8").replace(
            "    permissions:\n      contents: read\n",
            "    permissions:\n      contents: read\n      security-events: write\n",
            1,
        )
        pull_request_errors = CHECKER.workflow_errors(
            pull_request_path, CHECKER.yaml.safe_load(pull_request)
        )
        self.assertTrue(
            any(
                "must not grant security-events: write" in error
                for error in pull_request_errors
            ),
            "\n".join(pull_request_errors),
        )

        trusted_path = ROOT / ".github/workflows/ci-security-codeql.yml"
        trusted = trusted_path.read_text(encoding="utf-8").replace(
            "on:\n  push:\n",
            "on:\n  pull_request:\n    branches:\n      - master\n  push:\n",
            1,
        )
        trusted_errors = CHECKER.workflow_errors(
            trusted_path, CHECKER.yaml.safe_load(trusted)
        )
        self.assertTrue(
            any("must not run on pull_request" in error for error in trusted_errors),
            "\n".join(trusted_errors),
        )

    def test_workflow_lint_requires_a_pr_head_checkout(self) -> None:
        path = ROOT / ".github/workflows/ci-security-workflow-lint.yml"
        workflow = path.read_text(encoding="utf-8").replace(
            "${{ github.event.pull_request.head.sha || github.sha }}",
            "${{ github.sha }}",
            1,
        )
        errors = CHECKER.workflow_errors(path, CHECKER.yaml.safe_load(workflow))
        self.assertTrue(any("checkout must use ref" in error for error in errors))

    def test_cache_and_direct_sarif_uploads_are_rejected(self) -> None:
        scorecard_path = ROOT / ".github/workflows/ci-security-scorecard.yml"
        scorecard = scorecard_path.read_text(encoding="utf-8").replace(
            "      - name: Set up reviewed Python",
            "      - uses: actions/cache@0000000000000000000000000000000000 # v4.0.0\n"
            "      - name: Set up reviewed Python",
            1,
        )
        scorecard_errors = CHECKER.workflow_errors(
            scorecard_path, CHECKER.yaml.safe_load(scorecard)
        )
        self.assertTrue(any("persistent cache" in error for error in scorecard_errors))

        codeql_path = ROOT / ".github/workflows/ci-security-codeql.yml"
        codeql = codeql_path.read_text(encoding="utf-8").replace(
            "      - name: Analyze bounded Framework source",
            "      - uses: github/codeql-action/upload-sarif@0000000000000000000000000000000000000000 # v4.37.1\n"
            "      - name: Analyze bounded Framework source",
            1,
        )
        codeql_errors = CHECKER.workflow_errors(
            codeql_path, CHECKER.yaml.safe_load(codeql)
        )
        self.assertTrue(any("raw SARIF" in error for error in codeql_errors))

        quality_path = ROOT / ".github/workflows/ci-security-quality.yml"
        quality = quality_path.read_text(encoding="utf-8").replace(
            "      - name: Set up reviewed Python",
            "      - uses: actions/upload-artifact@0000000000000000000000000000000000000000 # v5.0.0\n"
            "      - name: Set up reviewed Python",
            1,
        )
        quality_errors = CHECKER.workflow_errors(
            quality_path, CHECKER.yaml.safe_load(quality)
        )
        self.assertTrue(
            any(
                "must not upload scanner artifacts" in error for error in quality_errors
            )
        )


if __name__ == "__main__":
    unittest.main()
