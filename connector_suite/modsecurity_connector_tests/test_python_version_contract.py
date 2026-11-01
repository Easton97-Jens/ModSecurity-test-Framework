"""Offline tests for the Parent Python workflow-version contract checker."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_source, framework_revision
from modsecurity_test_framework import workflow_sources
from modsecurity_test_framework.product_sources.ci.lib.framework_revision_pins import load_framework_revision_pins

import contextlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()
CHECKER_PATH = source_path('ci/checks/common/check-python-version-contract.py', root=ROOT)
FIXTURES = source_path('tests/fixtures/python-version-contract', root=ROOT)


def load_checker() -> object:
    module = load_source(CHECKER_PATH)
    return module


CHECKER = load_checker()
ACTION_PINS = load_source(source_path("ci/lib/workflow_action_pins.py", root=ROOT), fresh=False)


class PythonVersionContractTest(unittest.TestCase):
    def temporary_root(self) -> tempfile.TemporaryDirectory[str]:
        return tempfile.TemporaryDirectory(prefix="python-version-contract-")

    def cli_json_result(
        self, root: Path, *arguments: str
    ) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with (
            mock.patch.object(CHECKER, "repository_root", return_value=root),
            contextlib.redirect_stdout(output),
        ):
            exit_code = CHECKER.main((*arguments, "--json"))
        return exit_code, json.loads(output.getvalue())

    def fixture_root_result(
        self,
        fixture_names: tuple[str, ...],
        expected_normal_jobs: set[object],
        expected_candidate_job: object | None = None,
        expected_immutable_reusable_jobs: dict[object, str] | None = None,
        expected_local_reusable_callers: dict[object, str] | None = None,
    ) -> tuple[str, list[str], set[object]]:
        with self.temporary_root() as directory:
            root = Path(directory)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            for fixture_name in fixture_names:
                source = (FIXTURES / fixture_name).read_text()
                # These checked-in fixtures describe the former physical layout.
                # Project only the exact old verifier command; retain every
                # malformed selector, wrapper and ordering input around it.
                source = source.replace(
                    'python3 ci/checks/common/check-python-interpreter-contract.py --version-file .python-version --expected-python "$EXPECTED_PYTHON"',
                    CHECKER.NORMAL_VERIFIER_COMMAND,
                )
                (workflows / fixture_name).write_text(source)
            version_file = root / ".python-version"
            version_file.write_text("3.15.6\n", encoding="utf-8")
            return CHECKER.evaluate_workflow_contract(
                root,
                version_file,
                expected_normal_jobs=expected_normal_jobs,
                expected_candidate_job=expected_candidate_job,
                expected_immutable_reusable_jobs=expected_immutable_reusable_jobs or {},
                expected_local_reusable_callers=expected_local_reusable_callers or {},
                expected_system_python_jobs=(),
            )

    def fixture_result(self, fixture_name: str) -> tuple[str, list[str], set[object]]:
        identity = CHECKER.JobIdentity(fixture_name, "fixture-job")
        return self.fixture_root_result((fixture_name,), {identity})

    def assert_fixture_violation(self, fixture_name: str, expected: str) -> None:
        _, violations, _ = self.fixture_result(fixture_name)
        self.assertTrue(
            any(expected in violation for violation in violations),
            f"{fixture_name} did not report {expected!r}: {violations}",
        )

    def normal_job_block(self, job_name: str) -> str:
        return f'''  {job_name}:
    runs-on: ubuntu-26.04
    steps:
      - name: Set up toolchain
        id: setup-python
        uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version-file: '.python-version'
          check-latest: false
      - name: Verify Python interpreter contract
        env:
          EXPECTED_PYTHON: ${{{{ steps.setup-python.outputs.python-path }}}}
        run: python3 -P modules/ModSecurity-test-Framework/connector_suite/modsecurity_connector_ci/checks/common/check-python-interpreter-contract.py --version-file .python-version --expected-python "$EXPECTED_PYTHON"
      - name: Use Python
        run: python3 -c 'print("ok")'
'''

    def candidate_job_block(self) -> str:
        return '''  validate-python-patch:
    runs-on: ubuntu-26.04
    steps:
      - name: Set up candidate Python
        id: setup-python
        uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: ${{ needs.resolve-python-patch.outputs.latest_version }}
          check-latest: false
      - name: Verify Python candidate interpreter contract
        env:
          EXPECTED_VERSION: ${{ needs.resolve-python-patch.outputs.latest_version }}
          EXPECTED_PYTHON: ${{ steps.setup-python.outputs.python-path }}
        run: python3 -P modules/ModSecurity-test-Framework/connector_suite/modsecurity_connector_ci/checks/common/check-python-interpreter-contract.py --expected-version "$EXPECTED_VERSION" --expected-python "$EXPECTED_PYTHON"
      - name: Validate candidate
        run: python3 scripts/update-python-version.py --check
'''

    def immutable_reusable_job_block(self, job_name: str) -> str:
        return f'''  {job_name}:
    uses: {CHECKER.PROTECTED_NGINX_BROKER_REUSABLE_WORKFLOW}
'''

    def local_reusable_caller_block(self, job_name: str, reference: str) -> str:
        return f'''  {job_name}:
    uses: {reference}
'''

    def trusted_system_workflow_fixture(self) -> str:
        wrapper = (ROOT / ".github/workflows" / CHECKER.TRUSTED_SYSTEM_PYTHON_JOB.workflow).read_text()
        recorded_revision = load_framework_revision_pins(ROOT)["framework_sha"]
        prefix = "Easton97-Jens/ModSecurity-test-Framework/.github/workflows/connector-trusted-lighttpd-namespace.yml@"
        recorded_reference = prefix + recorded_revision
        if wrapper.count(recorded_reference) != 1:
            raise AssertionError("fixture requires exactly one canonical Parent-pinned Framework workflow")
        # Only isolated fixture text selects this working Framework's source.
        # The real Parent caller retains its immutable recorded reference.
        return wrapper.replace(recorded_reference, prefix + framework_revision(), 1)

    def write_complete_contract_root(self, root: Path, candidate_override: str | None = None) -> None:
        by_workflow: dict[str, list[str]] = {}
        for identity in sorted(CHECKER.EXPECTED_NORMAL_PYTHON_JOBS):
            by_workflow.setdefault(identity.workflow, []).append(
                self.normal_job_block(identity.job)
            )
        special = CHECKER.CANDIDATE_VALIDATION_JOB
        by_workflow.setdefault(special.workflow, []).append(
            candidate_override if candidate_override is not None else self.candidate_job_block()
        )
        for identity in sorted(CHECKER.EXPECTED_IMMUTABLE_REUSABLE_PYTHON_JOBS):
            by_workflow.setdefault(identity.workflow, []).append(
                self.immutable_reusable_job_block(identity.job)
            )
        for identity, reference in sorted(
            CHECKER.EXPECTED_LOCAL_REUSABLE_PYTHON_CALLERS.items()
        ):
            by_workflow.setdefault(identity.workflow, []).append(
                self.local_reusable_caller_block(identity.job, reference)
            )
        workflows = root / ".github" / "workflows"
        workflows.mkdir(parents=True)
        for workflow, jobs in by_workflow.items():
            (workflows / workflow).write_text(
                "name: generated test workflow\n\non:\n  workflow_dispatch:\n\njobs:\n"
                + "".join(jobs),
                encoding="utf-8",
            )
        wrapper = self.trusted_system_workflow_fixture()
        (workflows / CHECKER.TRUSTED_SYSTEM_PYTHON_JOB.workflow).write_text(wrapper)
        (root / ".python-version").write_text("3.15.6\n", encoding="utf-8")

    def trusted_base_job(self, source: str | None = None):
        if source is None:
            source = (ROOT / ".github/workflows/ci-security-codeql.yml").read_text()
        with self.temporary_root() as directory:
            path = Path(directory) / "ci-security-codeql.yml"
            path.write_text(source)
            jobs, errors = CHECKER.parse_jobs(path)
        self.assertEqual(errors, [])
        return jobs[CHECKER.TRUSTED_BASE_MIGRATION_JOB]

    def test_actual_trusted_base_dual_layout_verifier_is_accepted(self):
        self.assertEqual(CHECKER.validate_normal_job(self.trusted_base_job()), [])

    def test_trusted_base_dual_layout_normalization_retains_exact_shell_lines(self):
        source = (ROOT / ".github/workflows/ci-security-codeql.yml").read_text()
        source = source.replace('          set -eu\n          migrated=',
                                '          # reviewed compatibility boundary\n          set -eu\n          migrated=')
        self.assertEqual(CHECKER.validate_normal_job(self.trusted_base_job(source)), [])

    def test_trusted_base_dual_layout_is_rejected_for_any_other_job(self):
        job = self.trusted_base_job()
        wrong_job = CHECKER.Job(CHECKER.JobIdentity("ci-security-codeql.yml", "traefik-go"),
                                job.indent, job.lines)
        errors = CHECKER.validate_normal_job(wrong_job)
        self.assertTrue(any("verifier must invoke" in error for error in errors), errors)
        self.assertIsNotNone(CHECKER.first_python_use(wrong_job.steps(), wrong_job.identity))

    def test_trusted_base_dual_layout_rejects_every_changed_verifier_boundary(self):
        original = (ROOT / ".github/workflows/ci-security-codeql.yml").read_text()
        mutations = (
            ('migrated=modules/ModSecurity-test-Framework/connector_suite/', 'migrated=../foreign/'),
            ('legacy=ci/checks/common/check-python-interpreter-contract.py', 'legacy=../foreign.py'),
            ('python3 -P "$migrated"', 'python3 -I "$migrated"'),
            ('python3 -I "$legacy"', 'python3 -P "$legacy"'),
            ('"$migrated" --version-file .python-version', '"$migrated" --version-file other-version'),
            ('"$legacy" --version-file .python-version', '"$legacy" --version-file other-version'),
            ('--expected-python "$EXPECTED_PYTHON"', '--expected-python /foreign/python'),
            ('&& [ ! -L "$migrated" ]', '&& [ -e "$migrated" ]'),
            ('&& [ ! -L "$legacy" ]', '&& [ -e "$legacy" ]'),
            ("            exit 1", "            exit 0"),
            ("          fi\n      - id: version", "          fi\n          python3 -c pass\n      - id: version"),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                source = original.replace(old, new, 1)
                self.assertNotEqual(source, original)
                errors = CHECKER.validate_normal_job(self.trusted_base_job(source))
                self.assertTrue(any("verifier must invoke" in error for error in errors), errors)

    def test_trusted_base_dual_layout_requires_the_fixed_base_bootstrap(self):
        original = (ROOT / ".github/workflows/ci-security-codeql.yml").read_text()
        mutations = (
            ('ref: ${{ github.event.pull_request.base.sha || github.sha }}', 'ref: ${{ github.event.pull_request.head.sha || github.sha }}'),
            ('submodules: true', 'submodules: false'),
            ('persist-credentials: false', 'persist-credentials: true'),
            ('revision=$(git rev-parse HEAD:modules/ModSecurity-test-Framework)', 'revision=$(git rev-parse refs/heads/candidate)'),
            ("hashFiles('" + CHECKER.VERIFIER_PATH + "') != ''", 'true'),
            ('EXPECTED_FRAMEWORK_REVISION: ${{ steps.framework-gitlink.outputs.revision }}', 'EXPECTED_FRAMEWORK_REVISION: ${{ github.sha }}'),
        )
        for old, new in mutations:
            with self.subTest(old=old):
                source = original.replace(old, new, 1)
                self.assertNotEqual(source, original)
                errors = CHECKER.validate_normal_job(self.trusted_base_job(source))
                self.assertTrue(any("trusted-base migration" in error for error in errors), errors)

    def test_unproven_trusted_base_context_python_never_gains_order_exemption(self):
        original = (ROOT / ".github/workflows/ci-security-codeql.yml").read_text()
        source = original.replace("--tool connector-context", "--tool unproven-context", 1)
        self.assertNotEqual(source, original)
        errors = CHECKER.validate_normal_job(self.trusted_base_job(source))
        self.assertTrue(any("trusted-base migration" in error for error in errors), errors)
        self.assertTrue(any("first Python use" in error for error in errors), errors)

    def test_trusted_base_body_cannot_hide_an_unnamed_early_python_execution(self):
        original = (ROOT / ".github/workflows/ci-security-codeql.yml").read_text()
        injected = "      - name: Unreviewed early verifier clone\n        run: |\n"
        injected += "".join("          " + line + "\n"
                            for line in CHECKER.TRUSTED_BASE_VERIFIER_COMMAND.splitlines())
        source = original.replace("      - id: setup-python", injected + "      - id: setup-python", 1)
        errors = CHECKER.validate_normal_job(self.trusted_base_job(source))
        self.assertTrue(any("first Python use" in error for error in errors), errors)

    def test_normal_jobs_still_require_the_one_exact_current_verifier_command(self):
        source = self.normal_job_block("fixture-job")
        legacy = 'python3 ci/checks/common/check-python-interpreter-contract.py --version-file .python-version --expected-python "$EXPECTED_PYTHON"'
        source = source.replace(CHECKER.NORMAL_VERIFIER_COMMAND, legacy)
        with self.temporary_root() as directory:
            path = Path(directory) / "fixture.yml"
            path.write_text("jobs:\n" + source)
            jobs, errors = CHECKER.parse_jobs(path)
        self.assertEqual(errors, [])
        errors = CHECKER.validate_normal_job(jobs[CHECKER.JobIdentity("fixture.yml", "fixture-job")])
        self.assertTrue(any("verifier must invoke" in error for error in errors), errors)

    def test_expected_inventory_tracks_normal_and_candidate_jobs(self) -> None:
        self.assertEqual(len(CHECKER.EXPECTED_NORMAL_PYTHON_JOBS), 45)
        self.assertIn(
            CHECKER.JobIdentity("ci-security-workflow-lint.yml", "apr-util-provenance"),
            CHECKER.EXPECTED_NORMAL_PYTHON_JOBS,
        )
        self.assertIn(
            CHECKER.JobIdentity("nginx-root-broker.yml", "trusted-root-smoke"),
            CHECKER.EXPECTED_NORMAL_PYTHON_JOBS,
        )
        for identity in (
            CHECKER.JobIdentity("test-apache.yml", "apache-autotools-bootstrap"),
            CHECKER.JobIdentity("test-haproxy.yml", "haproxy-structure"),
            CHECKER.JobIdentity("update-submodules.yml", "create-submodule-update-pr"),
            CHECKER.JobIdentity("update-workflow-tools.yml", "publisher"),
            CHECKER.JobIdentity("update-workflow-tools.yml", "resolver"),
            CHECKER.JobIdentity("update-workflow-tools.yml", "validator"),
            CHECKER.JobIdentity("verified-report-governance.yml", "report-governance"),
            CHECKER.JobIdentity("sonarqube.yml", "analysis"),
        ):
            with self.subTest(identity=identity):
                self.assertIn(identity, CHECKER.EXPECTED_NORMAL_PYTHON_JOBS)
        self.assertNotIn(
            CHECKER.JobIdentity(
                "verified-report-governance.yml",
                "verified-report-contract-preflight",
            ),
            CHECKER.EXPECTED_NORMAL_PYTHON_JOBS,
        )
        for retired_identity in (
            CHECKER.JobIdentity(
                "check-actions-versions.yml", "check-actions-versions"
            ),
            CHECKER.JobIdentity(
                "update-actions-versions.yml", "update-actions-versions"
            ),
        ):
            with self.subTest(identity=retired_identity):
                self.assertNotIn(
                    retired_identity, CHECKER.EXPECTED_NORMAL_PYTHON_JOBS
                )
        self.assertEqual(
            {
                CHECKER.JobIdentity(
                    "reusable-five-connectors-profile.yml", job_name
                )
                for job_name in ("aggregate", "no-crs", "resolve-profile")
            },
            {
                identity
                for identity in CHECKER.EXPECTED_NORMAL_PYTHON_JOBS
                if identity.workflow == "reusable-five-connectors-profile.yml"
            },
        )
        self.assertEqual(
            CHECKER.EXPECTED_LOCAL_REUSABLE_PYTHON_CALLERS,
            {
                CHECKER.JobIdentity("all-connectors-no-crs.yml", "no-crs"): (
                    "./.github/workflows/reusable-five-connectors-profile.yml"
                )
            },
        )
        self.assertNotIn(
            CHECKER.JobIdentity("all-connectors-no-crs.yml", "aggregate"),
            CHECKER.EXPECTED_NORMAL_PYTHON_JOBS,
        )
        self.assertNotIn(
            CHECKER.JobIdentity("all-connectors-no-crs.yml", "no-crs"),
            CHECKER.EXPECTED_NORMAL_PYTHON_JOBS,
        )
        self.assertNotIn(
            CHECKER.CANDIDATE_VALIDATION_JOB, CHECKER.EXPECTED_NORMAL_PYTHON_JOBS
        )
        self.assertEqual(
            set(CHECKER.EXPECTED_IMMUTABLE_REUSABLE_PYTHON_JOBS),
            {
                CHECKER.JobIdentity(
                    "run-protected-nginx-root-broker.yml", "run-no-crs-broker"
                ),
                CHECKER.JobIdentity(
                    "run-protected-nginx-root-broker.yml", "run-with-crs-broker"
                ),
            },
        )

    def test_valid_yaml_control_is_accepted(self) -> None:
        version, violations, detected = self.fixture_result("valid-control.yaml")
        self.assertEqual(version, "3.15.6")
        self.assertEqual(violations, [])
        self.assertEqual(
            detected, {CHECKER.JobIdentity("valid-control.yaml", "fixture-job")}
        )

    def test_manual_mapping_parser_preserves_the_narrow_contract_shapes(self) -> None:
        self.assertEqual(CHECKER.mapping_entry("with:"), ("with", ""))
        self.assertEqual(
            CHECKER.mapping_entry("run: python3 -c 'print(\"value: preserved\")'"),
            ("run", "python3 -c 'print(\"value: preserved\")'"),
        )
        self.assertEqual(CHECKER.job_header("fixture-job: # comment"), "fixture-job")
        self.assertIsNone(CHECKER.job_header("fixture-job: unexpected-value"))
        self.assertIsNone(CHECKER.mapping_entry("not a mapping"))

    def test_structural_version_and_executable_recognition_remain_ascii_only(self) -> None:
        for version in ("3.15.0", "3.15.1", "3.15.6"):
            with self.subTest(version=version):
                self.assertEqual(version, CHECKER.parse_exact_version(version, "test"))

        dotted_patch = ".".join(("3", "15", "1", "0"))
        for version in ("3.15.01", "3.15.\u0661", dotted_patch, "3.16.1"):
            with self.subTest(version=version), self.assertRaises(
                CHECKER.ContractInputError
            ):
                CHECKER.parse_exact_version(version, "test")

        for command in ("python", "python3.15.6", "pip", "pip3.15"):
            with self.subTest(command=command):
                self.assertTrue(CHECKER.is_python_or_pip_command(command))

        for command in ("python3.15.", "python3.15.\u0661", "pythonx", "pipy"):
            with self.subTest(command=command):
                self.assertFalse(CHECKER.is_python_or_pip_command(command))

    def test_linear_shell_parser_detects_commands_without_text_false_positives(self) -> None:
        self.assertEqual(
            CHECKER.direct_python_or_pip_command(
                "/opt/toolchains/python3.15 -c 'print(\"direct\")'"
            ),
            "python3.15",
        )
        self.assertEqual(
            CHECKER.bare_pip_command("env TOOLCHAIN=checked pip3 --version"),
            "pip3",
        )
        self.assertEqual(CHECKER.python_make_target("make quick-check"), "quick-check")
        self.assertEqual(
            CHECKER.direct_python_or_pip_command(
                "status=$(python3 -c 'print(\"substitution\")')"
            ),
            "python3",
        )
        self.assertIsNone(CHECKER.shell_syntax_error("count=$((count + 1))"))

        harmless = CHECKER.analyze_shell_source(
            """# python3 and pip are comments, not commands.
echo \"python3 -m pip --version\"
cat <<'TEXT'
python3 -m pip --version
TEXT
printf '%s\\n' 'make quick-check'
"""
        )
        self.assertEqual(harmless.errors, ())
        command_names = [
            CHECKER.static_command_basename(command.command)
            for command in harmless.commands
        ]
        self.assertEqual(command_names, ["echo", "cat", "printf"])

    def test_unsupported_or_malformed_shell_syntax_fails_closed(self) -> None:
        self.assertEqual(
            CHECKER.shell_syntax_error('"$PYTHON" --version'),
            "dynamic shell command head is unsupported",
        )
        malformed_error = CHECKER.shell_syntax_error("python3 -c 'unterminated")
        self.assertIsNotNone(malformed_error)
        self.assertIn("unterminated", malformed_error)
        arithmetic_error = CHECKER.shell_syntax_error(
            "count=$(( $(python3 --version) + 1 ))"
        )
        self.assertIsNotNone(arithmetic_error)
        self.assertIn("arithmetic expansion", arithmetic_error)

    def test_missing_setup_is_rejected(self) -> None:
        self.assert_fixture_violation("missing-setup.yml", "must contain exactly one")

    def test_minor_patch_and_floating_selectors_are_rejected(self) -> None:
        for fixture in (
            "wrong-minor.yml",
            "wrong-patch.yml",
            "selector-3x.yml",
            "selector-latest.yml",
            "selector-matrix.yml",
        ):
            with self.subTest(fixture=fixture):
                self.assert_fixture_violation(fixture, "must not use python-version selectors")

    def test_python_and_pip_before_setup_are_rejected(self) -> None:
        for fixture in (
            "python-before-setup.yml",
            "pip-before-setup.yml",
            "python314-before-setup.yml",
            "versioned-python-before-setup.yml",
            "python-command-substitution-before-setup.yml",
        ):
            with self.subTest(fixture=fixture):
                self.assert_fixture_violation(fixture, "first Python use")

    def test_absent_and_non_equivalent_verifiers_are_rejected(self) -> None:
        self.assert_fixture_violation("verifier-absent.yml", "lacks exactly one")
        self.assert_fixture_violation("verifier-not-equivalent.yml", "EXPECTED_PYTHON")

    def test_setup_python_reference_requires_full_sha_and_v710_comment(self) -> None:
        for fixture in (
            "setup-python-mutable-tag.yml",
            "setup-python-short-sha.yml",
            "setup-python-missing-comment.yml",
            "setup-python-wrong-comment.yml",
        ):
            with self.subTest(fixture=fixture):
                self.assert_fixture_violation(
                    fixture,
                    "actions/setup-python must use exactly "
                    "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0",
                )

    def test_bare_pip_and_pip3_are_rejected_after_verified_setup(self) -> None:
        for fixture, command in (
            ("bare-pip.yml", "'pip'"),
            ("bare-pip3.yml", "'pip3'"),
        ):
            with self.subTest(fixture=fixture):
                self.assert_fixture_violation(fixture, f"bare pip command {command}")

    def test_make_inline_heredoc_and_python_module_pip_are_detected(self) -> None:
        for fixture in (
            "make-after-setup.yml",
            "inline-python-heredoc.yml",
            "python-module-pip.yml",
        ):
            with self.subTest(fixture=fixture):
                _, violations, detected = self.fixture_result(fixture)
                self.assertEqual(violations, [], violations)
                self.assertEqual(
                    detected, {CHECKER.JobIdentity(fixture, "fixture-job")}
                )

        self.assert_fixture_violation("make-before-setup.yml", "Make target quick-check")

    def test_python_matrix_axis_is_classified_and_rejected(self) -> None:
        for fixture in (
            "matrix-python-selector.yml",
            "matrix-version-selector.yml",
        ):
            with self.subTest(fixture=fixture):
                _, violations, detected = self.fixture_result(fixture)
                self.assertEqual(
                    detected, {CHECKER.JobIdentity(fixture, "fixture-job")}
                )
                self.assertTrue(
                    any(
                        "Python-related matrix selector" in violation
                        for violation in violations
                    ),
                    violations,
                )

    def test_shell_only_job_is_not_a_python_false_positive(self) -> None:
        _, violations, detected = self.fixture_root_result(
            ("shell-only.yml",), set()
        )
        self.assertEqual(violations, [], violations)
        self.assertEqual(set(), detected)

    def test_multiple_python_jobs_are_inventory_checked_independently(self) -> None:
        expected = {
            CHECKER.JobIdentity("multiple-python-jobs.yml", "python-one"),
            CHECKER.JobIdentity("multiple-python-jobs.yml", "python-two"),
        }
        _, violations, detected = self.fixture_root_result(
            ("multiple-python-jobs.yml",), expected
        )
        self.assertEqual(violations, [], violations)
        self.assertEqual(expected, detected)

    def test_local_reusable_workflow_caller_requires_exact_approved_path(self) -> None:
        callee = CHECKER.JobIdentity("reusable-callee.yml", "callee-python")
        _, safe_violations, safe_detected = self.fixture_root_result(
            ("reusable-callee.yml",), {callee}
        )
        self.assertEqual(safe_violations, [], safe_violations)
        self.assertEqual(safe_detected, {callee})

        caller = CHECKER.JobIdentity("reusable-caller.yml", "call-local-python")
        expected_caller = {caller: "./.github/workflows/reusable-callee.yml"}
        _, violations, detected = self.fixture_root_result(
            ("reusable-callee.yml", "reusable-caller.yml"),
            {callee},
            expected_local_reusable_callers=expected_caller,
        )
        self.assertIn(caller, detected)
        self.assertEqual(violations, [], violations)

        malformed_caller = {caller: "./.github/workflows/other-callee.yml"}
        _, violations, _ = self.fixture_root_result(
            ("reusable-callee.yml", "reusable-caller.yml"),
            {callee},
            expected_local_reusable_callers=malformed_caller,
        )
        self.assertTrue(
            any("must use exactly" in violation for violation in violations), violations
        )

    def test_malformed_canonical_version_is_an_input_error(self) -> None:
        with self.temporary_root() as directory:
            root = Path(directory)
            (root / ".github" / "workflows").mkdir(parents=True)
            shutil.copy2(FIXTURES / "malformed-version.txt", root / ".python-version")
            exit_code, payload = self.cli_json_result(root)
        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["status"], "error")
        self.assertIn("exact Python 3.15.N", payload["violations"][0])

    def test_json_cli_reports_contract_violations_with_exit_one(self) -> None:
        with self.temporary_root() as directory:
            root = Path(directory)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            shutil.copy2(FIXTURES / "missing-setup.yml", workflows / "missing-setup.yml")
            (root / ".python-version").write_text("3.15.6\n", encoding="utf-8")
            exit_code, payload = self.cli_json_result(root)
        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["status"], "violations")
        self.assertTrue(payload["violations"])

    def test_public_cli_rejects_user_controlled_root_and_nonliteral_version_file(self) -> None:
        stderr = io.StringIO()
        argument_parser = CHECKER.parser()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as context:
            argument_parser.parse_args(["--root", "/not-a-repository"])
        self.assertEqual(context.exception.code, 2)

        output = io.StringIO()
        with (
            mock.patch.object(
                CHECKER,
                "repository_root",
                side_effect=AssertionError("repository root must not be resolved"),
            ),
            contextlib.redirect_stdout(output),
        ):
            exit_code = CHECKER.main(
                ["--version-file", "../untrusted-version", "--json"]
            )
        self.assertEqual(exit_code, 2)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["status"], "error")
        self.assertIn("must be exactly", payload["violations"][0])

    def test_public_cli_requires_a_regular_nonsymlink_canonical_version_file(self) -> None:
        with self.temporary_root() as directory:
            root = Path(directory)
            target = root / "version-source"
            target.write_text("3.15.6\n", encoding="utf-8")
            (root / ".python-version").symlink_to(target)
            exit_code, payload = self.cli_json_result(root)
        self.assertEqual(exit_code, 2)
        self.assertIn("must not be a symlink", payload["violations"][0])

        with self.temporary_root() as directory:
            root = Path(directory)
            (root / ".python-version").mkdir()
            exit_code, payload = self.cli_json_result(root)
        self.assertEqual(exit_code, 2)
        self.assertIn("must be a regular file", payload["violations"][0])

    def test_downgrade_requires_explicit_authorization(self) -> None:
        with self.temporary_root() as directory:
            root = Path(directory)
            (root / ".github" / "workflows").mkdir(parents=True)
            version_file = root / ".python-version"
            version_file.write_text("3.15.5\n", encoding="utf-8")
            _, blocked, _ = CHECKER.evaluate_workflow_contract(
                root,
                version_file,
                previous_version="3.15.6",
                expected_normal_jobs=(),
                expected_candidate_job=None,
                expected_immutable_reusable_jobs={},
                expected_system_python_jobs=(),
            )
            _, authorized, _ = CHECKER.evaluate_workflow_contract(
                root,
                version_file,
                previous_version="3.15.6",
                allow_downgrade=True,
                expected_normal_jobs=(),
                expected_candidate_job=None,
                expected_immutable_reusable_jobs={},
                expected_system_python_jobs=(),
            )
        self.assertTrue(any("downgrade" in violation for violation in blocked))
        self.assertEqual(authorized, [])

    def test_special_candidate_job_is_strict_about_expected_outputs(self) -> None:
        malformed = self.candidate_job_block().replace(
            "${{ needs.resolve-python-patch.outputs.latest_version }}",
            "${{ needs.untrusted.outputs.version }}",
            1,
        )
        with self.temporary_root() as directory:
            root = Path(directory)
            self.write_complete_contract_root(root, candidate_override=malformed)
            _, violations, _ = CHECKER.evaluate_workflow_contract(
                root, root / ".python-version"
            )
        self.assertTrue(
            any("candidate setup-python must use exactly" in violation for violation in violations),
            violations,
        )

    def test_dynamic_python_output_alias_remains_fail_closed(self):
        commands = (
            '"$SETUP_PYTHON_PATH" -m pip --version',
            "printf -v SETUP_PYTHON_PATH '%s' /foreign/python; \"$SETUP_PYTHON_PATH\" -c pass",
            'read -r SETUP_PYTHON_PATH; "$SETUP_PYTHON_PATH" -c pass',
            '"$UNKNOWN_PYTHON" -m pip --version',
        )
        for command in commands:
            with self.subTest(command=command), self.temporary_root() as directory:
                root = Path(directory)
                workflows = root / ".github/workflows"
                workflows.mkdir(parents=True)
                source = self.normal_job_block("fixture-job")
                source += ("      - name: Reject dynamic command heads\n        env:\n"
                           f"          SETUP_PYTHON_PATH: {CHECKER.SETUP_PYTHON_OUTPUT}\n"
                           f"        run: |\n          {command}\n")
                (workflows / "fixture.yml").write_text("jobs:\n" + source)
                version = root / ".python-version"
                version.write_text("3.15.1\n")
                _, violations, _ = CHECKER.evaluate_workflow_contract(
                    root, version, expected_normal_jobs={CHECKER.JobIdentity("fixture.yml", "fixture-job")},
                    expected_candidate_job=None, expected_immutable_reusable_jobs={},
                    expected_local_reusable_callers={}, expected_system_python_jobs=())
                self.assertTrue(any("dynamic shell command head is unsupported" in item for item in violations), violations)

    def test_trusted_system_python_requires_the_complete_dedicated_contract(self):
        identity = CHECKER.TRUSTED_SYSTEM_PYTHON_JOB
        original = (test_root() / ".github/workflows/connector-trusted-lighttpd-namespace.yml").read_text()
        wrapper = self.trusted_system_workflow_fixture()
        with self.temporary_root() as directory:
            root = Path(directory)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            path = workflows / identity.workflow
            path.write_text(wrapper)
            for source, valid in ((original, True),
                                  (original.replace("/usr/bin/python3 -m unittest", "/foreign/python -m unittest"), False),
                                  (original.replace("      - id: resolve-target", "      - name: Unreviewed Python execution\n        run: /usr/bin/python3 -c pass\n      - id: resolve-target"), False)):
                with (self.subTest(valid=valid),
                      mock.patch.object(CHECKER, "read_protected_workflow_source", return_value=source),
                      mock.patch.object(workflow_sources, "read_protected_workflow_source", return_value=source)):
                    jobs, errors = CHECKER.parse_jobs(path)
                    self.assertEqual(errors, [])
                    errors = CHECKER.system_python_job_violations(root, jobs, frozenset({identity}))
                    self.assertEqual(not errors, valid, errors)
            unknown = CHECKER.JobIdentity(identity.workflow, "unreviewed-system-python")
            self.assertTrue(CHECKER.system_python_job_violations(root, jobs, frozenset({unknown})))

    def test_local_reusable_reference_accepts_only_fixed_equivalent_paths(self):
        identity = CHECKER.JobIdentity("local.yml", "call-local")
        expected = {identity: "./.github/workflows/reusable-five-connectors-profile.yml"}
        cases = (
            ("./.github/workflows/reusable-five-connectors-profile.yml", True),
            ("$/.github/workflows/reusable-five-connectors-profile.yml", True),
            ("$/.github/workflows/foreign-workflow.yml", False),
            ("${{ inputs.workflow }}", False),
        )
        for reference, valid in cases:
            with self.subTest(reference=reference), self.temporary_root() as directory:
                path = Path(directory) / identity.workflow
                path.write_text("jobs:\n" + self.local_reusable_caller_block(identity.job, reference))
                jobs, errors = CHECKER.parse_jobs(path)
                self.assertEqual(errors, [])
                errors = CHECKER.local_reusable_caller_violations(jobs, expected, {identity})
                self.assertEqual(not errors, valid, errors)

    def test_json_cli_accepts_complete_contract(self) -> None:
        with self.temporary_root() as directory:
            root = Path(directory)
            self.write_complete_contract_root(root)
            exit_code, payload = self.cli_json_result(root)
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["status"], "valid")
        self.assertEqual(len(payload["detected_python_jobs"]), 50)
        expected = set(CHECKER.EXPECTED_NORMAL_PYTHON_JOBS)
        expected.add(CHECKER.CANDIDATE_VALIDATION_JOB)
        expected.update(CHECKER.EXPECTED_IMMUTABLE_REUSABLE_PYTHON_JOBS)
        expected.update(CHECKER.EXPECTED_LOCAL_REUSABLE_PYTHON_CALLERS)
        expected.update(CHECKER.EXPECTED_SYSTEM_PYTHON_JOBS)
        self.assertEqual(set(payload["detected_python_jobs"]),
                         {identity.display() for identity in expected})


class WorkflowActionPinsTest(unittest.TestCase):
    def lock(self, root: Path, version: str = "v7.1.0", sha: str = "a" * 40) -> Path:
        path = root / ACTION_PINS.LOCK_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('schema_version: 1\nchecked_at: "2026-10-24"\npinned_actions:\n  actions/setup-python:\n'
                        f"    version: {version}\n    commit_sha: {sha}\n"
                        "    upstream: https://github.com/actions/setup-python\ntools:\ndispositions:\n")
        return path

    def test_reviewed_action_update_changes_the_exact_reference(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for version, sha in (("v7.1.0", "a" * 40), ("v7.2.0", "b" * 40), ("v10", "c" * 40)):
                self.lock(root, version, sha)
                self.assertEqual(ACTION_PINS.read_action_reference(root, "actions/setup-python"),
                                 f"actions/setup-python@{sha} # {version}")

    def test_ambiguous_or_nonimmutable_action_records_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.lock(root)
            valid = path.read_text()
            mutations = (
                valid.replace("    version: v7.1.0", "    version: v7.1.0\n    version: v7.2.0"),
                valid.replace("tools:\n", "  actions/setup-python:\ntools:\n", 1),
                valid.replace("v7.1.0", "v7.1.0rc1"),
                valid.replace("a" * 40, "a" * 16),
                valid.replace("https://github.com/actions/setup-python", "https://mirror.invalid/actions/setup-python"),
                valid.replace("    version:", "    alias:"),
                valid + "pinned_actions:\n",
                valid.replace("v7.1.0", "*untrusted"),
                valid + "pinned_actions: {}\n",
                valid + '"pinned_actions": {}\n',
                valid + "pinned_actions: &shadow {}\n",
                valid + "---\npinned_actions: {}\n",
            )
            for content in mutations:
                with self.subTest(content=content):
                    path.write_text(content)
                    with self.assertRaises(ACTION_PINS.ActionPinsError):
                        ACTION_PINS.read_action_reference(root, "actions/setup-python")

    def test_unsafe_action_lock_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self.lock(root)
            for data in (b"\xff", b" " * (ACTION_PINS.MAX_LOCK_BYTES + 1), b"pinned_actions:\n"):
                with self.subTest(data=data[:20]):
                    path.write_bytes(data)
                    with self.assertRaises(ACTION_PINS.ActionPinsError):
                        ACTION_PINS.read_action_reference(root, "actions/setup-python")
            path.unlink()
            path.symlink_to(ROOT / ACTION_PINS.LOCK_PATH)
            with self.assertRaises(ACTION_PINS.ActionPinsError):
                ACTION_PINS.read_action_reference(root, "actions/setup-python")

    def test_missing_action_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.lock(root)
            with self.assertRaises(ACTION_PINS.ActionPinsError):
                ACTION_PINS.read_action_reference(root, "actions/setup-go")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
