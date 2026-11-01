"""Regression tests for explicit optional-prerequisite CI status handling."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import ast
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

from modsecurity_connector_tests.framework_test_trust import trusted_framework_root


ROOT = connector_root()
STATUS_RUNNER = source_path('ci/tools/run-check-status.py', root=ROOT)
MAKEFILE = source_path('Makefile', root=ROOT)
MAKE = shutil.which("make")
SYNTHETIC_CHECK = "synthetic_apache_dependent_check"


def temporary_directory() -> tempfile.TemporaryDirectory[str]:
    """Keep synthetic fixtures below the configured external temporary root."""
    parent_value = os.environ.get("CODEX_TEMP_ROOT") or os.environ.get("RUNNER_TEMP")
    if parent_value:
        parent = Path(parent_value) / "test-optional-prerequisite-status"
        parent.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(prefix="case-", dir=parent)
    return tempfile.TemporaryDirectory(prefix="optional-prerequisite-status-")


def write_executable(path: Path, content: str) -> None:
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def isolated_make_environment(environment: dict[str, str]) -> dict[str, str]:
    """Keep outer Make assignments from overriding deliberate fixture bindings."""
    result = environment.copy()
    for variable in ("MAKEFLAGS", "MAKEOVERRIDES", "MFLAGS", "GNUMAKEFLAGS"):
        result.pop(variable, None)
    return result


class OptionalPrerequisiteStatusTests(unittest.TestCase):
    maxDiff = None

    def make_fixture(self, temporary: Path, apxs_present: bool) -> tuple[Path, dict[str, str]]:
        bin_dir = temporary / "bin"
        bin_dir.mkdir()
        if apxs_present:
            include_dir = temporary / "apache-include"
            include_dir.mkdir()
            (include_dir / "httpd.h").write_text("/* synthetic Apache header */\n", encoding="utf-8")
            write_executable(
                bin_dir / "apxs",
                f"""
                #!/bin/sh
                if [ "$1" = "-q" ] && [ "$2" = "INCLUDEDIR" ]; then
                    printf '%s\\n' {shlex.quote(str(include_dir))}
                    exit 0
                fi
                exit 2
                """,
            )
        dependent = temporary / "dependent-check"
        write_executable(
            dependent,
            """
            #!/bin/sh
            if ! command -v apxs >/dev/null 2>&1; then
                echo "CHECK_STATUS_REASON apache_development_prerequisite" >&2
                echo "BLOCKED: synthetic dependent check missing apxs" >&2
                exit 77
            fi
            case "${DEPENDENT_CHECK_MODE:-pass}" in
                pass)
                    exit 0
                    ;;
                fail)
                    echo "FAIL: synthetic dependent check failed" >&2
                    exit 23
                    ;;
                unknown)
                    echo "FAIL: synthetic dependent check returned an unknown code" >&2
                    exit 41
                    ;;
                unapproved-blocked)
                    echo "CHECK_STATUS_REASON framework_unavailable" >&2
                    echo "BLOCKED: synthetic dependent check missing Framework" >&2
                    exit 77
                    ;;
                spoof-approved-blocked-stderr)
                    echo "CHECK_STATUS_REASON apache_development_prerequisite" >&2
                    exit 77
                    ;;
                spoof-approved-blocked-stdout)
                    echo "CHECK_STATUS_REASON apache_development_prerequisite"
                    exit 77
                    ;;
            esac
            exit 99
            """,
        )
        environment = os.environ.copy()
        environment["PATH"] = str(bin_dir)
        return dependent, environment

    def run_status_runner(
        self,
        build_root: Path,
        dependent: Path | None,
        environment: dict[str, str],
        *options: str,
        check: str = SYNTHETIC_CHECK,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        environment = environment.copy()
        environment["BUILD_ROOT"] = str(build_root)
        status_file = self.status_file(build_root, check)
        command = [
            sys.executable,
            str(STATUS_RUNNER),
            "--check",
            check,
            *options,
        ]
        if dependent is not None:
            command.extend(["--", str(dependent)])
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        return result, json.loads(status_file.read_text(encoding="utf-8"))

    @staticmethod
    def status_file(build_root: Path, check: str) -> Path:
        return build_root / "check-status" / f"{check.replace('_', '-')}.json"

    @staticmethod
    def status_runner_command(
        check: str, dependent: Path | None, *options: str
    ) -> tuple[str, ...]:
        command = (sys.executable, str(STATUS_RUNNER), "--check", check, *options)
        if dependent is None:
            return command
        return (*command, "--", str(dependent))

    def run_runner_without_record(
        self, environment: dict[str, str], *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(STATUS_RUNNER), *arguments],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )

    def test_parent_apache_candidate_resolution_has_one_canonical_return(
        self,
    ) -> None:
        module = ast.parse(STATUS_RUNNER.read_text(encoding="utf-8"))
        functions = [
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "apache_development_candidates"
        ]

        self.assertEqual(len(functions), 1)
        returns = [
            node
            for node in ast.walk(functions[0])
            if isinstance(node, ast.Return)
        ]

        self.assertEqual(len(returns), 1)
        self.assertIsInstance(returns[0].value, ast.Name)
        self.assertEqual(returns[0].value.id, "candidates")

    def test_configured_apxs_candidate_is_a_valid_parent_preflight(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            _, environment = self.make_fixture(temporary, apxs_present=True)
            dependent = temporary / "dependent-pass"
            write_executable(dependent, "#!/bin/sh\nexit 0\n")
            environment["PATH"] = ""
            environment.pop("APXS_BIN", None)
            environment.pop("APXS", None)
            environment["CI_APXS_BIN_CANDIDATES"] = str(temporary / "bin" / "apxs")
            result, record = self.run_status_runner(
                temporary / "build",
                dependent,
                environment,
                "--allow-blocked-reason",
                "apache_development_prerequisite",
                "--blocked-if-missing-apache-development",
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record["status"], "passed")
        self.assertEqual(record["status_source"], "child_exit_code")

    def test_present_apxs_and_successful_dependent_check_passes(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            dependent, environment = self.make_fixture(temporary, apxs_present=True)
            result, record = self.run_status_runner(
                temporary / "build",
                dependent,
                environment,
                "--allow-blocked-reason",
                "apache_development_prerequisite",
                "--blocked-if-missing-apache-development",
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record["status"], "passed")
        self.assertEqual(record["command_exit_code"], 0)
        self.assertEqual(record["workflow_exit_code"], 0)
        self.assertFalse(record["allowed_by_contract"])
        self.assertEqual(record["status_source"], "child_exit_code")

    def test_present_apxs_and_real_dependent_failure_remains_failed(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            dependent, environment = self.make_fixture(temporary, apxs_present=True)
            environment["DEPENDENT_CHECK_MODE"] = "fail"
            result, record = self.run_status_runner(
                temporary / "build", dependent, environment
            )

        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["command_exit_code"], 23)
        self.assertEqual(record["workflow_exit_code"], 23)
        self.assertFalse(record["allowed_by_contract"])

    def test_missing_optional_apxs_is_blocked_but_explicitly_allowed(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            dependent, environment = self.make_fixture(temporary, apxs_present=False)
            result, record = self.run_status_runner(
                temporary / "build",
                dependent,
                environment,
                "--allow-blocked-reason",
                "apache_development_prerequisite",
                "--blocked-if-missing-apache-development",
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("CHECK_STATUS_REASON", result.stdout + result.stderr)
        self.assertIn("CHECK_STATUS", result.stdout)
        self.assertEqual(record["status"], "blocked")
        self.assertIsNone(record["command_exit_code"])
        self.assertEqual(record["reason"], "apache_development_prerequisite")
        self.assertEqual(record["workflow_exit_code"], 0)
        self.assertTrue(record["allowed_by_contract"])
        self.assertEqual(record["status_source"], "parent_preflight")

    @unittest.skipIf(MAKE is None, "GNU Make is required by the repository")
    def test_missing_mandatory_apxs_remains_red_through_make(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            dependent, environment = self.make_fixture(temporary, apxs_present=False)
            build_root = temporary / "build"
            environment["BUILD_ROOT"] = str(build_root)
            status_file = self.status_file(build_root, "mandatory_apache_dependent_check")
            makefile = temporary / "Makefile"
            command = " ".join(
                shlex.quote(part)
                for part in self.status_runner_command(
                    "mandatory_apache_dependent_check", dependent
                )
            )
            makefile.write_text(f"mandatory:\n\t{command}\n", encoding="utf-8")
            result = subprocess.run(
                [MAKE, "-f", str(makefile), "mandatory"],
                cwd=temporary,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=isolated_make_environment(environment),
            )
            record = json.loads(status_file.read_text(encoding="utf-8"))

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(record["status"], "blocked")
        self.assertEqual(record["command_exit_code"], 77)
        self.assertEqual(record["reason"], "unclassified direct blocked exit code 77")
        self.assertEqual(record["workflow_exit_code"], 77)
        self.assertFalse(record["allowed_by_contract"])
        self.assertEqual(record["status_source"], "child_exit_code")

    def test_unapproved_blocked_reason_remains_nonzero(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            dependent, environment = self.make_fixture(temporary, apxs_present=True)
            environment["DEPENDENT_CHECK_MODE"] = "unapproved-blocked"
            result, record = self.run_status_runner(
                temporary / "build",
                dependent,
                environment,
                "--allow-blocked-reason",
                "apache_development_prerequisite",
            )

        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertEqual(record["status"], "blocked")
        self.assertEqual(record["reason"], "unclassified direct blocked exit code 77")
        self.assertEqual(record["workflow_exit_code"], 77)
        self.assertFalse(record["allowed_by_contract"])
        self.assertEqual(record["status_source"], "child_exit_code")

    def test_child_stderr_marker_cannot_authorize_an_allowed_block(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            dependent, environment = self.make_fixture(temporary, apxs_present=True)
            environment["DEPENDENT_CHECK_MODE"] = "spoof-approved-blocked-stderr"
            result, record = self.run_status_runner(
                temporary / "build",
                dependent,
                environment,
                "--allow-blocked-reason",
                "apache_development_prerequisite",
            )

        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertEqual(record["status"], "blocked")
        self.assertEqual(record["reason"], "unclassified direct blocked exit code 77")
        self.assertEqual(record["workflow_exit_code"], 77)
        self.assertFalse(record["allowed_by_contract"])
        self.assertEqual(record["status_source"], "child_exit_code")

    def test_child_stdout_marker_cannot_authorize_an_allowed_block(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            dependent, environment = self.make_fixture(temporary, apxs_present=True)
            environment["DEPENDENT_CHECK_MODE"] = "spoof-approved-blocked-stdout"
            result, record = self.run_status_runner(
                temporary / "build",
                dependent,
                environment,
                "--allow-blocked-reason",
                "apache_development_prerequisite",
            )

        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertEqual(record["status"], "blocked")
        self.assertEqual(record["reason"], "unclassified direct blocked exit code 77")
        self.assertEqual(record["workflow_exit_code"], 77)
        self.assertFalse(record["allowed_by_contract"])
        self.assertEqual(record["status_source"], "child_exit_code")

    @unittest.skipIf(MAKE is None, "GNU Make is required by the repository")
    def test_recursive_make_keeps_the_persisted_blocked_classification(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            dependent, environment = self.make_fixture(temporary, apxs_present=False)
            build_root = temporary / "build"
            environment["BUILD_ROOT"] = str(build_root)
            status_file = self.status_file(build_root, "optional_apache_dependent_check")
            inner = temporary / "inner.mk"
            outer = temporary / "outer.mk"
            command = " ".join(
                shlex.quote(part)
                for part in self.status_runner_command(
                    "optional_apache_dependent_check",
                    dependent,
                    "--allow-blocked-reason",
                    "apache_development_prerequisite",
                    "--blocked-if-missing-apache-development",
                )
            )
            inner.write_text(f"optional:\n\t{command}\n", encoding="utf-8")
            outer.write_text(
                f"MAKE := {shlex.quote(MAKE)}\nouter:\n\t$(MAKE) -f {shlex.quote(str(inner))} optional\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [MAKE, "-f", str(outer), "outer"],
                cwd=temporary,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=isolated_make_environment(environment),
            )
            record = json.loads(status_file.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(record["status"], "blocked")
        self.assertIsNone(record["command_exit_code"])
        self.assertEqual(record["workflow_exit_code"], 0)
        self.assertEqual(record["status_source"], "parent_preflight")

    @unittest.skipIf(MAKE is None, "GNU Make is required by the repository")
    def test_lint_target_rejects_an_unclassified_framework_block(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            build_root = temporary / "build"
            status_file = self.status_file(
                build_root, "apache_request_transaction_cleanup"
            )
            environment = os.environ.copy()
            environment["FRAMEWORK_ROOT"] = str(temporary / "missing-framework")
            environment["BUILD_ROOT"] = str(build_root)
            environment["PYTHON"] = sys.executable
            include_dir = temporary / "apache-include"
            include_dir.mkdir()
            (include_dir / "httpd.h").write_text("/* synthetic Apache header */\n", encoding="utf-8")
            apxs = temporary / "apxs"
            write_executable(
                apxs,
                f"""
                #!/bin/sh
                if [ "$1" = "-q" ] && [ "$2" = "INCLUDEDIR" ]; then
                    printf '%s\\n' {shlex.quote(str(include_dir))}
                    exit 0
                fi
                exit 2
                """,
            )
            environment["APXS"] = str(apxs)
            environment.pop("APXS_BIN", None)
            result = subprocess.run(
                [MAKE, "--no-print-directory", "check-apache-request-transaction-cleanup-lint"],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=isolated_make_environment(environment),
            )
            record = json.loads(status_file.read_text(encoding="utf-8"))

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("missing framework common.sh", result.stderr)
        self.assertEqual(record["status"], "blocked")
        self.assertEqual(record["reason"], "unclassified direct blocked exit code 77")
        self.assertEqual(record["workflow_exit_code"], 77)
        self.assertFalse(record["allowed_by_contract"])
        self.assertEqual(record["status_source"], "child_exit_code")

    def test_unknown_exit_code_remains_a_failure(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            dependent, environment = self.make_fixture(temporary, apxs_present=True)
            environment["DEPENDENT_CHECK_MODE"] = "unknown"
            result, record = self.run_status_runner(
                temporary / "build",
                dependent,
                environment,
                "--allow-blocked-reason",
                "apache_development_prerequisite",
            )

        self.assertEqual(result.returncode, 41, result.stderr)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["command_exit_code"], 41)
        self.assertEqual(record["workflow_exit_code"], 41)
        self.assertFalse(record["allowed_by_contract"])

    @unittest.skipIf(MAKE is None, "GNU Make is required by the repository")
    def assert_independent_recipe_remains_failed(
        self, recipe_name: str, recipe_exit_code: int
    ) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            dependent, environment = self.make_fixture(temporary, apxs_present=False)
            build_root = temporary / "build"
            environment["BUILD_ROOT"] = str(build_root)
            status_file = self.status_file(build_root, "optional_apache_dependent_check")
            makefile = temporary / "Makefile"
            command = " ".join(
                shlex.quote(part)
                for part in self.status_runner_command(
                    "optional_apache_dependent_check",
                    dependent,
                    "--allow-blocked-reason",
                    "apache_development_prerequisite",
                    "--blocked-if-missing-apache-development",
                )
            )
            makefile.write_text(
                f"all: optional {recipe_name}\n\noptional:\n\t{command}\n\n"
                f"{recipe_name}:\n\t@exit {recipe_exit_code}\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [MAKE, "-f", str(makefile), "all"],
                cwd=temporary,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=isolated_make_environment(environment),
            )
            record = json.loads(status_file.read_text(encoding="utf-8"))

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(record["status"], "blocked")
        self.assertTrue(record["allowed_by_contract"])
        self.assertIn(f"Error {recipe_exit_code}", result.stderr)

    @unittest.skipIf(MAKE is None, "GNU Make is required by the repository")
    def test_other_common_check_is_not_skipped_after_optional_block(self) -> None:
        self.assert_independent_recipe_remains_failed("common", 19)

    @unittest.skipIf(MAKE is None, "GNU Make is required by the repository")
    def test_other_connector_check_is_not_skipped_after_optional_block(self) -> None:
        self.assert_independent_recipe_remains_failed("connector", 29)

    def test_explicit_non_execution_statuses_follow_the_documented_contract(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            environment = os.environ.copy()
            not_applicable_result, not_applicable_record = self.run_status_runner(
                temporary / "not-applicable-build",
                None,
                environment,
                "--allow-not-applicable",
                "--not-applicable",
                "synthetic scope excludes this path",
            )
            not_executed_result, not_executed_record = self.run_status_runner(
                temporary / "not-executed-build",
                None,
                environment,
                "--not-executed",
                "synthetic command was deliberately not started",
            )

        self.assertEqual(not_applicable_result.returncode, 0, not_applicable_result.stderr)
        self.assertEqual(not_applicable_record["status"], "not_applicable")
        self.assertTrue(not_applicable_record["allowed_by_contract"])
        self.assertNotEqual(not_executed_result.returncode, 0)
        self.assertEqual(not_executed_record["status"], "not_executed")
        self.assertFalse(not_executed_record["allowed_by_contract"])

    def test_status_writer_rejects_missing_checkout_and_noncanonical_build_roots(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            arguments = (
                "--check",
                SYNTHETIC_CHECK,
                "--not-applicable",
                "synthetic scope excludes this path",
            )

            missing_root_environment = os.environ.copy()
            missing_root_environment.pop("BUILD_ROOT", None)
            missing_root = self.run_runner_without_record(
                missing_root_environment, *arguments
            )

            checkout_root_environment = os.environ.copy()
            checkout_root_environment["BUILD_ROOT"] = str(ROOT)
            checkout_root = self.run_runner_without_record(
                checkout_root_environment, *arguments
            )

            noncanonical_root_environment = os.environ.copy()
            noncanonical_root_environment["BUILD_ROOT"] = str(
                temporary / "build" / ".." / "escaped"
            )
            noncanonical_root = self.run_runner_without_record(
                noncanonical_root_environment, *arguments
            )

        self.assertEqual(missing_root.returncode, 2)
        self.assertIn("BUILD_ROOT must be set", missing_root.stderr)
        self.assertEqual(checkout_root.returncode, 2)
        self.assertIn("must stay outside the checkout", checkout_root.stderr)
        self.assertEqual(noncanonical_root.returncode, 2)
        self.assertIn("absolute canonical path", noncanonical_root.stderr)
        self.assertFalse((source_path('check-status', root=ROOT)).exists())

    def test_status_writer_rejects_symlinked_root_and_status_file(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            arguments = (
                "--check",
                SYNTHETIC_CHECK,
                "--not-applicable",
                "synthetic scope excludes this path",
            )
            external_parent = temporary / "external-parent"
            external_parent.mkdir()
            linked_build_root = temporary / "linked-build-root"
            linked_build_root.symlink_to(external_parent, target_is_directory=True)
            linked_root_environment = os.environ.copy()
            linked_root_environment["BUILD_ROOT"] = str(linked_build_root)
            linked_root = self.run_runner_without_record(
                linked_root_environment, *arguments
            )

            build_root = temporary / "build"
            status_file = self.status_file(build_root, SYNTHETIC_CHECK)
            status_file.parent.mkdir(parents=True)
            protected_file = temporary / "protected.json"
            protected_file.write_text("unchanged\n", encoding="utf-8")
            status_file.symlink_to(protected_file)
            target_environment = os.environ.copy()
            target_environment["BUILD_ROOT"] = str(build_root)
            symlinked_target = self.run_runner_without_record(
                target_environment, *arguments
            )
            linked_parent_created = (external_parent / "check-status").exists()
            protected_contents = protected_file.read_text(encoding="utf-8")

        self.assertEqual(linked_root.returncode, 2)
        self.assertIn("must not use symbolic links", linked_root.stderr)
        self.assertFalse(linked_parent_created)
        self.assertEqual(symlinked_target.returncode, 2)
        self.assertIn("status file must not be a symlink", symlinked_target.stderr)
        self.assertEqual(protected_contents, "unchanged\n")

    def test_status_writer_has_no_arbitrary_status_file_or_check_path_interface(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            protected_file = temporary / "protected.json"
            protected_file.write_text("unchanged\n", encoding="utf-8")
            environment = os.environ.copy()
            environment["BUILD_ROOT"] = str(temporary / "build")
            legacy_path = self.run_runner_without_record(
                environment,
                "--check",
                SYNTHETIC_CHECK,
                "--status-file",
                str(protected_file),
                "--not-applicable",
                "synthetic scope excludes this path",
            )
            path_like_check = self.run_runner_without_record(
                environment,
                "--check",
                "../../outside",
                "--not-applicable",
                "synthetic scope excludes this path",
            )
            protected_contents = protected_file.read_text(encoding="utf-8")

        self.assertEqual(legacy_path.returncode, 2)
        self.assertIn("unrecognized arguments: --status-file", legacy_path.stderr)
        self.assertEqual(path_like_check.returncode, 2)
        self.assertIn("--check must use lowercase letters", path_like_check.stderr)
        self.assertEqual(protected_contents, "unchanged\n")

    def test_status_writer_keeps_its_open_directory_after_child_path_swap(self) -> None:
        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            build_root = temporary / "build"
            replaced_build_root = temporary / "build-original"
            external_root = temporary / "external-root"
            protected_status_file = self.status_file(external_root, SYNTHETIC_CHECK)
            protected_status_file.parent.mkdir(parents=True)
            protected_status_file.write_text("unchanged\n", encoding="utf-8")
            child = temporary / "replace-build-root"
            write_executable(
                child,
                """
                #!/bin/sh
                set -eu
                mv "$BUILD_ROOT" "$REPLACED_BUILD_ROOT"
                ln -s "$EXTERNAL_BUILD_ROOT" "$BUILD_ROOT"
                """,
            )
            environment = os.environ.copy()
            environment["BUILD_ROOT"] = str(build_root)
            environment["REPLACED_BUILD_ROOT"] = str(replaced_build_root)
            environment["EXTERNAL_BUILD_ROOT"] = str(external_root)
            result = self.run_runner_without_record(
                environment, "--check", SYNTHETIC_CHECK, "--", str(child)
            )
            anchored_status_file = self.status_file(
                replaced_build_root, SYNTHETIC_CHECK
            )
            build_root_replaced = build_root.is_symlink()
            protected_contents = protected_status_file.read_text(encoding="utf-8")
            anchored_record = json.loads(anchored_status_file.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(build_root_replaced)
        self.assertEqual(protected_contents, "unchanged\n")
        self.assertEqual(anchored_record["status"], "passed")

    @unittest.skipIf(MAKE is None, "GNU Make is required by the repository")
    def test_lint_target_uses_parent_apache_development_preflight(self) -> None:
        makefile = MAKEFILE.read_text(encoding="utf-8")
        target = makefile.split("check-apache-request-transaction-cleanup-lint:\n", 1)[1].split(
            "\n\n", 1
        )[0]
        self.assertIn("ci/tools/run-check-status.py", target)
        self.assertIn(
            "--allow-blocked-reason apache_development_prerequisite", target
        )
        self.assertIn("--blocked-if-missing-apache-development", target)
        self.assertNotIn("--status-file", target)
        self.assertIn("check-apache-request-transaction-cleanup.sh", target)
        self.assertNotIn("$(MAKE)", target)
        cleanup_check = (
            source_path('ci/checks/connectors/apache/check-apache-request-transaction-cleanup.sh', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertNotIn("CHECK_STATUS_REASON", cleanup_check)

        with temporary_directory() as temporary_name:
            temporary = Path(temporary_name)
            build_root = temporary / "build"
            status_file = self.status_file(
                build_root, "apache_request_transaction_cleanup"
            )
            include_dir = temporary / "apache-include"
            include_dir.mkdir()
            apxs_without_headers = temporary / "apxs-without-headers"
            write_executable(
                apxs_without_headers,
                f"""
                #!/bin/sh
                if [ \"$1\" = \"-q\" ] && [ \"$2\" = \"INCLUDEDIR\" ]; then
                    printf '%s\\n' {shlex.quote(str(include_dir))}
                fi
                """,
            )
            environment = os.environ.copy()
            environment.pop("APXS_BIN", None)
            environment["APXS"] = str(apxs_without_headers)
            framework_root, error = trusted_framework_root(
                ROOT,
                Path(
                    os.environ.get(
                        "PARENT_TEST_FRAMEWORK_ROOT",
                        source_path('modules/ModSecurity-test-Framework', root=ROOT),
                    )
                ),
            )
            if framework_root is None:
                self.skipTest(error)
            environment["FRAMEWORK_ROOT"] = str(framework_root)
            environment["BUILD_ROOT"] = str(build_root)
            environment["CONNECTOR_COMPONENT_CACHE"] = str(temporary / "component-cache")
            environment["CI_APXS_BIN_CANDIDATES"] = "synthetic-no-apxs"
            environment["CC"] = sys.executable
            environment["PYTHON"] = sys.executable
            result = subprocess.run(
                [MAKE, "--no-print-directory", "check-apache-request-transaction-cleanup-lint"],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=isolated_make_environment(environment),
            )
            record = json.loads(status_file.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("CHECK_STATUS_REASON", result.stdout + result.stderr)
        self.assertEqual(record["status"], "blocked")
        self.assertEqual(record["reason"], "apache_development_prerequisite")
        self.assertIsNone(record["command_exit_code"])
        self.assertEqual(record["workflow_exit_code"], 0)
        self.assertTrue(record["allowed_by_contract"])
        self.assertEqual(record["status_source"], "parent_preflight")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
