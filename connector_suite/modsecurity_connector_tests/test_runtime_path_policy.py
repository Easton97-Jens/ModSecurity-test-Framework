from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import ModuleType
import unittest


ROOT = connector_root()
CHECKER = source_path('ci/checks/security/check-runtime-path-policy.py', root=ROOT)
CI_LIB = source_path('ci/lib', root=ROOT)


from modsecurity_connector_ci.lib.runtime_path_utils import default_verified_run_root, is_allowed_runtime_path, is_system_write_path, fixed_runtime_temp_parent, verified_runtime_paths


def load_checker() -> ModuleType:
    checker = load_source(CHECKER)
    return checker


class RuntimePathPolicyTest(unittest.TestCase):
    def test_mutable_project_roots_cannot_authorize_system_runtime_paths(self) -> None:
        """Project-location inputs must never turn system paths into runtime roots."""
        with tempfile.TemporaryDirectory(prefix="runtime-path-policy-control-") as temporary:
            safe_run_root = Path(temporary) / "verified-run"
            poisoned_env = {
                "VERIFIED_RUN_ROOT": str(safe_run_root),
                "REPO_ROOT": "/",
                "CONNECTOR_ROOT": "/",
                "FRAMEWORK_ROOT": "/",
            }

            for attempted_path in (Path("/etc/evidence-escape"), Path("/root/evidence-escape")):
                with self.subTest(attempted_path=attempted_path):
                    self.assertTrue(is_system_write_path(attempted_path, poisoned_env))
                    self.assertFalse(is_allowed_runtime_path(attempted_path, poisoned_env))

            safe_control = safe_run_root / "build" / "apache" / "control-run"
            self.assertFalse(is_system_write_path(safe_control, poisoned_env))
            self.assertTrue(is_allowed_runtime_path(safe_control, poisoned_env))

    def test_broad_runner_parent_cannot_expand_runtime_allowlist(self) -> None:
        """A broad RUNNER_TEMP or TMPDIR value must not authorize arbitrary descendants."""
        with tempfile.TemporaryDirectory(prefix="runtime-path-policy-control-") as temporary:
            env = {
                "VERIFIED_RUN_ROOT": str(Path(temporary) / "verified-run"),
                "RUNNER_TEMP": "/",
                "TMPDIR": "/",
            }

            self.assertFalse(is_allowed_runtime_path(Path("/etc/evidence-escape"), env))
            self.assertFalse(is_allowed_runtime_path(Path("/root/evidence-escape"), env))
            self.assertEqual(
                fixed_runtime_temp_parent() / "ModSecurity-conector-verified",
                default_verified_run_root(env),
            )

    def test_verified_runtime_paths_reject_broad_or_system_writable_roots(self) -> None:
        """Runtime paths must remain narrow external locations, never broad/system roots."""
        with tempfile.TemporaryDirectory(prefix="runtime-path-policy-control-") as temporary:
            safe_run_root = Path(temporary) / "verified-run"
            broad_root_env = {"VERIFIED_RUN_ROOT": "/"}
            direct_root_env = {"VERIFIED_RUN_ROOT": "/runtime-escape"}
            system_build_env = {
                "VERIFIED_RUN_ROOT": str(safe_run_root),
                "BUILD_ROOT": "/etc/evidence-escape",
            }
            system_source_env = {
                "VERIFIED_RUN_ROOT": str(safe_run_root),
                "SOURCE_ROOT": "/etc/evidence-escape",
            }
            with self.assertRaises(ValueError):
                verified_runtime_paths(broad_root_env)
            with self.assertRaises(ValueError):
                verified_runtime_paths(direct_root_env)
            with self.assertRaises(ValueError):
                verified_runtime_paths(system_build_env)
            with self.assertRaises(ValueError):
                verified_runtime_paths(system_source_env)

            external_build_root = safe_run_root.parent / "separate-safe-build-root"
            external_matrix_root = fixed_runtime_temp_parent() / "codex/ModSecurity-conector/matrix"
            safe_external_env = {
                "VERIFIED_RUN_ROOT": str(safe_run_root),
                "BUILD_ROOT": str(external_build_root),
                "MATRIX_ROOT": str(external_matrix_root),
            }
            paths = verified_runtime_paths(safe_external_env)
            self.assertEqual(str(external_build_root), paths["BUILD_ROOT"])
            self.assertEqual(str(external_matrix_root), paths["MATRIX_ROOT"])

    def test_python_path_policy_selftest_accepts_only_writable_run_paths(self) -> None:
        """The reusable Python policy distinguishes runtime writes from source reads."""
        checker = load_checker()
        checker.check_python_policy()

    def test_explicit_build_root_cannot_be_overridden_by_environment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runtime-path-override-") as temporary:
            parent = Path(temporary)
            run_root = parent / "verified-run"
            explicit = parent / "explicit-build"
            inherited = parent / "inherited-build"
            paths = verified_runtime_paths(
                {
                    "VERIFIED_RUN_ROOT": str(run_root),
                    "BUILD_ROOT": str(inherited),
                },
                build_root_override=explicit,
            )

            self.assertEqual(str(explicit.resolve()), paths["BUILD_ROOT"])

    def test_policy_environment_uses_only_the_verified_run_root_for_temp_controls(self) -> None:
        """Self-test child processes cannot inherit broad public temp directories."""
        checker = load_checker()
        environment = checker.policy_environment()
        self.assertEqual(str(checker.VERIFIED_ROOT), environment["RUNNER_TEMP"])
        self.assertEqual(str(checker.VERIFIED_ROOT), environment["TMPDIR"])
        self.assertNotIn("/tmp", (environment["RUNNER_TEMP"], environment["TMPDIR"]))
        self.assertNotIn("/tmp/runner-temp", (environment["RUNNER_TEMP"], environment["TMPDIR"]))
        self.assertEqual(
            checker.VERIFIED_ROOT / "runtime-policy-control",
            checker.RUNTIME_POLICY_CONTROL_ROOT,
        )

    def test_shell_policy_allows_framework_to_reject_source_roots_as_runtime_paths(self) -> None:
        """A source root is non-system/read-only, not a required write-safe path."""
        checker = load_checker()
        source_paths = (
            "/src",
            "/src/ModSecurity-conector-build",
            str(ROOT),
            str(source_path('build', root=ROOT)),
        )
        system_paths = (
            "/var",
            "/var/lib/foo",
            "/var/log/foo",
            "/var/cache/foo",
            "/etc/foo",
            "/usr/local/foo",
        )
        calls: list[str] = []
        original_shell_status = checker.shell_status

        def candidate_shell_status(script: str) -> int:
            calls.append(script)
            if "ci_path_is_system_path" in script:
                return 0 if any(checker.sh_quote(path) in script for path in system_paths) else 1
            if "assert_safe_runtime_path" in script:
                if any(
                    f"assert_safe_runtime_path {checker.sh_quote(path)} test_path" in script
                    for path in source_paths
                ):
                    return 77
                if "assert_safe_runtime_path /root/.local/state/foo test_path" in script:
                    return 77
                return 0
            if "HAPROXY_SMOKE_POLICY_SELFTEST=1" in script:
                return 77 if any(f"SOURCE_ROOT={checker.sh_quote(path)}" in script for path in system_paths) else 0
            return 0

        try:
            checker.shell_status = candidate_shell_status
            checker.check_shell_policy()
        finally:
            checker.shell_status = original_shell_status

        for source_path in source_paths:
            self.assertNotIn(
                f"assert_safe_runtime_path {checker.sh_quote(source_path)} test_path",
                calls,
            )

    def test_checker_fixed_deny_fixtures_preserve_values_and_grouping(self) -> None:
        checker = load_checker()
        named_paths = (
            "/var/lib/foo",
            "/var/log/foo",
            "/etc/foo",
            "/usr/local/foo",
        )
        self.assertEqual(
            named_paths,
            (
                checker.VAR_LIB_SELFTEST_PATH,
                checker.VAR_LOG_SELFTEST_PATH,
                checker.ETC_SELFTEST_PATH,
                checker.USR_LOCAL_SELFTEST_PATH,
            ),
        )
        self.assertEqual(
            checker.PYTHON_BLOCKED_RUNTIME_PATHS,
            (
                "/var",
                named_paths[0],
                named_paths[1],
                "/var/cache/foo",
                named_paths[2],
                named_paths[3],
                "/root/.local/state/foo",
            ),
        )
        self.assertEqual(
            checker.SHELL_SYSTEM_PATH_SELFTEST_PATHS,
            checker.PYTHON_BLOCKED_RUNTIME_PATHS[:-1],
        )
        self.assertEqual(
            checker.HAPROXY_BLOCKED_SOURCE_ROOTS,
            (named_paths[0], named_paths[1], named_paths[3], named_paths[2]),
        )

    def test_default_policy_selftest_ignores_caller_cache_overrides(self) -> None:
        """A custom verified root must not poison the checker’s default probe."""
        with tempfile.TemporaryDirectory(prefix="runtime-path-policy-") as temporary:
            caller_root = Path(temporary) / "custom-run"
            env = {
                **os.environ,
                "VERIFIED_RUN_ROOT": str(caller_root),
                "CACHE_ROOT": str(caller_root / "cache-v2"),
                "VERIFIED_COMPONENT_CACHE": str(caller_root / "cache-v2" / "shared"),
                "BUILD_ROOT": str(caller_root / "build"),
                "TMP_ROOT": str(caller_root / "build" / "tmp"),
                "LOG_ROOT": str(caller_root / "build" / "logs"),
            }
            result = subprocess.run(
                [sys.executable, str(CHECKER)],
                cwd=ROOT,
                env=env,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_open_connector_workflow_keeps_runtime_reports_outside_source_checkout(self) -> None:
        workflow = (source_path('.github/workflows/open-connectors-smoke.yml', root=ROOT)).read_text(
            encoding="utf-8"
        )
        start = workflow.index("      - name: Initialize runtime paths\n")
        end = workflow.index("\n      - name: Install local Python dependencies\n", start)
        initialize_paths = workflow[start:end]

        self.assertIn(
            'build_root="$verified_root/build"',
            initialize_paths,
        )
        self.assertIn(
            'echo "BUILD_ROOT=$build_root"',
            initialize_paths,
        )
        self.assertIn(
            'echo "RUNTIME_REPORT_OUTPUT_ROOT=$build_root/runtime-component-reports"',
            initialize_paths,
        )
        self.assertNotIn("$GITHUB_WORKSPACE", initialize_paths)
        self.assertNotIn("ci-artifacts/open-connectors/runtime-cache-reports", initialize_paths)

        run_marker = "        run: |\n"
        run_script = initialize_paths.split(run_marker, 1)[1]
        run_script = "\n".join(
            line.removeprefix("          ") for line in run_script.splitlines()
        )
        with tempfile.TemporaryDirectory(prefix="open-connectors-runtime-paths-") as temporary:
            github_env = Path(temporary) / "github-env"
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-eu", "-c", run_script],
                cwd=temporary,
                env={"GITHUB_ENV": str(github_env), "PATH": os.environ["PATH"]},
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            written_environment = github_env.read_text(encoding="utf-8")
            self.assertIn(
                "RUNTIME_REPORT_OUTPUT_ROOT=/tmp/ModSecurity-conector-verified/build/runtime-component-reports",
                written_environment,
            )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
