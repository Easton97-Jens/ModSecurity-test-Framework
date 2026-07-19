from __future__ import annotations

import shlex
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "ci/lib/common.sh"


def run_common_shell(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", "-c", script],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class CommonShellSonarContractsTest(unittest.TestCase):
    def test_library_helpers_return_expected_statuses_without_exiting_caller(self) -> None:
        script = textwrap.dedent(
            f"""
            . {shlex.quote(str(COMMON))}

            skip_blocked synthetic >/dev/null 2>&1
            skip_status=$?
            [ "$skip_status" -eq 77 ] || exit 1

            ci_fail_local_provisioning synthetic >/dev/null 2>&1
            failure_status=$?
            [ "$failure_status" -eq 1 ] || exit 1

            ci_is_https_url https://example.invalid || exit 1
            ci_is_https_url http://example.invalid && exit 1

            envoy_build_paths >/dev/null || exit 1
            traefik_build_paths >/dev/null || exit 1
            lighttpd_build_paths >/dev/null || exit 1
            exit 0
            """
        )

        result = run_common_shell(script)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_prerequisite_wrappers_propagate_blocked_and_failed_statuses(self) -> None:
        script = textwrap.dedent(
            f"""
            . {shlex.quote(str(COMMON))}

            expect_status() {{
                expected_status=$1
                shift
                "$@" >/dev/null 2>&1
                actual_status=$?
                [ "$actual_status" -eq "$expected_status" ] || exit 1
            }}

            ci_command_path() {{ return 1; }}
            expect_status 77 require_command_or_blocked missing-command
            ci_command_path() {{ return 0; }}
            expect_status 0 require_command_or_blocked present-command

            modsecurity_include_flags_or_blocked() {{ return 77; }}
            expect_status 77 require_modsecurity_headers_or_blocked
            modsecurity_include_flags_or_blocked() {{ return 0; }}
            expect_status 0 require_modsecurity_headers_or_blocked

            nginx_include_flags_or_blocked() {{ return 77; }}
            expect_status 77 require_nginx_headers_or_blocked
            nginx_include_flags_or_blocked() {{ return 0; }}
            expect_status 0 require_nginx_headers_or_blocked

            haproxy_include_flags_or_blocked() {{ return 77; }}
            expect_status 77 require_haproxy_headers_or_blocked
            haproxy_include_flags_or_blocked() {{ return 0; }}
            expect_status 0 require_haproxy_headers_or_blocked

            is_local_run() {{ return 1; }}
            framework_find_apxs() {{ return 1; }}
            ci_modsecurity_include_flags() {{ return 1; }}
            ci_nginx_include_flags() {{ return 1; }}
            ci_haproxy_include_flags() {{ return 1; }}
            framework_prepare_runtime_components() {{ return 99; }}

            expect_status 77 require_or_provision_apxs
            expect_status 77 require_or_provision_modsecurity_headers
            expect_status 77 require_or_provision_nginx_headers
            expect_status 77 require_or_provision_haproxy_headers

            is_local_run() {{ return 0; }}
            expect_status 1 require_or_provision_apxs
            expect_status 1 require_or_provision_modsecurity_headers
            expect_status 1 require_or_provision_nginx_headers
            expect_status 1 require_or_provision_haproxy_headers
            exit 0
            """
        )

        result = run_common_shell(script)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_default_case_paths_preserve_the_existing_safe_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "REPO_ROOT": root / "repo",
                "FRAMEWORK_ROOT": root / "framework",
                "CONNECTOR_ROOT": root / "connector",
                "BUILD_ROOT": root / "build",
                "TMP_ROOT": root / "tmp",
                "LOG_ROOT": root / "logs",
                "VERIFIED_RUN_ROOT": root / "verified",
                "MRTS_BUILD_ROOT": root / "mrts-build",
                "MRTS_NATIVE_ROOT": root / "mrts-native",
                "CONNECTOR_COMPONENT_CACHE": root / "cache",
                "XDG_STATE_HOME": root / "state",
                "XDG_CACHE_HOME": root / "cache-home",
            }
            assignments = "\n".join(
                f"{name}={shlex.quote(str(path))}" for name, path in paths.items()
            )
            allowed_paths = " ".join(
                shlex.quote(str(path / "allowed"))
                for name, path in paths.items()
                if name
                in {
                    "BUILD_ROOT",
                    "TMP_ROOT",
                    "LOG_ROOT",
                    "VERIFIED_RUN_ROOT",
                    "MRTS_BUILD_ROOT",
                    "MRTS_NATIVE_ROOT",
                    "CONNECTOR_COMPONENT_CACHE",
                    "XDG_STATE_HOME",
                    "XDG_CACHE_HOME",
                }
            )
            script = textwrap.dedent(
                f"""
                . {shlex.quote(str(COMMON))}
                {assignments}
                mkdir -p {allowed_paths}

                ci_path_is_configured_project_path {shlex.quote(str(root / "unmatched"))} && exit 1

                for allowed_path in {allowed_paths}; do
                    assert_safe_runtime_path "$allowed_path" synthetic || exit 1
                done

                mkdir -p {shlex.quote(str(paths["TMP_ROOT"] / "removable"))}
                safe_remove_runtime_path \
                    {shlex.quote(str(paths["TMP_ROOT"] / "removable"))} \
                    {shlex.quote(str(paths["TMP_ROOT"]))} synthetic || exit 1
                [ ! -e {shlex.quote(str(paths["TMP_ROOT"] / "removable"))} ] || exit 1
                exit 0
                """
            )

            result = run_common_shell(script)
            self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
