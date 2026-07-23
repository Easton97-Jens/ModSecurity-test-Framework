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
        self.assertEqual(result.returncode, 0, result.stderr)

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
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_runtime_provisioning_requires_explicit_download_and_build_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "provisioning-invoked"
            script = textwrap.dedent(
                f"""
                . {shlex.quote(str(COMMON))}
                ENVOY_BIN=/definitely/missing/envoy
                TRAEFIK_BIN=/definitely/missing/traefik
                LIGHTTPD_BIN=/definitely/missing/lighttpd
                LIGHTTPD_INCLUDE_DIR=/definitely/missing/include
                ci_stage_matching_runtime_binary() {{ return 1; }}
                sh() {{ : > {shlex.quote(str(marker))}; return 1; }}

                ALLOW_RUNTIME_DOWNLOADS=0
                ALLOW_RUNTIME_BUILDS=0
                require_or_provision_envoy >/dev/null 2>&1 || :
                require_or_provision_traefik >/dev/null 2>&1 || :
                require_or_provision_lighttpd >/dev/null 2>&1 || :
                [ ! -e {shlex.quote(str(marker))} ] || exit 1

                ALLOW_RUNTIME_DOWNLOADS=1
                require_or_provision_envoy >/dev/null 2>&1 || :
                [ -e {shlex.quote(str(marker))} ] || exit 1
                exit 0
                """
            )
            result = run_common_shell(script)
        self.assertEqual(result.returncode, 0, result.stderr)

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
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_runtime_path_guard_rejects_all_source_checkout_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo_root = root / "repo"
            framework_root = root / "framework"
            connector_root = root / "connector"
            build_root = root / "build"
            for path in (repo_root, framework_root, connector_root, build_root):
                path.mkdir()
            script = textwrap.dedent(
                f"""
                . {shlex.quote(str(COMMON))}
                REPO_ROOT={shlex.quote(str(repo_root))}
                FRAMEWORK_ROOT={shlex.quote(str(framework_root))}
                CONNECTOR_ROOT={shlex.quote(str(connector_root))}
                BUILD_ROOT={shlex.quote(str(build_root))}
                TMP_ROOT={shlex.quote(str(build_root / 'tmp'))}
                LOG_ROOT={shlex.quote(str(build_root / 'logs'))}
                XDG_STATE_HOME={shlex.quote(str(root / 'state'))}
                XDG_CACHE_HOME={shlex.quote(str(root / 'cache'))}

                assert_safe_runtime_path {shlex.quote(str(build_root / 'owned'))} build || exit 1
                for source_path in \
                    {shlex.quote(str(repo_root / 'generated'))} \
                    {shlex.quote(str(framework_root / 'generated'))} \
                    {shlex.quote(str(connector_root / 'generated'))}; do
                    assert_safe_runtime_path "$source_path" source >/dev/null 2>&1 && exit 1
                done
                exit 0
                """
            )
            result = run_common_shell(script)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mrts_generated_paths_are_confined_to_the_build_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_root = root / "build"
            generated_root = build_root / "mrts"
            outside = root / "outside"
            generated_root.mkdir(parents=True)
            outside.mkdir()
            script = textwrap.dedent(
                f"""
                . {shlex.quote(str(COMMON))}
                BUILD_ROOT={shlex.quote(str(build_root))}
                TMP_ROOT={shlex.quote(str(build_root / 'tmp'))}
                LOG_ROOT={shlex.quote(str(build_root / 'logs'))}
                MRTS_BUILD_ROOT={shlex.quote(str(generated_root))}
                assert_runtime_path_under_root {shlex.quote(str(generated_root / 'rules'))} {shlex.quote(str(generated_root))} rules || exit 1
                assert_runtime_path_under_root {shlex.quote(str(outside / 'rules'))} {shlex.quote(str(generated_root))} rules >/dev/null 2>&1 && exit 1
                exit 0
                """
            )
            result = run_common_shell(script)
        self.assertEqual(result.returncode, 0, result.stderr)

        for relative_path in ("ci/provisioning/generate-mrts.sh", "ci/provisioning/write-mrts-load.sh"):
            source = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertIn('assert_runtime_path_under_root "$MRTS_BUILD_ROOT" "$BUILD_ROOT/mrts"', source)


if __name__ == "__main__":
    unittest.main()
