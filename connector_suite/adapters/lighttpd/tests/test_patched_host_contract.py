from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = connector_root()
CONNECTOR = source_path('connectors/lighttpd', root=REPO_ROOT)
CONTRACT = CONNECTOR / "lighttpd-version.contract"


def contract_values() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in CONTRACT.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if not separator or name in values or not value:
            raise ValueError("invalid lighttpd version contract")
        values[name] = value
    if set(values) != {
        "LIGHTTPD_SERIES",
        "LIGHTTPD_VERSION",
        "LIGHTTPD_SOURCE_URL",
        "LIGHTTPD_DOWNLOAD_URL",
        "LIGHTTPD_SHA256",
        "LIGHTTPD_PATCH_FILENAME",
    }:
        raise ValueError("invalid lighttpd version contract fields")
    return values


def contract_value(key: str) -> str:
    values = contract_values()
    return values[key]


LIGHTTPD_SERIES = contract_value("LIGHTTPD_SERIES")
LIGHTTPD_VERSION = contract_value("LIGHTTPD_VERSION")
PATCH = CONNECTOR / "patches" / contract_value("LIGHTTPD_PATCH_FILENAME")


def _load_no_crs_namespace_tests():
    """Load the namespace integration tests without importing test packages."""

    path = CONNECTOR / "tests" / "test_no_crs_fixture_namespace.py"
    specification = importlib.util.spec_from_file_location(
        "lighttpd_no_crs_fixture_namespace_tests", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load No-CRS namespace integration tests")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class PatchedCoreBootstrapTest(unittest.TestCase):
    CORE_BUILDER = CONNECTOR / "build" / "build_patched_core.sh"

    @staticmethod
    def _configure_script() -> str:
        return (
            "#!/bin/sh\n"
            "set -eu\n"
            "printf '%s\\n' '#define LIGHTTPD_TEST_CONFIG 1' > config.h\n"
        )

    @staticmethod
    def _write_script(path: Path, content: str, *, executable: bool = True) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755 if executable else 0o644)

    def _fixture(
        self,
        root: Path,
        *,
        configure: bool,
        autogen: str,
        non_executable_configure: bool = False,
    ) -> dict[str, object]:
        source = root / "verified lighttpd source"
        patched_root = root / "patched lighttpd build"
        patched_source = patched_root / f"lighttpd-{LIGHTTPD_VERSION}"
        core_build = patched_root / f"build-{LIGHTTPD_VERSION}"
        stage_root = patched_root / "stage"
        tools = root / "test tools"
        trace = root / "autogen trace.txt"

        (source / "src").mkdir(parents=True)
        (source / "src" / "plugin.h").write_text(
            "#define LIGHTTPD_TEST_SOURCE 1\n", encoding="utf-8"
        )
        (source / "configure.ac").write_text(
            f"AC_INIT([lighttpd],[{LIGHTTPD_VERSION}])\n", encoding="utf-8"
        )
        tools.mkdir()

        self._write_script(tools / "cc", "#!/bin/sh\nexit 0\n")
        self._write_script(
            tools / "patch",
            "#!/bin/sh\n"
            "set -eu\n"
            "target=\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "    case \"$1\" in\n"
            "        -d) target=$2; shift 2 ;;\n"
            "        *) shift ;;\n"
            "    esac\n"
            "done\n"
            "[ -n \"$target\" ]\n"
            "printf '%s\\n' '#define LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION 2' > \"$target/src/plugin.h\"\n"
            "printf '%s\\n' '#define LIGHTTPD_MSCONNECTOR_PLUGIN_ABI_VERSION 2' >> \"$target/src/plugin.h\"\n",
        )
        self._write_script(
            tools / "make",
            "#!/bin/sh\n"
            "set -eu\n"
            "install_mode=0\n"
            "for argument in \"$@\"; do\n"
            "    [ \"$argument\" = install ] && install_mode=1\n"
            "done\n"
            "[ \"$install_mode\" -eq 1 ] || exit 0\n"
            "stage=${LIGHTTPD_TEST_STAGE_ROOT:?}\n"
            "mkdir -p \"$stage/bin\"\n"
            "cat > \"$stage/bin/lighttpd\" <<'EOF'\n"
            "#!/bin/sh\n"
            "if [ \"${1:-}\" = -v ]; then\n"
            f"    printf '%s\\n' 'lighttpd/{LIGHTTPD_VERSION}'\n"
            "fi\n"
            "EOF\n"
            "chmod +x \"$stage/bin/lighttpd\"\n",
        )
        self._write_script(
            tools / "nm",
            "#!/bin/sh\n"
            "printf '%s\\n' '00000000 T plugins_call_handle_request_body'\n"
            "printf '%s\\n' '00000000 T plugins_call_handle_response_body'\n"
            "printf '%s\\n' '00000000 T plugins_call_handle_response_abort'\n",
        )

        if configure:
            self._write_script(
                source / "configure",
                self._configure_script(),
                executable=not non_executable_configure,
            )

        if autogen != "missing":
            autogen_shebang = (
                "#!/usr/bin/env bash\n"
                if autogen == "unsupported_non_executable"
                else "#!/bin/sh\n"
            )
            autogen_script = f"{autogen_shebang}set -eu\n"
            autogen_script += 'printf "%s\\n" "$PWD" >> "$AUTOGEN_TRACE"\n'
            if autogen == "fails":
                autogen_script += "printf '%s\\n' 'missing bootstrap tool: test-autoreconf' >&2\nexit 41\n"
            elif autogen == "no_configure":
                autogen_script += "exit 0\n"
            elif autogen == "unsupported_non_executable":
                autogen_script += "exit 0\n"
            elif autogen in ("succeeds", "succeeds_non_executable"):
                autogen_script += (
                    "cat > configure <<'EOF'\n"
                    f"{self._configure_script()}"
                    "EOF\n"
                    "chmod +x configure\n"
                )
            elif autogen == "must_not_run":
                autogen_script += "printf '%s\\n' 'autogen should not have run' >&2\nexit 97\n"
            else:
                raise ValueError(f"unsupported autogen fixture: {autogen}")
            self._write_script(
                source / "autogen.sh",
                autogen_script,
                executable=autogen
                not in ("succeeds_non_executable", "unsupported_non_executable"),
            )

        environment = os.environ.copy()
        environment.update(
            {
                "BUILD_ROOT": str(root / "build root"),
                "LIGHTTPD_PATCHED_ROOT": str(patched_root),
                "LIGHTTPD_SOURCE_DIR": str(source),
                "LIGHTTPD_TEST_STAGE_ROOT": str(stage_root),
                "LIGHTTPD_MAKE_JOBS": "1",
                "AUTOGEN_TRACE": str(trace),
                "CC": "cc",
                "MAKE": "make",
                "NM": "nm",
                "PATH": f"{tools}{os.pathsep}{environment['PATH']}",
            }
        )
        return {
            "environment": environment,
            "patched_source": patched_source,
            "core_build": core_build,
            "trace": trace,
        }

    def _run_builder(self, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(self.CORE_BUILDER)],
            cwd=REPO_ROOT,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_existing_executable_configure_skips_autogen(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lighttpd-bootstrap-") as temporary:
            fixture = self._fixture(
                Path(temporary) / "path with spaces", configure=True, autogen="must_not_run"
            )
            result = self._run_builder(fixture["environment"])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("mode=build", result.stdout)
            self.assertFalse(fixture["trace"].exists())

    def test_missing_configure_bootstraps_with_posix_non_executable_autogen(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lighttpd-bootstrap-") as temporary:
            fixture = self._fixture(
                Path(temporary) / "path with spaces",
                configure=False,
                autogen="succeeds_non_executable",
            )
            result = self._run_builder(fixture["environment"])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                fixture["trace"].read_text(encoding="utf-8").splitlines(),
                [str(fixture["patched_source"])],
            )
            self.assertTrue((fixture["patched_source"] / "configure").stat().st_mode & 0o111)

    def test_non_executable_configure_bootstraps_in_the_patched_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lighttpd-bootstrap-") as temporary:
            fixture = self._fixture(
                Path(temporary) / "path with spaces",
                configure=True,
                autogen="succeeds",
                non_executable_configure=True,
            )
            result = self._run_builder(fixture["environment"])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                fixture["trace"].read_text(encoding="utf-8").splitlines(),
                [str(fixture["patched_source"])],
            )
            self.assertTrue((fixture["patched_source"] / "configure").stat().st_mode & 0o111)

    def test_missing_configure_and_autogen_blocks_before_build_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lighttpd-bootstrap-") as temporary:
            fixture = self._fixture(
                Path(temporary) / "path with spaces", configure=False, autogen="missing"
            )
            result = self._run_builder(fixture["environment"])
            self.assertEqual(result.returncode, 77)
            self.assertIn("bootstrap script is missing", result.stderr)
            self.assertIn(str(fixture["patched_source"] / "autogen.sh"), result.stderr)
            self.assertFalse(fixture["core_build"].exists())

    def test_failing_autogen_reports_exit_status_and_stops(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lighttpd-bootstrap-") as temporary:
            fixture = self._fixture(
                Path(temporary) / "path with spaces", configure=False, autogen="fails"
            )
            result = self._run_builder(fixture["environment"])
            self.assertEqual(result.returncode, 77)
            self.assertIn("exit status 41", result.stderr)
            self.assertIn("missing bootstrap tool: test-autoreconf", result.stderr)
            self.assertFalse(fixture["core_build"].exists())

    def test_successful_autogen_without_executable_configure_blocks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lighttpd-bootstrap-") as temporary:
            fixture = self._fixture(
                Path(temporary) / "path with spaces",
                configure=False,
                autogen="no_configure",
            )
            result = self._run_builder(fixture["environment"])
            self.assertEqual(result.returncode, 77)
            self.assertIn("without an executable configure script", result.stderr)
            self.assertFalse(fixture["core_build"].exists())

    def test_non_executable_autogen_with_unsupported_interpreter_blocks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lighttpd-bootstrap-") as temporary:
            fixture = self._fixture(
                Path(temporary) / "path with spaces",
                configure=False,
                autogen="unsupported_non_executable",
            )
            result = self._run_builder(fixture["environment"])
            self.assertEqual(result.returncode, 77)
            self.assertIn("does not declare a supported POSIX shell", result.stderr)
            self.assertFalse(fixture["core_build"].exists())

    def test_repeat_build_reuses_configure_without_second_autogen(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lighttpd-bootstrap-") as temporary:
            fixture = self._fixture(
                Path(temporary) / "path with spaces", configure=False, autogen="succeeds"
            )
            first = self._run_builder(fixture["environment"])
            second = self._run_builder(fixture["environment"])
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("mode=reused", second.stdout)
            self.assertEqual(
                fixture["trace"].read_text(encoding="utf-8").splitlines(),
                [str(fixture["patched_source"])],
            )


class PatchedHostContractTest(unittest.TestCase):
    def test_series_provenance_contract_and_reader_are_consistent(self) -> None:
        values = contract_values()
        self.assertRegex(LIGHTTPD_SERIES, r"^[0-9]+\.[0-9]+$")
        self.assertRegex(LIGHTTPD_VERSION, r"^[0-9]+\.[0-9]+\.[0-9]+$")
        self.assertEqual(".".join(LIGHTTPD_VERSION.split(".")[:2]), LIGHTTPD_SERIES)
        expected_source = (
            "https://download.lighttpd.net/lighttpd/"
            f"releases-{LIGHTTPD_SERIES}.x/"
        )
        self.assertEqual(values["LIGHTTPD_SOURCE_URL"], expected_source)
        self.assertEqual(
            values["LIGHTTPD_DOWNLOAD_URL"],
            f"{expected_source}lighttpd-{LIGHTTPD_VERSION}.tar.xz",
        )
        source_map = json.loads((CONNECTOR / "SOURCE_MAP.json").read_text(encoding="utf-8"))
        self.assertEqual(source_map["upstream"]["series"], LIGHTTPD_SERIES)
        self.assertEqual(source_map["upstream"]["version"], LIGHTTPD_VERSION)
        self.assertEqual(source_map["upstream"]["repository"], expected_source)
        self.assertEqual(source_map["upstream"]["download_url"], values["LIGHTTPD_DOWNLOAD_URL"])
        reader = CONNECTOR / "build" / "read_version.sh"
        for key in (
            "LIGHTTPD_SERIES",
            "LIGHTTPD_VERSION",
            "LIGHTTPD_SOURCE_URL",
            "LIGHTTPD_DOWNLOAD_URL",
            "LIGHTTPD_SHA256",
        ):
            with self.subTest(key=key):
                result = subprocess.run(
                    ["sh", str(reader), key],
                    cwd=REPO_ROOT,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), values[key])

    def test_patch_uses_a_file_scope_compile_time_size_check(self) -> None:
        patch = PATCH.read_text(encoding="utf-8")
        self.assertNotIn("ck_static_assert", patch)
        self.assertIn("plugin_fn_request_body_data_must_match_plugin_fn_data", patch)
        self.assertIn("plugin_fn_response_body_data_must_match_plugin_fn_data", patch)
        self.assertIn("plugin_fn_response_abort_data_must_match_plugin_fn_data", patch)

    def test_abort_slot_diff_is_valid_c_and_fail_closed_before_authorizer_success(self) -> None:
        patch = PATCH.read_text(encoding="utf-8")
        self.assertIn("+\t\tif (p->handle_response_abort)", patch)
        self.assertNotIn("++\t\tif (p->handle_response_abort)", patch)
        self.assertIn("+            http_response_backend_error(r);", patch)
        self.assertIn("+            gw_connection_close(hctx, r);", patch)
        self.assertIn("+            return HANDLER_FINISHED;", patch)
        guard = patch.split("@@ -2433,4 +2433,18 @@", 1)[1].split(
            "--- a/src/plugin.h", 1
        )[0]
        self.assertLess(
            guard.index("http_response_backend_error(r);"),
            guard.index("gw_connection_close(hctx, r);")
        )
        self.assertLess(
            guard.index("gw_connection_close(hctx, r);"),
            guard.index("if (hctx->gw_mode == GW_AUTHORIZER")
        )

    def test_patch_advances_response_hook_step_by_record_size(self) -> None:
        patch = PATCH.read_text(encoding="utf-8")
        self.assertIn("--- a/src/response.c\n+++ b/src/response.c\n", patch)
        self.assertIn("@@ -490,5 +490,5 @@", patch)
        self.assertIn(
            "for (; (rc = plfd->fn(r, plfd->data)) == HANDLER_GO_ON; ++plfd)\n"
            "-        ++r->resp_fn_step;\n"
            "+        r->resp_fn_step += sizeof(*plfd);",
            patch,
        )
        self.assertNotIn("+        ++r->resp_fn_step;", patch)

    def test_patched_core_and_host_targets_are_separate_from_no_crs(self) -> None:
        makefile = (CONNECTOR / "Makefile").read_text(encoding="utf-8")
        self.assertIn("build-lighttpd-patched-core", makefile)
        self.assertIn("build-lighttpd-patched-host", makefile)
        self.assertIn("check-lighttpd-patched-host", makefile)
        self.assertIn("runtime-smoke-lighttpd-patched", makefile)

        patched_target = makefile.split("runtime-smoke-lighttpd-patched:", 1)[1].split(
            "\n\n", 1
        )[0]
        self.assertNotIn("MSCONNECTOR_NO_CRS_BASELINE", patched_target)

    def test_patched_build_contract_stages_a_verified_core_and_module(self) -> None:
        core = (CONNECTOR / "build" / "build_patched_core.sh").read_text(encoding="utf-8")
        host = (CONNECTOR / "build" / "build_patched_host.sh").read_text(encoding="utf-8")
        check = (CONNECTOR / "harness" / "check_patched_lifecycle_host.sh").read_text(
            encoding="utf-8"
        )

        for required in (
            "AC_INIT([lighttpd],[$LIGHTTPD_VERSION]",
            "configure",
            '"$MAKE_BIN" -C "$CORE_BUILD_DIR" -j "$MAKE_JOBS"',
            '"$MAKE_BIN" -C "$CORE_BUILD_DIR" install',
            "plugins_call_handle_request_body",
            "plugins_call_handle_response_body",
            "plugins_call_handle_response_abort",
            "LIGHTTPD_MSCONNECTOR_PLUGIN_ABI_VERSION",
            "patched-core-build-info.txt",
        ):
            self.assertIn(required, core)
        self.assertIn("LIGHTTPD_MSCONNECTOR_CORE_MODE=patched", host)
        self.assertIn("LIGHTTPD_MODULE_DIR=\"$MODULE_DIR\"", host)
        self.assertIn("patched-host-build-info.txt", host)
        self.assertIn("module_sha256", check)
        self.assertIn("core_binary_sha256", check)
        self.assertIn("PROXY_MODULE_PATH", host)
        self.assertIn("mod_proxy_plugin_init", host)
        self.assertIn("proxy_module_sha256", host)
        self.assertIn("proxy_module_sha256", check)
        self.assertIn("hook_abi_from_header", core)
        self.assertIn("hook_abi_from_header", host)
        self.assertIn("plugin_hook_abi=%s", host)
        self.assertNotIn("plugin_hook_abi=1", core)
        self.assertNotIn("plugin_hook_abi=1", host)

    def test_patched_build_contract_requires_exact_v2_and_abort_export(self) -> None:
        core = (CONNECTOR / "build" / "build_patched_core.sh").read_text(encoding="utf-8")
        host = (CONNECTOR / "build" / "build_patched_host.sh").read_text(encoding="utf-8")
        patcher = (CONNECTOR / "build" / "apply_core_patch.sh").read_text(encoding="utf-8")
        for script in (core, host, patcher):
            self.assertIn("response-abort hook ABI v2", script) if script is not patcher else self.assertIn("exactly ABI v2", script)
        self.assertIn("plugins_call_handle_response_abort", core)
        self.assertIn("plugins_call_handle_response_abort", host)
        self.assertIn("plugin_hook_abi=2", core)

    def test_patched_config_allows_only_identity_entity_body_input(self) -> None:
        preparer = CONNECTOR / "harness" / "prepare_patched_lifecycle_smoke.sh"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "lighttpd-core-patched" / f"lighttpd-{LIGHTTPD_VERSION}" / "src"
            source.mkdir(parents=True)
            (source / "plugin.h").write_text(
                "#define LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION 1\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "BUILD_ROOT": str(root),
                    "LIGHTTPD_PATCHED_ROOT": str(root / "lighttpd-core-patched"),
                    "LIGHTTPD_PATCHED_RESPONSE_BODY_MODE": "streaming",
                }
            )
            result = subprocess.run(
                ["sh", str(preparer)],
                cwd=REPO_ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            config = Path(result.stdout.strip())
            self.assertIn(
                "response_body_mode=streaming",
                (config.parent / "msconnector-runtime.conf").read_text(encoding="utf-8"),
            )

    def test_patched_config_adds_only_the_http1_proxy_routes_for_streaming(self) -> None:
        preparer = CONNECTOR / "harness" / "prepare_patched_lifecycle_smoke.sh"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "lighttpd-core-patched" / f"lighttpd-{LIGHTTPD_VERSION}" / "src"
            source.mkdir(parents=True)
            (source / "plugin.h").write_text(
                "#define LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION 1\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "BUILD_ROOT": str(root),
                    "LIGHTTPD_PATCHED_ROOT": str(root / "lighttpd-core-patched"),
                    "LIGHTTPD_PATCHED_REQUEST_BODY_MODE": "streaming",
                    "LIGHTTPD_PATCHED_RESPONSE_BODY_MODE": "streaming",
                    "LIGHTTPD_PROXY_BARRIER_PORT": "19001",
                    "LIGHTTPD_PROXY_FIXTURE_PORT": "19002",
                }
            )
            result = subprocess.run(
                ["sh", str(preparer)],
                cwd=REPO_ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            config = Path(result.stdout.strip()).read_text(encoding="utf-8")
        self.assertIn('server.modules = ( "mod_proxy", "mod_msconnector" )', config)
        self.assertIn("server.stream-response-body = 1", config)
        self.assertIn('msconnector.request-body-gate = "pre-upstream"', config)
        self.assertIn('"/p4/barrier/"', config)
        self.assertIn('"/p4/fixture/"', config)
        self.assertNotIn("mod_h2", config)

    def test_patched_config_rejects_unproven_content_encoding(self) -> None:
        preparer = CONNECTOR / "harness" / "prepare_patched_lifecycle_smoke.sh"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "lighttpd-core-patched" / f"lighttpd-{LIGHTTPD_VERSION}" / "src"
            source.mkdir(parents=True)
            (source / "plugin.h").write_text(
                "#define LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION 1\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "BUILD_ROOT": str(root),
                    "LIGHTTPD_PATCHED_ROOT": str(root / "lighttpd-core-patched"),
                    "LIGHTTPD_PATCHED_RESPONSE_BODY_MODE": "streaming",
                    "LIGHTTPD_PATCHED_ENTITY_ENCODING": "gzip",
                }
            )
            result = subprocess.run(
                ["sh", str(preparer)],
                cwd=REPO_ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(result.returncode, 77)
        self.assertIn("identity entity-body input", result.stderr)

    def test_response_callback_ingests_entity_ranges_and_finishes_at_eos(self) -> None:
        module = (CONNECTOR / "module" / "mod_msconnector.c").read_text(encoding="utf-8")
        callback = module.rsplit("static plugin_body_hook_result mod_msconnector_handle_response_body", 1)[1].split(
            "#endif", 1
        )[0]
        finish = module.rsplit("static plugin_body_hook_result mod_msconnector_finish_response_body", 1)[1].split(
            "static plugin_body_hook_result mod_msconnector_handle_response_body", 1
        )[0]
        self.assertIn("const unsigned char *data", callback)
        self.assertIn("msconnector_runtime_transaction_append_response_body_chunk", callback)
        self.assertIn("msconnector_runtime_transaction_set_response_commit_state", callback)
        self.assertIn("mod_msconnector_finish_response_body", callback)
        self.assertIn("mod_msconnector_handle_response_start(r, p)", callback)
        self.assertNotIn("lighttpd_modsecurity_visit_body_range", callback)
        self.assertIn("msconnector_runtime_transaction_finish_response_body", finish)
        self.assertIn("msconnector_late_intervention_resolve", finish)
        self.assertIn("msconnector_runtime_phase4_mode", finish)
        self.assertIn("NOT EXECUTED", finish)

    def test_safe_phase4_host_action_marks_late_only_after_commit(self) -> None:
        module = (CONNECTOR / "module" / "mod_msconnector.c").read_text(encoding="utf-8")
        finish = module.rsplit("static plugin_body_hook_result mod_msconnector_finish_response_body", 1)[1].split(
            "static plugin_body_hook_result mod_msconnector_handle_response_body", 1
        )[0]
        self.assertIn("MSCONNECTOR_LATE_INTERVENTION_DENY_IF_POSSIBLE", finish)
        self.assertIn("mod_msconnector_apply_decision(r, p, ctx, &decision)", finish)
        self.assertIn("decision.late_intervention = 1;", finish)
        self.assertLess(
            finish.index("decision.late_intervention = 1;"),
            finish.index("msconnector_runtime_transaction_record_host_action"),
        )

    def test_patch_hooks_entity_bytes_before_transfer_encoding_not_socket_write(self) -> None:
        patch = PATCH.read_text(encoding="utf-8")
        self.assertIn("http_chunk_msconnector_entity_body", patch)
        self.assertIn("http_chunk_msconnector_entity_close", patch)
        self.assertIn("resp_body_entity_hook_suppressed", patch)
        self.assertIn("if (r->gw_dechunk->done) {", patch)
        self.assertIn("return http_chunk_msconnector_entity_close(r);", patch)
        self.assertNotIn("msconnector-eos-debug", patch)
        self.assertIn("http1_entity_body_before_transfer_encoding", (
            CONNECTOR / "build" / "build_patched_core.sh"
        ).read_text(encoding="utf-8"))
        self.assertNotIn("--- a/src/connections.c", patch)
        self.assertNotIn("network_write", patch)
        self.assertLess(
            patch.index("http_chunk_msconnector_entity_body(r,"),
            patch.index("if (http_chunk_uses_tempfile(cq, len))"),
        )

    def test_unobserved_response_lifecycle_is_not_synthesized_after_entity_disconnect(self) -> None:
        module = (CONNECTOR / "module" / "mod_msconnector.c").read_text(
            encoding="utf-8"
        )
        response_start = module.split(
            "REQUEST_FUNC(mod_msconnector_handle_response_start)", 1
        )[1].split("REQUEST_FUNC(mod_msconnector_handle_request_reset)", 1)[0]
        request_reset = module.rsplit(
            "REQUEST_FUNC(mod_msconnector_handle_request_reset)", 1
        )[1]
        self.assertNotIn("mod_msconnector_finish_uninspected_response_body", response_start)
        self.assertIn("mod_msconnector_finish_uninspected_response_body(r, ctx)", request_reset)
        self.assertIn("no synthetic Phase-4 finalization", request_reset)
        self.assertIn(
            "msconnector_runtime_transaction_finish_unobserved_response_body",
            module,
        )
        self.assertNotIn(
            "msconnector_runtime_transaction_finish_response_body(r, ctx)", request_reset
        )

    def test_missing_eos_reset_defers_exactly_one_finish_attempt_to_destroy(self) -> None:
        module = (CONNECTOR / "module" / "mod_msconnector.c").read_text(
            encoding="utf-8"
        )
        request_reset = module.rsplit(
            "REQUEST_FUNC(mod_msconnector_handle_request_reset)", 1
        )[1]
        missing_eos = request_reset.split("#else", 1)[0]
        self.assertIn("int defer_transaction_finish = 0;", request_reset)
        self.assertIn("ctx->response_body_aborted", missing_eos)
        self.assertIn("defer_transaction_finish = 1;", missing_eos)
        self.assertIn("no synthetic Phase-4 finalization", missing_eos)
        self.assertIn("if (!defer_transaction_finish)", request_reset)
        self.assertIn("handler_ctx_destroy(ctx_slot);", request_reset)
        self.assertLess(
            request_reset.index("if (!defer_transaction_finish)"),
            # The earlier technical-failure branch destroys its own context.
            # Compare the deferred-finish guard with the normal teardown.
            request_reset.rindex("handler_ctx_destroy(ctx_slot);")
        )
        self.assertNotIn(
            "msconnector_runtime_transaction_finish_response_body", missing_eos
        )

    def test_request_body_mapper_uses_an_unsigned_size_bound(self) -> None:
        mapper = (CONNECTOR / "src" / "lighttpd_modsecurity_mapper.c").read_text(
            encoding="utf-8"
        )
        self.assertIn("(uintmax_t)take > (uintmax_t)SIZE_MAX", mapper)
        self.assertNotIn("take > (off_t)SIZE_MAX", mapper)

    def test_disruptive_host_action_is_recorded_after_status_selection(self) -> None:
        module = (CONNECTOR / "module" / "mod_msconnector.c").read_text(
            encoding="utf-8"
        )
        action = module.split("static handler_t mod_msconnector_apply_decision", 1)[1].split(
            "#ifdef LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION", 1
        )[0]
        self.assertIn("? http_status_set_err_fin(r, status)", action)
        self.assertIn(": http_status_set_err(r, status);", action)
        self.assertIn("http_response_reset(r);", action)
        self.assertIn("msconnector_runtime_transaction_record_host_action", action)
        self.assertLess(
            action.index(": http_status_set_err(r, status);"),
            action.index("msconnector_runtime_transaction_record_host_action"),
        )
        self.assertIn("MSCONNECTOR_DECISION_ACTION_DENY", action)
        self.assertIn('"http_status"', action)

    def test_runtime_labels_raw_events_with_the_selected_host_abi(self) -> None:
        module = (CONNECTOR / "module" / "mod_msconnector.c").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "#ifdef LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION\n"
            "#define MSCONNECTOR_LIGHTTPD_EVENT_INTEGRATION_MODE \"patched-native-lighttpd\"\n"
            "#else\n"
            "#define MSCONNECTOR_LIGHTTPD_EVENT_INTEGRATION_MODE \"native-lighttpd-plugin\"\n"
            "#endif",
            module,
        )
        self.assertIn("msconnector_runtime_set_event_integration_mode", module)
        self.assertIn(
            "p->runtime, MSCONNECTOR_LIGHTTPD_EVENT_INTEGRATION_MODE", module
        )
        self.assertIn(
            '"msconnector runtime could not set %s event integration mode"', module
        )

    def test_host_transaction_identifier_uses_a_process_local_serial(self) -> None:
        module = (CONNECTOR / "module" / "mod_msconnector.c").read_text(
            encoding="utf-8"
        )
        self.assertIn("unsigned long host_transaction_counter;", module)
        factory = module.split("static handler_ctx *handler_ctx_create", 1)[1].split(
            "static void handler_ctx_destroy", 1
        )[0]
        self.assertIn("++p->host_transaction_counter;", factory)
        self.assertIn('"lighttpd-%ld-%lu"', factory)
        self.assertNotIn('"lighttpd-%ld-%d-%u-%u"', factory)

    def test_host_transaction_response_evidence_is_opt_in_and_not_client_reflected(self) -> None:
        module = (CONNECTOR / "module" / "mod_msconnector.c").read_text(
            encoding="utf-8"
        )
        emitter = module.split("static int mod_msconnector_emit_host_transaction_id", 1)[1].split(
            "#ifdef LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION", 1
        )[0]
        response_start = module.rsplit("REQUEST_FUNC(mod_msconnector_handle_response_start)", 1)[1].split(
            "REQUEST_FUNC(mod_msconnector_handle_request_reset)", 1
        )[0]

        self.assertIn("int expose_host_transaction_id;", module)
        self.assertIn('"msconnector.expose-host-transaction-id"', module)
        self.assertIn("T_CONFIG_BOOL", module)
        self.assertIn('CONST_STR_LEN("X-Msconnector-Host-Transaction-Id")', emitter)
        self.assertIn("http_header_response_set", emitter)
        self.assertNotIn("http_header_response_insert", emitter)
        self.assertNotIn("http_header_request_get", emitter)
        self.assertIn("!p->defaults.expose_host_transaction_id", emitter)
        self.assertIn("mod_msconnector_response_headers_committed", emitter)
        self.assertIn(
            "if (ctx->request_intervened || ctx->request_body_gate_rejected)",
            response_start,
        )
        self.assertIn("mod_msconnector_emit_host_transaction_id(r, p, ctx)", response_start)
        self.assertLess(
            response_start.index("msconnector_runtime_transaction_process_response_headers"),
            response_start.rindex("mod_msconnector_emit_host_transaction_id(r, p, ctx)"),
        )

        preparer = CONNECTOR / "harness" / "prepare_native_smoke.sh"
        with tempfile.TemporaryDirectory(prefix="lighttpd-host-id-header-") as temporary:
            root = Path(temporary)
            environment = os.environ.copy()
            environment.update(
                {
                    "BUILD_ROOT": str(root / "build"),
                    "LIGHTTPD_SMOKE_DIR": str(root / "smoke"),
                    "LIGHTTPD_SMOKE_PORT": "18084",
                    "MSCONNECTOR_RULES_FILE": str(
                        source_path('common/rules/modsecurity_targeted_smoke.conf', root=REPO_ROOT)
                    ),
                    "LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID": "0",
                    "LIGHTTPD_RESPONSE_HEADER_MARKER": "block",
                }
            )
            disabled = subprocess.run(
                ["sh", str(preparer)],
                cwd=REPO_ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(disabled.returncode, 0, disabled.stderr)
            disabled_config = Path(disabled.stdout.strip()).read_text(encoding="utf-8")
            self.assertNotIn("msconnector.expose-host-transaction-id", disabled_config)
            self.assertNotIn("untrusted-upstream-value", disabled_config)

            environment["LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID"] = "1"
            enabled = subprocess.run(
                ["sh", str(preparer)],
                cwd=REPO_ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(enabled.returncode, 0, enabled.stderr)
            enabled_config = Path(enabled.stdout.strip()).read_text(encoding="utf-8")
            self.assertIn(
                'msconnector.expose-host-transaction-id = "enable"', enabled_config
            )
            self.assertIn("untrusted-upstream-value", enabled_config)

            environment["LIGHTTPD_EXPOSE_HOST_TRANSACTION_ID"] = "unexpected"
            rejected = subprocess.run(
                ["sh", str(preparer)],
                cwd=REPO_ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(rejected.returncode, 77)
            self.assertIn("must be 0 or 1", rejected.stderr)

    def test_stock_and_patched_paths_share_only_generic_response_helpers(self) -> None:
        module = (CONNECTOR / "module" / "mod_msconnector.c").read_text(
            encoding="utf-8"
        )
        apply_decision = module.index("static handler_t mod_msconnector_apply_decision")
        guard = module.index(
            "#ifdef LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION", apply_decision
        )
        headers_committed = module.index(
            "static int mod_msconnector_response_headers_committed"
        )
        emitter = module.index("static int mod_msconnector_emit_host_transaction_id")
        response_body_committed = module.index(
            "static int mod_msconnector_response_body_committed"
        )
        response_start = module.rindex("REQUEST_FUNC(mod_msconnector_handle_response_start)")
        request_reset = module.rindex("REQUEST_FUNC(mod_msconnector_handle_request_reset)")

        self.assertLess(headers_committed, guard)
        self.assertLess(emitter, guard)
        self.assertGreater(response_body_committed, guard)
        self.assertGreater(response_start, guard)
        self.assertIn("http_header_response_set", module[:guard])
        self.assertNotIn("mod_msconnector_response_body_committed", module[:guard])

        response_hook = module[response_start:request_reset]
        self.assertNotIn("#ifdef LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION", response_hook)
        self.assertEqual(response_hook.count("mod_msconnector_emit_host_transaction_id"), 2)

    def test_crs_harness_records_private_wire_correlation_without_a_client_transaction_id(self) -> None:
        runner = (CONNECTOR / "harness" / "run_patched_full_lifecycle.sh").read_text(
            encoding="utf-8"
        )
        crs_branch = runner.split("run_crs_runtime() {", 1)[1].split(
            'if [ "$MSCONNECTOR_CRS_RUNTIME" = 1 ]; then', 1
        )[0]

        self.assertIn("CRS_EVIDENCE_DIR=$SMOKE_DIR/crs-request-evidence", runner)
        self.assertIn("prepare_crs_request_evidence", runner)
        self.assertIn("safe_output_path", runner)
        self.assertIn("safe_input_path", crs_branch)
        self.assertIn("os.fchmod(descriptor, 0o700)", runner)
        self.assertIn("O_NOFOLLOW", runner)
        self.assertIn("read_private_wire_artifact", crs_branch)
        self.assertIn("stat.S_IMODE(details.st_mode) & 0o077", crs_branch)
        self.assertIn("def parse_curl_request_lines(trace, case):", crs_branch)
        self.assertIn("CURL_TRACE_DATA_ROW", crs_branch)
        self.assertIn("CURL_TRACE_INFO_LINE", crs_branch)
        self.assertIn("== Info: Request completely sent off", crs_branch)
        self.assertIn("span == visible_length + 2", crs_branch)
        self.assertIn("non-contiguous outgoing-header offset", crs_branch)
        self.assertIn("MAX_CRS_WIRE_EVIDENCE_BYTES = 65536", crs_branch)
        self.assertIn("def parse_single_response_headers(headers, case, expected_status):", crs_branch)
        self.assertIn("one complete response block", crs_branch)
        self.assertIn("--trace-ascii", crs_branch)
        self.assertIn("--dump-header", crs_branch)
        self.assertIn("X-Framework-Request-ID", crs_branch)
        self.assertNotIn('--header "X-Modsec-Transaction-Id:', crs_branch)
        self.assertIn("CRS_RESPONSE_TRANSACTION_HEADER=X-Msconnector-Host-Transaction-Id", runner)
        self.assertIn('"$CRS_RESPONSE_TRANSACTION_HEADER"', crs_branch)
        self.assertIn("response_transaction_header_origin=server_generated_lighttpd_host", crs_branch)
        self.assertIn("Common transaction id does not match", crs_branch)
        self.assertIn("def serialized_event_uri(uri):", crs_branch)
        self.assertIn('event.get("uri") == expected_event_uri', crs_branch)
        self.assertIn('event.get("redacted") is (expected_event_uri != uri)', crs_branch)
        self.assertIn(
            'event.get("transaction_id") == response_transaction_id', crs_branch
        )
        self.assertIn('secret in event["uri"].lower()', crs_branch)
        self.assertIn('"password", "union", "select"', crs_branch)
        self.assertIn('require_exactly_one_raw_crs_record(raw_log, transaction_id, request_id)', crs_branch)
        self.assertIn("require_exactly_one_raw_crs_record", crs_branch)
        self.assertIn("len(correlated_raw_lines) != 1", crs_branch)

    def test_crs_wire_parsers_reconstruct_curl_folding_and_reject_multiple_responses(self) -> None:
        runner = (CONNECTOR / "harness" / "run_patched_full_lifecycle.sh").read_text(
            encoding="utf-8"
        )
        parser_source = "CURL_TRACE_SEND_HEADER =" + runner.split(
            "CURL_TRACE_SEND_HEADER =", 1
        )[1].split("def host_transaction_id", 1)[0]
        namespace: dict[str, object] = {"re": re}
        exec(parser_source, namespace)
        parse_request = namespace["parse_curl_request_lines"]
        parse_response = namespace["parse_single_response_headers"]

        folded_trace = (
            "=> Send header, 261 bytes (0x105)\n"
            "0000: GET /?id=1%20uNiOn%20SeLeCt%20password%20FrOm%20users HTTP/1.1\n"
            "0040: Host: crs-runtime.test\n"
            "0058: User-Agent: curl/8.18.0\n"
            "0071: Accept: */*\n"
            "007e: X-Framework-Run-ID: lighttpd-host-id-crs-delivery3-20260820\n"
            "00bb: X-Framework-Request-ID: lighttpd-host-id-crs-delivery3-20260820-\n"
            "00fb: bypass\n"
            "0103: \n"
            "* Request completely sent off\n"
        )
        request_lines = parse_request(folded_trace, "bypass")
        self.assertEqual(
            request_lines[-2],
            "X-Framework-Request-ID: lighttpd-host-id-crs-delivery3-20260820-bypass",
        )
        malformed_offset_trace = folded_trace.replace("00bb:", "00bc:", 1)
        with self.assertRaises(SystemExit):
            parse_request(malformed_offset_trace, "bypass")

        info_trace = folded_trace.replace(
            "* Request completely sent off\n",
            "== Info: sent request bytes\n"
            "== Info: Request completely sent off\n",
        )
        self.assertEqual(parse_request(info_trace, "bypass"), request_lines)
        receive_boundary_trace = folded_trace.replace(
            "* Request completely sent off\n",
            "<= Recv header, 26 bytes (0x1a)\n",
        )
        self.assertEqual(parse_request(receive_boundary_trace, "bypass"), request_lines)
        duplicated_receive_boundary_trace = receive_boundary_trace.replace(
            "0103: \n",
            "<= Recv header, 26 bytes (0x1a)\n0103: \n",
        )
        with self.assertRaises(SystemExit):
            parse_request(duplicated_receive_boundary_trace, "bypass")
        receive_data_boundary_trace = receive_boundary_trace.replace(
            "<= Recv header, 26 bytes (0x1a)",
            "<= Recv data, 26 bytes (0x1a)",
        )
        with self.assertRaises(SystemExit):
            parse_request(receive_data_boundary_trace, "bypass")
        unexpected_diagnostic_trace = folded_trace.replace(
            "* Request completely sent off\n",
            "* unexpected diagnostic row\n"
            "* Request completely sent off\n",
        )
        with self.assertRaises(SystemExit):
            parse_request(unexpected_diagnostic_trace, "bypass")
        hostile_record = "* attacker-controlled-header: secret-value"
        hostile_diagnostic_trace = folded_trace.replace(
            "* Request completely sent off\n",
            f"{hostile_record}\n* Request completely sent off\n",
        )
        with self.assertRaises(SystemExit) as raised:
            parse_request(hostile_diagnostic_trace, "bypass")
        diagnostic = str(raised.exception)
        self.assertIn("unsupported star trace record family", diagnostic)
        self.assertNotIn("attacker-controlled-header", diagnostic)
        self.assertNotIn("secret-value", diagnostic)

        parsed = parse_response(
            "HTTP/1.1 403 Forbidden\r\n"
            "X-Msconnector-Host-Transaction-Id: lighttpd-60-3\r\n"
            "Content-Length: 158\r\n\r\n",
            "bypass",
            "403",
        )
        self.assertIn(
            ("X-Msconnector-Host-Transaction-Id", "lighttpd-60-3"), parsed
        )
        with self.assertRaises(SystemExit):
            parse_response(
                "HTTP/1.1 100 Continue\r\n\r\n"
                "HTTP/1.1 403 Forbidden\r\n"
                "X-Msconnector-Host-Transaction-Id: lighttpd-60-3\r\n\r\n",
                "bypass",
                "403",
            )

    def test_crs_raw_rule_correlation_requires_exactly_one_record(self) -> None:
        runner = (CONNECTOR / "harness" / "run_patched_full_lifecycle.sh").read_text(
            encoding="utf-8"
        )
        helper_source = "def require_exactly_one_raw_crs_record" + runner.split(
            "def require_exactly_one_raw_crs_record", 1
        )[1].split("def observed", 1)[0]
        namespace: dict[str, object] = {}
        exec(helper_source, namespace)
        require_record = namespace["require_exactly_one_raw_crs_record"]

        transaction_id = "lighttpd-60-2"
        line = f'[id "942270"] [unique_id "{transaction_id}"]'
        self.assertEqual(
            require_record(line, transaction_id, "block"),
            line,
        )
        with self.assertRaises(SystemExit):
            require_record(f"{line}\n{line}", transaction_id, "block")

    def test_crs_event_uri_redaction_preserves_raw_wire_uri_expectation(self) -> None:
        runner = (CONNECTOR / "harness" / "run_patched_full_lifecycle.sh").read_text(
            encoding="utf-8"
        )
        helper_source = "def serialized_event_uri" + runner.split(
            "def serialized_event_uri", 1
        )[1].split("def observed", 1)[0]
        namespace: dict[str, object] = {}
        exec(helper_source, namespace)
        serialized_uri = namespace["serialized_event_uri"]
        self.assertEqual(serialized_uri("/?id=1%20UNION%20SELECT"), "/?<redacted>")
        self.assertEqual(serialized_uri("/?id=1%20uNiOn%20SeLeCt"), "/?<redacted>")
        self.assertEqual(serialized_uri("/?id=42"), "/?<redacted>")
        self.assertNotIn("UNION", serialized_uri("/?id=1%20UNION%20SELECT"))
        self.assertNotIn("password", serialized_uri("/?id=1%20UNION%20SELECT"))
        self.assertEqual(serialized_uri("/"), "/")

    def test_crs_observation_correlates_same_redacted_uri_by_transaction_id(self) -> None:
        runner = (CONNECTOR / "harness" / "run_patched_full_lifecycle.sh").read_text(
            encoding="utf-8"
        )
        helper_source = "def require_exactly_one_raw_crs_record" + runner.split(
            "def require_exactly_one_raw_crs_record", 1
        )[1].split("block_transaction_id, block_intervention_rule_id", 1)[0]
        matching_event = {
            "connector": "lighttpd",
            "integration_mode": "patched-native-lighttpd",
            "method": "GET",
            "uri": "/?<redacted>",
            "redacted": True,
            "rule_id": "949110",
            "http_status": 403,
            "visible_http_status": 403,
            "transport_result": "http_status",
            "actual_action": "deny",
        }
        namespace: dict[str, object] = {
            "events": [
                {**matching_event, "transaction_id": "block-transaction"},
                {**matching_event, "transaction_id": "bypass-transaction"},
            ],
            "raw_log": (
                '[id "942270"] [unique_id "block-transaction"]\n'
                '[id "942270"] [unique_id "bypass-transaction"]'
            ),
        }
        exec(helper_source, namespace)
        observed = namespace["observed"]
        self.assertEqual(
            observed("/?id=CANARY", "block", "block-transaction"),
            ("block-transaction", "949110"),
        )

    def test_crs_mode_never_materializes_the_no_crs_entity_fixture(self) -> None:
        runner = (CONNECTOR / "harness" / "run_patched_full_lifecycle.sh").read_text(
            encoding="utf-8"
        )
        setup = runner.split('mkdir -p "$SMOKE_DIR" "$FIRST_BYTE_DIR"', 1)[1].split(
            "CRS_UPSTREAM_READY=", 1
        )[0]

        self.assertNotIn('mkdir -p "$SMOKE_DIR" "$FIRST_BYTE_DIR" "$FIXTURE_DIR"', runner)
        self.assertNotIn("prepare_crs_fixture_directory", runner)
        self.assertNotIn("cleanup_crs_fixture_directory", runner)
        self.assertNotIn("CRS_FIXTURE_DIR_OWNED", runner)
        self.assertIn('if [ "$MSCONNECTOR_CRS_RUNTIME" = 0 ]; then', setup)
        self.assertIn("prepare_no_crs_fixture_directory", setup)
        self.assertNotIn('mkdir -p "$FIXTURE_DIR"', setup)
        self.assertNotIn('rm -f "$FIXTURE_DIR', setup)

    @property
    def _no_crs_fixture_io(self) -> Path:
        return CONNECTOR / "harness" / "no_crs_fixture_descriptor_io.py"

    def _run_no_crs_fixture_io(
        self, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(self._no_crs_fixture_io), *arguments],
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _create_no_crs_fixture(self, root: Path) -> tuple[str, str, Path]:
        created = self._run_no_crs_fixture_io(
            "create", "--runtime-output-root", str(root)
        )
        self.assertEqual(created.returncode, 0, created.stderr)
        record = created.stdout.strip().split("\t")
        self.assertEqual(len(record), 2, created.stdout)
        name, identity = record
        self.assertRegex(name, r"^\.entity-fixtures-[a-f0-9]{32}$")
        self.assertRegex(identity, r"^[0-9]+:[0-9]+$")
        fixture = root / name
        self.assertEqual(fixture.stat().st_mode & 0o777, 0o700)
        return name, identity, fixture

    def _fixture_command(
        self, command: str, root: Path, name: str, identity: str, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        return self._run_no_crs_fixture_io(
            command,
            "--runtime-output-root",
            str(root),
            "--fixture-name",
            name,
            "--fixture-identity",
            identity,
            *arguments,
        )

    def _load_bound_fixture_result(
        self, root: Path, name: str, identity: str
    ) -> subprocess.CompletedProcess[str]:
        harness = CONNECTOR / "harness"
        code = (
            "from pathlib import Path\n"
            "import sys\n"
            f"sys.path.insert(0, {str(harness)!r})\n"
            "from write_patched_lifecycle_results import load_fixture_result\n"
            "result = load_fixture_result(\n"
            "    Path(sys.argv[1]),\n"
            "    fixture_directory_name=sys.argv[2],\n"
            "    fixture_directory_identity=sys.argv[3],\n"
            ")\n"
            "print(f'{result[0]},{result[1]}')\n"
        )
        return subprocess.run(
            [sys.executable, "-B", "-c", code, str(root), name, identity],
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _stop_owned_test_fixture(self, process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def _no_crs_fixture_test_parent(self) -> str:
        parent = Path(
            os.environ.get(
                "LIGHTTPD_TEST_RUNTIME_PARENT", "/var/tmp/codex/ModSecurity-conector"
            )
        )
        self.assertTrue(parent.is_dir(), f"private fixture test parent is missing: {parent}")
        self.assertFalse(parent.is_symlink(), f"private fixture test parent is a symlink: {parent}")
        details = parent.lstat()
        self.assertTrue(stat.S_ISDIR(details.st_mode))
        self.assertEqual(details.st_uid, os.geteuid())
        self.assertEqual(details.st_mode & 0o077, 0)
        return str(parent)

    def _assert_migrated_namespace_test(self, method_name: str) -> None:
        """Run the migrated fixture test through the trusted namespace gate.

        These historical host-contract names retain their coverage role, but
        their implementation now lives in the dedicated namespace suite. A
        nested test case is intentional: it preserves the old contract suite's
        lifecycle coverage while ensuring the real fixture and same-UID race
        execute only inside the capability-checked private mount namespace.
        """

        namespace_tests = _load_no_crs_namespace_tests()
        case = namespace_tests.NamespaceIntegrationTest(methodName=method_name)
        result = unittest.TestResult()
        case.run(result)
        if result.skipped:
            self.skipTest(result.skipped[0][1])
        if result.errors or result.failures:
            details = "\n".join(
                detail for _test, detail in (*result.errors, *result.failures)
            )
            self.fail(details)
        self.assertTrue(result.wasSuccessful())

    def test_no_crs_fixture_lifecycle_is_private_identity_bound_and_fail_closed(self) -> None:
        self._assert_migrated_namespace_test(
            "test_descriptor_fixture_io_lifecycle_is_real_private_and_host_mount_disappears"
        )

    def test_no_crs_fixture_lifecycle_rejects_legacy_symlink_replacement_and_foreign_content(self) -> None:
        self._assert_migrated_namespace_test(
            "test_private_descriptor_rejections_and_same_uid_actual_fixture_race"
        )

    def test_opt_in_host_transaction_header_covers_p1_p2_and_p3_response_paths(self) -> None:
        runner = (CONNECTOR / "harness" / "run_patched_full_lifecycle.sh").read_text(
            encoding="utf-8"
        )
        preparer = (CONNECTOR / "harness" / "prepare_native_smoke.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("HOST_TRANSACTION_EVIDENCE_DIR=$SMOKE_DIR/host-transaction-evidence", runner)
        self.assertIn("prepare_host_transaction_evidence", runner)
        self.assertIn("verify_host_transaction_response_headers", runner)
        self.assertIn('"$CRS_RESPONSE_TRANSACTION_HEADER" <<\'PY\'\nimport os', runner)
        self.assertIn("p1-allow.response.headers", runner)
        self.assertIn("p1-deny.response.headers", runner)
        self.assertIn("p2-deny.response.headers", runner)
        self.assertIn("p3-deny.response.headers", runner)
        self.assertIn("client_label, \"untrusted-client-value\"", runner)
        self.assertIn("untrusted-client-value", runner)
        self.assertIn("ordinary No-CRS requests do", runner)
        self.assertIn("untrusted-upstream-value", runner)
        self.assertIn("setenv.add-response-header", preparer)
        self.assertIn('"X-Msconnector-Host-Transaction-Id" => "untrusted-upstream-value"', preparer)

    def test_full_lifecycle_runner_uses_real_http1_entity_and_barrier_evidence(self) -> None:
        runner = (CONNECTOR / "harness" / "run_patched_full_lifecycle.sh").read_text(
            encoding="utf-8"
        )
        fixture_io = (CONNECTOR / "harness" / "no_crs_fixture_descriptor_io.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("LIGHTTPD_PATCHED_RESPONSE_BODY_MODE=streaming", runner)
        self.assertIn("no_crs_fixture_descriptor_io.py", runner)
        self.assertIn("fixture_no_crs_io serve", runner)
        self.assertIn("fixture_no_crs_io curl-case", runner)
        self.assertIn('--entity-fixture-directory-name "$FIXTURE_BASENAME"', runner)
        self.assertIn('--entity-fixture-directory-identity "$FIXTURE_IDENTITY"', runner)
        self.assertNotIn("$FIXTURE_DIR/", runner)
        self.assertIn("lighttpd_http1_entity_fixture_upstream", fixture_io)
        self.assertIn('"--dump-header",', fixture_io)
        self.assertIn('"-",', fixture_io)
        self.assertIn("MAX_CURL_OUTPUT_BYTES = MAX_HEADER_BYTES + 3", fixture_io)
        self.assertIn("_bounded_curl_output", fixture_io)
        self.assertIn("stdout=subprocess.PIPE", fixture_io)
        self.assertIn("stderr=subprocess.DEVNULL", fixture_io)
        self.assertNotIn("runtime-output-directory-fd", fixture_io)
        self.assertNotIn("open_inherited_private_runtime_directory", fixture_io)
        self.assertIn("verify_runtime_output_paths", runner)
        self.assertIn("safe_output_path(root, Path(sys.argv[3])", runner)
        self.assertIn("--merge-evidence", runner)
        self.assertIn("FULL_LIFECYCLE_EVIDENCE_OUTPUT", runner)
        self.assertIn("phase4_end_of_stream_evaluation_status", runner)
        self.assertIn("phase4_first_byte_before_response_end_status", runner)
        self.assertIn("phase4_no_full_response_buffering_status", runner)
        self.assertNotIn("wire bytes", runner)
        self.assertIn(': "${NO_CRS_RUN_ID:?NO_CRS_RUN_ID is required}"', runner)

        serve_command = runner.split(
            '"$PYTHON_BIN" "$SYNCHRONIZED_UPSTREAM" --serve', 1
        )[1].split("BARRIER_PID=$!", 1)[0]
        merge_command = runner.split(
            '"$PYTHON_BIN" "$SYNCHRONIZED_UPSTREAM" --merge-evidence', 1
        )[1].split('fail "could not write payload-free synchronized first-byte evidence"', 1)[0]
        self.assertIn('--control-root "$SMOKE_DIR"', serve_command)
        self.assertIn('--control-root "$SMOKE_DIR"', merge_command)
        writer_command = runner.split('"$PYTHON_BIN" "$RESULT_WRITER" \\\n', 1)[1].split(
            "if grep -Fq", 1
        )[0]
        self.assertIn('--run-id "$NO_CRS_RUN_ID"', writer_command)

    def test_parent_routes_lighttpd_first_byte_evidence_through_the_smoke_root(self) -> None:
        lifecycle = (source_path('ci/runtime/lifecycle/run-no-crs-baseline.sh', root=REPO_ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "FIRST_BYTE_EVIDENCE=$CONNECTOR_RUN_ROOT/first-byte-evidence.json",
            lifecycle,
        )
        self.assertIn(
            'if [ "$connector" = lighttpd ] && [ "$NO_CRS_ARTIFACT_PROFILE" = full_lifecycle ]; then',
            lifecycle,
        )
        self.assertIn(
            "LIGHTTPD_STAGE_FIRST_BYTE_EVIDENCE=$LIGHTTPD_RUNTIME_ROOT/first-byte-evidence.json",
            lifecycle,
        )
        self.assertIn(
            "FIRST_BYTE_EVIDENCE_SOURCE=$LIGHTTPD_STAGE_FIRST_BYTE_EVIDENCE",
            lifecycle,
        )
        self.assertIn(
            'FULL_LIFECYCLE_EVIDENCE_OUTPUT="$STAGE_FIRST_BYTE_EVIDENCE_OUTPUT"',
            lifecycle,
        )
        self.assertIn(
            'cp "$FIRST_BYTE_EVIDENCE_SOURCE" "$FIRST_BYTE_EVIDENCE"',
            lifecycle,
        )

    def test_full_lifecycle_runner_centralizes_fixed_status_and_diagnostic_literals(self) -> None:
        runner = (CONNECTOR / "harness" / "run_patched_full_lifecycle.sh").read_text(
            encoding="utf-8"
        )
        status_name = "HTTP_STATUS_FORMAT"
        diagnostic_name = "DIAGNOSTIC_LINES"
        status_value = "%{" + "http_code" + "}"
        diagnostic_value = ",".join(("1", "200")) + "p"
        status_declaration = f"{status_name}='{status_value}'"
        diagnostic_declaration = f"{diagnostic_name}='{diagnostic_value}'"
        status_use = f'--write-out "${status_name}"'
        diagnostic_use = f'sed -n "${diagnostic_name}"'

        self.assertEqual(runner.count(status_declaration), 1)
        self.assertEqual(runner.count(diagnostic_declaration), 1)
        self.assertLess(runner.index(status_declaration), runner.index(status_use))
        self.assertLess(runner.index(diagnostic_declaration), runner.index(diagnostic_use))
        self.assertLess(runner.index(status_declaration), runner.index("blocked() {"))
        self.assertLess(runner.index(diagnostic_declaration), runner.index("blocked() {"))
        self.assertEqual(runner.count(status_use), 4)
        self.assertEqual(runner.count(diagnostic_use), 5)

        fixture_io = (CONNECTOR / "harness" / "no_crs_fixture_descriptor_io.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"--write-out",', fixture_io)
        self.assertIn('"%{http_code}",', fixture_io)
        self.assertIn("fixture_no_crs_io diagnostics", runner)

        source_without_declarations = runner.replace(status_declaration, "").replace(
            diagnostic_declaration, ""
        )
        self.assertNotIn(status_value, source_without_declarations)
        self.assertNotIn(diagnostic_value, source_without_declarations)
        self.assertNotIn(f"export {status_name}", runner)
        self.assertNotIn(f"export {diagnostic_name}", runner)

        for control in (
            "set -eu",
            "trap cleanup EXIT",
            "trap 'on_signal 129' HUP",
            "trap 'on_signal 130' INT",
            "trap 'on_signal 143' TERM",
            "trap - EXIT HUP INT TERM",
            'if ! wait "$FIRST_BYTE_CLIENT_PID"; then',
            'if grep -Fq \'"status": "FAIL"\' "$RESULTS_PATH"; then',
        ):
            self.assertIn(control, runner)

        self.assertIn("CHILD_STOP_ATTEMPTS=50", runner)
        self.assertIn('kill -KILL "$child_pid"', runner)
        self.assertIn("owned_child_is_current", runner)
        self.assertIn('if ! verify_crs_cleanup \\', runner)
        self.assertIn('"$cleanup_server_pid" "$cleanup_server_token"', runner)
        self.assertIn("require_exactly_one_raw_crs_record", runner)
        self.assertIn("len(correlated_raw_lines) != 1", runner)

        success = "2" + "00"
        denied = "4" + "03"
        alternative = "4" + "29"
        for result_name, expected in (
            ("allow_status", success),
            ("deny_status", denied),
            ("alternative_status", alternative),
            ("request_body_status", denied),
            ("response_header_status", denied),
            ("content_length_status", success),
            ("chunked_status", success),
            ("phase4_safe_status", success),
        ):
            self.assertIn(f'[ "${result_name}" = {expected} ] || fail', runner)

    def test_result_writer_projects_only_bounded_eos_metadata_from_one_safe_event(self) -> None:
        writer = CONNECTOR / "harness" / "write_patched_lifecycle_results.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def safe_event(size: int, transaction_id: str) -> dict[str, object]:
                return {
                    "connector": "lighttpd",
                    "integration_mode": "patched-native-lighttpd",
                    "event": "response_blocked",
                    "message_id": "response_blocked",
                    "transaction_id": transaction_id,
                    "rule_id": "1100301",
                    "phase": "response_body",
                    "status": "blocked",
                    "http_status": 403,
                    "original_http_status": 200,
                    "visible_http_status": 200,
                    "requested_action": "deny",
                    "actual_action": "log_only",
                    "late_intervention": True,
                    "late_intervention_mode": "safe",
                    "headers_sent": True,
                    "body_started": True,
                    "response_committed": True,
                    "connection_aborted": False,
                    "transport_result": "log_only",
                    "body_bytes_seen": size,
                    "body_bytes_inspected": size,
                }

            barrier = root / "barrier.jsonl"
            content_length = root / "content-length.jsonl"
            chunked = root / "chunked.jsonl"
            events = root / "events.jsonl"
            for path, event in (
                (barrier, safe_event(31, "tx-barrier")),
                (content_length, safe_event(29, "tx-content-length")),
                (chunked, safe_event(24, "tx-chunked")),
            ):
                path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            events.write_text("", encoding="utf-8")
            fixture = root / "fixture.json"
            fixture.write_text(
                json.dumps(
                    {
                        "evidence_type": "lighttpd_http1_entity_fixture_result",
                        "body_payload_persisted": False,
                        "content_length_requests": 1,
                        "chunked_requests": 1,
                        "content_length_entity_bytes": 29,
                        "chunked_entity_bytes": 24,
                    }
                ),
                encoding="utf-8",
            )
            evidence = root / "first-byte.json"
            evidence.write_text("{}\n", encoding="utf-8")
            output = root / "results.jsonl"
            projection = root / "projection.jsonl"
            summary = root / "summary.json"
            result = subprocess.run(
                [
                    "python3",
                    str(writer),
                    "--events", str(events),
                    "--run-id", "lighttpd-current-run",
                    "--output", str(output),
                    "--selected-case-ids",
                    "phase4_rule_observed phase4_end_of_stream_evaluation "
                    "phase4_deny_after_commit_log_only_safe "
                    "phase4_first_byte_before_response_end "
                    "phase4_no_full_response_buffering",
                    "--allow-status", "200",
                    "--deny-status", "403",
                    "--alternative-status", "429",
                    "--request-body-status", "403",
                    "--response-header-status", "403",
                    "--phase4-safe-events", str(barrier),
                    "--phase4-projected-events-output", str(projection),
                    "--phase4-safe-status", "200",
                    "--phase4-first-byte-evidence", str(evidence),
                    "--content-length-events", str(content_length),
                    "--chunked-events", str(chunked),
                    "--entity-fixture-result", str(fixture),
                    "--phase4-summary-output", str(summary),
                    "--runtime-output-root", str(root),
                ],
                cwd=REPO_ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            projected = json.loads(projection.read_text(encoding="utf-8"))
            self.assertTrue(projected["eos_seen"])
            self.assertTrue(projected["end_of_stream_evaluation"])
            self.assertEqual(projected["run_id"], "lighttpd-current-run")
            self.assertNotIn("event_hash", projected)
            rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            self.assertEqual({row["status"] for row in rows}, {"PASS"})
            self.assertTrue(all(row["transaction_ids"] == ["tx-barrier"] for row in rows))
            self.assertEqual(
                {row["first_byte_evidence_path"] for row in rows},
                {str(evidence)},
            )
            summary_value = json.loads(summary.read_text(encoding="utf-8"))
            self.assertEqual(summary_value["phase4_end_of_stream_evaluation_status"], 200)
            self.assertEqual(summary_value["phase4_first_byte_before_response_end_status"], 200)
            self.assertEqual(summary_value["phase4_no_full_response_buffering_status"], 200)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
