#!/usr/bin/env python3
"""Contract tests for the local C17/C++17 diagnostics foundation."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = connector_root()
CDB_TOOL = source_path('ci/checks/analysis/compile_database.py', root=ROOT)
NGINX_CONFIG = source_path('connectors/nginx/config', root=ROOT)
NGINX_CHECK = source_path('ci/checks/connectors/nginx/check-nginx-c-standards.sh', root=ROOT)
NGINX_DATABASE_CHECK = source_path('ci/checks/analysis/compile-db-nginx-c17.sh', root=ROOT)
CPP_DATABASE_CHECK = source_path('ci/checks/analysis/compile-db-cpp17.sh', root=ROOT)
CPP_EVALUATOR_CHECK = source_path('ci/checks/analysis/check-targeted-evaluator-cpp17.sh', root=ROOT)
ANALYSIS_TOOLS_CHECK = source_path('ci/checks/analysis/check-analysis-tools.sh', root=ROOT)


def nginx_config_sources() -> set[Path]:
    sources: set[Path] = set()
    for connector_source, common_source, registry_source in re.findall(
        r"\$ngx_addon_dir/(src/[A-Za-z0-9_./-]+\.c)|\$MSCONNECTOR_COMMON_SRC/([A-Za-z0-9_./-]+\.c)|\$MSCONNECTOR_PROFILE_REGISTRY_ROOT/([A-Za-z0-9_./-]+\.c)",
        NGINX_CONFIG.read_text(encoding="utf-8"),
    ):
        if connector_source:
            sources.add((source_path('connectors/nginx', root=ROOT) / connector_source).resolve())
        elif common_source:
            sources.add((source_path('common/src', root=ROOT) / common_source).resolve())
        else:
            sources.add((ROOT / registry_source).resolve())
    return sources


def cdb_entry(source: Path, output_root: Path) -> dict[str, object]:
    relative = source.relative_to(ROOT).as_posix().replace("/", "_")
    if source.suffix == ".c":
        arguments = [
            "/usr/bin/cc",
            "-std=c17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-c",
            str(source),
            "-o",
            str(output_root / f"{relative}.o"),
        ]
        output = output_root / f"{relative}.o"
    else:
        arguments = [
            "/usr/bin/c++",
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(source),
            "-o",
            str(output_root / "modsecurity_targeted_eval"),
        ]
        output = output_root / "modsecurity_targeted_eval"
    return {
        "directory": str(ROOT),
        "file": str(source),
        "arguments": arguments,
        "output": str(output),
    }


class CAndCppDiagnosticsContractTests(unittest.TestCase):
    maxDiff = None

    def test_staged_nginx_config_resolves_registry_only_from_valid_common_layout(self) -> None:
        config_prefix = NGINX_CONFIG.read_text().split("YAJL_EXTRA=", 1)[0]
        with tempfile.TemporaryDirectory(prefix="nginx-registry-root-") as temporary:
            root = Path(temporary)
            staged = root / "staged-connector"
            staged.mkdir()
            unrelated = root / "unrelated/include"
            unrelated.mkdir(parents=True)
            cases = (
                (source_path('common/include', root=ROOT), "", 0, str(ROOT)),
                (source_path('common/include', root=ROOT), str(ROOT), 0, str(ROOT)),
                (source_path('common/include', root=ROOT), str(root / "missing"), 1, "invalid profile registry root"),
                (unrelated, "", 1, "missing profile registry root"),
            )
            for common_include, explicit_registry, status, expected in cases:
                with self.subTest(include=common_include, explicit=explicit_registry):
                    result = subprocess.run(
                        ["sh", "-c", config_prefix + '\nprintf "%s\\n" "$MSCONNECTOR_PROFILE_REGISTRY_ROOT"'],
                        env={**os.environ, "ngx_addon_dir": str(staged),
                             "MSCONNECTOR_COMMON_INC": str(common_include),
                             "MSCONNECTOR_COMMON_SRC": str(source_path('common/src', root=ROOT)),
                             "MSCONNECTOR_PROFILE_REGISTRY_ROOT": explicit_registry},
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertIn(expected, result.stdout + result.stderr)

    def run_cdb_tool(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [sys.executable, str(CDB_TOOL), "--repo-root", str(ROOT), *arguments],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_nginx_config_and_c17_check_cover_the_same_real_sources(self) -> None:
        config_text = NGINX_CONFIG.read_text(encoding="utf-8")
        self.assertIn(
            "$MSCONNECTOR_PROFILE_REGISTRY_ROOT/connectors/profile_registry.c",
            config_text,
        )
        dynamic_branch, static_branch = config_text.split(
            'if test -n "$ngx_module_link"; then', 1
        )[1].split("\nelse\n", 1)
        self.assertIn(
            "$MSCONNECTOR_PROFILE_REGISTRY_ROOT/connectors/profile_registry.c",
            dynamic_branch,
        )
        self.assertEqual(
            dynamic_branch.count("$MSCONNECTOR_PROFILE_REGISTRY_ROOT/connectors/profile_registry.c"),
            1,
        )
        self.assertEqual(
            dynamic_branch.count("$MSCONNECTOR_PROFILE_REGISTRY_ROOT/connectors/profile_registry.h"),
            1,
        )
        self.assertIn(
            "$MSCONNECTOR_PROFILE_REGISTRY_ROOT/connectors/profile_registry.c",
            static_branch,
        )
        self.assertEqual(
            static_branch.count("$MSCONNECTOR_PROFILE_REGISTRY_ROOT/connectors/profile_registry.c"),
            1,
        )
        self.assertEqual(
            static_branch.count("$MSCONNECTOR_PROFILE_REGISTRY_ROOT/connectors/profile_registry.h"),
            1,
        )
        self.assertIn(
            'ngx_module_incs="$ngx_feature_path $MSCONNECTOR_COMMON_INC $MSCONNECTOR_PROFILE_REGISTRY_ROOT"',
            config_text,
        )
        self.assertIn(
            'CORE_INCS="$CORE_INCS $ngx_feature_path $MSCONNECTOR_COMMON_INC $MSCONNECTOR_PROFILE_REGISTRY_ROOT"',
            config_text,
        )
        self.assertIn("ngx_msconnector_profile_registry_opt_I", config_text)
        configured = nginx_config_sources()
        checked = {
            (ROOT / source).resolve()
            for source in re.findall(
                r"(?:connectors/nginx|connectors|common)/[A-Za-z0-9_./-]+\.c",
                NGINX_CHECK.read_text(encoding="utf-8"),
            )
        }

        self.assertTrue(configured)
        self.assertSetEqual(configured, checked)
        self.assertTrue(all(source.is_file() for source in configured))
        self.assertIn(source_path('common/src/late_intervention.c', root=ROOT), checked)
        self.assertIn(source_path('connectors/profile_registry.c', root=ROOT), checked)
        self.assertIn("-I$ROOT", NGINX_CHECK.read_text(encoding="utf-8"))

    def test_make_targets_keep_analysis_opt_in_and_clangd_non_mutating(self) -> None:
        makefile = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
        for target in (
            "check-analysis-tools",
            "compile-db-nginx-c17",
            "check-targeted-evaluator-cpp17",
            "compile-db-cpp17",
            "check-clangd-c17",
        ):
            self.assertIn(f"{target}:", makefile)
        self.assertIn(
            ".PHONY: check-analysis-tools compile-db-nginx-c17 "
            "check-targeted-evaluator-cpp17 compile-db-cpp17 check-clangd-c17",
            makefile,
        )

        clangd_script = (source_path('ci/checks/analysis/check-clangd-c17.sh', root=ROOT)).read_text(
            encoding="utf-8"
        )
        self.assertIn("--clang-tidy=false", clangd_script)
        self.assertIn("--enable-config=false", clangd_script)
        self.assertIn("--tweaks=", clangd_script)
        self.assertIn("--compile-commands-dir", clangd_script)
        self.assertIn("--log=error", clangd_script)
        for database_script in (NGINX_DATABASE_CHECK, CPP_DATABASE_CHECK):
            database_text = database_script.read_text(encoding="utf-8")
            self.assertIn("--capture-root \"$CAPTURE_DIR\"", database_text)
        evaluator_script = (
            source_path('ci/checks/analysis/check-targeted-evaluator-cpp17.sh', root=ROOT)
        ).read_text(encoding="utf-8")
        self.assertIn("-isystem \"$MODSECURITY_INCLUDE_DIR\"", evaluator_script)
        self.assertIn("-Wall -Wextra -Werror", evaluator_script)
        self.assertNotIn("check-analysis-tools", makefile[makefile.index("lint:") :])
        self.assertFalse((source_path('.clangd', root=ROOT)).exists())
        self.assertFalse((source_path('.clang-tidy', root=ROOT)).exists())

    def test_checkout_output_requests_are_rejected_before_creating_directories(self) -> None:
        test_root = source_path('.c-cpp-diagnostics-output-regression', root=ROOT)
        self.assertFalse(test_root.exists())
        self.addCleanup(shutil.rmtree, test_root, ignore_errors=True)

        for script, variable in (
            (NGINX_DATABASE_CHECK, "COMPDB_OUTPUT"),
            (CPP_DATABASE_CHECK, "COMPDB_OUTPUT"),
            (CPP_EVALUATOR_CHECK, "CPP_BUILD_ROOT"),
        ):
            environment = os.environ.copy()
            target = test_root / (
                "compile_commands.json" if variable == "COMPDB_OUTPUT" else "build"
            )
            environment[variable] = str(target)
            result = subprocess.run(
                [str(script)],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("outside the checkout", result.stderr)
            self.assertFalse(test_root.exists())

    def test_external_output_requests_continue_to_dependency_checks(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="c-cpp-diagnostics-external-output-"
        ) as temporary_directory:
            temporary_root = Path(temporary_directory)
            for script, variable, target, tool_variable, expected_message, defaults in (
                (
                    CPP_DATABASE_CHECK,
                    "COMPDB_OUTPUT",
                    temporary_root / "cpp" / "compile_commands.json",
                    "CXX",
                    "BLOCKED: missing C++ compiler",
                    2,
                ),
                (
                    NGINX_DATABASE_CHECK,
                    "COMPDB_OUTPUT",
                    temporary_root / "nginx" / "compile_commands.json",
                    "CC",
                    "BLOCKED: missing C compiler",
                    2,
                ),
                (
                    CPP_EVALUATOR_CHECK,
                    "CPP_BUILD_ROOT",
                    temporary_root / "evaluator",
                    "CXX",
                    "BLOCKED: missing C++ compiler",
                    1,
                ),
            ):
                environment = os.environ.copy()
                environment[variable] = str(target)
                environment[tool_variable] = "codex-missing-compiler-for-contract-test"
                result = subprocess.run(
                    [str(script)],
                    cwd=ROOT,
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                script_text = script.read_text(encoding="utf-8")
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertIn(expected_message, result.stderr)
                self.assertNotIn("outside the checkout", result.stderr)
                created_path = target.parent if variable == "COMPDB_OUTPUT" else target
                self.assertTrue(created_path.exists())
                self.assertEqual(script_text.count("*) : ;;"), defaults)

    def test_missing_analysis_tool_returns_documented_blocked_status(self) -> None:
        environment = os.environ.copy()
        environment["CC"] = "codex-missing-c-compiler-for-contract-test"
        result = subprocess.run(
            [str(ANALYSIS_TOOLS_CHECK)],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("BLOCKED: CC is unavailable", result.stderr)

    def test_compilation_database_filtering_validation_merging_and_atomic_publish(self) -> None:
        temporary_parent = os.environ.get("TMPDIR")
        with tempfile.TemporaryDirectory(
            prefix="c-cpp-diagnostics-", dir=temporary_parent
        ) as temporary_directory:
            temporary_root = Path(temporary_directory)
            output_root = temporary_root / "objects"
            output_root.mkdir()
            database = temporary_root / "compile_commands.json"
            capture_root = temporary_root / ".compile-db-contract"
            capture_root.mkdir(mode=0o700)
            c_sources = sorted(nginx_config_sources(), key=lambda path: path.as_posix())
            cpp_source = (source_path('common/scripts/modsecurity_targeted_eval.cc', root=ROOT)).resolve()
            generated_probe = temporary_root / "generated-probe.c"
            generated_probe.write_text("int generated_probe(void) { return 0; }\n", encoding="utf-8")

            c_capture = capture_root / "nginx-raw.json"
            c_capture.write_text(
                json.dumps(
                    [cdb_entry(source, output_root) for source in c_sources]
                    + [
                        cdb_entry(c_sources[0], output_root),
                        {
                            "directory": str(ROOT),
                            "file": str(generated_probe),
                            "arguments": [
                                "/usr/bin/cc",
                                "-std=c17",
                                "-Wall",
                                "-Wextra",
                                "-Werror",
                            ],
                            "output": str(output_root / "generated-probe.o"),
                        },
                    ]
                ),
                encoding="utf-8",
            )
            c_result = self.run_cdb_tool(
                "--input",
                str(c_capture),
                "--capture-root",
                str(capture_root),
                "--output",
                str(database),
                "--require",
                "nginx",
            )
            self.assertEqual(c_result.returncode, 0, c_result.stderr)
            self.assertIn("FILTERED: duplicate translation unit", c_result.stdout)
            self.assertIn("FILTERED: entry", c_result.stdout)

            missing_c_capture = capture_root / "missing-c-raw.json"
            missing_c_capture.write_text(
                json.dumps([cdb_entry(source, output_root) for source in c_sources[1:]]),
                encoding="utf-8",
            )
            missing_c_database = temporary_root / "missing-c-compile_commands.json"
            missing_c_result = self.run_cdb_tool(
                "--input",
                str(missing_c_capture),
                "--capture-root",
                str(capture_root),
                "--output",
                str(missing_c_database),
                "--require",
                "nginx",
            )
            self.assertNotEqual(missing_c_result.returncode, 0)
            self.assertIn("coverage is incomplete", missing_c_result.stderr)
            self.assertIn(
                str(c_sources[0].relative_to(ROOT)), missing_c_result.stderr
            )
            self.assertFalse(missing_c_database.exists())

            missing_cpp_result = self.run_cdb_tool(
                "--output",
                str(database),
                "--verify-only",
                "--require",
                "nginx",
                "--require",
                "cpp",
            )
            self.assertNotEqual(missing_cpp_result.returncode, 0)
            self.assertIn("coverage is incomplete", missing_cpp_result.stderr)
            self.assertIn(
                "common/scripts/modsecurity_targeted_eval.cc", missing_cpp_result.stderr
            )

            cpp_capture = capture_root / "cpp-raw.json"
            cpp_capture.write_text(
                json.dumps([cdb_entry(cpp_source, output_root)]), encoding="utf-8"
            )
            cpp_result = self.run_cdb_tool(
                "--input",
                str(cpp_capture),
                "--capture-root",
                str(capture_root),
                "--output",
                str(database),
                "--merge-existing",
                "--require",
                "cpp",
            )
            self.assertEqual(cpp_result.returncode, 0, cpp_result.stderr)

            verify_result = self.run_cdb_tool(
                "--output",
                str(database),
                "--verify-only",
                "--require",
                "nginx",
                "--require",
                "cpp",
            )
            self.assertEqual(verify_result.returncode, 0, verify_result.stderr)

            published = json.loads(database.read_text(encoding="utf-8"))
            self.assertIsInstance(published, list)
            published_sources = {Path(entry["file"]).resolve() for entry in published}
            self.assertSetEqual(published_sources, set(c_sources) | {cpp_source})
            self.assertEqual(len(published), len(published_sources))
            self.assertTrue(all(source.is_file() and ROOT in source.parents for source in published_sources))
            self.assertTrue(all(Path(entry["output"]).is_absolute() for entry in published))
            self.assertTrue(all(ROOT not in Path(entry["output"]).resolve().parents for entry in published))
            for entry in published:
                source = Path(entry["file"])
                arguments = entry["arguments"]
                self.assertIn("-Wall", arguments)
                self.assertIn("-Wextra", arguments)
                self.assertIn("-Werror", arguments)
                self.assertIn("-std=c17" if source.suffix == ".c" else "-std=c++17", arguments)

            original_database = database.read_bytes()
            invalid_capture = capture_root / "invalid-raw.json"
            invalid_capture.write_text(
                json.dumps(
                    [
                        {
                            "directory": str(ROOT),
                            "file": str(temporary_root / "copied-external.c"),
                            "arguments": [
                                "/usr/bin/cc",
                                "-std=c17",
                                "-Wall",
                                "-Wextra",
                                "-Werror",
                            ],
                            "output": str(output_root / "copied-external.o"),
                        }
                    ]
                ),
                encoding="utf-8",
            )
            invalid_result = self.run_cdb_tool(
                "--input",
                str(invalid_capture),
                "--capture-root",
                str(capture_root),
                "--output",
                str(database),
                "--merge-existing",
                "--require",
                "nginx",
            )
            self.assertNotEqual(invalid_result.returncode, 0)
            self.assertEqual(database.read_bytes(), original_database)

            checkout_output_result = self.run_cdb_tool(
                "--input",
                str(c_capture),
                "--capture-root",
                str(capture_root),
                "--output",
                str(source_path('compile_commands.json', root=ROOT)),
                "--require",
                "nginx",
            )
            self.assertNotEqual(checkout_output_result.returncode, 0)
            self.assertIn("outside the checkout", checkout_output_result.stderr)

    def test_capture_input_requires_a_private_external_capture_root(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="c-cpp-capture-input-"
        ) as temporary_directory:
            temporary_root = Path(temporary_directory)
            capture_root = temporary_root / ".compile-db-contract"
            capture_root.mkdir(mode=0o700)
            output_root = temporary_root / "objects"
            output_root.mkdir()
            output = temporary_root / "compile_commands.json"
            source = sorted(nginx_config_sources(), key=lambda path: path.as_posix())[0]
            valid_capture = capture_root / "valid.json"
            valid_capture.write_text(
                json.dumps([cdb_entry(source, output_root)]), encoding="utf-8"
            )

            valid_result = self.run_cdb_tool(
                "--input",
                str(valid_capture),
                "--capture-root",
                str(capture_root),
                "--output",
                str(output),
            )
            self.assertEqual(valid_result.returncode, 0, valid_result.stderr)

            missing_root_result = self.run_cdb_tool(
                "--input",
                str(valid_capture),
                "--output",
                str(temporary_root / "missing-root-output.json"),
            )
            self.assertNotEqual(missing_root_result.returncode, 0)
            self.assertIn(
                "--capture-root is required with --input",
                missing_root_result.stderr,
            )

            relative_result = self.run_cdb_tool(
                "--input",
                "relative-capture.json",
                "--capture-root",
                str(capture_root),
                "--output",
                str(temporary_root / "relative-output.json"),
            )
            self.assertNotEqual(relative_result.returncode, 0)
            self.assertIn("capture input must be an absolute path", relative_result.stderr)
            self.assertFalse((temporary_root / "relative-output.json").exists())

            checkout_result = self.run_cdb_tool(
                "--input",
                str(source_path('Makefile', root=ROOT)),
                "--capture-root",
                str(capture_root),
                "--output",
                str(temporary_root / "checkout-output.json"),
            )
            self.assertNotEqual(checkout_result.returncode, 0)
            self.assertIn(
                "capture input must be outside the checkout",
                checkout_result.stderr,
            )
            self.assertFalse((temporary_root / "checkout-output.json").exists())

            outside_capture = temporary_root / "outside.json"
            outside_capture.write_text("not compilation database JSON\n", encoding="utf-8")
            escaping_capture = capture_root / "escape.json"
            escaping_capture.symlink_to(outside_capture)
            escape_result = self.run_cdb_tool(
                "--input",
                str(escaping_capture),
                "--capture-root",
                str(capture_root),
                "--output",
                str(temporary_root / "escape-output.json"),
            )
            self.assertNotEqual(escape_result.returncode, 0)
            self.assertIn("capture root", escape_result.stderr)
            self.assertFalse((temporary_root / "escape-output.json").exists())

            loop_capture = capture_root / "loop.json"
            loop_capture.symlink_to(loop_capture)
            loop_result = self.run_cdb_tool(
                "--input",
                str(loop_capture),
                "--capture-root",
                str(capture_root),
                "--output",
                str(temporary_root / "loop-output.json"),
            )
            self.assertNotEqual(loop_result.returncode, 0)
            self.assertIn("capture input cannot be resolved", loop_result.stderr)
            self.assertFalse((temporary_root / "loop-output.json").exists())

            unsafe_capture_root = temporary_root / ".compile-db-group-writable"
            unsafe_capture_root.mkdir(mode=0o700)
            unsafe_capture_root.chmod(0o770)
            unsafe_capture = unsafe_capture_root / "unsafe.json"
            unsafe_capture.write_text(
                valid_capture.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            unsafe_root_result = self.run_cdb_tool(
                "--input",
                str(unsafe_capture),
                "--capture-root",
                str(unsafe_capture_root),
                "--output",
                str(temporary_root / "unsafe-root-output.json"),
            )
            self.assertNotEqual(unsafe_root_result.returncode, 0)
            self.assertIn(
                "capture root must not be group writable or accessible by others",
                unsafe_root_result.stderr,
            )
            self.assertFalse((temporary_root / "unsafe-root-output.json").exists())

            world_accessible_capture_root = temporary_root / ".compile-db-world-accessible"
            world_accessible_capture_root.mkdir(mode=0o700)
            world_accessible_capture_root.chmod(0o755)
            world_accessible_capture = world_accessible_capture_root / "world.json"
            world_accessible_capture.write_text(
                valid_capture.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            world_accessible_result = self.run_cdb_tool(
                "--input",
                str(world_accessible_capture),
                "--capture-root",
                str(world_accessible_capture_root),
                "--output",
                str(temporary_root / "world-root-output.json"),
            )
            self.assertNotEqual(world_accessible_result.returncode, 0)
            self.assertIn(
                "capture root must not be group writable or accessible by others",
                world_accessible_result.stderr,
            )
            self.assertFalse((temporary_root / "world-root-output.json").exists())

            linked_capture_root = temporary_root / ".compile-db-linked"
            linked_capture_root.symlink_to(capture_root, target_is_directory=True)
            linked_root_result = self.run_cdb_tool(
                "--input",
                str(valid_capture),
                "--capture-root",
                str(linked_capture_root),
                "--output",
                str(temporary_root / "linked-root-output.json"),
            )
            self.assertNotEqual(linked_root_result.returncode, 0)
            self.assertIn("capture root must not be a symlink", linked_root_result.stderr)
            self.assertFalse((temporary_root / "linked-root-output.json").exists())

            verify_result = self.run_cdb_tool(
                "--output",
                str(output),
                "--capture-root",
                str(capture_root),
                "--verify-only",
            )
            self.assertNotEqual(verify_result.returncode, 0)
            self.assertIn("--capture-root cannot be combined with --verify-only", verify_result.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
