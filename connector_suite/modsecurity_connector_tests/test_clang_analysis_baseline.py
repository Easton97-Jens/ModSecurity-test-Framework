#!/usr/bin/env python3
"""Contract tests for the advisory Clang analysis baseline."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = connector_root()
RUNNER = source_path('ci/checks/analysis/clang_analysis_baseline.py', root=ROOT)
TOOLS_CHECK = source_path('ci/checks/analysis/check-clang-analysis-tools.sh', root=ROOT)
SOURCE = source_path('common/src/block_statuses.c', root=ROOT)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_status() -> bytes:
    return subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        check=True,
        capture_output=True,
    ).stdout


class ClangAnalysisBaselineContractTests(unittest.TestCase):
    maxDiff = None

    def temporary_directory(self) -> tempfile.TemporaryDirectory[str]:
        return tempfile.TemporaryDirectory(
            prefix="clang-analysis-baseline-", dir=os.environ.get("TMPDIR")
        )

    def make_temp_root(self, parent: Path) -> Path:
        root = parent / "codex-temp"
        (root / "tmp").mkdir(parents=True)
        (root / ".codex-temp-root").write_text("test marker\n", encoding="utf-8")
        return root

    def write_cdb(
        self,
        temp_root: Path,
        *,
        arguments: list[str] | None = None,
        raw: object | None = None,
    ) -> Path:
        cdb = temp_root / "input" / "compile_commands.json"
        cdb.parent.mkdir(parents=True)
        if raw is not None:
            cdb.write_text(json.dumps(raw), encoding="utf-8")
            return cdb
        output = temp_root / "objects" / "block_statuses.o"
        entry_arguments = arguments or [
            "/usr/bin/cc",
            "-std=c17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-isystem",
            str(temp_root / "vendor/include"),
            "-c",
            str(SOURCE),
            "-o",
            str(output),
        ]
        cdb.write_text(
            json.dumps(
                [
                    {
                        "directory": str(ROOT),
                        "file": str(SOURCE),
                        "arguments": entry_arguments,
                        "output": str(output),
                    }
                ]
            ),
            encoding="utf-8",
        )
        return cdb

    def write_fake_tools(self, parent: Path) -> dict[str, Path]:
        tools = parent / "tools"
        tools.mkdir()
        tidy = tools / "clang-tidy"
        analyzer = tools / "clang"
        analyzer_cpp = tools / "clang++"
        tidy.write_text(
            """#!/bin/sh
set -eu
if [ "${1:-}" = "--version" ]; then
    echo "fake clang-tidy 1.0"
    exit 0
fi
for argument in "$@"; do
    case "$argument" in
        --fix*|--export-fixes*)
            echo "unexpected fix argument: $argument" >&2
            exit 98
            ;;
    esac
done
if [ "${1:-}" = "--list-checks" ]; then
    echo "Enabled checks:"
    echo "    bugprone-test"
    echo "    cert-test"
    exit 0
fi
printf '%s\\n' "$@" >> "${FAKE_TOOL_LOG:?}"
if [ "${FAKE_TIDY_FAIL:-0}" = "1" ]; then
    echo "fake clang-tidy technical failure" >&2
    exit 9
fi
printf '%s:4:2: warning: repository diagnostic [bugprone-test,cert-test]\\n' "${FAKE_REPOSITORY_SOURCE:?}" >&2
printf '/usr/include/stdio.h:8:1: warning: system header diagnostic [bugprone-test]\\n' >&2
printf '%s:9:1: warning: vendor header diagnostic [bugprone-test]\\n' "${FAKE_VENDOR_HEADER:?}" >&2
""",
            encoding="utf-8",
        )
        analyzer.write_text(
            """#!/bin/sh
set -eu
if [ "${1:-}" = "--version" ]; then
    echo "fake clang 1.0"
    exit 0
fi
printf '%s\\n' "$@" >> "${FAKE_TOOL_LOG:?}"
if [ "${FAKE_ANALYZER_FAIL:-0}" = "1" ]; then
    echo "fake clang technical failure" >&2
    exit 9
fi
output=""
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-o" ]; then
        output=$2
        shift 2
        continue
    fi
    shift
done
if [ -z "$output" ]; then
    echo "missing SARIF output" >&2
    exit 8
fi
printf '{"version":"2.1.0","runs":[{"results":[{"ruleId":"security.insecureAPI","level":"warning","message":{"text":"analyzer security candidate"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"%s"},"region":{"startLine":3,"startColumn":1}}}]}]}]}' "${FAKE_REPOSITORY_SOURCE:?}" > "$output"
""",
            encoding="utf-8",
        )
        shutil.copyfile(analyzer, analyzer_cpp)
        for tool in (tidy, analyzer, analyzer_cpp):
            tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
        return {"tidy": tidy, "clang": analyzer, "clangxx": analyzer_cpp}

    def run_runner(
        self,
        *,
        mode: str,
        temp_root: Path,
        cdb: Path,
        output: Path,
        tools: dict[str, Path],
        extra_environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "CODEX_TEMP_ROOT": str(temp_root),
                "TMPDIR": str(temp_root / "tmp"),
                "PYTHONDONTWRITEBYTECODE": "1",
                "FAKE_REPOSITORY_SOURCE": str(SOURCE),
                "FAKE_VENDOR_HEADER": str(temp_root / "vendor/include/vendor.h"),
                "FAKE_TOOL_LOG": str(temp_root / "tool-arguments.log"),
            }
        )
        if extra_environment:
            environment.update(extra_environment)
        return subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--mode",
                mode,
                "--compdb-output",
                str(cdb),
                "--analysis-output",
                str(output),
                "--clang-tidy",
                str(tools["tidy"]),
                "--clang",
                str(tools["clang"]),
                "--clangxx",
                str(tools["clangxx"]),
            ],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_make_targets_are_opt_in_and_no_configuration_file_is_added(self) -> None:
        makefile = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
        for target in (
            "check-clang-analysis-tools",
            "clang-tidy-baseline",
            "clang-analyzer-baseline",
            "clang-analysis-baseline",
        ):
            self.assertIn(f"{target}:", makefile)
            self.assertIn(target, makefile)
        self.assertIn(
            ".PHONY: check-clang-analysis-tools clang-tidy-baseline "
            "clang-analyzer-baseline clang-analysis-baseline",
            makefile,
        )
        lint_block = makefile[makefile.index("lint:") : makefile.index("summary:")]
        for target in (
            "check-clang-analysis-tools",
            "clang-tidy-baseline",
            "clang-analyzer-baseline",
            "clang-analysis-baseline",
        ):
            self.assertNotIn(target, lint_block)
        self.assertFalse((source_path('.clang-tidy', root=ROOT)).exists())
        self.assertFalse((source_path('.clangd', root=ROOT)).exists())
        self.assertNotIn("NOLINT", RUNNER.read_text(encoding="utf-8"))

    def test_missing_or_invalid_cdb_preserves_output(self) -> None:
        with self.temporary_directory() as temporary_directory:
            parent = Path(temporary_directory)
            temp_root = self.make_temp_root(parent)
            tools = self.write_fake_tools(parent)
            missing = temp_root / "input/missing.json"
            output = temp_root / "analysis/missing"
            missing_result = self.run_runner(
                mode="tidy", temp_root=temp_root, cdb=missing, output=output, tools=tools
            )
            self.assertEqual(missing_result.returncode, 77, missing_result.stderr)
            self.assertFalse(output.exists())

            invalid = self.write_cdb(temp_root, raw={"not": "an array"})
            invalid_result = self.run_runner(
                mode="tidy", temp_root=temp_root, cdb=invalid, output=output, tools=tools
            )
            self.assertEqual(invalid_result.returncode, 2, invalid_result.stderr)
            self.assertFalse(output.exists())

    def test_relative_checkout_and_symlink_escaping_paths_are_rejected_before_writes(self) -> None:
        with self.temporary_directory() as temporary_directory:
            parent = Path(temporary_directory)
            temp_root = self.make_temp_root(parent)
            tools = self.write_fake_tools(parent)
            cdb = self.write_cdb(temp_root)
            output = temp_root / "analysis/valid"
            environment = os.environ.copy()
            environment.update({"CODEX_TEMP_ROOT": str(temp_root), "PYTHONDONTWRITEBYTECODE": "1"})
            relative = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--mode",
                    "tidy",
                    "--compdb-output",
                    "relative.json",
                    "--analysis-output",
                    str(output),
                    "--clang-tidy",
                    str(tools["tidy"]),
                    "--clang",
                    str(tools["clang"]),
                    "--clangxx",
                    str(tools["clangxx"]),
                ],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(relative.returncode, 2, relative.stderr)
            self.assertFalse(output.exists())

            checkout_output = source_path('.clang-analysis-baseline-contract-output', root=ROOT)
            self.addCleanup(shutil.rmtree, checkout_output, ignore_errors=True)
            checkout_result = self.run_runner(
                mode="tidy",
                temp_root=temp_root,
                cdb=cdb,
                output=checkout_output,
                tools=tools,
            )
            self.assertEqual(checkout_result.returncode, 2, checkout_result.stderr)
            self.assertFalse(checkout_output.exists())

            outside = parent / "outside"
            outside.mkdir()
            escape = temp_root / "escape"
            escape.symlink_to(outside, target_is_directory=True)
            escaped_result = self.run_runner(
                mode="tidy",
                temp_root=temp_root,
                cdb=cdb,
                output=escape / "analysis",
                tools=tools,
            )
            self.assertEqual(escaped_result.returncode, 2, escaped_result.stderr)
            self.assertEqual(list(outside.iterdir()), [])

    def test_missing_tool_returns_blocked_before_output_creation(self) -> None:
        with self.temporary_directory() as temporary_directory:
            parent = Path(temporary_directory)
            temp_root = self.make_temp_root(parent)
            tools = self.write_fake_tools(parent)
            cdb = self.write_cdb(temp_root)
            output = temp_root / "analysis/missing-tool"
            tools["tidy"] = parent / "not-installed-clang-tidy"
            result = self.run_runner(
                mode="tidy", temp_root=temp_root, cdb=cdb, output=output, tools=tools
            )
            self.assertEqual(result.returncode, 77, result.stderr)
            self.assertIn("clang-tidy is unavailable", result.stderr)
            self.assertFalse(output.exists())

    def test_findings_are_normalized_read_only_and_do_not_fail_the_tidy_baseline(self) -> None:
        with self.temporary_directory() as temporary_directory:
            parent = Path(temporary_directory)
            temp_root = self.make_temp_root(parent)
            tools = self.write_fake_tools(parent)
            cdb = self.write_cdb(temp_root)
            output = temp_root / "analysis/tidy"
            output.mkdir(parents=True)
            sentinel = output / "foreign-sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")
            source_hash_before = sha256(SOURCE)
            cdb_hash_before = sha256(cdb)
            status_before = git_status()

            result = self.run_runner(
                mode="tidy", temp_root=temp_root, cdb=cdb, output=output, tools=tools
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(source_hash_before, sha256(SOURCE))
            self.assertEqual(cdb_hash_before, sha256(cdb))
            self.assertEqual(status_before, git_status())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")
            self.assertEqual(list(output.glob(".clang-analysis-stage-*")), [])

            summary = json.loads((output / "clang-tidy-baseline.json").read_text(encoding="utf-8"))
            for field in (
                "schema_version",
                "mode",
                "status",
                "analysis_complete",
                "compilation_database",
                "tools",
                "profiles",
                "raw_occurrence_count",
                "unique_finding_count",
                "allowed_classifications",
                "classification_counts",
                "findings",
                "technical_failures",
                "read_only_verification",
            ):
                self.assertIn(field, summary)
            self.assertEqual(summary["mode"], "tidy")
            self.assertTrue(summary["analysis_complete"])
            self.assertGreater(summary["unique_finding_count"], 0)
            self.assertSetEqual(
                set(summary["classification_counts"]), set(summary["allowed_classifications"])
            )
            self.assertSetEqual(
                set(summary["allowed_classifications"]),
                {
                    "confirmed_bug",
                    "needs_validation",
                    "possible_security_candidate",
                    "false_positive",
                    "third_party_header",
                    "intentional_pattern",
                    "out_of_scope",
                },
            )
            self.assertTrue(
                all(
                    finding["classification"] in summary["allowed_classifications"]
                    for finding in summary["findings"]
                )
            )
            self.assertIn("possible_security_candidate", {item["classification"] for item in summary["findings"]})
            external_headers = [
                item for item in summary["findings"] if item["classification"] == "third_party_header"
            ]
            self.assertEqual({item["header_origin"] for item in external_headers}, {"system", "third_party"})
            self.assertTrue(all(item["occurrence_count"] >= 1 for item in summary["findings"]))
            self.assertTrue(all("--fix" not in line for line in (temp_root / "tool-arguments.log").read_text(encoding="utf-8").splitlines()))
            self.assertTrue(summary["read_only_verification"]["worktree_status_unchanged"])
            self.assertTrue(summary["read_only_verification"]["analyzed_source_files_unchanged"])
            self.assertTrue(summary["read_only_verification"]["compilation_database_unchanged"])

    def test_analyzer_technical_error_is_nonzero_and_safe(self) -> None:
        with self.temporary_directory() as temporary_directory:
            parent = Path(temporary_directory)
            temp_root = self.make_temp_root(parent)
            tools = self.write_fake_tools(parent)
            cdb = self.write_cdb(temp_root)
            output = temp_root / "analysis/analyzer"
            output.mkdir(parents=True)
            sentinel = output / "foreign-sentinel.txt"
            sentinel.write_text("keep\n", encoding="utf-8")

            result = self.run_runner(
                mode="analyzer",
                temp_root=temp_root,
                cdb=cdb,
                output=output,
                tools=tools,
                extra_environment={"FAKE_ANALYZER_FAIL": "1"},
            )

            self.assertEqual(result.returncode, 1, result.stderr)
            summary = json.loads((output / "clang-analyzer-baseline.json").read_text(encoding="utf-8"))
            self.assertFalse(summary["analysis_complete"])
            self.assertEqual(summary["status"], "technical_error")
            self.assertTrue(summary["technical_failures"])
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep\n")
            self.assertEqual(list(output.glob(".clang-analysis-stage-*")), [])

    def test_unsafe_compiler_arguments_are_usage_errors_before_writes(self) -> None:
        with self.temporary_directory() as temporary_directory:
            parent = Path(temporary_directory)
            temp_root = self.make_temp_root(parent)
            tools = self.write_fake_tools(parent)
            output = temp_root / "analysis/unsafe"
            cdb = self.write_cdb(
                temp_root,
                arguments=[
                    "/usr/bin/cc",
                    "-std=c17",
                    "-fplugin=/tmp/untrusted.so",
                    "-c",
                    str(SOURCE),
                    "-o",
                    str(temp_root / "objects/out.o"),
                ],
            )
            result = self.run_runner(
                mode="analyzer", temp_root=temp_root, cdb=cdb, output=output, tools=tools
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("unsafe compiler argument", result.stderr)
            self.assertFalse(output.exists())

    def test_tool_check_is_a_narrow_clang_prerequisite_probe(self) -> None:
        with self.temporary_directory() as temporary_directory:
            parent = Path(temporary_directory)
            tools = self.write_fake_tools(parent)
            environment = os.environ.copy()
            environment.update(
                {
                    "PYTHON": sys.executable,
                    "CLANG_TIDY": str(tools["tidy"]),
                    "CLANG": str(tools["clang"]),
                    "CLANGXX": str(tools["clangxx"]),
                    "PYTHONDONTWRITEBYTECODE": "1",
                }
            )
            result = subprocess.run(
                [str(TOOLS_CHECK)],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PASS: clang-tidy", result.stdout)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
