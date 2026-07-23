"""Regression coverage for the POSIX-safe MRTS helper control flow."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "ci/lib/mrts-common.sh"


class MrtsCommonSonarRegressionTests(unittest.TestCase):
    """Exercise only synthetic paths while preserving MRTS safety controls."""

    def shell_environment(self, temporary_root: Path) -> dict[str, str]:
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith("MRTS_")
        }
        for name in (
            "BUILD_ROOT",
            "EXTRA_CASE_ROOTS",
            "FRAMEWORK_ROOT",
            "MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO",
            "MODSECURITY_MRTS_PREPARED",
            "MODSECURITY_MRTS_VARIANT",
            "MODSECURITY_RULE_PREAMBLE_FILE",
            "MODSECURITY_TEST_VARIANT",
            "REFERENCE_CASE_ROOTS",
            "RESULTS_DIR",
            "TMP_ROOT",
            "VERIFIED_BUILD_ROOT",
            "VERIFIED_RUN_ROOT",
            "VERIFIED_TMP_ROOT",
        ):
            environment.pop(name, None)
        environment.update(
            {
                "BUILD_ROOT": str(temporary_root / "build"),
                "FRAMEWORK_ROOT": str(temporary_root / "framework"),
                "HELPER_PATH": str(HELPER),
                "MODSECURITY_MRTS_VARIANT": "no-mrts",
                "MRTS_ROOT": str(temporary_root / "synthetic-mrts"),
                "TMP_ROOT": str(temporary_root / "tmp"),
                "VERIFIED_BUILD_ROOT": str(temporary_root / "verified" / "build"),
                "VERIFIED_RUN_ROOT": str(temporary_root / "verified"),
                "VERIFIED_TMP_ROOT": str(temporary_root / "verified" / "tmp"),
            }
        )
        return environment

    def run_shell(
        self,
        script: str,
        temporary_root: Path,
        **environment_overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        environment = self.shell_environment(temporary_root)
        environment.update(environment_overrides)
        return subprocess.run(
            ["sh", "-c", script],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )

    def test_variant_validation_accepts_supported_values_and_reports_errors_on_stderr(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mrts-common-variant-") as temporary:
            temporary_root = Path(temporary)
            valid = self.run_shell(
                '. "$HELPER_PATH"\nvalidate_mrts_variant\nprintf "valid\\n"',
                temporary_root,
            )
            invalid = self.run_shell(
                '. "$HELPER_PATH"\nvalidate_mrts_variant',
                temporary_root,
                MODSECURITY_MRTS_VARIANT="unsupported",
            )

            self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
            self.assertEqual(valid.stdout, "valid\n")
            self.assertEqual(valid.stderr, "")
            self.assertEqual(invalid.returncode, 2, invalid.stdout + invalid.stderr)
            self.assertEqual(invalid.stdout, "")
            self.assertIn(
                "ERROR: invalid MODSECURITY_MRTS_VARIANT=unsupported",
                invalid.stderr,
            )

    def test_case_roots_remain_deduplicated_for_synthetic_safe_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mrts-common-case-roots-") as temporary:
            temporary_root = Path(temporary)
            safe_root = temporary_root / "safe cases"
            safe_root.mkdir()
            result = self.run_shell(
                "\n".join(
                    (
                        '. "$HELPER_PATH"',
                        'mrts_append_extra_case_root "$SAFE_ROOT"',
                        'mrts_append_extra_case_root "$SAFE_ROOT"',
                        'mrts_append_reference_case_root "$SAFE_ROOT"',
                        'mrts_append_reference_case_root "$SAFE_ROOT"',
                        'printf "%s\\n%s\\n" "$EXTRA_CASE_ROOTS" "$REFERENCE_CASE_ROOTS"',
                    )
                ),
                temporary_root,
                SAFE_ROOT=str(safe_root),
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                result.stdout,
                f"{safe_root}\n{safe_root}\n",
            )
            self.assertEqual(result.stderr, "")

    def test_golden_reference_roots_remain_blocked_on_synthetic_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mrts-common-golden-root-") as temporary:
            temporary_root = Path(temporary)
            golden_root = temporary_root / "synthetic-mrts" / "generated"
            golden_root.mkdir(parents=True)

            for function_name, expected_message in (
                (
                    "mrts_append_extra_case_root",
                    "ERROR: refusing to add MRTS golden references as case roots:",
                ),
                (
                    "mrts_append_reference_case_root",
                    "ERROR: refusing to add MRTS golden references as reference case roots:",
                ),
            ):
                with self.subTest(function_name=function_name):
                    result = self.run_shell(
                        f'. "$HELPER_PATH"\n{function_name} "$GOLDEN_ROOT"',
                        temporary_root,
                        GOLDEN_ROOT=str(golden_root),
                    )

                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(expected_message, result.stderr)

    def test_rule_preamble_combines_only_synthetic_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mrts-common-preamble-") as temporary:
            temporary_root = Path(temporary)
            existing_preamble = temporary_root / "existing.load"
            new_preamble = temporary_root / "new.load"
            existing_preamble.write_text("Include \"existing.conf\"\n", encoding="utf-8")
            new_preamble.write_text("Include \"new.conf\"\n", encoding="utf-8")
            result = self.run_shell(
                "\n".join(
                    (
                        '. "$HELPER_PATH"',
                        "assert_safe_runtime_path() { return 0; }",
                        "assert_not_system_path_for_write() { return 0; }",
                        'MODSECURITY_RULE_PREAMBLE_FILE="$EXISTING_PREAMBLE"',
                        'mrts_append_rule_preamble "$NEW_PREAMBLE"',
                        'printf "%s\\n" "$MODSECURITY_RULE_PREAMBLE_FILE"',
                    )
                ),
                temporary_root,
                EXISTING_PREAMBLE=str(existing_preamble),
                NEW_PREAMBLE=str(new_preamble),
            )
            combined = temporary_root / "build" / "preambles" / "mrts-combined.load"

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout, f"{combined}\n")
            self.assertEqual(result.stderr, "")
            self.assertEqual(
                combined.read_text(encoding="utf-8"),
                f'Include "{existing_preamble}"\nInclude "{new_preamble}"\n',
            )

    def test_no_mrts_and_results_helpers_return_success_without_corpus_access(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mrts-common-no-corpus-") as temporary:
            temporary_root = Path(temporary)
            extra_root = temporary_root / "extra cases"
            extra_root.mkdir()
            result = self.run_shell(
                "\n".join(
                    (
                        '. "$HELPER_PATH"',
                        "prepare_mrts_variant",
                        "prepare_mrts_runtime_variant",
                        "set_mrts_results_dir",
                        'printf "%s\\n%s\\n" "$EXTRA_CASE_ROOTS" "$RESULTS_DIR"',
                    )
                ),
                temporary_root,
                EXTRA_CASE_ROOTS=str(extra_root),
                MODSECURITY_TEST_VARIANT="synthetic",
            )

            expected_results = (
                temporary_root / "build" / "results" / "synthetic" / "no-mrts"
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout, f"{extra_root}\n{expected_results}\n")
            self.assertEqual(result.stderr, "")

    def test_shell_source_uses_posix_test_and_explicit_terminal_returns(self) -> None:
        source = HELPER.read_text(encoding="utf-8")
        self.assertNotRegex(source, r"(?m)^\s*(?:if|elif)\s+\[")
        self.assertNotIn("[[", source)

        functions = (
            "validate_mrts_variant",
            "mrts_append_extra_case_root",
            "mrts_append_reference_case_root",
            "mrts_generate_upstream",
            "mrts_generate_feature_demo",
            "mrts_generate_all_corpora",
            "mrts_rule_ids",
            "mrts_check_feature_demo_runtime_safe",
            "mrts_append_rule_preamble",
            "mrts_import_cases",
            "prepare_mrts_variant",
            "prepare_mrts_runtime_variant",
            "set_mrts_results_dir",
        )
        for function_name in functions:
            with self.subTest(function_name=function_name):
                match = re.search(
                    rf"(?ms)^{re.escape(function_name)}\(\) \{{\n(.*?)(?=^\}}$)",
                    source,
                )
                self.assertIsNotNone(match)
                last_statement = match.group(1).rstrip().splitlines()[-1].strip()
                self.assertRegex(last_statement, r"^return (?:0|\$\?)$")

        for function_name in (
            "mrts_append_extra_case_root",
            "mrts_append_reference_case_root",
        ):
            with self.subTest(function_name=function_name, check="default-case"):
                match = re.search(
                    rf"(?ms)^{re.escape(function_name)}\(\) \{{\n(.*?)(?=^\}}$)",
                    source,
                )
                self.assertIsNotNone(match)
                self.assertRegex(
                    match.group(1),
                    r"(?ms)case \"\$\(CDPATH='' cd .*?^\s*\*\)\n\s*;;\n\s*esac",
                )


if __name__ == "__main__":
    unittest.main()
