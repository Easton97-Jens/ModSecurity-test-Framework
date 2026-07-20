from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "ci/lib/mrts-common.sh"


class MrtsCommonPosixReliabilityTests(unittest.TestCase):
    def shell_environment(self, temporary_root: Path) -> dict[str, str]:
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith(("MODSECURITY_", "MRTS_"))
        }
        for name in (
            "BUILD_ROOT",
            "EXTRA_CASE_ROOTS",
            "FRAMEWORK_ROOT",
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
                "MRTS_ROOT": str(temporary_root / "synthetic-mrts"),
                "TMP_ROOT": str(temporary_root / "tmp * [literal]"),
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
            ["sh", "-eu", "-c", script],
            cwd=temporary_root,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )

    def prepared_variant_script(self) -> str:
        return "\n".join(
            (
                '. "$HELPER_PATH"',
                'MRTS_UPSTREAM_CASE_ROOT="$CASE_ROOT"',
                'MRTS_FEATURE_DEMO_LOAD_FILE="${FEATURE_LOAD_FILE:-$MRTS_FEATURE_DEMO_LOAD_FILE}"',
                "mrts_append_rule_preamble() { :; }",
                "mrts_append_extra_case_root() { :; }",
                "mrts_append_reference_case_root() { :; }",
                'cd "$SYNTHETIC_ROOT"',
                "prepare_mrts_variant",
                'printf "ready\\n"',
            )
        )

    def test_source_has_no_test_command_or_bash_conditional(self) -> None:
        source = HELPER.read_text(encoding="utf-8")

        self.assertNotRegex(source, r"(?m)\btest\b")
        self.assertNotIn("[[", source)
        self.assertIn("mrts_path_matches() (", source)
        self.assertIn("mrts_path_matches_kind=$2", source)
        self.assertNotIn('case "$2" in', source)
        self.assertIn('return "$mrts_path_matches_status"', source)
        self.assertEqual(3, source.count("command -p find -H"))

    def test_path_classifier_rejects_unknown_match_kind(self) -> None:
        unknown_kind_script = "\n".join(
            (
                '. "$HELPER_PATH"',
                'if mrts_path_matches "$NORMAL_PATH" unexpected; then',
                '    printf "bypass\\n"',
                "    exit 0",
                "else",
                "status=$?",
                'printf "rejected:%s\\n" "$status"',
                'exit "$status"',
                "fi",
            )
        )

        with tempfile.TemporaryDirectory(prefix="mrts-common-posix-") as temporary:
            temporary_root = Path(temporary)
            normal_file = temporary_root / "normal file"
            normal_file.write_text("fixture\n", encoding="utf-8")
            result = self.run_shell(
                unknown_kind_script,
                temporary_root,
                NORMAL_PATH=str(normal_file),
            )

            self.assertEqual(2, result.returncode, result.stdout + result.stderr)
            self.assertEqual("rejected:2\n", result.stdout)
            self.assertEqual("", result.stderr)

    def test_path_classifier_rejects_function_and_path_shadowing(self) -> None:
        missing_path_script = "\n".join(
            (
                '. "$HELPER_PATH"',
                'if mrts_path_matches "$MISSING_PATH" regular; then',
                '    printf "bypass\\n"',
                "    exit 0",
                "else",
                "    status=$?",
                '    printf "rejected:%s\\n" "$status"',
                '    exit "$status"',
                "fi",
            )
        )

        with tempfile.TemporaryDirectory(prefix="mrts-common-posix-") as temporary:
            temporary_root = Path(temporary)
            normal_file = temporary_root / "normal file"
            normal_directory = temporary_root / "normal directory"
            normal_file.write_text("fixture\n", encoding="utf-8")
            normal_directory.mkdir()
            for shadowing_script in (
                "find() { printf x; }",
                "PATH=/nonexistent",
            ):
                with self.subTest(shadowing_script=shadowing_script):
                    result = self.run_shell(
                        "\n".join((
                            '. "$HELPER_PATH"',
                            shadowing_script,
                            *missing_path_script.splitlines()[1:],
                        )),
                        temporary_root,
                        MISSING_PATH=str(temporary_root / "missing path"),
                    )

                    self.assertNotEqual(0, result.returncode)
                    self.assertRegex(result.stdout, r"^rejected:[1-9][0-9]*\n$")
                    self.assertEqual(
                        f"rejected:{result.returncode}\n", result.stdout
                    )
                    self.assertEqual("", result.stderr)

                    for match_kind, normal_path in (
                        ("regular", normal_file),
                        ("directory", normal_directory),
                        ("nonempty", normal_file),
                    ):
                        with self.subTest(
                            shadowing_script=shadowing_script,
                            match_kind=match_kind,
                        ):
                            legitimate = self.run_shell(
                                "\n".join(
                                    (
                                        '. "$HELPER_PATH"',
                                        shadowing_script,
                                        f'if mrts_path_matches "$NORMAL_PATH" {match_kind}; then',
                                        f'    printf "accepted:{match_kind}\\n"',
                                        "else",
                                        "    status=$?",
                                        '    printf "rejected:%s\\n" "$status"',
                                        '    exit "$status"',
                                        "fi",
                                    )
                                ),
                                temporary_root,
                                NORMAL_PATH=str(normal_path),
                            )

                            self.assertEqual(
                                0,
                                legitimate.returncode,
                                legitimate.stdout + legitimate.stderr,
                            )
                            self.assertEqual(
                                f"accepted:{match_kind}\n", legitimate.stdout
                            )
                            self.assertEqual("", legitimate.stderr)

    def test_case_root_values_remain_literal_under_posix_sh(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mrts-common-posix-") as temporary:
            temporary_root = Path(temporary)
            safe_root = temporary_root / "safe root * [literal]"
            safe_root.mkdir()

            for variable, function_name in (
                ("EXTRA_CASE_ROOTS", "mrts_append_extra_case_root"),
                ("REFERENCE_CASE_ROOTS", "mrts_append_reference_case_root"),
            ):
                for initial_value in ("", "  ", "*", "-option"):
                    with self.subTest(
                        variable=variable,
                        initial_value=initial_value,
                    ):
                        result = self.run_shell(
                            "\n".join(
                                (
                                    '. "$HELPER_PATH"',
                                    f'{function_name} "$SAFE_ROOT"',
                                    f'printf "%s\\n" "${variable}"',
                                )
                            ),
                            temporary_root,
                            SAFE_ROOT=str(safe_root),
                            **{variable: initial_value},
                        )
                        expected_value = (
                            str(safe_root)
                            if initial_value == ""
                            else f"{initial_value}:{safe_root}"
                        )

                        self.assertEqual(
                            0,
                            result.returncode,
                            result.stdout + result.stderr,
                        )
                        self.assertEqual(f"{expected_value}\n", result.stdout)
                        self.assertEqual("", result.stderr)

    def test_results_dir_preserves_nonempty_literal_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mrts-common-posix-") as temporary:
            temporary_root = Path(temporary)

            for results_dir in ("  ", "*", "-results"):
                with self.subTest(results_dir=results_dir):
                    result = self.run_shell(
                        "\n".join(
                            (
                                '. "$HELPER_PATH"',
                                "set_mrts_results_dir",
                                'printf "%s\\n" "$RESULTS_DIR"',
                            )
                        ),
                        temporary_root,
                        RESULTS_DIR=results_dir,
                    )

                    self.assertEqual(
                        0,
                        result.returncode,
                        result.stdout + result.stderr,
                    )
                    self.assertEqual(f"{results_dir}\n", result.stdout)
                    self.assertEqual("", result.stderr)

    def test_glob_like_preamble_path_is_compared_literally(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mrts-common-posix-") as temporary:
            temporary_root = Path(temporary)
            preamble = temporary_root / "-preamble * [literal] ?.load"
            preamble.write_text('Include "literal.conf"\n', encoding="utf-8")
            result = self.run_shell(
                "\n".join(
                    (
                        '. "$HELPER_PATH"',
                        'MODSECURITY_RULE_PREAMBLE_FILE="$PREAMBLE"',
                        'mrts_append_rule_preamble "$PREAMBLE"',
                        'printf "%s\\n" "$MODSECURITY_RULE_PREAMBLE_FILE"',
                    )
                ),
                temporary_root,
                PREAMBLE=str(preamble),
            )

            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(f"{preamble}\n", result.stdout)
            self.assertEqual("", result.stderr)
            self.assertFalse(
                (temporary_root / "build" / "preambles" / "mrts-combined.load").exists()
            )

    def test_prepared_variant_accepts_option_like_literal_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mrts-common-posix-") as temporary:
            temporary_root = Path(temporary)
            load_file = "-load * [literal] ?.load"
            case_root = "-case root * [literal]"
            (temporary_root / load_file).write_text("load\n", encoding="utf-8")
            (temporary_root / case_root).mkdir()
            result = self.run_shell(
                self.prepared_variant_script(),
                temporary_root,
                MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO="0",
                MODSECURITY_MRTS_PREPARED="1",
                MODSECURITY_MRTS_VARIANT="with-mrts",
                MRTS_LOAD_FILE=load_file,
                CASE_ROOT=case_root,
                SYNTHETIC_ROOT=str(temporary_root),
            )

            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual("ready\n", result.stdout)
            self.assertEqual("", result.stderr)

    def test_prepared_variant_fails_closed_for_missing_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mrts-common-posix-") as temporary:
            temporary_root = Path(temporary)
            case_root = "-case root * [literal]"
            (temporary_root / case_root).mkdir()

            missing_load = self.run_shell(
                self.prepared_variant_script(),
                temporary_root,
                MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO="0",
                MODSECURITY_MRTS_PREPARED="1",
                MODSECURITY_MRTS_VARIANT="with-mrts",
                MRTS_LOAD_FILE="-missing load * [literal]",
                CASE_ROOT=case_root,
                SYNTHETIC_ROOT=str(temporary_root),
            )

            self.assertEqual(
                77,
                missing_load.returncode,
                missing_load.stdout + missing_load.stderr,
            )
            self.assertIn("prepared MRTS load file missing", missing_load.stderr)

            load_file = "-load * [literal] ?.load"
            (temporary_root / load_file).write_text("load\n", encoding="utf-8")
            missing_case_root = self.run_shell(
                self.prepared_variant_script(),
                temporary_root,
                MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO="0",
                MODSECURITY_MRTS_PREPARED="1",
                MODSECURITY_MRTS_VARIANT="with-mrts",
                MRTS_LOAD_FILE=load_file,
                CASE_ROOT="-missing root * [literal]",
                SYNTHETIC_ROOT=str(temporary_root),
            )

            self.assertEqual(
                77,
                missing_case_root.returncode,
                missing_case_root.stdout + missing_case_root.stderr,
            )
            self.assertIn("prepared MRTS case root missing", missing_case_root.stderr)

    def test_prepared_variant_blocks_shadowed_missing_load_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mrts-common-posix-") as temporary:
            temporary_root = Path(temporary)
            case_root = "-case root * [literal]"
            (temporary_root / case_root).mkdir()

            for shadowing_script in (
                "find() { printf x; }",
                "PATH=/nonexistent",
            ):
                with self.subTest(shadowing_script=shadowing_script):
                    result = self.run_shell(
                        "\n".join(
                            (
                                '. "$HELPER_PATH"',
                                shadowing_script,
                                'MRTS_UPSTREAM_CASE_ROOT="$CASE_ROOT"',
                                'MRTS_FEATURE_DEMO_LOAD_FILE="${FEATURE_LOAD_FILE:-$MRTS_FEATURE_DEMO_LOAD_FILE}"',
                                "mrts_append_rule_preamble() { :; }",
                                "mrts_append_extra_case_root() { :; }",
                                "mrts_append_reference_case_root() { :; }",
                                'cd "$SYNTHETIC_ROOT"',
                                "prepare_mrts_variant",
                            )
                        ),
                        temporary_root,
                        CASE_ROOT=case_root,
                        MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO="0",
                        MODSECURITY_MRTS_PREPARED="1",
                        MODSECURITY_MRTS_VARIANT="with-mrts",
                        MRTS_LOAD_FILE="-missing load * [literal]",
                        SYNTHETIC_ROOT=str(temporary_root),
                    )

                    self.assertEqual(
                        77,
                        result.returncode,
                        result.stdout + result.stderr,
                    )
                    self.assertEqual("", result.stdout)
                    self.assertIn("prepared MRTS load file missing", result.stderr)

    def test_prepared_feature_demo_requires_a_literal_regular_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mrts-common-posix-") as temporary:
            temporary_root = Path(temporary)
            load_file = "-load * [literal] ?.load"
            case_root = "-case root * [literal]"
            feature_load_file = "-feature load * [literal] ?.load"
            (temporary_root / load_file).write_text("load\n", encoding="utf-8")
            (temporary_root / case_root).mkdir()
            (temporary_root / feature_load_file).write_text(
                "feature\n", encoding="utf-8"
            )

            enabled = self.run_shell(
                self.prepared_variant_script(),
                temporary_root,
                MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO="1",
                MODSECURITY_MRTS_PREPARED="1",
                MODSECURITY_MRTS_VARIANT="with-mrts",
                FEATURE_LOAD_FILE=feature_load_file,
                MRTS_LOAD_FILE=load_file,
                CASE_ROOT=case_root,
                SYNTHETIC_ROOT=str(temporary_root),
            )

            self.assertEqual(0, enabled.returncode, enabled.stdout + enabled.stderr)
            self.assertEqual("ready\n", enabled.stdout)
            self.assertEqual("", enabled.stderr)

            missing = self.run_shell(
                self.prepared_variant_script(),
                temporary_root,
                MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO="1",
                MODSECURITY_MRTS_PREPARED="1",
                MODSECURITY_MRTS_VARIANT="with-mrts",
                FEATURE_LOAD_FILE="-missing feature * [literal]",
                MRTS_LOAD_FILE=load_file,
                CASE_ROOT=case_root,
                SYNTHETIC_ROOT=str(temporary_root),
            )

            self.assertEqual(77, missing.returncode, missing.stdout + missing.stderr)
            self.assertIn(
                "prepared feature-demo MRTS load file missing", missing.stderr
            )

    def test_duplicate_rule_ids_block_and_distinct_ids_continue(self) -> None:
        duplicate_script = "\n".join(
            (
                '. "$HELPER_PATH"',
                "assert_safe_runtime_path() { :; }",
                "mrts_rule_ids() { printf '100\\n'; }",
                "mrts_check_feature_demo_runtime_safe",
            )
        )
        distinct_script = "\n".join(
            (
                '. "$HELPER_PATH"',
                "assert_safe_runtime_path() { :; }",
                "mrts_rule_ids() {",
                '    case "$1" in',
                '        "$MRTS_UPSTREAM_RULES_OUT") printf "100\\n" ;;',
                '        *) printf "200\\n" ;;',
                "    esac",
                "}",
                "mrts_check_feature_demo_runtime_safe",
                'printf "safe\\n"',
            )
        )

        with tempfile.TemporaryDirectory(prefix="mrts-common-posix-") as temporary:
            temporary_root = Path(temporary)
            duplicate = self.run_shell(duplicate_script, temporary_root)
            distinct = self.run_shell(distinct_script, temporary_root)

            self.assertEqual(
                77,
                duplicate.returncode,
                duplicate.stdout + duplicate.stderr,
            )
            self.assertIn("duplicate rule IDs", duplicate.stderr)
            self.assertEqual(0, distinct.returncode, distinct.stdout + distinct.stderr)
            self.assertEqual("safe\n", distinct.stdout)
            self.assertEqual("", distinct.stderr)

    def test_feature_and_prepared_values_select_only_the_literal_enabled_path(self) -> None:
        import_script = "\n".join(
            (
                '. "$HELPER_PATH"',
                "assert_safe_runtime_path() { :; }",
                'MRTS_UPSTREAM_CASE_ROOT="$UPSTREAM_CASE_ROOT"',
                'MRTS_FEATURE_DEMO_CASE_ROOT="$FEATURE_CASE_ROOT"',
                "mrts_check_feature_demo_runtime_safe() { printf 'checked\\n'; }",
                "mrts_import_cases",
                'printf "done\\n"',
            )
        )
        runtime_script = "\n".join(
            (
                '. "$HELPER_PATH"',
                "prepare_mrts_variant() { :; }",
                "mrts_import_cases() { printf 'imported\\n'; }",
                "prepare_mrts_runtime_variant",
            )
        )

        with tempfile.TemporaryDirectory(prefix="mrts-common-posix-") as temporary:
            temporary_root = Path(temporary)
            import_roots = {
                "FEATURE_CASE_ROOT": str(temporary_root / "feature cases"),
                "PYTHON": "/bin/true",
                "UPSTREAM_CASE_ROOT": str(temporary_root / "upstream cases"),
            }

            enabled = self.run_shell(
                import_script,
                temporary_root,
                MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO="1",
                **import_roots,
            )
            self.assertEqual(0, enabled.returncode, enabled.stdout + enabled.stderr)
            self.assertEqual("checked\ndone\n", enabled.stdout)
            self.assertEqual("", enabled.stderr)

            for feature_value in ("", " ", "*", "-1"):
                with self.subTest(feature_value=feature_value):
                    disabled = self.run_shell(
                        import_script,
                        temporary_root,
                        MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=feature_value,
                        **import_roots,
                    )
                    self.assertEqual(
                        0,
                        disabled.returncode,
                        disabled.stdout + disabled.stderr,
                    )
                    self.assertEqual("done\n", disabled.stdout)
                    self.assertEqual("", disabled.stderr)

            for prepared_value, expected_output in (
                ("1", ""),
                ("", "imported\n"),
                (" ", "imported\n"),
                ("*", "imported\n"),
                ("-1", "imported\n"),
            ):
                with self.subTest(prepared_value=prepared_value):
                    runtime = self.run_shell(
                        runtime_script,
                        temporary_root,
                        MODSECURITY_MRTS_PREPARED=prepared_value,
                        MODSECURITY_MRTS_VARIANT="with-mrts",
                    )
                    self.assertEqual(
                        0,
                        runtime.returncode,
                        runtime.stdout + runtime.stderr,
                    )
                    self.assertEqual(expected_output, runtime.stdout)
                    self.assertEqual("", runtime.stderr)


if __name__ == "__main__":
    unittest.main()
