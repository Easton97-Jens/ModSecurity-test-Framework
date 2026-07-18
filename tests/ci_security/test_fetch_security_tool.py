from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
FETCHER_PATH = ROOT / "ci/tools/fetch-security-tool.py"
LOCK_PATH = ROOT / "ci/tooling/security-tools.lock.yml"


def load_fetcher():
    spec = importlib.util.spec_from_file_location("security_tool_fetcher", FETCHER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {FETCHER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FETCHER = load_fetcher()


class LockPathValidationTest(unittest.TestCase):
    def test_accepts_the_repository_lock_from_relative_or_absolute_input(self) -> None:
        self.assertEqual(
            FETCHER.confined_lock_path(Path("ci/tooling/security-tools.lock.yml")),
            LOCK_PATH,
        )
        self.assertEqual(FETCHER.confined_lock_path(LOCK_PATH), LOCK_PATH)

    def test_cli_preserves_the_legitimate_relative_lock_invocation(self) -> None:
        expected_output = ROOT / "unused-output"
        with (
            patch.object(
                FETCHER, "read_tool_record", return_value={"name": "fixture"}
            ) as read_record,
            patch.object(FETCHER, "fetch", return_value=expected_output),
            patch.object(
                sys,
                "argv",
                [
                    str(FETCHER_PATH),
                    "--lock",
                    "ci/tooling/security-tools.lock.yml",
                    "--tool",
                    "fixture",
                    "--output-dir",
                    str(expected_output.parent),
                ],
            ),
        ):
            self.assertEqual(FETCHER.main(), 0)
        read_record.assert_called_once_with(LOCK_PATH, "fixture")

    def test_rejects_out_of_root_and_traversal_lock_paths_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            framework_root = temporary_root / "framework"
            framework_root.mkdir()
            outside_lock = temporary_root / "outside-lock.yml"
            outside_lock.write_text("tools: {}\n", encoding="utf-8")

            with patch.object(FETCHER, "framework_root", return_value=framework_root):
                with self.assertRaisesRegex(FETCHER.ToolError, "Framework root"):
                    FETCHER.confined_lock_path(outside_lock)
                with self.assertRaisesRegex(FETCHER.ToolError, "traversal"):
                    FETCHER.confined_lock_path(Path("../outside-lock.yml"))

                with patch.object(FETCHER, "read_tool_record") as read_record:
                    with patch.object(
                        sys,
                        "argv",
                        [
                            str(FETCHER_PATH),
                            "--lock",
                            str(outside_lock),
                            "--tool",
                            "fixture",
                            "--output-dir",
                            str(temporary_root / "output"),
                        ],
                    ):
                        with self.assertRaisesRegex(
                            FETCHER.ToolError, "Framework root"
                        ):
                            FETCHER.main()
                read_record.assert_not_called()

    def test_reading_a_record_rejects_an_untrusted_lock_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            outside_lock = Path(temporary_directory) / "outside-lock.yml"
            outside_lock.write_text("tools: {}\n", encoding="utf-8")
            with patch.object(FETCHER.Path, "read_text") as read_text:
                with self.assertRaisesRegex(FETCHER.ToolError, "Framework root"):
                    FETCHER.read_tool_record(outside_lock, "fixture")
            read_text.assert_not_called()

    def test_rejects_lock_symlink_escapes_and_nonregular_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            framework_root = temporary_root / "framework"
            framework_root.mkdir()
            outside_directory = temporary_root / "outside"
            outside_directory.mkdir()
            outside_lock = outside_directory / "outside-lock.yml"
            outside_lock.write_text("tools: {}\n", encoding="utf-8")
            linked_lock = framework_root / "linked-lock.yml"
            linked_lock.symlink_to(outside_lock)
            linked_directory = framework_root / "linked-directory"
            linked_directory.symlink_to(outside_directory, target_is_directory=True)

            with patch.object(FETCHER, "framework_root", return_value=framework_root):
                with self.assertRaisesRegex(FETCHER.ToolError, "symlink"):
                    FETCHER.confined_lock_path(linked_lock)
                with self.assertRaisesRegex(FETCHER.ToolError, "symlink"):
                    FETCHER.confined_lock_path(linked_directory / "outside-lock.yml")
                with self.assertRaisesRegex(FETCHER.ToolError, "regular non-symlink"):
                    FETCHER.confined_lock_path(framework_root)


class RunnerOwnedOutputDirectoryTest(unittest.TestCase):
    def test_accepts_a_direct_child_of_runner_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner_temp = Path(temporary_directory) / "runner-temp"
            runner_temp.mkdir()
            output_dir = runner_temp / "tools"
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                self.assertEqual(
                    FETCHER.runner_owned_output_dir(output_dir), output_dir
                )

    def test_rejects_missing_runner_temp(self) -> None:
        relative_output = Path("relative-output")
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(FETCHER.ToolError, "runner-owned directory"):
                FETCHER.runner_owned_output_dir(relative_output)

    def test_rejects_relative_output_path(self) -> None:
        relative_output = Path("relative-output")
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner_temp = Path(temporary_directory) / "runner-temp"
            runner_temp.mkdir()
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                with self.assertRaisesRegex(FETCHER.ToolError, "absolute paths"):
                    FETCHER.runner_owned_output_dir(relative_output)

    def test_rejects_the_runner_root_and_paths_outside_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            runner_temp = root / "runner-temp"
            outside = root / "outside"
            runner_temp.mkdir()
            outside.mkdir()
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                with self.assertRaisesRegex(FETCHER.ToolError, "strict child"):
                    FETCHER.runner_owned_output_dir(runner_temp)
                with self.assertRaisesRegex(FETCHER.ToolError, "strict child"):
                    FETCHER.runner_owned_output_dir(outside / "tools")

    def test_rejects_existing_symlink_components(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            runner_temp = root / "runner-temp"
            outside = root / "outside"
            runner_temp.mkdir()
            outside.mkdir()
            (runner_temp / "escape").symlink_to(outside, target_is_directory=True)
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                with self.assertRaisesRegex(FETCHER.ToolError, "symlink"):
                    FETCHER.runner_owned_output_dir(runner_temp / "escape" / "tools")

    def test_rejects_a_symlinked_runner_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            actual_runner_temp = root / "actual-runner-temp"
            runner_temp_alias = root / "runner-temp-alias"
            actual_runner_temp.mkdir()
            runner_temp_alias.symlink_to(actual_runner_temp, target_is_directory=True)
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp_alias)}):
                with self.assertRaisesRegex(FETCHER.ToolError, "non-symlink"):
                    FETCHER.runner_owned_output_dir(runner_temp_alias / "tools")

    def test_requires_runner_temp_to_belong_to_the_current_user(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            runner_temp = Path(temporary_directory) / "runner-temp"
            runner_temp.mkdir()
            other_user_id = runner_temp.stat().st_uid + 1
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                with patch.object(FETCHER.os, "geteuid", return_value=other_user_id):
                    with self.assertRaisesRegex(FETCHER.ToolError, "not owned"):
                        FETCHER.runner_owned_output_dir(runner_temp / "tools")


if __name__ == "__main__":
    unittest.main()
