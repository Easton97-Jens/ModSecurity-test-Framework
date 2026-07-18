from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
FETCHER_PATH = ROOT / "ci/tools/fetch-security-tool.py"


def load_fetcher():
    spec = importlib.util.spec_from_file_location("security_tool_fetcher", FETCHER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {FETCHER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FETCHER = load_fetcher()


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

    def test_rejects_missing_or_relative_runner_paths(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(FETCHER.ToolError, "runner-owned directory"):
                FETCHER.runner_owned_output_dir(Path("relative-output"))

        with tempfile.TemporaryDirectory() as temporary_directory:
            runner_temp = Path(temporary_directory) / "runner-temp"
            runner_temp.mkdir()
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                with self.assertRaisesRegex(FETCHER.ToolError, "absolute paths"):
                    FETCHER.runner_owned_output_dir(Path("relative-output"))

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
