"""Regression coverage for materialized runner output containment."""

from __future__ import annotations

import argparse
import importlib
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNERS = ROOT / "tests" / "runners"

if str(RUNNERS) not in sys.path:
    sys.path.insert(0, str(RUNNERS))

runner_core = importlib.import_module("runner_core")
case_cli = importlib.import_module("case_cli")


class RunnerCoreOutputContainmentTests(unittest.TestCase):
    def test_rejects_a_cli_write_target_outside_the_trusted_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "output"
            outside = Path(temporary_directory) / "outside.conf"
            with self.assertRaisesRegex(ValueError, "escapes output root"):
                runner_core.write_rules_file(
                    {"rules": "SecRuleEngine On"},
                    outside,
                    output_root=root,
                )
            self.assertFalse(outside.exists())

    def test_rejects_case_controlled_nginx_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "output"
            outside = Path(temporary_directory) / "escaped.conf"
            case = {"nginx": {"files": {"../escaped.conf": "forbidden"}}}
            with self.assertRaisesRegex(ValueError, "escapes runtime config directory"):
                runner_core.write_nginx_runtime_files(
                    case,
                    root / "location.conf",
                    root / "nginx",
                    output_root=root,
                )
            self.assertFalse(outside.exists())

    def test_accepts_nested_runtime_file_below_output_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "output"
            case = {"nginx": {"files": {"includes/test.conf": "location / {}"}}}
            runner_core.write_nginx_runtime_files(
                case,
                root / "location.conf",
                root / "nginx",
                output_root=root,
            )
            self.assertEqual(
                "location / {}\n",
                (root / "nginx" / "includes" / "test.conf").read_text(encoding="utf-8"),
            )

    def test_case_info_rejects_an_output_outside_the_trusted_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "output"
            outside = Path(temporary_directory) / "outside.json"
            args = argparse.Namespace(output=str(outside), output_root=str(root))
            with self.assertRaisesRegex(ValueError, "escapes output root"):
                case_cli._write_or_print_case_info({"untrusted": "content"}, args)
            self.assertFalse(outside.exists())
