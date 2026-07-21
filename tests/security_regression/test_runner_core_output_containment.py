"""Regression coverage for materialized runner output containment."""

from __future__ import annotations

import argparse
import importlib
import json
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

    def test_rules_file_writes_nested_output_within_the_trusted_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "output"
            target = root / "nested" / "rules.conf"
            runner_core.write_rules_file(
                {"rules": "SecRuleEngine On"},
                target,
                output_root=root,
            )
            self.assertEqual("SecRuleEngine On\n", target.read_text(encoding="utf-8"))

    def test_rules_file_rejects_a_linked_target_outside_the_trusted_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "output"
            root.mkdir()
            outside = Path(temporary_directory) / "outside.conf"
            outside.write_text("unchanged\n", encoding="utf-8")
            linked_target = root / "linked.conf"
            linked_target.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "escapes output root"):
                runner_core.write_rules_file(
                    {"rules": "SecRuleEngine On"},
                    linked_target,
                    output_root=root,
                )
            self.assertTrue(linked_target.is_symlink())
            self.assertEqual("unchanged\n", outside.read_text(encoding="utf-8"))

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

    def test_case_info_writes_nested_output_within_the_trusted_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "output"
            target = root / "nested" / "case.json"
            args = argparse.Namespace(output=str(target), output_root=str(root))
            case_cli._write_or_print_case_info({"untrusted": "content"}, args)
            self.assertEqual({"untrusted": "content"}, json.loads(target.read_text(encoding="utf-8")))

    def test_case_info_rejects_a_linked_target_outside_the_trusted_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "output"
            root.mkdir()
            outside = Path(temporary_directory) / "outside.json"
            outside.write_text("unchanged\n", encoding="utf-8")
            linked_target = root / "linked.json"
            linked_target.symlink_to(outside)
            args = argparse.Namespace(output=str(linked_target), output_root=str(root))
            with self.assertRaisesRegex(ValueError, "escapes output root"):
                case_cli._write_or_print_case_info({"untrusted": "content"}, args)
            self.assertTrue(linked_target.is_symlink())
            self.assertEqual("unchanged\n", outside.read_text(encoding="utf-8"))
