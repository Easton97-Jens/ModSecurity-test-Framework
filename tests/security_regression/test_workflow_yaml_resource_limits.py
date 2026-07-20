"""Regression coverage for bounded workflow YAML loading."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import ModuleType
import unittest


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "ci/checks/documentation/check-workflow-yaml.py"


def load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("workflow_yaml_limit_checker", CHECKER)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load workflow YAML checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER_MODULE = load_checker()


class WorkflowYamlResourceLimitTests(unittest.TestCase):
    def run_checker(
        self, workflows: dict[str, str | bytes]
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary_root:
            workflow_root = Path(temporary_root) / ".github/workflows"
            workflow_root.mkdir(parents=True)
            for name, content in workflows.items():
                path = workflow_root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if isinstance(content, bytes):
                    path.write_bytes(content)
                else:
                    path.write_text(content, encoding="utf-8")
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            environment["PYTHONNOUSERSITE"] = "1"
            return subprocess.run(
                [sys.executable, str(CHECKER)],
                cwd=Path(temporary_root),
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

    def assert_rejected(self, content: str | bytes, expected_error: str) -> None:
        result = self.run_checker({"unsafe.yml": content})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error .github/workflows/unsafe.yml:", result.stderr)
        self.assertIn(expected_error, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_framework_workflows_remain_valid(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONNOUSERSITE"] = "1"
        result = subprocess.run(
            [sys.executable, str(CHECKER)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_small_valid_aliases_remain_supported(self) -> None:
        result = self.run_checker(
            {
                "alias.yml": """\
name: alias control
on: pull_request
shared_env: &shared_env
  EXAMPLE: value
jobs:
  lint:
    runs-on: ubuntu-latest
    env: *shared_env
    steps:
      - run: true
"""
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_safe_loader_rejects_unsafe_python_tags_with_a_controlled_error(self) -> None:
        self.assert_rejected(
            "unsafe: !!python/object/apply:os.system ['echo should-not-run']\n",
            "invalid YAML",
        )

    def test_malformed_yaml_has_a_controlled_error(self) -> None:
        self.assert_rejected("name: [unterminated\n", "invalid YAML")

    def test_byte_limit_has_a_controlled_error(self) -> None:
        self.assert_rejected(
            b"#" * (CHECKER_MODULE.MAX_WORKFLOW_YAML_BYTES + 1),
            "byte limit",
        )

    def test_nesting_depth_limit_has_a_controlled_error(self) -> None:
        lines = [
            f"{'  ' * depth}level_{depth}:"
            for depth in range(CHECKER_MODULE.MAX_WORKFLOW_YAML_DEPTH + 1)
        ]
        lines.append(
            f"{'  ' * (CHECKER_MODULE.MAX_WORKFLOW_YAML_DEPTH + 1)}value: done"
        )
        self.assert_rejected("\n".join(lines) + "\n", "nesting depth limit")

    def test_flow_style_depth_limit_has_a_controlled_error(self) -> None:
        depth = CHECKER_MODULE.MAX_WORKFLOW_YAML_DEPTH + 1
        self.assert_rejected(
            "value: " + "[" * depth + "value" + "]" * depth,
            "nesting",
        )

    def test_node_limit_has_a_controlled_error(self) -> None:
        workflow = "items:\n" + "".join(
            "  - value\n"
            for _ in range(CHECKER_MODULE.MAX_WORKFLOW_YAML_NODES + 1)
        )
        self.assert_rejected(workflow, "node limit")

    def test_alias_limit_has_a_controlled_error(self) -> None:
        workflow = "anchor: &anchor value\naliases:\n" + "".join(
            "  - *anchor\n"
            for _ in range(CHECKER_MODULE.MAX_WORKFLOW_YAML_ALIASES + 1)
        )
        self.assert_rejected(workflow, "alias limit")


if __name__ == "__main__":
    unittest.main()
