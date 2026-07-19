from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_CHECKER = ROOT / "ci/checks/security/check-github-actions-workflows.py"
REPORT_UTILS = ROOT / "ci/lib/generated_report_utils.py"
COMMON = ROOT / "ci/lib/common.sh"


def load_report_utils():
    spec = importlib.util.spec_from_file_location(
        "sonarcloud_utility_wave_report_utils", REPORT_UTILS
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load generated report utilities")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class WorkflowMappingValueRegressionTests(unittest.TestCase):
    def run_pin_check(self, text: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary_root:
            root = Path(temporary_root)
            workflow = root / "workflow.yml"
            workflow.write_text(text, encoding="utf-8")
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            environment["PYTHONNOUSERSITE"] = "1"
            return subprocess.run(
                [
                    sys.executable,
                    str(WORKFLOW_CHECKER),
                    "--workflow-root",
                    str(workflow),
                    "--check",
                    "pins",
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

    def test_advanced_mapping_values_are_rejected_without_rejecting_long_comments(
        self,
    ) -> None:
        for value in ("!forbidden", "&forbidden", "*forbidden"):
            with self.subTest(value=value):
                result = self.run_pin_check(f"name: {value}\n")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("YAML tags, anchors, aliases, and merge keys", result.stderr)

        self.assertEqual(self.run_pin_check("name: ordinary\n").returncode, 0)
        self.assertEqual(self.run_pin_check("- # ordinary workflow comment\n").returncode, 0)
        long_comment = " " * 200_000 + "# ordinary workflow comment\n"
        self.assertEqual(self.run_pin_check(long_comment).returncode, 0)


class GeneratedReportPathRedactionRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.utils = load_report_utils()

    def test_home_root_paths_use_one_portable_reference(self) -> None:
        home_root_reference = self.utils._LOCAL_HOME_ROOT_REFERENCE
        cases = {
            "/root/secret": f"{home_root_reference}/secret",
            "/home/alice/secret": f"{home_root_reference}/secret",
            "/Users/alice/secret": f"{home_root_reference}/secret",
            "/home/": home_root_reference,
        }
        for raw_path, expected in cases.items():
            with self.subTest(raw_path=raw_path):
                self.assertEqual(self.utils.portable_path_reference(raw_path), expected)


class CommonShellStatusRegressionTests(unittest.TestCase):
    def test_modsecurity_git_wrapper_propagates_stubbed_statuses(self) -> None:
        script = textwrap.dedent(
            f"""
            . {shlex.quote(str(COMMON))}

            git() {{
                return "$CI_GIT_STATUS"
            }}

            CI_GIT_STATUS=0
            ci_modsecurity_v3_git status
            [ "$?" -eq 0 ] || exit 1

            CI_GIT_STATUS=77
            ci_modsecurity_v3_git status
            [ "$?" -eq 77 ] || exit 1
            """
        )
        result = subprocess.run(
            ["sh", "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
