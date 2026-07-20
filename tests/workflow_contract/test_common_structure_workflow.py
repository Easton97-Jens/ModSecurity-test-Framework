"""Protect the dynamic case-discovery contract in the common CI workflow."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "test-common.yml"


class CommonStructureWorkflowTest(unittest.TestCase):
    def test_common_structure_uses_dynamic_discovery_with_non_empty_guards(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(
            'yaml_count=$(find tests/cases -type f -name "*.yaml" | wc -l)',
            workflow,
        )
        self.assertIn('if [ "$yaml_count" -eq 0 ]; then', workflow)
        self.assertIn(
            'echo "expected at least one YAML case, found none" >&2',
            workflow,
        )
        self.assertNotRegex(workflow, r'\[ "\$yaml_count" -ne [0-9]+ \]')
        self.assertNotIn("expected 141 YAML cases", workflow)
        self.assertIn('out="$VERIFIED_RUN_ROOT/case-runner"', workflow)
        self.assertNotIn('out="$RUNNER_TEMP/case-runner"', workflow)

        list_cases = '            --scope common > "$out/apache-common-cases.txt"'
        non_empty_selection = 'if [ ! -s "$out/apache-common-cases.txt" ]; then'
        materialization_loop = 'while IFS= read -r case_file; do'
        self.assertIn(list_cases, workflow)
        self.assertIn(non_empty_selection, workflow)
        self.assertLess(workflow.index(list_cases), workflow.index(non_empty_selection))
        self.assertLess(
            workflow.index(non_empty_selection),
            workflow.index(materialization_loop),
        )

    def test_common_selection_excludes_non_runtime_catalog_cases(self) -> None:
        environment = os.environ.copy()
        environment.update(
            {
                "EXTRA_CASE_ROOTS": "",
                "FORCE_ALL_CASES": "",
                "NO_CRS_BASELINE": "",
                "MODSECURITY_TEST_VARIANT": "no-crs",
            }
        )
        result = subprocess.run(
            [
                sys.executable,
                "tests/runners/case_cli.py",
                "list-cases",
                "--repo-root",
                str(ROOT),
                "--framework-root",
                str(ROOT),
                "--connector-root",
                str(ROOT),
                "--connector",
                "apache",
                "--scope",
                "common",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        selected_cases = [line for line in result.stdout.splitlines() if line]
        self.assertTrue(selected_cases, "expected at least one Apache common case")
        self.assertFalse(
            any("/security-data-flow/" in case for case in selected_cases),
            "non-runtime security-data-flow catalog cases must not reach materialization",
        )
