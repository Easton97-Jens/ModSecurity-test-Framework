"""Focused equivalence controls for the runtime-snapshot Sonar refactor."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from unittest import mock
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER_DIRECTORY = ROOT / "tests" / "runners"
SNAPSHOT_PATH = ROOT / "ci" / "reporting" / "update-runtime-snapshot.py"


def load_snapshot_module():
    if str(RUNNER_DIRECTORY) not in sys.path:
        sys.path.insert(0, str(RUNNER_DIRECTORY))
    specification = importlib.util.spec_from_file_location("runtime_snapshot_sonar", SNAPSHOT_PATH)
    if specification is None or specification.loader is None:
        raise RuntimeError("could not load update-runtime-snapshot.py")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


class RuntimeSnapshotSonarTests(unittest.TestCase):
    def setUp(self) -> None:
        self.snapshot = load_snapshot_module()
        self.metadata = {
            "yaml_status": "active",
            "case_group": "synthetic",
            "classification": "active",
            "former_xfail": False,
            "response_body_related": False,
        }

    def test_case_row_keeps_strict_abort_non_promotable(self) -> None:
        summary = {
            "apache": {
                "cases": {
                    "case-a": {
                        "path": "common/case-a.yaml",
                        "status": "pass",
                        "expected_status": 200,
                        "actual_status": 200,
                        "strict_abort": True,
                    }
                }
            }
        }
        with mock.patch.object(self.snapshot, "case_metadata", return_value=self.metadata):
            rows = self.snapshot.case_rows(summary, "apache", Path("/safe/results/apache-summary.json"))

        self.assertEqual(1, len(rows))
        self.assertEqual("NOT_EXECUTABLE", rows[0]["matrix_status"])
        self.assertFalse(rows[0]["promotion_allowed"])
        self.assertFalse(rows[0]["runtime_verified"])

    def test_connector_smoke_uses_summary_exit_status_only_with_case_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            summary_path = root / "apache-summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "apache": {
                            "exit_status": 0,
                            "build": "compiled",
                            "summary": {"pass": 1},
                            "cases": {"case-a": {"path": "case-a.yaml", "status": "pass"}},
                        }
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(self.snapshot, "case_metadata", return_value=self.metadata):
                row = self.snapshot.connector_smoke(
                    "apache", "make smoke-apache", "not_run", summary_path, root / "apache-summary.txt"
                )

        self.assertEqual("PASS", row["status"])
        self.assertEqual(0, row["exit_code"])
        self.assertEqual("available", row["per_case_results"])

    def test_connector_smoke_preserves_missing_case_blocker_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            summary_path = root / "apache-summary.json"
            text_path = root / "apache-summary.txt"
            summary_path.write_text(json.dumps({"apache": {"build": "blocked"}}), encoding="utf-8")
            text_path.write_text("first failing detail\nsecond detail\n", encoding="utf-8")

            row = self.snapshot.connector_smoke("apache", "make smoke-apache", "1", summary_path, text_path)

        self.assertEqual("FAIL", row["status"])
        self.assertEqual("unavailable", row["per_case_results"])
        self.assertIn("build=blocked", row["per_case_unavailable_reason"])
        self.assertIn("first failing detail", row["per_case_unavailable_reason"])
        self.assertEqual(row["per_case_unavailable_reason"], row["blocker"]["reason"])
