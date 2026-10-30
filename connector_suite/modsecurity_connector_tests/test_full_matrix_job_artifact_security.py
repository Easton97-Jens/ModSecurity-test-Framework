from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = connector_root()
runner = load_source(source_path('ci/runtime/lifecycle/run-full-matrix-job.py', root=ROOT))


class FullMatrixJobArtifactSecurityTest(unittest.TestCase):
    def test_job_artifacts_accepts_complete_private_job(self) -> None:
        with tempfile.TemporaryDirectory(prefix="matrix-job-artifacts-") as temporary:
            root = Path(temporary)
            results = root / "results" / "force-all"
            results.mkdir(parents=True)
            summary = results / "apache-summary.json"
            summary.write_text(json.dumps({"apache": {"cases": {"control": {}}}}), encoding="utf-8")
            (results / "apache-results.jsonl").write_text("{}\n", encoding="utf-8")
            (root / "job.json").write_text(
                json.dumps(
                    {
                        "status": "completed",
                        "return_code": 0,
                        "ended_at": "2026-08-01T00:00:00Z",
                        "summary_path": str(summary),
                    }
                ),
                encoding="utf-8",
            )
            artifacts = runner.job_artifacts(root, "apache")
            self.assertTrue(artifacts["complete"])
            self.assertEqual(artifacts["summary_cases"], 1)

    def test_job_artifacts_rejects_summary_path_outside_private_job(self) -> None:
        with tempfile.TemporaryDirectory(prefix="matrix-job-artifacts-") as temporary:
            root = Path(temporary)
            outside = root.parent / "outside-summary.json"
            outside.write_text(json.dumps({"apache": {"cases": {"forged": {}}}}), encoding="utf-8")
            try:
                (root / "job.json").write_text(
                    json.dumps({"summary_path": str(outside)}),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, "below the runtime root"):
                    runner.job_artifacts(root, "apache")
            finally:
                outside.unlink(missing_ok=True)

    def test_timeout_record_rejects_final_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="matrix-job-artifacts-") as temporary:
            root = Path(temporary)
            victim = root / "victim.json"
            victim.write_text("unchanged\n", encoding="utf-8")
            (root / "job-timeout.json").symlink_to(victim)
            with self.assertRaisesRegex(ValueError, "must not be a symbolic link"):
                runner.write_timeout_record(root, "apache", "no-crs", "no-mrts", "start", 1.0)
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged\n")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
