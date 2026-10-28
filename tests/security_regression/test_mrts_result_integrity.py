"""On-demand MRTS native result integrity regressions."""
from __future__ import annotations

import importlib.util
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ci/lib"))
import mrts_results
spec = importlib.util.spec_from_file_location("mrts_native_integrity_report", ROOT / "ci/reporting/generate-mrts-native-report.py")
REPORT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(REPORT)


class MRTSResultIntegrityTests(unittest.TestCase):
    def make_job(self, temporary, stats):
        root = Path(temporary)
        ftw = root / "selected-ftw"
        ftw.mkdir(parents=True)
        (ftw / "case.yaml").write_text("tests:\n- ruleid: 100000\n  test_id: 1\n- ruleid: 100000\n  test_id: 2\n")
        (root / "run.log").write_text("run 2 total tests\n")
        (root / "go-ftw.json").write_text(json.dumps(stats))
        return argparse.Namespace(output=root / "job.json", target="apache2_ubuntu", status="PASS",
            reason="completed", exit_code=0, duration=1, run_log=root / "run.log",
            summary_path=root / "job.json", ftw_dir=ftw, stats_file=root / "go-ftw.json")

    def temporary(self):
        return tempfile.TemporaryDirectory(prefix="mrts-results-", dir=os.environ.get("RUNNER_TEMP", os.environ.get("TMPDIR")))

    def test_skipped_and_missing_ids_never_become_passes(self):
        result = mrts_results.observed_results(
            ["100000-1", "100000-2", "100000-3"],
            {"run": 2, "success": ["100000-1"], "skipped": ["100000-2"]},
        )
        self.assertEqual((result["passed"], result["skipped"], result["missing"]), (1, 1, 1))
        self.assertEqual(result["executed"], 1)
        self.assertFalse(result["complete"])

    def test_duplicate_conflicting_and_forced_results_are_invalid(self):
        result = mrts_results.observed_results(
            ["100000-1", "100000-2"],
            {"run": 4, "success": ["100000-1", "100000-1"],
             "failed": ["100000-1"], "forced-pass": ["100000-2"]},
        )
        self.assertFalse(result["complete"])
        self.assertEqual(result["passed"], 0)
        self.assertEqual(result["forced"], 1)
        self.assertTrue(result["errors"])

    def test_empty_required_results_are_incomplete(self):
        result = mrts_results.observed_results([], {"run": 0, "success": []})
        self.assertFalse(result["complete"])
        self.assertEqual(result["passed"], 0)

    def test_invalid_scalar_result_fields_fail_visibly(self):
        with self.assertRaises(ValueError):
            mrts_results.observed_results(["100000-1"], {"run": 1, "success": False})

    def test_unexpected_success_is_not_selected_pass(self):
        result = mrts_results.observed_results(["100000-1"], {"run": 1, "success": ["999999-1"]})
        self.assertEqual(result["passed"], 0)
        self.assertFalse(result["complete"])

    def test_complete_explicit_results_have_unique_case_outcomes(self):
        result = mrts_results.observed_results(
            ["100000-1", "100000-2"],
            {"run": 2, "success": ["100000-1"], "failed": ["100000-2"]},
        )
        self.assertTrue(result["complete"])
        self.assertEqual(result["failed_cases"], ["100000-2"])
        self.assertEqual(result["outcomes"], {"100000-1": "PASS", "100000-2": "FAIL"})

    def test_summary_totals_do_not_supply_missing_case_results(self):
        result = mrts_results.results_from_log("run 12 total tests\n1 test(s) failed to run: [\"100000-1\"]\n")
        self.assertEqual(result["passed"], 0)
        self.assertEqual(result["failed"], 1)
        self.assertFalse(result["complete"])

    def test_writer_and_report_preserve_complete_explicit_pass(self):
        with self.temporary() as temporary:
            args = self.make_job(temporary, {"run": 2, "success": ["100000-1", "100000-2"]})
            self.assertEqual(mrts_results.write_job(args), 0)
            self.assertEqual(json.loads(args.output.read_text())["status"], "PASS")
            counts = REPORT.collect_run_counts(args.run_log, "PASS", [Path(temporary)],
                ftw_dir=args.ftw_dir, stats_file=args.stats_file)
            self.assertEqual((counts["pass"], counts["selected"], counts["executed"]), (2, 2, 2))
            self.assertTrue(counts["complete"])

    def test_zero_exit_with_skips_and_missing_results_writes_incomplete(self):
        with self.temporary() as temporary:
            args = self.make_job(temporary, {"run": 1, "skipped": ["100000-1"]})
            self.assertEqual(mrts_results.write_job(args), 2)
            job = json.loads(args.output.read_text())
            self.assertEqual(job["status"], "INCOMPLETE")
            self.assertEqual(job["go_ftw"]["passed"], 0)
            self.assertEqual(job["go_ftw"]["missing_cases"], ["100000-2"])

    def test_report_rejects_claimed_pass_with_missing_structured_results(self):
        with self.temporary() as temporary:
            target = Path(temporary) / "apache2_ubuntu"
            target.mkdir()
            args = self.make_job(target, {"run": 0})
            args.output.write_text(json.dumps({"status": "PASS", "run_log": str(args.run_log)}))
            result = REPORT.normalize_job("apache2_ubuntu", Path(temporary))
            self.assertEqual(result["status"], "INCOMPLETE")
            self.assertEqual(result["counts"]["pass"], 0)

    def test_writer_error_is_not_converted_to_success(self):
        with self.temporary() as temporary:
            args = self.make_job(temporary, {"run": 2, "success": ["100000-1", "100000-2"]})
            args.output = Path(temporary) / "missing/job.json"
            with self.assertRaises(OSError):
                mrts_results.write_job(args)

    def test_nonzero_exit_cannot_be_requested_as_pass(self):
        with self.temporary() as temporary:
            args = self.make_job(temporary, {"run": 2, "success": ["100000-1", "100000-2"]})
            args.exit_code = 3
            self.assertEqual(mrts_results.write_job(args), 2)
            self.assertEqual(json.loads(args.output.read_text())["status"], "FAIL")

    def test_combined_selection_retains_separate_corpus_outcomes(self):
        with self.temporary() as temporary:
            root = Path(temporary)
            for corpus, ruleid in (("upstream-config-tests", 100000), ("feature-demo", 200000)):
                directory = root / "selected-ftw" / corpus
                directory.mkdir(parents=True)
                (directory / "case.yaml").write_text(f"tests:\n- ruleid: {ruleid}\n  test_id: 1\n")
            stats = root / "go-ftw.json"
            stats.write_text(json.dumps({"run": 2, "success": ["100000-1"], "failed": ["200000-1"]}))
            result = mrts_results.read_results(stats,
                mrts_results.selected_ftw_ids(root / "selected-ftw"), root / "selected-ftw")
            self.assertEqual(result["corpora"]["upstream-config-tests"]["passed"], 1)
            self.assertEqual(result["corpora"]["feature-demo"]["failed"], 1)
            self.assertEqual(result["passed"], 1)


if __name__ == "__main__":
    unittest.main()
