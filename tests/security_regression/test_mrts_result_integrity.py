"""On-demand MRTS native result integrity regressions."""
from __future__ import annotations

import importlib.util
import argparse
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest import mock

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
            self.assertEqual(mrts_results.write_job(args, approved_root=Path(temporary)), 0)
            self.assertEqual(json.loads(args.output.read_text())["status"], "PASS")
            counts = REPORT.collect_run_counts(args.run_log, "PASS", [Path(temporary)],
                ftw_dir=args.ftw_dir, stats_file=args.stats_file)
            self.assertEqual((counts["pass"], counts["selected"], counts["executed"]), (2, 2, 2))
            self.assertTrue(counts["complete"])

    def test_zero_exit_with_skips_and_missing_results_writes_incomplete(self):
        with self.temporary() as temporary:
            args = self.make_job(temporary, {"run": 1, "skipped": ["100000-1"]})
            self.assertEqual(mrts_results.write_job(args, approved_root=Path(temporary)), 2)
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
                mrts_results.write_job(args, approved_root=Path(temporary))

    def test_nonzero_exit_cannot_be_requested_as_pass(self):
        with self.temporary() as temporary:
            args = self.make_job(temporary, {"run": 2, "success": ["100000-1", "100000-2"]})
            args.exit_code = 3
            self.assertEqual(mrts_results.write_job(args, approved_root=Path(temporary)), 2)
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
                mrts_results.selected_ftw_ids(root / "selected-ftw", approved_root=root),
                root / "selected-ftw", approved_root=root)
            self.assertEqual(result["corpora"]["upstream-config-tests"]["passed"], 1)
            self.assertEqual(result["corpora"]["feature-demo"]["failed"], 1)
            self.assertEqual(result["passed"], 1)

    def test_non_ascii_case_ids_are_rejected(self):
        with self.assertRaises(ValueError):
            mrts_results.observed_results(["١٠٠٠٠٠-1"], {"run": 1, "success": ["١٠٠٠٠٠-1"]})
        result = mrts_results.results_from_log('failed to run: ["١٠٠٠٠٠-1"]\n')
        self.assertEqual(result["failed"], 0)

    def test_long_invalid_failed_list_is_bounded(self):
        program = (
            "import sys; sys.path.insert(0, sys.argv[1]); import mrts_results; "
            "result=mrts_results.results_from_log('failed to run: [\\\"'+'9'*200000+'\\\"]'); "
            "assert result['passed']==result['failed']==0"
        )
        result = subprocess.run([sys.executable, "-c", program, str(ROOT / "ci/lib")],
            text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_reader_rejects_sibling_prefix_escape(self):
        with self.temporary() as temporary:
            base = Path(temporary)
            approved = base / "allowed"
            approved.mkdir(mode=0o700)
            sibling = base / "allowed-elsewhere.txt"
            sibling.write_text("outside sentinel")
            with self.assertRaises(ValueError):
                mrts_results.read_bounded(sibling, approved_root=approved)

    def test_reader_rejects_lexical_traversal(self):
        with self.temporary() as temporary:
            root = Path(temporary)
            (root / "input.txt").write_text("legitimate")
            (root / "child").mkdir()
            with self.assertRaises(ValueError):
                mrts_results.read_bounded(root / "child/../input.txt", approved_root=root)

    def test_reader_rejects_symlinked_ancestor(self):
        with self.temporary() as temporary:
            root = Path(temporary)
            directory = root / "regular"
            directory.mkdir()
            (directory / "input.txt").write_text("legitimate")
            (root / "linked").symlink_to(directory, target_is_directory=True)
            with self.assertRaises(ValueError):
                mrts_results.read_bounded(root / "linked/input.txt", approved_root=root)

    def test_writer_rejects_symlinked_output_ancestor(self):
        with self.temporary() as temporary:
            root = Path(temporary)
            args = self.make_job(root, {"run": 2, "success": ["100000-1", "100000-2"]})
            destination = root / "destination"
            destination.mkdir()
            sentinel = destination / "job.json"
            sentinel.write_text("unchanged")
            (root / "linked").symlink_to(destination, target_is_directory=True)
            args.output = root / "linked/job.json"
            with self.assertRaises(ValueError):
                mrts_results.write_job(args, approved_root=root)
            self.assertEqual(sentinel.read_text(), "unchanged")

    def test_reader_rejects_non_regular_file_without_blocking(self):
        with self.temporary() as temporary:
            root = Path(temporary)
            fifo = root / "input.fifo"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                mrts_results.read_bounded(fifo, approved_root=root)

    def test_reader_rejects_oversized_regular_file(self):
        with self.temporary() as temporary:
            root = Path(temporary)
            oversized = root / "oversized.txt"
            oversized.write_bytes(b"x" * (mrts_results.MAX_RESULT_BYTES + 1))
            with self.assertRaises(ValueError):
                mrts_results.read_bounded(oversized, approved_root=root)

    def test_report_rejects_system_root_before_reading(self):
        with mock.patch.object(REPORT, "read_bounded_run_log") as reader:
            with self.assertRaises(ValueError):
                REPORT.collect_run_counts(Path("/etc/unused.txt"), "PASS", [Path("/etc")])
            reader.assert_not_called()

    def test_cli_uses_exported_build_root_and_rejects_external_output(self):
        with self.temporary() as temporary:
            root = Path(temporary)
            approved = root / "allowed"
            approved.mkdir(mode=0o700)
            args = self.make_job(approved, {"run": 2, "success": ["100000-1", "100000-2"]})
            command = [sys.executable, str(ROOT / "ci/lib/mrts_results.py")]
            for name in ("output", "run_log", "summary_path", "ftw_dir", "stats_file",
                         "target", "status", "reason", "exit_code", "duration"):
                command.extend(["--" + name.replace("_", "-"), str(getattr(args, name))])
            environment = dict(os.environ, BUILD_ROOT=str(approved))
            legitimate = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=5)
            self.assertEqual(legitimate.returncode, 0, legitimate.stderr)
            self.assertEqual(json.loads(args.output.read_text())["status"], "PASS")
            output = root / "outside.json"
            output.write_text("unchanged")
            command[command.index("--output") + 1] = str(output)
            rejected = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=5)
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(output.read_text(), "unchanged")


if __name__ == "__main__":
    unittest.main()
