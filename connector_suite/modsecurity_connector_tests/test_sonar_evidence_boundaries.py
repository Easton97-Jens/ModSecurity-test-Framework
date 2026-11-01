"""Protect evidence consumers from paths selected by stored JSON records."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = connector_root()


def load(name: str, filename: str):
    module = load_source(source_path('ci/runtime/lifecycle', root=ROOT) / filename)
    return module


RUNNER = load("sonar_verified_report_boundaries", "run-verified-report-run.py")
NATIVE = load("sonar_native_report_boundaries", "run-native-case-comparison.py")
TARGET = "full-matrix-job:apache:no-crs:no-mrts"


class SonarEvidenceBoundaryTests(unittest.TestCase):
    def test_current_run_marker_rejects_outside_symlink_before_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {}, clear=True):
            root = Path(temporary)
            marker = root / "verified-runs/current-run-id"
            marker.parent.mkdir(mode=0o755)
            outside = root / "outside-id"
            outside.write_text("outside-sentinel\n", encoding="utf-8")
            marker.symlink_to(outside)
            args = argparse.Namespace(phase="checks")
            with self.assertRaises(ValueError):
                RUNNER.restore_current_verified_run_id(args, marker)
            self.assertNotIn("VERIFIED_RUN_ID", os.environ)
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside-sentinel\n")

    def test_current_run_marker_fifo_fails_without_waiting_for_a_writer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "current-run-id"
            os.mkfifo(marker)
            script = """
import argparse, os, runpy, sys
runner = runpy.run_path(sys.argv[1])
os.environ.pop("VERIFIED_RUN_ID", None)
try:
    runner["restore_current_verified_run_id"](argparse.Namespace(phase="checks"), runner["Path"](sys.argv[2]))
except ValueError:
    sys.exit(0)
sys.exit(1)
"""
            result = subprocess.run(
                [sys.executable, "-c", script, RUNNER.__file__, str(marker)],
                capture_output=True, timeout=5, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))

    def test_current_run_marker_cannot_alias_an_outside_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {}, clear=True):
            root = Path(temporary)
            marker = root / "verified-runs/current-run-id"
            marker.parent.mkdir()
            outside = root / "outside-id"
            outside.write_text("outside-sentinel\n", encoding="utf-8")
            os.link(outside, marker)
            args = argparse.Namespace(phase="checks")
            with self.assertRaises(ValueError):
                RUNNER.restore_current_verified_run_id(args, marker)
            self.assertNotIn("VERIFIED_RUN_ID", os.environ)
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside-sentinel\n")

    def test_current_run_marker_rejects_oversized_input_without_unbounded_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {}, clear=True):
            marker = Path(temporary) / "current-run-id"
            marker.write_text("valid-run" + " " * 8192, encoding="utf-8")
            args = argparse.Namespace(phase="checks")
            with mock.patch.object(RUNNER.os, "read", wraps=os.read) as read:
                with self.assertRaises(ValueError):
                    RUNNER.restore_current_verified_run_id(args, marker)
            self.assertEqual(read.call_args.args[1], 4097)
            self.assertNotIn("VERIFIED_RUN_ID", os.environ)

    def test_current_run_marker_checks_directory_trust_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {}, clear=True):
            directory = Path(temporary) / "verified-runs"
            directory.mkdir()
            directory.chmod(0o777)
            marker = directory / "current-run-id"
            marker.write_text("untrusted-run\n", encoding="utf-8")
            args = argparse.Namespace(phase="checks")
            with self.assertRaises(ValueError):
                RUNNER.restore_current_verified_run_id(args, marker)
            self.assertNotIn("VERIFIED_RUN_ID", os.environ)

    def test_current_run_marker_does_not_accept_a_valid_prefix_after_short_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {}, clear=True):
            marker = Path(temporary) / "current-run-id"
            marker.write_bytes(b"valid-run\ninvalid/suffix\n")
            args = argparse.Namespace(phase="checks")
            with mock.patch.object(RUNNER.os, "read", side_effect=[b"valid-run", b"\ninvalid/suffix\n", b""]):
                with self.assertRaises(ValueError):
                    RUNNER.restore_current_verified_run_id(args, marker)
            self.assertNotIn("VERIFIED_RUN_ID", os.environ)

    def test_owned_legacy_marker_preserves_append_and_explicit_id_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {}, clear=True):
            directory = Path(temporary) / "verified-runs"
            directory.mkdir(mode=0o755)
            marker = directory / "current-run-id"
            args = argparse.Namespace(phase="checks")
            RUNNER.restore_current_verified_run_id(args, marker)
            self.assertNotIn("VERIFIED_RUN_ID", os.environ)
            marker.write_text(" \tlegacy-run-123\n\n", encoding="utf-8")
            marker.chmod(0o644)
            RUNNER.restore_current_verified_run_id(argparse.Namespace(phase="all"), marker)
            self.assertNotIn("VERIFIED_RUN_ID", os.environ)
            RUNNER.restore_current_verified_run_id(args, marker)
            self.assertEqual(os.environ["VERIFIED_RUN_ID"], "legacy-run-123")
            marker.unlink()
            marker.symlink_to(directory / "missing")
            RUNNER.restore_current_verified_run_id(args, marker)
            self.assertEqual(os.environ["VERIFIED_RUN_ID"], "legacy-run-123")
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)

    def test_public_prepare_cannot_overwrite_an_outside_marker_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            marker = build / "verified-runs/current-run-id"
            marker.parent.mkdir(parents=True)
            outside = root / "outside-id"
            outside.write_text("outside-sentinel\n", encoding="utf-8")
            marker.symlink_to(outside)
            parser = RUNNER.build_argument_parser()
            args = parser.parse_args(["--build-root", str(build)])
            environment = {"VERIFIED_RUN_ID": "explicit-run", "VERIFIED_RUN_ROOT": str(root / "runtime")}
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(RUNNER, "canonical_roots_from_arguments", return_value=(ROOT, root / "framework")),
            ):
                with self.assertRaises(ValueError):
                    RUNNER.prepare_verified_run_context(parser, args)
                marker.unlink()
                context = RUNNER.prepare_verified_run_context(parser, args)
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside-sentinel\n")
            self.assertEqual(context.verified_run_id, "explicit-run")
            self.assertEqual(marker.read_text(encoding="utf-8"), "explicit-run\n")
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)

    def job(self, temporary: str) -> tuple[Path, Path, Path]:
        base = Path(temporary)
        matrix = base / "matrix"
        job = matrix / "no-crs/no-mrts/apache"
        results = job / "results/force-all"
        results.mkdir(parents=True)
        summary = results / "apache-summary.json"
        summary.write_text(json.dumps({"apache": {"cases": {"control": {}}}}), encoding="utf-8")
        (results / "apache-results.jsonl").write_text("{}\n", encoding="utf-8")
        self.write_job(job, summary)
        return matrix, job, summary

    def write_job(self, job: Path, summary: Path) -> None:
        (job / "job.json").write_text(json.dumps({
            "summary_path": str(summary), "ended_at": "2026-10-25T00:00:00Z",
            "status": "completed", "return_code": 0,
        }), encoding="utf-8")

    def test_private_job_summary_still_proves_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            matrix, _, summary = self.job(temporary)
            result = RUNNER.full_matrix_job_artifacts({"MATRIX_ROOT": str(matrix)}, TARGET)
            self.assertTrue(result["complete"])
            self.assertEqual(result["summary_cases"], 1)
            self.assertEqual(result["summary_path"], str(summary))

    def test_stored_summary_cannot_read_outside_private_job(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            matrix, job, _ = self.job(temporary)
            outside = Path(temporary) / "outside.json"
            outside.write_text('{"apache":{"cases":{"forged":{}}}}', encoding="utf-8")
            self.write_job(job, outside)
            with self.assertRaises(ValueError):
                RUNNER.full_matrix_job_artifacts({"MATRIX_ROOT": str(matrix)}, TARGET)

    def test_stored_summary_cannot_follow_a_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            matrix, job, summary = self.job(temporary)
            outside = Path(temporary) / "outside.json"
            outside.write_text('{"apache":{"cases":{"forged":{}}}}', encoding="utf-8")
            summary.unlink()
            summary.symlink_to(outside)
            with self.assertRaises(ValueError):
                RUNNER.full_matrix_job_artifacts({"MATRIX_ROOT": str(matrix)}, TARGET)

    def test_refresh_uses_only_the_invocations_log_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs = root / "logs"
            logs.mkdir()
            inside = logs / "refresh.log"
            outside = root / "other.log"
            inside.write_text("SKIPPED_STALE_INPUT\n", encoding="utf-8")
            outside.write_text("SKIPPED_STALE_INPUT\n", encoding="utf-8")
            env = {"VERIFIED_RUN_LOG_ROOT": str(logs)}
            def result(path):
                return RUNNER.apply_command_semantics({
                    "logical_target": "refresh-all-reports", "return_code": 1,
                    "log_path": str(path),
                }, env, "full")["refresh_status"]
            self.assertEqual(result(inside), "consumer_stale")
            self.assertEqual(result(outside), "refresh_failed")

    def test_latest_native_record_retains_its_actual_loaded_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / "native-case-runs/20261025-control"
            run.mkdir(parents=True)
            (run / NATIVE.NATIVE_CASE_RUN_FILENAME).write_text(json.dumps({
                "case": "control", "run_dir": "/untrusted/location", "status": "blocked",
            }), encoding="utf-8")
            result = NATIVE.latest_case_runs(root, ("control",))
            self.assertEqual(result[0]["run_dir"], str(run))

    def test_supplied_native_records_cannot_authorize_external_metadata_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            verified = root / "verified"
            verified.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (outside / NATIVE.NATIVE_CASE_RUN_FILENAME).write_text("{}", encoding="utf-8")
            report = {"case": "control", "run_dir": str(outside), "status": "blocked"}
            with mock.patch.object(NATIVE, "refresh_official_context", side_effect=lambda _, rows: rows):
                with self.assertRaises(ValueError):
                    NATIVE.write_summary_report(ROOT, root / "framework", verified,
                                                ("control",), [report], root / "summary")

    def test_native_metadata_uses_fixture_identity_and_confined_record_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            framework = root / "framework"
            fixture = framework / "tests/cases/control.yaml"
            fixture.parent.mkdir(parents=True)
            fixture.write_text("name: control\n", encoding="utf-8")
            verified = root / "verified"
            run = verified / "native-case-runs/20261025-control"
            run.mkdir(parents=True)
            contents = b'{"case":"control","status":"blocked"}\r\n'
            run_json = run / NATIVE.NATIVE_CASE_RUN_FILENAME
            run_json.write_bytes(contents)
            reports = [{"case": "control", "case_path": "/untrusted/fixture.yaml",
                        "run_dir": str(run), "status": "blocked"}]
            with (
                mock.patch.object(NATIVE, "refresh_official_context", side_effect=lambda _, rows: rows),
                mock.patch.object(NATIVE, "build_metadata", wraps=NATIVE.build_metadata) as build,
            ):
                result = NATIVE.write_summary_report(ROOT, framework, verified, ("control",),
                                                     reports, root / "summary")
            self.assertTrue(Path(result["json"]).is_file())
            self.assertIn(fixture, build.call_args.kwargs["inputs"])
            self.assertNotIn("/untrusted/fixture.yaml", build.call_args.kwargs["inputs"])
            metadata = json.loads(Path(result["json"]).read_text(encoding="utf-8"))["metadata"]
            record = next(item for item in metadata["inputs"] if item["path"] == str(run_json))
            self.assertEqual(record["sha256"], hashlib.sha256(contents).hexdigest())

    def test_latest_native_record_does_not_follow_a_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / "native-case-runs/20261025-control"
            run.mkdir(parents=True)
            outside = root / "outside.json"
            outside.write_text('{"case":"control"}', encoding="utf-8")
            (run / NATIVE.NATIVE_CASE_RUN_FILENAME).symlink_to(outside)
            with self.assertRaises(ValueError):
                NATIVE.latest_case_runs(root, ("control",))


# Parent discovery remains inventory-bound; only an explicit selected Master
# assessment may opt into the complete module without importing helpers eagerly.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    unittest.main()
