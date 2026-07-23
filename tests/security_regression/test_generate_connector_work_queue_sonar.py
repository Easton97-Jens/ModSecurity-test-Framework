from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "ci/reporting/generate-connector-work-queue.py"


def load_queue_module(name: str):
    spec = importlib.util.spec_from_file_location(name, SOURCE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SOURCE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ConnectorWorkQueueSonarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.queue = load_queue_module("connector_work_queue_sonar_test")

    def test_private_runtime_root_rejects_public_parent_and_accepts_private_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            private_root = root / "private"
            private_root.mkdir(mode=0o700)
            public_root = root / "public"
            public_root.mkdir()
            public_root.chmod(0o777)

            self.assertEqual(
                private_root.resolve(),
                self.queue.private_runtime_root(private_root, "private test root"),
            )
            with self.assertRaisesRegex(ValueError, "publicly writable"):
                self.queue.private_runtime_root(public_root, "public test root")
            with patch.dict(os.environ, {"TMPDIR": str(public_root)}, clear=True):
                isolated = load_queue_module("connector_work_queue_public_tmp_test")
            self.assertIsNone(isolated.DEFAULT_RUN_ROOT)
            self.assertIsNone(isolated.DEFAULT_BUILD_ROOT)

    def test_summary_paths_are_confined_before_any_file_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            connector_root = root / "connector"
            connector_root.mkdir()
            summary = connector_root / "runtime" / "apache-summary.json"
            summary.parent.mkdir()
            summary.write_text(
                json.dumps({"apache": {"cases": {"safe": {"status": "pass"}}}}),
                encoding="utf-8",
            )
            outside = root / "outside-summary.json"
            outside.write_text(
                json.dumps({"apache": {"cases": {"outside": {"status": "fail"}}}}),
                encoding="utf-8",
            )
            symlink = connector_root / "runtime" / "escape.json"
            symlink.symlink_to(outside)

            approved_roots = [connector_root.resolve()]
            safe_path, error = self.queue.summary_path_from_run(
                {"runtime_summary_path": str(summary)}, approved_roots,
            )
            self.assertEqual(summary, safe_path)
            self.assertIsNone(error)
            self.assertEqual(
                self.queue.read_cases_from_summary(safe_path, "apache"),
                {"safe": {"status": "pass"}},
            )

            escaped_path, outside_error = self.queue.summary_path_from_run(
                {"runtime_summary_path": str(outside)}, approved_roots,
            )
            self.assertIsNone(escaped_path)
            self.assertEqual(outside_error, "runtime summary path is outside approved roots")

            linked_path, symlink_error = self.queue.summary_path_from_run(
                {"runtime_summary_path": str(symlink)}, approved_roots,
            )
            self.assertIsNone(linked_path)
            self.assertEqual(symlink_error, "runtime summary path must not contain a symlink")

            blocked_entries = self.queue.entries_for_run(
                {"connector": "apache", "runtime_summary_path": str(outside)},
                {},
                {},
                approved_roots,
            )
            self.assertEqual(blocked_entries[0]["runtime_status"], "BLOCKED")
            self.assertEqual(blocked_entries[0]["reason"], "runtime summary path is outside approved roots")

    def test_output_root_is_limited_to_the_trusted_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            connector_root = root / "connector"
            framework_root = root / "framework"
            outside_root = root / "outside"
            for directory in (connector_root, framework_root, outside_root):
                directory.mkdir()

            self.assertEqual(
                connector_root.resolve(),
                self.queue.configured_output_root(connector_root, connector_root, framework_root),
            )
            self.assertEqual(
                framework_root.resolve(),
                self.queue.configured_output_root(framework_root, connector_root, framework_root),
            )
            with self.assertRaisesRegex(ValueError, "connector root or framework root"):
                self.queue.configured_output_root(outside_root, connector_root, framework_root)

    def test_refactored_classification_and_priority_contracts(self) -> None:
        self.assertEqual(
            self.queue.choose_work_direction(
                "apache", ["expected_block_got_501"], ["request_body_json"], False,
            ),
            "request_body_processor",
        )
        self.assertEqual(
            self.queue.choose_work_direction("haproxy", ["expected_200_got_501"], [], False),
            "connector_gap",
        )
        meta = self.queue.CaseMeta(case_id="phase4-action", path="", source_kind="framework-owned")
        self.assertIn(
            "action_intervention",
            self.queue.functional_areas(meta, {"expected_intervention": "deny"}),
        )
        self.assertEqual(self.queue.initial_priority("PASS", [], [], False), "P3")

        entry = {
            "classification": "active",
            "failure_pattern": ["expected_block_got_200"],
            "connector_pattern": ["all_connectors_fail"],
            "functional_area": ["action_intervention"],
            "phase": "2",
            "runtime_status": "FAIL",
            "connector": "apache",
            "priority": "P1",
        }
        self.queue.apply_priority_rules([entry])
        self.assertEqual(entry["priority"], "P0")

    def test_main_rejects_untrusted_output_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            connector_root = root / "connector"
            output_root = root / "outside"
            connector_root.mkdir()
            output_root.mkdir()
            environment = dict(os.environ)
            for name in ("VERIFIED_RUN_ROOT", "BUILD_ROOT", "MRTS_BUILD_ROOT", "MRTS_ROOT"):
                environment.pop(name, None)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SOURCE),
                    "--framework-root",
                    str(ROOT),
                    "--connector-root",
                    str(connector_root),
                    "--output-root",
                    str(output_root),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                env=environment,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("output root must resolve exactly", result.stderr)
            self.assertFalse((output_root / "reports").exists())

    def test_main_writes_only_under_a_valid_connector_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            connector_root = Path(temporary_directory) / "connector"
            connector_root.mkdir()
            environment = dict(os.environ)
            for name in ("VERIFIED_RUN_ROOT", "BUILD_ROOT", "MRTS_BUILD_ROOT", "MRTS_ROOT"):
                environment.pop(name, None)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SOURCE),
                    "--framework-root",
                    str(ROOT),
                    "--connector-root",
                    str(connector_root),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            generated_root = connector_root / "reports/testing/generated/canonical"
            self.assertTrue((generated_root / "connector_work_queue.generated.json").is_file())
            self.assertTrue((generated_root / "connector_work_queue.generated.md").is_file())


if __name__ == "__main__":
    unittest.main()
