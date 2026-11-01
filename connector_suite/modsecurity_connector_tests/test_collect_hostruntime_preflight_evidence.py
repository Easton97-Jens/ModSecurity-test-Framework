"""Focused regression tests for shared host-runtime preflight evidence."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = connector_root()
COLLECTOR_PATH = source_path('ci/runtime/common/collect_hostruntime_preflight_evidence.py', root=ROOT)


def load_collector():
    module = load_source(COLLECTOR_PATH)
    return module


COLLECTOR = load_collector()


def valid_raw(profile: str) -> dict[str, object]:
    return {
        "status": "PASS",
        "reason_code": "ready",
        "profile": profile,
        "lock_profile": profile,
        "expected_version": "1.2.3",
        "actual_version": "1.2.3",
        "host": {"os": "linux", "arch": "amd64"},
        "runtime_lock": {"name": "fixture", "asset_id": "fixture-linux-amd64"},
        "checks": [],
    }


class CollectHostRuntimePreflightEvidenceTests(unittest.TestCase):
    def temporary_directory(self) -> tempfile.TemporaryDirectory[str]:
        runner_temp = os.environ.get("RUNNER_TEMP")
        directory = runner_temp if runner_temp and Path(runner_temp).is_dir() else None
        return tempfile.TemporaryDirectory(dir=directory)

    def test_projection_is_allowlisted_and_fail_closed(self) -> None:
        cases = (
            ("pass", valid_raw("fixture"), 0, "PASS", "ready"),
            (
                "nonzero pass",
                valid_raw("fixture"),
                1,
                "BLOCKED",
                "preflight_exit_without_pass_evidence",
            ),
            (
                "missing lock",
                {"status": "PASS", "lock_profile": "fixture"},
                0,
                "BLOCKED",
                "runtime_lock_missing",
            ),
            (
                "binary check",
                {
                    **valid_raw("fixture"),
                    "checks": [{"reason_code": "binary_missing"}],
                },
                0,
                "BLOCKED",
                "binary_missing",
            ),
            (
                "malformed payload",
                ["not", "an", "object"],
                0,
                "BLOCKED",
                "invalid_or_missing_preflight_status",
            ),
        )
        for name, raw, exit_code, expected_status, expected_reason in cases:
            with self.subTest(name=name):
                record = COLLECTOR.project_preflight_record(
                    raw,
                    connector="fixture",
                    profile="fixture",
                    exit_code=exit_code,
                )
                self.assertEqual(record["status"], expected_status)
                self.assertEqual(record["reason_code"], expected_reason)
                self.assertEqual(record["runtime_status"], "NOT_RUN")
                self.assertEqual(
                    set(record),
                    {
                        "schema_version",
                        "evidence_kind",
                        "connector",
                        "profile",
                        "lock_profile",
                        "status",
                        "runtime_status",
                        "reason_code",
                        "exit_code",
                        "expected_version",
                        "actual_version",
                        "host",
                        "runtime_lock",
                    },
                )

    def test_collect_preserves_profile_inputs_and_nginx_markdown_format(self) -> None:
        with self.temporary_directory() as temporary_directory:
            runner_temp = Path(temporary_directory) / "runner-temp"
            commands: list[list[str]] = []

            def write_valid_result(command: list[str]) -> int:
                commands.append(command)
                output = Path(command[command.index("--output") + 1])
                profile = command[command.index("--profile") + 1]
                output.write_text(json.dumps(valid_raw(profile)), encoding="utf-8")
                return 0

            evidence_dir = COLLECTOR.collect(
                connector="nginx",
                runtime_lock="modules/ModSecurity-test-Framework/ci/provisioning/runtime-component-lock.json",
                runner_temp=runner_temp,
                binary_name="collector-fixture-binary",
                profiles=(
                    COLLECTOR.ProfileSpec(
                        "nginx-h1",
                        "connectors/nginx/harness/nginx_smoke.conf",
                        "modules/ModSecurity-test-Framework/tests/cases/connector-specific/nginx/nginx_tx_scoring_absolute_block.yaml",
                    ),
                ),
                markdown_code=True,
                command_runner=write_valid_result,
            )

            self.assertEqual(len(commands), 1)
            command = commands[0]
            self.assertEqual(command[0], sys.executable)
            self.assertIn("--config", command)
            self.assertIn("connectors/nginx/harness/nginx_smoke.conf", command)
            self.assertIn("--fixture", command)
            self.assertNotIn("shell", command)
            record = json.loads(
                (evidence_dir / "preflight/nginx-h1/status.json").read_text(encoding="utf-8")
            )
            self.assertEqual(record["status"], "PASS")
            self.assertEqual(record["runtime_status"], "NOT_RUN")
            self.assertIn("- status: `PASS`", (evidence_dir / "preflight/nginx-h1/summary.md").read_text())
            runtime = json.loads((evidence_dir / "hostruntime-record.json").read_text(encoding="utf-8"))
            self.assertEqual(runtime["preflight_status"], "PASS")
            self.assertEqual(runtime["reason_code"], "runtime_execution_not_configured")

    def test_collect_fails_closed_for_malformed_preflight_status(self) -> None:
        with self.temporary_directory() as temporary_directory:
            runner_temp = Path(temporary_directory) / "runner-temp"

            def write_malformed_result(command: list[str]) -> int:
                output = Path(command[command.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text("{", encoding="utf-8")
                return 0

            profile = COLLECTOR.ProfileSpec("nginx-h1", "nginx.conf", "fixture.json")
            evidence_dir = COLLECTOR.collect(
                connector="nginx",
                runtime_lock="lock.json",
                runner_temp=runner_temp,
                binary_name="collector-fixture-binary",
                profiles=(profile,),
                markdown_code=True,
                command_runner=write_malformed_result,
            )

            record = json.loads(
                (evidence_dir / "preflight/nginx-h1/status.json").read_text(encoding="utf-8")
            )
            self.assertEqual(record["status"], "BLOCKED")
            self.assertEqual(record["reason_code"], "invalid_or_missing_preflight_status")

    def test_collect_rejects_preseeded_evidence_root_symlink(self) -> None:
        with self.temporary_directory() as temporary_directory:
            runner_temp = Path(temporary_directory) / "runner-temp"
            runner_temp.mkdir()
            redirected = Path(temporary_directory) / "redirected"
            redirected.mkdir()
            sentinel = redirected / "status.json"
            sentinel.write_text("unchanged\n", encoding="utf-8")
            (runner_temp / "hostruntime-evidence").symlink_to(
                redirected, target_is_directory=True
            )
            profile = COLLECTOR.ProfileSpec("nginx-h1", "nginx.conf", "fixture.json")

            with self.assertRaises(ValueError):
                COLLECTOR.collect(
                    connector="nginx",
                    runtime_lock="lock.json",
                    runner_temp=runner_temp,
                    binary_name="collector-fixture-binary",
                    profiles=(profile,),
                    markdown_code=True,
                )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged\n")

    def test_collect_rejects_preseeded_status_symlink(self) -> None:
        with self.temporary_directory() as temporary_directory:
            runner_temp = Path(temporary_directory) / "runner-temp"
            status_path = (
                runner_temp
                / "hostruntime-evidence"
                / "nginx"
                / "preflight"
                / "nginx-h1"
                / "status.json"
            )
            status_path.parent.mkdir(parents=True)
            sentinel = Path(temporary_directory) / "outside-status.json"
            sentinel.write_text("unchanged\n", encoding="utf-8")
            status_path.symlink_to(sentinel)
            profile = COLLECTOR.ProfileSpec("nginx-h1", "nginx.conf", "fixture.json")

            with self.assertRaises(ValueError):
                COLLECTOR.collect(
                    connector="nginx",
                    runtime_lock="lock.json",
                    runner_temp=runner_temp,
                    binary_name="collector-fixture-binary",
                    profiles=(profile,),
                    markdown_code=True,
                )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged\n")

    def test_cli_rejects_traversal_and_unpaired_profile_arguments(self) -> None:
        common = (
            "--runtime-lock",
            "lock.json",
            "--runner-temp",
            "/tmp/runner",
            "--binary-name",
            "nginx",
        )
        self.assertEqual(COLLECTOR.main(("--connector", "../nginx", *common)), 2)
        self.assertEqual(
            COLLECTOR.main(
                (
                    "--connector",
                    "nginx",
                    *common,
                    "--profile",
                    "nginx-h1",
                    "--config",
                    "../nginx.conf",
                    "--fixture",
                    "fixture.json",
                )
            ),
            2,
        )
        self.assertEqual(
            COLLECTOR.main(
                (
                    "--connector",
                    "nginx",
                    *common,
                    "--profile",
                    "nginx-h1",
                )
            ),
            2,
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
