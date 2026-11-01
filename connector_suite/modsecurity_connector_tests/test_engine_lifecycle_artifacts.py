from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = connector_root()
WRITER = source_path('ci/runtime/lifecycle/write-engine-lifecycle-artifacts.py', root=ROOT)


class EngineLifecycleArtifactsTest(unittest.TestCase):
    def run_writer(
        self,
        root: Path,
        events: list[dict[str, object]],
        *,
        output: Path | None = None,
        library_symlink: bool = False,
        library_target_escapes: bool = False,
        rules_root: Path | None = None,
        transport_lifecycle_records: list[dict[str, object]] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        source = root / "source-result.json"
        source.write_text(json.dumps({"transaction_ids": ["tx-one", "tx-two"]}), encoding="utf-8")
        event_file = root / "events.jsonl"
        event_file.write_text(
            "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
        )
        rules = (rules_root or root) / "rules.conf"
        rules.parent.mkdir(parents=True, exist_ok=True)
        rules.write_text("SecRuleEngine On\n", encoding="utf-8")
        library_root = root / "managed-library"
        library_root.mkdir()
        library = library_root / "libmodsecurity.so"
        library_payload = b"current-engine-library"
        if library_symlink:
            target = (root / "outside-libmodsecurity.so.3") if library_target_escapes else (library_root / "libmodsecurity.so.3")
            target.write_bytes(library_payload)
            library.symlink_to(target)
        else:
            library.write_bytes(library_payload)
        result_dir = output or root / "engine-artifacts"
        command = [
            sys.executable,
            str(WRITER),
            "--connector",
            "envoy",
            "--source-result",
            str(source),
            "--source-events",
            str(event_file),
            "--rules-file",
            str(rules),
            "--libmodsecurity-version",
            "git:abc;build:def",
            "--libmodsecurity-library",
            str(library),
            "--libmodsecurity-library-root",
            str(library_root),
            "--stage-exit-code",
            "0",
        ]
        if rules_root is not None:
            command.extend(["--framework-root", str(rules_root)])
        if transport_lifecycle_records is not None:
            transport_lifecycle = root / "connection-lifecycle.json"
            transport_lifecycle.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "connector": "envoy",
                        "integration_mode": "ext_proc",
                        "run_id": "run-one",
                        "records": transport_lifecycle_records,
                    }
                ),
                encoding="utf-8",
            )
            command.extend(["--transport-lifecycle", str(transport_lifecycle)])
        command.extend(["--output-dir", str(result_dir)])
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "VERIFIED_RUN_ROOT": str(root)},
        )

    def test_writes_payload_free_current_host_inventory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engine-lifecycle-artifacts-") as temporary:
            root = Path(temporary)
            completed = self.run_writer(
                root,
                [
                    {"transaction_id": "tx-one", "phase": 2, "status": "blocked"},
                    {"transaction_id": "tx-one", "phase": 4, "status": "blocked", "actual_action": "abort_connection"},
                    {
                        "transaction_id": "tx-one",
                        "phase": 4,
                        "transport_result": "stream_reset",
                        "stream_reset": True,
                        "client_disconnected": True,
                        "cancelled": True,
                        "timeout_stage": "response_body",
                        "write_result": "short_write",
                        "cleanup_reason": "strict_abort",
                    },
                    {
                        "transaction_id": "tx-two",
                        "phase": 3,
                        "transport_result": "upstream_reset",
                        "upstream_disconnected": True,
                        "write_result": "write_would_block",
                        "cleanup_reason": "cancelled",
                    },
                    {"transaction_id": "tx-two", "phase": 3, "status": "blocked"},
                    {"transaction_id": "tx-two", "phase": 3, "status": "blocked"},
                ],
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = root / "engine-artifacts"
            self.assertEqual((output / "engine-version.txt").read_text(encoding="utf-8"), "git:abc;build:def\n")
            self.assertEqual(
                hashlib.sha256(b"current-engine-library").hexdigest(),
                (output / "engine-library-sha256.txt").read_text(encoding="utf-8").strip(),
            )
            self.assertEqual(
                hashlib.sha256(b"SecRuleEngine On\n").hexdigest(),
                (output / "ruleset-sha256.txt").read_text(encoding="utf-8").strip(),
            )
            counts = json.loads((output / "transaction-counts.json").read_text(encoding="utf-8"))
            lifecycle = json.loads((output / "lifecycle-counters.json").read_text(encoding="utf-8"))
            self.assertEqual(counts["transaction_ids"], ["tx-one", "tx-two"])
            self.assertEqual(counts["transactions_observed"], 2)
            self.assertEqual(counts["unique_engine_events_observed"], 5)
            self.assertEqual(lifecycle["transactions_started"], 2)
            self.assertEqual(lifecycle["transactions_finished"], 2)
            self.assertEqual(lifecycle["transactions_destroyed"], 2)
            self.assertEqual(lifecycle["request_body_finishes"], 1)
            self.assertEqual(lifecycle["response_body_finishes"], 1)
            self.assertEqual(lifecycle["intentional_aborts"], 1)
            self.assertEqual(lifecycle["client_disconnects"], 1)
            self.assertEqual(lifecycle["upstream_disconnects"], 1)
            self.assertEqual(lifecycle["stream_resets"], 1)
            self.assertEqual(lifecycle["timeouts"], 1)
            self.assertEqual(lifecycle["short_writes"], 1)
            self.assertEqual(lifecycle["write_would_block"], 1)
            self.assertEqual(lifecycle["cleanup_cancel"], 1)
            self.assertEqual(lifecycle["cleanup_abort"], 1)
            self.assertEqual(lifecycle["cleanup_normal"], 0)
            self.assertFalse(lifecycle["transport_counters_bound"])
            self.assertNotIn("secret", json.dumps(lifecycle))

    def test_hashes_rules_under_an_explicit_framework_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engine-lifecycle-artifacts-") as temporary:
            root = Path(temporary)
            runtime_root = root / "runtime"
            framework_root = root / "framework"
            runtime_root.mkdir()
            framework_root.mkdir()
            completed = self.run_writer(
                runtime_root,
                [{"transaction_id": "tx-one", "phase": 1, "status": "blocked"}],
                rules_root=framework_root,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(
                (runtime_root / "engine-artifacts/ruleset-sha256.txt").is_file()
            )

    def test_uses_causal_lifecycle_records_for_bound_transport_counters(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engine-lifecycle-artifacts-") as temporary:
            root = Path(temporary)
            record = {
                "transaction_id": "tx-one",
                "transport_case_id": "phase4_strict_http1_client_abort",
                "transaction_started": 1,
                "transaction_finished": 1,
                "transaction_destroyed": 1,
                "request_body_finished": 1,
                "response_body_finished": 1,
                "eos_seen": 0,
                "intentional_abort": 1,
                "client_disconnect": 1,
                "upstream_disconnect": 0,
                "stream_reset": 0,
                "timeout": 0,
                "short_writes": 1,
                "write_would_block": 0,
                "cleanup_reason": "strict_abort",
            }
            completed = self.run_writer(
                root,
                [
                    {
                        "transaction_id": "tx-one",
                        "phase": 4,
                        "actual_action": "abort_connection",
                        "intentional_abort": True,
                    },
                    {
                        "transaction_id": "tx-two",
                        "phase": 3,
                        "actual_action": "abort_connection",
                        "intentional_abort": True,
                    },
                ],
                transport_lifecycle_records=[record],
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            lifecycle = json.loads(
                (root / "engine-artifacts/lifecycle-counters.json").read_text(encoding="utf-8")
            )
            self.assertTrue(lifecycle["transport_counters_bound"])
            self.assertEqual(lifecycle["request_body_finishes"], 1)
            self.assertEqual(lifecycle["response_body_finishes"], 1)
            self.assertEqual(lifecycle["intentional_aborts"], 1)
            self.assertEqual(lifecycle["client_disconnects"], 1)
            self.assertEqual(lifecycle["short_writes"], 1)
            self.assertEqual(lifecycle["cleanup_abort"], 1)

    def test_bound_upstream_disconnect_counts_as_cancel_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engine-lifecycle-artifacts-") as temporary:
            root = Path(temporary)
            record = {
                "transaction_id": "tx-one",
                "transport_case_id": "upstream-disconnect",
                "transaction_started": 1,
                "transaction_finished": 1,
                "transaction_destroyed": 1,
                "request_body_finished": 0,
                "response_body_finished": 0,
                "eos_seen": 0,
                "intentional_abort": 0,
                "client_disconnect": 0,
                "upstream_disconnect": 1,
                "stream_reset": 0,
                "timeout": 0,
                "short_writes": 0,
                "write_would_block": 0,
                "cleanup_reason": "upstream_disconnected",
            }
            completed = self.run_writer(
                root,
                [{"transaction_id": "tx-one", "upstream_disconnected": True}],
                transport_lifecycle_records=[record],
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            lifecycle = json.loads(
                (root / "engine-artifacts/lifecycle-counters.json").read_text(encoding="utf-8")
            )
            self.assertEqual(lifecycle["upstream_disconnects"], 1)
            self.assertEqual(lifecycle["cleanup_cancel"], 1)
            self.assertEqual(lifecycle["intentional_aborts"], 0)

    def test_rejects_payload_bearing_event_input(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engine-lifecycle-artifacts-") as temporary:
            root = Path(temporary)
            completed = self.run_writer(
                root,
                [{"transaction_id": "tx-one", "phase": 2, "request_body": "secret"}],
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("forbidden payload metadata", completed.stderr)
            self.assertFalse((root / "engine-artifacts/lifecycle-counters.json").exists())

    def test_hashes_managed_soname_library_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engine-lifecycle-artifacts-") as temporary:
            root = Path(temporary)
            completed = self.run_writer(
                root,
                [{"transaction_id": "tx-one", "phase": 1, "status": "blocked"}],
                library_symlink=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                hashlib.sha256(b"current-engine-library").hexdigest(),
                (root / "engine-artifacts/engine-library-sha256.txt").read_text(encoding="utf-8").strip(),
            )

    def test_rejects_soname_target_outside_managed_library_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engine-lifecycle-artifacts-") as temporary:
            root = Path(temporary)
            completed = self.run_writer(
                root,
                [{"transaction_id": "tx-one", "phase": 1, "status": "blocked"}],
                library_symlink=True,
                library_target_escapes=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("managed library root", completed.stderr)
            self.assertFalse((root / "engine-artifacts/engine-library-sha256.txt").exists())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
