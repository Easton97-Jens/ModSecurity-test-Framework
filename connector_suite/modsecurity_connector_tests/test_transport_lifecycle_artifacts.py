from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from modsecurity_connector_tests.framework_test_trust import trusted_framework_root


ROOT = connector_root()
FRAMEWORK_ROOT = Path(
    os.environ.get("PARENT_TEST_FRAMEWORK_ROOT", source_path('modules/ModSecurity-test-Framework', root=ROOT))
)
artifacts = load_source(source_path('ci/runtime/lifecycle/write-transport-lifecycle-artifacts.py', root=ROOT))


class TransportLifecycleArtifactsTest(unittest.TestCase):
    def test_emits_only_payload_free_inventory_without_client_inference(self) -> None:
        events = [
            {
                # Canonical events retain only the transport case relation;
                # the sidecar uses it as the asserted catalog case identity.
                "transport_case_id": "phase4_first_byte_before_response_end",
                "transaction_id": "tx-one",
                "negotiated_protocol": "h2",
                "stream_id": 3,
                "phase": 4,
                "rule_id": 1100301,
                "event": "phase4_intervention",
                "message_id": "MSCONN_EVENT_PHASE4_HARD_ABORT_AFTER_200",
                "requested_action": "deny",
                "actual_action": "stream_reset",
                "transport_result": "stream_reset",
                "response_committed": True,
                "client_disconnected": True,
                "stream_reset": True,
                "cancelled": True,
                "eos_seen": True,
                "transaction_started": True,
                "transaction_finished": True,
                "transaction_destroyed": True,
                "request_body_finished": True,
                "response_body_finished": True,
                "intentional_abort": True,
                "host_survived": True,
                "followup_request_result": "completed",
                "cleanup_reason": "strict_abort",
                "first_byte_before_response_end": True,
                "client_first_byte_received": True,
                "upstream_paused": True,
                "upstream_eos_sent_at_first_byte": False,
                "first_chunk_size": 11,
            }
        ]
        observations, lifecycle, barriers, counters = artifacts.build_artifacts("nginx", "run-1", events)
        self.assertEqual(observations["run_id"], "run-1")
        self.assertEqual(observations["observations"][0]["client_result"], "not_observable")
        self.assertTrue(observations["observations"][0]["host_survived"])
        self.assertEqual(
            observations["observations"][0]["case_id"],
            "phase4_first_byte_before_response_end",
        )
        self.assertEqual(counters["stream_resets"], 1)
        self.assertEqual(counters["client_disconnects"], 1)
        self.assertEqual(len(barriers), 1)
        self.assertEqual(barriers[0]["connector"], "nginx")
        self.assertEqual(barriers[0]["run_id"], "run-1")
        self.assertNotIn("case_id", barriers[0])
        self.assertNotIn("protocol", barriers[0])
        self.assertFalse(barriers[0]["upstream_eos_sent_at_first_byte"])
        self.assertEqual(len(lifecycle["records"]), 1)
        self.assertEqual(lifecycle["records"][0]["intentional_abort"], 1)
        self.assertNotIn("body", json.dumps(observations))

    def test_barrier_record_is_accepted_as_a_framework_canonical_event(self) -> None:
        event = {
            "transport_case_id": "phase4_first_byte_before_response_end",
            "transaction_id": "tx-barrier",
            "negotiated_protocol": "h2",
            "stream_id": 3,
            "phase": 4,
            "rule_id": 1100301,
            "event": "phase4_intervention",
            "message_id": "MSCONN_EVENT_PHASE4",
            "requested_action": "deny",
            "actual_action": "stream_reset",
            "transport_result": "stream_reset",
            "response_committed": True,
            "client_first_byte_received": True,
            "first_byte_before_response_end": True,
            "upstream_paused": True,
            "upstream_eos_sent_at_first_byte": False,
        }
        barrier = artifacts.barrier_record(
            event, "nginx", "native-nginx-http-module", "run-barrier"
        )
        self.assertIsNotNone(barrier)
        framework_root, error = trusted_framework_root(ROOT, FRAMEWORK_ROOT)
        if framework_root is None:
            self.skipTest(error)
        framework_ci = framework_root / "ci" / "checks" / "catalog"
        framework_runners = framework_root / "tests" / "runners"
        probe = (
            "import json, sys; "
            "sys.path[:0] = [sys.argv[1], sys.argv[2]]; "
            "import no_crs_baseline as no_crs; "
            "errors = no_crs.canonical_event_errors(json.loads(sys.argv[3]), 'barrier', "
            "'nginx', 'native-nginx-http-module'); "
            "print('\\n'.join(errors)); raise SystemExit(bool(errors))"
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                probe,
                str(framework_ci),
                str(framework_runners),
                json.dumps(barrier),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)

    def test_h3_connection_id_is_retained_only_as_a_hash(self) -> None:
        base = {
            "transport_case_id": "h3-case",
            "transaction_id": "tx-h3",
            "negotiated_protocol": "h3",
            "stream_id": 1,
            "phase": 4,
            "event": "phase4",
            "message_id": "MSCONN_EVENT",
            "rule_id": 1100301,
            "requested_action": "deny",
            "actual_action": "stream_reset",
            "transport_result": "stream_reset",
            "host_survived": True,
            "followup_request_result": "completed",
        }
        raw_observations, _lifecycle, _barriers, _counters = artifacts.build_artifacts(
            "nginx", "run-h3", [{**base, "connection_id": "raw-quic-cid"}]
        )
        hashed_observations, _lifecycle, _barriers, _counters = artifacts.build_artifacts(
            "nginx", "run-h3", [{**base, "connection_id": "sha256:0123456789abcdef"}]
        )
        self.assertIsNone(raw_observations["observations"][0]["connection_id"])
        self.assertEqual(
            hashed_observations["observations"][0]["connection_id"],
            "sha256:0123456789abcdef",
        )

    def test_rejects_payload_bearing_source_event(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-lifecycle-") as temporary:
            root = Path(temporary)
            source = root / "events.jsonl"
            source.write_text('{"transaction_id":"tx","response_body":"secret"}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "forbidden payload metadata"):
                artifacts.load_events(source)

    def test_effective_config_keeps_only_hashes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-config-") as temporary:
            root = Path(temporary)
            source = root / "runtime.conf"
            source.write_text("secret-looking but never copied\n", encoding="utf-8")
            output = root / "effective-config"
            artifacts.write_effective_config(
                output,
                "apache",
                "run-one",
                [f"runtime.conf={source}"],
                root,
            )
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["run_id"], "run-one")
            self.assertEqual(
                hashlib.sha256(source.read_bytes()).hexdigest(),
                manifest["files"][0]["sha256"],
            )
            self.assertNotIn("secret-looking", (output / "manifest.json").read_text(encoding="utf-8"))

    def test_effective_config_uses_a_distinct_verified_build_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-config-") as temporary:
            root = Path(temporary)
            run_root = root / "run"
            build_root = root / "build"
            framework_root = root / "framework"
            other_root = root / "other"
            run_root.mkdir()
            build_root.mkdir()
            framework_root.mkdir()
            other_root.mkdir()
            source = build_root / "runtime-components.env"
            source.write_text("component=verified\n", encoding="utf-8")
            framework_rule = framework_root / "tests/rules/no-crs-baseline.conf"
            framework_rule.parent.mkdir(parents=True)
            framework_rule.write_text("SecRuleEngine On\n", encoding="utf-8")
            outside = other_root / "outside.env"
            outside.write_text("component=outside\n", encoding="utf-8")

            output = run_root / "effective-config"
            artifacts.write_effective_config(
                output,
                "apache",
                "run-one",
                [
                    f"runtime-components.env={source}",
                    f"rules/no-crs-baseline.conf={framework_rule}",
                ],
                run_root,
                build_root,
                framework_root,
            )
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(
                [entry["path"] for entry in manifest["files"]],
                ["rules/no-crs-baseline.conf", "runtime-components.env"],
            )

            with self.assertRaisesRegex(ValueError, "effective config source must be below"):
                artifacts.write_effective_config(
                    run_root / "other-effective-config",
                    "apache",
                    "run-one",
                    [f"outside.env={outside}"],
                    run_root,
                    build_root,
                    framework_root,
                )

    def test_selected_framework_root_rejects_path_aliases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-framework-root-") as temporary:
            root = Path(temporary)
            framework = root / "framework"
            framework.mkdir()
            alias = root / "framework-alias"
            alias.symlink_to(framework, target_is_directory=True)

            self.assertEqual(
                artifacts.canonical_source_root(framework, "framework root"),
                framework,
            )
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                artifacts.canonical_source_root(alias, "framework root")
            with self.assertRaisesRegex(ValueError, "must not contain '..'"):
                artifacts.canonical_source_root(
                    framework / ".." / "framework", "framework root"
                )

    def test_rejects_symlinked_transport_artifact_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transport-lifecycle-") as temporary:
            root = Path(temporary)
            events = root / "events.jsonl"
            events.write_text("{}\n", encoding="utf-8")
            output = root / "transport-artifacts"
            output.mkdir()
            victim = root / "victim.json"
            victim.write_text("unchanged\n", encoding="utf-8")
            (output / "transport-observations.json").symlink_to(victim)
            with self.assertRaisesRegex(ValueError, "must not be a symbolic link"):
                artifacts.main(
                    [
                        "--connector", "apache",
                        "--run-id", "run-one",
                        "--runtime-root", str(root),
                        "--events", str(events),
                        "--output-dir", str(output),
                    ]
                )
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged\n")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
