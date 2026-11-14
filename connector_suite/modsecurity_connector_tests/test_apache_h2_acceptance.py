"""Reader corruption controls; host qualification remains a separate real run."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest

from modsecurity_test_framework.connector_context import load_source, test_root

RUNNER = load_source(test_root() / "connector_suite/adapters/apache/harness/apache_h2_acceptance.py")


class ApacheH2AcceptanceTests(unittest.TestCase):
    def fixture(self, output):
        paths = {name: f"/apache-h2/unit/{name}" for name in ("target", "peer", "followup")}
        completed = {name: {"stream_id": stream} for name, stream in (("target", 3), ("peer", 1), ("followup", 5))}
        for name, item in completed.items():
            item["status"] = 403 if name == "target" else 200
        cleanup = [{"uri": path, "transaction_id": path, "stream_id": completed[name]["stream_id"],
                    "stream_tag": "19000-0-" + str(completed[name]["stream_id"]),
                    "connection_id": 19, "context_seen": True, "native_context_cleared": True,
                    "monotonic_ns": 1000 + completed[name]["stream_id"]}
                   for name, path in paths.items()]
        access = [{"uri": path, "protocol": "HTTP/2.0", "stream_id": str(completed[name]["stream_id"]),
                   "stream_tag": "19000-0-" + str(completed[name]["stream_id"]), "status": completed[name]["status"]}
                  for name, path in paths.items()]
        native = [{"transaction_id": paths[name], "rule_id": str(1199100 + phase)}
                  for name in ("peer", "followup") for phase in range(1, 5)]
        native.append({"transaction_id": paths["target"], "rule_id": "1199201", "requested_action": "deny", "actual_action": "deny"})
        for item in native:
            item.update(connector="apache", integration_mode="native-httpd-module", uri=item["transaction_id"])
        values = {"native-events.jsonl": native, "native-cleanup.jsonl": cleanup, "access.jsonl": access}
        (output / "error.log").write_text("\n".join(
            f'[id "{1199100 + phase}"] [uri "{paths[name]}"] [unique_id "{paths[name]}"]'
            for name in ("peer", "followup") for phase in (3, 4)) + "\n")
        self.write(output, values)
        return paths, completed, values

    def write(self, output, values):
        for name, rows in values.items():
            (output / name).write_text("".join(json.dumps(row) + "\n" for row in rows))

    def test_reader_accepts_complete_independent_native_binding(self):
        with tempfile.TemporaryDirectory(prefix="apache-h2-reader-") as directory:
            output = Path(directory)
            paths, completed, _values = self.fixture(output)
            proof = RUNNER.validate_native(output, paths, completed, "phase1")
            self.assertEqual(proof["native_cleanup_count"], 3)

    def test_reader_rejects_missing_duplicate_wrong_stream_and_foreign_cleanup(self):
        for mutation in ("missing", "duplicate", "wrong_stream", "foreign_tx", "not_cleared", "never_seen"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="apache-h2-corrupt-") as directory:
                output = Path(directory)
                paths, completed, baseline = self.fixture(output)
                values = copy.deepcopy(baseline)
                rows = values["native-cleanup.jsonl"]
                if mutation == "missing":
                    rows.pop()
                elif mutation == "duplicate":
                    rows.append(dict(rows[0]))
                elif mutation == "wrong_stream":
                    rows[0]["stream_id"] = 7
                elif mutation == "foreign_tx":
                    rows[0]["transaction_id"] = "/foreign/transaction"
                elif mutation == "not_cleared":
                    rows[0]["native_context_cleared"] = False
                else:
                    rows[0]["context_seen"] = False
                self.write(output, values)
                with self.assertRaises(ValueError):
                    RUNNER.validate_native(output, paths, completed, "phase1")

    def test_reader_rejects_native_h1_fallback_rule_and_connection_misbinding(self):
        for mutation in ("h1", "rule", "connection", "foreign_event"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="apache-h2-binding-") as directory:
                output = Path(directory)
                paths, completed, values = self.fixture(output)
                if mutation == "h1":
                    values["access.jsonl"][0]["protocol"] = "HTTP/1.1"
                elif mutation == "rule":
                    values["native-events.jsonl"][-1]["rule_id"] = "1199202"
                elif mutation == "connection":
                    values["native-cleanup.jsonl"][1]["stream_tag"] = "19000-9-1"
                    values["access.jsonl"][1]["stream_tag"] = "19000-9-1"
                else:
                    values["native-events.jsonl"][0]["transaction_id"] = "/foreign"
                self.write(output, values)
                with self.assertRaises(ValueError):
                    RUNNER.validate_native(output, paths, completed, "phase1")

    def test_partial_json_and_zero_native_records_fail(self):
        with tempfile.TemporaryDirectory(prefix="apache-h2-partial-") as directory:
            output = Path(directory)
            paths, completed, _values = self.fixture(output)
            (output / "native-events.jsonl").write_bytes(b'{"incomplete":')
            with self.assertRaises(ValueError):
                RUNNER.validate_native(output, paths, completed, "phase1")
            (output / "native-events.jsonl").write_bytes(b"")
            with self.assertRaises(ValueError):
                RUNNER.validate_native(output, paths, completed, "phase1")

    def test_native_response_phase_marker_requires_exact_rule_and_transaction(self):
        with tempfile.TemporaryDirectory(prefix="apache-h2-phase-log-") as directory:
            output = Path(directory)
            paths, completed, _values = self.fixture(output)
            original = (output / "error.log").read_text()
            for corrupted in ("", original.replace(paths["peer"], "/foreign"),
                              original + original, original.replace('1199104', '1199109')):
                (output / "error.log").write_text(corrupted)
                with self.subTest(log=corrupted), self.assertRaises(ValueError):
                    RUNNER.validate_native(output, paths, completed, "phase1")

    def test_bundle_rejects_changed_file_before_semantic_evaluation(self):
        with tempfile.TemporaryDirectory(prefix="apache-h2-integrity-") as directory:
            output = Path(directory)
            (output / "client.jsonl").write_text("{}\n")
            (output / "receipt.json").write_text(json.dumps({"case_id": "apache_h2_allow", "sha256": {"client.jsonl": "0" * 64}}))
            with self.assertRaisesRegex(ValueError, "digest"):
                RUNNER.validate_bundle(output, "apache_h2_allow", {})

    def test_native_peer_cleanup_cannot_precede_observed_reset(self):
        with tempfile.TemporaryDirectory(prefix="apache-h2-barrier-") as directory:
            output = Path(directory)
            paths, _completed, values = self.fixture(output)
            reset = {"monotonic_ns": 500}
            RUNNER.validate_cleanup_barrier(output, paths, "strict", [], reset)
            values["native-cleanup.jsonl"][1]["monotonic_ns"] = 400
            self.write(output, values)
            with self.assertRaisesRegex(ValueError, "preceded"):
                RUNNER.validate_cleanup_barrier(output, paths, "strict", [], reset)

    def test_client_release_request_waits_for_real_matching_native_cleanup(self):
        gate = RUNNER.CleanupGate()
        gate.set()
        self.assertTrue(gate.requested.is_set())
        self.assertFalse(gate.is_set())
        backend = SimpleNamespace(lock=threading.Lock(), peer_release=gate, target_stream=3,
                                  proof={"native_cleanup_gate": {}})
        target = {"transaction_id": "/target", "stream_id": 3, "context_seen": True,
                  "native_context_cleared": True, "monotonic_ns": 10}
        for field, wrong in (("transaction_id", "/foreign"), ("stream_id", 7),
                             ("context_seen", False), ("native_context_cleared", False)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                RUNNER.allow_peer_after_cleanup(backend, dict(target, **{field: wrong}), {"target": "/target"})
            self.assertFalse(gate.is_set())
        RUNNER.allow_peer_after_cleanup(backend, target, {"target": "/target"})
        self.assertTrue(gate.is_set())

    def test_late_forced_or_foreign_cleanup_cannot_qualify_live_peer(self):
        with tempfile.TemporaryDirectory(prefix="apache-h2-live-gate-") as directory:
            output = Path(directory)
            paths, _completed, _values = self.fixture(output)
            baseline = {"released": True, "forced": False, "error": None, "target_stream": 3,
                        "target_cleanup_ns": 1003, "peer_released_ns": 1010}
            rows = [{"name": name, "event": event, "monotonic_ns": timestamp} for name, event, timestamp in (
                ("peer", "first_data", 1020), ("peer", "completed", 1030), ("followup", "request_started", 1040))]
            (output / "upstream.json").write_text(json.dumps({"native_cleanup_gate": baseline}))
            RUNNER.validate_live_cleanup_gate(output, paths, rows)
            for field, wrong in (("released", False), ("forced", True), ("error", "bad"),
                                 ("target_stream", 7), ("target_cleanup_ns", 1004), ("peer_released_ns", 1035)):
                (output / "upstream.json").write_text(json.dumps({"native_cleanup_gate": dict(baseline, **{field: wrong})}))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    RUNNER.validate_live_cleanup_gate(output, paths, rows)


if __name__ == "__main__":
    unittest.main()
