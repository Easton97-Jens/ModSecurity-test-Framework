"""Offline barrier/collector regression fixtures, never runtime evidence."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import json
import os
from pathlib import Path
import tempfile
import unittest

from modsecurity_connector_tests.test_collect_no_crs_source_helpers import COLLECTOR
from modsecurity_connector_ci.lib.first_byte_binding import create_binding, verify_binding


class FirstByteBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log, self.snapshot = self.root / "events.jsonl", self.root / "snapshot.json"
        self.paused, self.release = self.root / "paused.json", self.root / "release"
        self.paused.write_text(json.dumps({"evidence_type": "synchronized_upstream_paused",
                                          "upstream_paused": True, "upstream_eos_sent": False,
                                          "body_payload_persisted": False}))
        self.event = {"event": "phase4_append", "phase": 4, "transaction_id": "tx",
                      "response_committed": True, "eos_seen": False,
                      "body_bytes_seen": 17, "body_bytes_inspected": 17}
        self.evidence = {"response_committed": True, "body_bytes_seen": 17,
                         "body_bytes_inspected": 17, "first_chunk_size": 17,
                         "client_first_byte_received": True,
                         "first_byte_before_response_end": True, "upstream_paused": True,
                         "upstream_eos_sent_at_first_byte": False,
                         "upstream_response_finished_at_first_byte": False,
                         "no_full_response_buffering": True}
        self.log.write_text(json.dumps(self.event) + '\n')
        self.snapshot.write_text(json.dumps(self.evidence))
        self.binding = create_binding(self.log, self.snapshot, self.paused, self.release)
        Path(str(self.snapshot) + ".binding.json").write_text(json.dumps(self.binding))
        self.release.touch()

    def test_later_counters_not_overwritten_or_marked_mismatch(self):
        later = dict(self.event, body_bytes_seen=44, body_bytes_inspected=44,
                     event="phase4_completion", eos_seen=True)
        records = COLLECTOR.merge_first_byte_evidence(
            [self.event, later], self.evidence, self.binding)
        self.assertTrue(records[0]["first_byte_before_response_end"])
        self.assertNotIn("first_byte_before_response_end", records[1])
        self.assertEqual(records[1]["body_bytes_seen"], 44)
        outcome = COLLECTOR.canonical_semantics(records)
        self.assertEqual(outcome["body_bytes_seen"], 17)

    def test_snapshot_from_other_invocation_rejected_even_equal_numbers(self):
        other = self.root / "other.json"
        other.write_bytes(self.snapshot.read_bytes())
        with self.assertRaisesRegex(ValueError, "invocation"):
            verify_binding(self.binding, self.log, other, self.root)

    def test_changed_snapshot_rejected(self):
        self.snapshot.write_text(json.dumps(dict(self.evidence, first_chunk_size=18)))
        with self.assertRaisesRegex(ValueError, "bytes changed"):
            verify_binding(self.binding, self.log, self.snapshot, self.root)

    def test_invalid_position_precedes_changed_prefix(self):
        self.log.write_text('{}\n')
        for changes in ({"log_prefix_size": True}, {"event_index": False},
                        {"log_prefix_size": 0}, {"event_index": -1}):
            with self.subTest(changes=changes), self.assertRaisesRegex(
                    ValueError, "^invalid first-byte event position$"):
                verify_binding(dict(self.binding, **changes), self.log, self.snapshot, self.root)

    def test_snapshot_mismatch_precedes_invalid_position(self):
        self.snapshot.write_text('{}')
        with self.assertRaisesRegex(ValueError, "^first-byte snapshot bytes changed$"):
            verify_binding(dict(self.binding, event_index=-1), self.log, self.snapshot, self.root)

    def test_wrong_transaction_or_event_position_rejected(self):
        for changes in ({"transaction_id": "other"}, {"event_index": 1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                verify_binding(dict(self.binding, **changes), self.log, self.snapshot, self.root)

    def test_same_numbers_on_earlier_append_do_not_prove_snapshot_position(self):
        self.log.write_text(json.dumps(self.event) + '\n' + json.dumps(self.event) + '\n')
        self.release.unlink()
        binding = create_binding(self.log, self.snapshot, self.paused, self.release)
        Path(str(self.snapshot) + ".binding.json").write_text(json.dumps(binding))
        self.release.touch()
        with self.assertRaisesRegex(ValueError, "position"):
            verify_binding(dict(binding, event_index=0), self.log, self.snapshot, self.root)

    def test_counter_conflict_at_bound_point_is_not_silently_accepted(self):
        records = COLLECTOR.merge_first_byte_evidence(
            [self.event], dict(self.evidence, body_bytes_seen=18), self.binding)
        self.assertTrue(records[0]["first_byte_evidence_counter_mismatch"])
        self.assertIn("unapproved-field", COLLECTOR.event_record_violation(records[0], "test"))

    def test_duplicate_equal_append_cannot_be_promoted_twice(self):
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            COLLECTOR.merge_first_byte_evidence([self.event, self.event], self.evidence, self.binding)

    def test_later_completion_still_permits_original_prefix(self):
        with self.log.open("a") as stream:
            stream.write(json.dumps(dict(self.event, event="phase4_completion", eos_seen=True)) + '\n')
        self.assertEqual(verify_binding(self.binding, self.log, self.snapshot, self.root), self.event)
        self.release.unlink()
        with self.assertRaisesRegex(ValueError, "after response completion"):
            create_binding(self.log, self.snapshot, self.paused, self.release)

    def test_snapshot_after_release_rejected(self):
        self.release.touch()
        with self.assertRaisesRegex(ValueError, "precede"):
            create_binding(self.log, self.snapshot, self.paused, self.release)

    def test_changed_pause_evidence_is_rejected(self):
        self.paused.write_text('{}')
        with self.assertRaisesRegex(ValueError, "paused invocation"):
            verify_binding(self.binding, self.log, self.snapshot, self.root)

    def test_stale_or_post_release_binding_is_rejected(self):
        after_release = self.release.stat().st_mtime_ns + 1_000_000_000
        os.utime(Path(str(self.snapshot) + ".binding.json"), ns=(after_release, after_release))
        with self.assertRaisesRegex(ValueError, "after upstream release"):
            verify_binding(self.binding, self.log, self.snapshot, self.root)

    def test_harness_captures_metadata_and_evidence_before_release(self):
        source = (connector_root() /
                  "connectors/nginx/harness/run_nginx_smoke.sh").read_text()
        block = source.split("send_synchronized_first_byte_request() {", 1)[1].split(
            "stop_stale_runtime_pid()", 1)[0]
        self.assertLess(block.index('write-first-byte-host-metadata.py'),
                        block.index(': > "$SYNCHRONIZED_RELEASE_FILE"'))
        self.assertLess(block.index('--merge-evidence'),
                        block.index(': > "$SYNCHRONIZED_RELEASE_FILE"'))

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
