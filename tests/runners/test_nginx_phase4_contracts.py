"""Closed native Phase-4 trigger specifications, not runtime evidence."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nginx_phase4_contracts as contracts


class Phase4ContractsTest(unittest.TestCase):
    def test_all_assigned_records_remain_visible(self):
        self.assertEqual(len(contracts.RECORD_IDS), 8)
        self.assertIn("phase4_deny_after_commit_log_only_minimal", contracts.RECORD_IDS)

    def test_split_spans_two_nonempty_chunks_not_individually_matching(self):
        spec = contracts.operation("phase4_marker_split_across_chunks")
        chunks = spec["response_chunks"]
        self.assertEqual(len(chunks), 2)
        self.assertTrue(all(chunks))
        self.assertTrue(all(contracts.MARKER not in chunk for chunk in chunks))
        self.assertIn(contracts.MARKER, "".join(chunks))
        self.assertEqual(spec["nginx_phase4_mode"], "safe")

    def test_eos_reuses_only_exact_split_source(self):
        spec = contracts.operation("phase4_end_of_stream_evaluation")
        self.assertEqual(spec["source_record_id"], "phase4_marker_split_across_chunks")
        self.assertEqual(spec["response_chunks"], contracts.operation(spec["source_record_id"])["response_chunks"])

    def test_engine_limits_use_exact_boundary_and_explicit_engine_actions(self):
        for record, size, action in (
            ("phase4_body_at_limit", 64, "ProcessPartial"),
            ("phase4_body_over_limit", 65, "ProcessPartial"),
            ("phase4_body_process_partial", 65, "ProcessPartial"),
            ("phase4_body_reject", 65, "Reject"),
        ):
            with self.subTest(record=record):
                spec = contracts.operation(record)
                self.assertEqual(len("".join(spec["response_chunks"]).encode()), size)
                self.assertIn("SecResponseBodyLimit 64", spec["rules"])
                self.assertIn("SecResponseBodyLimitAction " + action, spec["rules"])
                self.assertNotIn("modsecurity_phase4_body_limit", spec["rules"])

    def test_metadata_reuse_is_exact_over_limit_not_arbitrary_native_event(self):
        spec = contracts.operation("full_lifecycle_event_metadata_bounded")
        self.assertEqual(spec["source_record_id"], "phase4_body_over_limit")
        self.assertEqual(spec["response_chunks"], contracts.operation(spec["source_record_id"])["response_chunks"])

    def test_user_authorized_minimal_identity_migration_executes_existing_safe(self):
        spec = contracts.operation("phase4_deny_after_commit_log_only_minimal")
        self.assertEqual(spec["nginx_phase4_mode"], "safe")
        self.assertTrue(spec["pause_between_chunks"])
        self.assertNotIn("minimal", spec["rules"])

    def test_unknown_case_and_path_input_are_rejected(self):
        for record in ("phase4_body_reject/../other", "other", "", None):
            with self.subTest(record=record), self.assertRaises(ValueError):
                contracts.operation(record)

    def test_spec_is_not_native_evidence_or_mutable_shared_state(self):
        spec = contracts.operation("phase4_body_at_limit")
        self.assertNotIn("status", spec)
        self.assertNotIn("observed_outcome", spec)
        spec["response_chunks"].append("changed")
        self.assertEqual(len("".join(contracts.operation("phase4_body_at_limit")["response_chunks"])), 64)

    def test_rules_retain_actual_engine_default_scope_without_same_load_clear(self):
        for record in contracts.RECORD_IDS:
            self.assertNotIn("SecResponseBodyMimeTypesClear", contracts.operation(record)["rules"])


if __name__ == "__main__":
    unittest.main()
