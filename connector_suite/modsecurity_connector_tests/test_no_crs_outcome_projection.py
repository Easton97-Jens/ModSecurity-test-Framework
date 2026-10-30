"""Collector regression fixtures, not new runtime evidence."""
import unittest

from modsecurity_connector_tests.test_collect_no_crs_source_helpers import COLLECTOR


class OutcomeProjectionTests(unittest.TestCase):
    def intervention(self, tx="one"):
        return {"event": "phase4_intervention", "transaction_id": tx,
                "phase": 4, "rule_id": 1100301, "http_status": 403,
                "original_http_status": 200, "visible_http_status": 200,
                "requested_action": "deny", "actual_action": "log_only",
                "late_intervention": True, "response_committed": True}

    def test_completion_does_not_replace_intervention_outcome(self):
        outcome = COLLECTOR.canonical_semantics([
            self.intervention(), {"event": "phase4_completion", "phase": 4,
                                 "transaction_id": "one", "http_status": 0,
                                 "late_intervention": False},
            {"event": "cleanup", "transaction_id": "one", "response_committed": False}])
        self.assertEqual(outcome["http_status"], 403)
        self.assertTrue(outcome["late_intervention"])
        self.assertTrue(outcome["response_committed"])

    def test_later_technical_failure_is_not_hidden(self):
        records = [self.intervention(), {"event": "internal_error", "phase": 4,
                   "transaction_id": "one", "status": "error", "http_status": 500,
                   "transport_result": "engine_error"}]
        outcome = COLLECTOR.canonical_semantics(records)
        self.assertEqual(outcome["http_status"], 500)
        self.assertEqual(outcome["transport_result"], "engine_error")

    def test_different_transactions_are_not_combined(self):
        self.assertEqual(COLLECTOR.canonical_semantics([
            self.intervention(), self.intervention("two")]), {})

    def test_wrong_rule_or_phase_cannot_fill_matching_decision(self):
        for changes in ({"rule_id": 1100302}, {"phase": 3}):
            with self.subTest(changes=changes):
                outcome = COLLECTOR.canonical_semantics(
                    [dict(self.intervention(), **changes)], "1100301", 4)
                self.assertNotIn("actual_action", outcome)
                self.assertNotIn("http_status", outcome)

    def test_non_intervention_observation_keeps_own_values(self):
        self.assertEqual(COLLECTOR.canonical_semantics([
            {"visible_http_status": 200}]), {"visible_http_status": 200})

    def test_conflicting_matching_decisions_fail_closed(self):
        self.assertEqual(COLLECTOR.canonical_semantics([
            self.intervention(), dict(self.intervention(), http_status=404)],
            "1100301", 4), {})

    def test_snapshot_restoration_preserves_first_fault_decision(self):
        outcome = COLLECTOR.canonical_semantics([
            self.intervention(),
            {"transaction_id": "one", "client_first_byte_received": True,
             "body_bytes_seen": 17, "body_bytes_inspected": 17},
            {"transaction_id": "one", "status": "error", "http_status": 500,
             "body_bytes_seen": 44},
            {"transaction_id": "one", "status": "error", "http_status": 502}],
            "1100301", 4)
        self.assertEqual(outcome["http_status"], 500)
        self.assertEqual(outcome["body_bytes_seen"], 17)

    def test_first_technical_error_keeps_priority(self):
        outcome = COLLECTOR.canonical_semantics([
            self.intervention(), {"event": "internal_error", "status": "error",
                                 "transaction_id": "one", "http_status": 500},
            {"event": "internal_error", "status": "error",
             "transaction_id": "one", "http_status": 502}])
        self.assertEqual(outcome["http_status"], 500)

    def test_fault_without_outcome_fields_still_prevents_case_pass(self):
        records = [self.intervention(), {"event": "internal_error", "phase": 4,
                   "transaction_id": "one", "status": "error"}]
        self.assertFalse(COLLECTOR.case_passes(
            "PASS", True, 200, None, "1100301", 4,
            "phase4_deny_after_commit_log_only", {"1100301"}, records))

    def test_explicit_generic_fault_contracts_remain_observable(self):
        cases = (
            ("upstream_reset_before_headers", 3, "upstream_reset", None),
            ("upstream_reset_after_headers", 4, "upstream_reset", None),
            ("upstream_reset_during_body", 4, "upstream_reset", None),
            ("upstream_timeout", 4, "timeout", None),
            ("response_short_write_resume", 4, "short_write", "1100301"),
        )
        for case_id, phase, transport, rule in cases:
            with self.subTest(case_id=case_id):
                records = [{"phase": phase, "transaction_id": "one",
                            "transport_result": transport}]
                self.assertTrue(COLLECTOR.case_passes(
                    "PASS", True, 502, None, rule, phase, case_id,
                    {rule} if rule else set(), records))

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
