"""Actual timeout event pairing cannot be replaced by requested delay or HTTP."""
import copy
import unittest

from tests.no_crs import test_nginx_lifecycle_sequence as sequence_tests


class EngineBudgetSequenceTests(unittest.TestCase):
    setUp = sequence_tests.SequenceContractTests.setUp

    def observation(self, after_commit=False):
        value = sequence_tests.SequenceContractTests.observation(self)
        case = "engine_timeout_after_commit" if after_commit else "engine_timeout_before_commit"
        value["case_id"] = case
        value["requests"] = [dict(value["requests"][0], observed_status=200 if after_commit else 504,
                                  declared_length=None if after_commit else 10,
                                  framing="chunked" if after_commit else "content_length",
                                  client_error="incomplete_read" if after_commit else None,
                                  transport_result="connection_aborted" if after_commit else "completed")]
        value["native_access"] = [dict(value["native_access"][0], status=200 if after_commit else 504)]
        value["budget_ms"] = 10
        value["native_budget"] = [{"native_operation": "msc_process_response_body" if after_commit else "msc_process_request_headers",
                                   "native_phase": 4 if after_commit else 1, "observed_return": 1,
                                   "worker_pid": 11, "transaction_id": "a" * 32,
                                   "start_ns": 1000000000, "end_ns": 1025000000,
                                   "elapsed_ns": 25000000, "requested_delay_ns": 25000000}]
        value["native_cleanup"] = [{"native_operation": "msconnector_transaction_contract_cleanup",
                                    "observed_return": 0, "worker_pid": 11, "transaction_id": "a" * 32,
                                    "cleanup_complete": 1, "error_class_code": 4,
                                    "error_class_name": "engine_timeout", "timeout_error_preserved": 1,
                                    "timed_phase_completed": 0}]
        stage = "response_body" if after_commit else "request_headers"
        identity = {"connector": "nginx", "integration_mode": "native-nginx-http-module",
                    "transaction_id": "a" * 32, "uri": value["requests"][0]["path"],
                    "phase": stage, "rule_id": "", "status": "error",
                    "requested_action": "error", "eos_seen": after_commit, "http_status": 504}
        terminal = dict(identity, timeout_stage=stage, response_committed=after_commit,
                        headers_sent=after_commit,
                        original_http_status=200 if after_commit else 0,
                        visible_http_status=200 if after_commit else 0,
                        actual_action="abort_connection" if after_commit else "",
                        connection_aborted=after_commit,
                        transport_result="connection_aborted" if after_commit else "not_observable")
        # Emitted immediately after the Engine returns, before the caller
        # chooses its terminal host action. It has no timeout_stage metadata.
        timing = dict(identity, response_committed=False, headers_sent=False,
                      original_http_status=0, visible_http_status=0,
                      actual_action="", connection_aborted=False,
                      transport_result="not_observable")
        value["native_events"] = [
            dict(timing, event="engine_call_budget_exceeded", message_id="MSCONN_ENGINE_CALL_BUDGET",
                 reason="budget_ms=10;elapsed_ns=26000000;native_return=1;common_completed=0"),
            dict(terminal, event="engine_timeout", message_id="MSCONN_EVENT_ENGINE_TIMEOUT", reason="engine_timeout")]
        if after_commit:
            value["upstream_barrier"] = {"prefix_sent": True, "client_headers_seen": True,
                                         "marker_sent": True, "barrier_timeout": False,
                                         "upstream_write_failed": False}
            value["post_sequence_roles"] = dict(value["roles"])
        return value

    def errors(self, value):
        return self.helper.observation_errors(value, value["case_id"], "run-1")

    def test_actual_precommit_504_requires_pair_and_delegated_cleanup(self):
        self.assertEqual(self.errors(self.observation()), [])

    def test_actual_postcommit_abort_keeps_engine_eos_true(self):
        self.assertEqual(self.errors(self.observation(True)), [])

    def test_timing_and_terminal_identity_remain_strict_in_both_phases(self):
        for after_commit in (False, True):
            base = self.observation(after_commit)
            for index in (0, 1):
                for field, replacement in (("connector", "apache"), ("integration_mode", "foreign"),
                                           ("transaction_id", "b" * 32), ("uri", "/foreign"),
                                           ("phase", "request_headers" if after_commit else "response_body"),
                                           ("rule_id", "1100301"), ("status", "ok"),
                                           ("requested_action", "deny"), ("http_status", 500),
                                           ("eos_seen", not after_commit)):
                    with self.subTest(after_commit=after_commit, index=index, field=field):
                        value = copy.deepcopy(base)
                        value["native_events"][index][field] = replacement
                        self.assertTrue(self.errors(value))

    def test_timing_does_not_claim_the_later_terminal_action(self):
        for after_commit in (False, True):
            base = self.observation(after_commit)
            for field, replacement in (("response_committed", True), ("headers_sent", True),
                                       ("original_http_status", 200), ("visible_http_status", 200),
                                       ("actual_action", "abort_connection"),
                                       ("connection_aborted", True), ("transport_result", "connection_aborted")):
                with self.subTest(after_commit=after_commit, field=field):
                    value = copy.deepcopy(base)
                    value["native_events"][0][field] = replacement
                    self.assertTrue(self.errors(value))

    def test_terminal_host_action_and_stage_remain_required(self):
        for after_commit in (False, True):
            base = self.observation(after_commit)
            terminal = base["native_events"][1]
            for field in ("timeout_stage", "response_committed", "headers_sent", "original_http_status",
                          "visible_http_status", "actual_action", "connection_aborted", "transport_result"):
                with self.subTest(after_commit=after_commit, field=field):
                    value = copy.deepcopy(base)
                    value["native_events"][1].pop(field)
                    self.assertTrue(self.errors(value))
                    value = copy.deepcopy(base)
                    value["native_events"][1][field] = (not terminal[field] if type(terminal[field]) is bool
                                                      else "foreign")
                    self.assertTrue(self.errors(value))

    def test_missing_duplicate_or_foreign_native_event_is_rejected(self):
        base = self.observation()
        for index in (0, 1):
            value = copy.deepcopy(base)
            value["native_events"].pop(index)
            self.assertTrue(self.errors(value))
            value = copy.deepcopy(base)
            value["native_events"].append(dict(value["native_events"][index]))
            self.assertTrue(self.errors(value))
            for field, replacement in (("transaction_id", "b" * 32), ("rule_id", "1100301"),
                                       ("phase", "response_body"), ("response_committed", 0)):
                value = copy.deepcopy(base)
                value["native_events"][index][field] = replacement
                self.assertTrue(self.errors(value))

    def test_requested_delay_and_false_clock_results_cannot_prove_timeout(self):
        base = self.observation()
        for field, replacement in (("elapsed_ns", 10000000), ("observed_return", -1),
                                   ("worker_pid", 12), ("transaction_id", "b" * 32),
                                   ("start_ns", True), ("end_ns", 2**64)):
            value = copy.deepcopy(base)
            value["native_budget"][0][field] = replacement
            self.assertTrue(self.errors(value))
        for reason in ("budget_ms=10;elapsed_ns=10000000;native_return=1;common_completed=0",
                       "budget_ms=10;elapsed_ns=26000000;native_return=-1;common_completed=0",
                       "budget_ms=10;elapsed_ns=26000000;native_return=1;common_completed=1",
                       "budget_ms=10;elapsed_ns=26000000;native_return=1;common_completed=0;payload=x"):
            value = copy.deepcopy(base)
            value["native_events"][0]["reason"] = reason
            self.assertTrue(self.errors(value))

    def test_timeout_cleanup_must_retain_actual_class_and_complete(self):
        base = self.observation()
        for field, replacement in (("observed_return", -1), ("cleanup_complete", 0),
                                   ("worker_pid", 12), ("transaction_id", "b" * 32),
                                   ("error_class_code", 6), ("error_class_name", "invalid_engine_response"),
                                   ("timeout_error_preserved", 0), ("timed_phase_completed", 1)):
            value = copy.deepcopy(base)
            value["native_cleanup"][0][field] = replacement
            self.assertTrue(self.errors(value))

    def test_postcommit_complete_wire_or_false_eos_is_rejected(self):
        base = self.observation(True)
        for field, replacement in (("transport_result", "completed"), ("client_error", None)):
            value = copy.deepcopy(base)
            value["requests"][0][field] = replacement
            self.assertTrue(self.errors(value))
        for index in (0, 1):
            invalid_fields = (("eos_seen", False), ("visible_http_status", 504),
                              ("actual_action", "log_only"),
                              ("connection_aborted", index == 0))
            for field, replacement in invalid_fields:
                value = copy.deepcopy(base)
                value["native_events"][index][field] = replacement
                self.assertTrue(self.errors(value))


if __name__ == "__main__":
    unittest.main()
