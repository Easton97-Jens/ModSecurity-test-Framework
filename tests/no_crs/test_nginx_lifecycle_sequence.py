"""Strict host-native lifecycle sequence contract regression tests."""
import importlib.util
from pathlib import Path
import unittest


HELPER = Path(__file__).parents[1] / "runners/nginx_lifecycle_sequence.py"


class SequenceContractTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("nginx_sequence", HELPER)
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)

    def observation(self):
        return {
            "schema_version": 1, "case_id": "keepalive_allow_deny_allow", "run_id": "run-1",
            "protocol": "http1", "operation": "request_sequence", "client_exit_code": 0,
            "requests": [
                {"path": "/no-crs/sequence/0", "observed_status": 200, "bytes_received": 10},
                {"path": "/no-crs/sequence/1", "observed_status": 403, "bytes_received": 20},
                {"path": "/no-crs/sequence/2", "observed_status": 200, "bytes_received": 10},
            ],
            "native_access": [
                {"uri": "/no-crs/sequence/0", "status": 200, "connection": "10", "connection_requests": 1, "transaction_id": "a" * 32},
                {"uri": "/no-crs/sequence/1", "status": 403, "connection": "10", "connection_requests": 2, "transaction_id": "b" * 32},
                {"uri": "/no-crs/sequence/2", "status": 200, "connection": "10", "connection_requests": 3, "transaction_id": "c" * 32},
            ],
            "roles": {"master_pid": 10, "worker_pid": 11, "master_uid": 0, "worker_uid": 65534},
            "cleanup": {"verified": True, "master_running": False, "worker_running": False, "listener_open": False},
        }

    def errors(self, value):
        return self.helper.observation_errors(value, "keepalive_allow_deny_allow", "run-1")

    def test_real_same_connection_sequence_is_accepted(self):
        self.assertEqual(self.errors(self.observation()), [])

    def test_reconnecting_client_does_not_prove_keepalive(self):
        value = self.observation()
        value["native_access"][1]["connection"] = "11"
        self.assertTrue(self.errors(value))

    def test_duplicate_transaction_is_rejected(self):
        value = self.observation()
        value["native_access"][1]["transaction_id"] = value["native_access"][0]["transaction_id"]
        self.assertTrue(self.errors(value))

    def test_http_200_does_not_replace_expected_deny(self):
        value = self.observation()
        value["requests"][1]["observed_status"] = 200
        value["native_access"][1]["status"] = 200
        self.assertTrue(self.errors(value))

    def test_foreign_case_and_run_are_rejected(self):
        for field in ("case_id", "run_id"):
            value = self.observation()
            value[field] = "foreign"
            self.assertTrue(self.errors(value))

    def test_missing_cleanup_or_root_worker_split_is_rejected(self):
        value = self.observation()
        value["roles"]["worker_uid"] = 0
        self.assertTrue(self.errors(value))
        value = self.observation()
        value["cleanup"]["listener_open"] = True
        self.assertTrue(self.errors(value))

    def test_requested_fault_cannot_replace_observed_fault(self):
        value = self.observation()
        value["case_id"] = "engine_timeout_before_commit"
        self.assertTrue(self.helper.observation_errors(value, value["case_id"], "run-1"))

    def test_native_budget_ledger_requires_actual_monotonic_overrun(self):
        value = self.observation()
        value["requests"] = value["requests"][:1]
        value["native_access"] = value["native_access"][:1]
        value["budget_ms"] = 10
        value["native_budget"] = [{"native_operation": "msc_process_request_headers", "native_phase": 1,
                                  "observed_return": 1, "worker_pid": 11, "transaction_id": "a" * 32,
                                  "start_ns": 1000000000, "end_ns": 1025000000,
                                  "elapsed_ns": 25000000, "requested_delay_ns": 25000000}]
        self.assertEqual(self.helper.native_budget_errors(value, 1), [])
        for field, mismatch in (("elapsed_ns", 10000000), ("worker_pid", 12),
                                ("transaction_id", "b" * 32), ("observed_return", -1),
                                ("native_phase", 4), ("native_operation", "msc_process_response_body")):
            original = value["native_budget"][0][field]
            value["native_budget"][0][field] = mismatch
            self.assertTrue(self.helper.native_budget_errors(value, 1))
            value["native_budget"][0][field] = original
        value["native_budget"] = []
        self.assertTrue(self.helper.native_budget_errors(value, 1))

    def test_early_mapping_failure_requires_exact_native_reason(self):
        value = self.observation()
        value["case_id"] = "early_mapping_failure_cleanup"
        value["requests"] = [dict(value["requests"][0], observed_status=500)]
        value["native_access"] = [dict(value["native_access"][0], status=500)]
        value["fault"] = {"requested": "early_mapping_failure", "triggered": True,
                          "native_diagnostic": "ModSecurity: invalid canonical transaction identifier"}
        self.assertEqual(self.helper.observation_errors(value, value["case_id"], "run-1"), [])
        value["fault"]["native_diagnostic"] = "unrelated error"
        self.assertTrue(self.helper.observation_errors(value, value["case_id"], "run-1"))

    def test_begin_failure_requires_native_allocation_rejection(self):
        value = self.observation()
        value["case_id"] = "transaction_begin_failure_cleanup"
        value["requests"] = [dict(value["requests"][0], observed_status=500)]
        value["native_access"] = [dict(value["native_access"][0], status=500)]
        value["fault"] = {"requested": "transaction_begin_failure", "triggered": True,
                          "native_diagnostic": "ModSecurity: failed to create transaction"}
        self.assertEqual(self.helper.observation_errors(value, value["case_id"], "run-1"), [])
        value["fault"]["triggered"] = False
        self.assertTrue(self.helper.observation_errors(value, value["case_id"], "run-1"))

    def late_observation(self, strict=True):
        value = self.observation()
        value["case_id"] = "phase4_strict_followup_request_succeeds" if strict else "keepalive_safe_followup"
        value["requests"] = [dict(row, observed_status=200) for row in value["requests"][:2]]
        value["native_access"] = [dict(row, status=200) for row in value["native_access"][:2]]
        value["requests"][0].update(declared_length=100, bytes_received=50 if strict else 100,
                                    transport_result="connection_aborted" if strict else "completed")
        if strict:
            value["native_access"][1].update(connection="11", connection_requests=1)
        value["upstream_barrier"] = {"prefix_sent": True, "client_headers_seen": True,
                                     "marker_sent": True, "barrier_timeout": False, "upstream_write_failed": False}
        value["post_sequence_roles"] = dict(value["roles"])
        value["native_events"] = [{"transaction_id": "a" * 32, "event": "phase4_intervention",
                                    "connector": "nginx", "integration_mode": "native-nginx-http-module",
                                    "uri": value["requests"][0]["path"], "phase": 4, "rule_id": "1100301",
                                    "requested_action": "deny", "actual_action": "abort_connection" if strict else "log_only",
                                    "response_committed": True, "eos_seen": True}]
        return value

    def test_strict_abort_and_fresh_followup_and_safe_reuse(self):
        for strict in (True, False):
            value = self.late_observation(strict)
            self.assertEqual(self.helper.observation_errors(value, value["case_id"], "run-1"), [])

    def test_driver_knowing_marker_cannot_replace_native_intervention(self):
        value = self.late_observation()
        value["native_events"] = []
        self.assertTrue(self.helper.observation_errors(value, value["case_id"], "run-1"))

    def test_strict_abort_does_not_accept_complete_http_200(self):
        value = self.late_observation()
        value["requests"][0].update(transport_result="completed", bytes_received=100)
        self.assertTrue(self.helper.observation_errors(value, value["case_id"], "run-1"))

    def test_foreign_native_transaction_cannot_bind_followup(self):
        value = self.late_observation()
        value["native_events"][0]["transaction_id"] = "b" * 32
        self.assertTrue(self.helper.observation_errors(value, value["case_id"], "run-1"))

    def test_restarted_worker_is_not_same_host_survival(self):
        value = self.late_observation()
        value["post_sequence_roles"]["worker_pid"] = 12
        self.assertTrue(self.helper.observation_errors(value, value["case_id"], "run-1"))

    def write_observation(self, blocked=False):
        value = self.late_observation(strict=False)
        value["case_id"] = "response_write_would_block_resume" if blocked else "response_short_write_resume"
        value["requests"] = value["requests"][:1]
        value["native_access"] = value["native_access"][:1]
        value["native_access"][0]["remote_port"] = 19000
        value["native_events"][0].update(body_bytes_seen=100, body_bytes_inspected=100)
        value["native_writes"] = [
            {"pid": 11, "fd": 9, "peer_port": 19000, "requested_bytes": 100,
             "returned_bytes": -1 if blocked else 1, "errno": 11 if blocked else 0, "fault_triggered": True},
            {"pid": 11, "fd": 9, "peer_port": 19000, "requested_bytes": 100,
             "returned_bytes": 100, "errno": 0, "fault_triggered": False},
        ]
        return value

    def test_short_write_and_would_block_require_actual_resume(self):
        for blocked in (True, False):
            value = self.write_observation(blocked)
            self.assertEqual(self.helper.observation_errors(value, value["case_id"], "run-1"), [])
            value["native_writes"] = value["native_writes"][:1]
            self.assertTrue(self.helper.observation_errors(value, value["case_id"], "run-1"))

    def test_foreign_writer_and_duplicate_body_inspection_are_rejected(self):
        value = self.write_observation()
        value["native_writes"][0]["pid"] = 12
        self.assertTrue(self.helper.observation_errors(value, value["case_id"], "run-1"))
        value = self.write_observation()
        value["native_events"][0]["body_bytes_inspected"] = 200
        self.assertTrue(self.helper.observation_errors(value, value["case_id"], "run-1"))

    def test_post_response_finish_failure_preserves_200_and_requires_cleanup(self):
        import hashlib
        value = self.observation()
        value["case_id"] = "finish_failure_propagation"
        value["requests"] = [dict(value["requests"][0], bytes_received=23, body_sha256=hashlib.sha256(b"bounded-owned-sequence\n").hexdigest())]
        value["native_access"] = value["native_access"][:1]
        value["fault"] = {"requested": "finish_failure", "triggered": True,
                          "native_diagnostic": "ModSecurity: native logging phase processing failed"}
        value["native_finish"] = [
            {"native_operation": op, "observed_return": result, "worker_pid": 11, "transaction_id": "a" * 32}
            for op, result in (("msc_process_logging", -1), ("msconnector_transaction_contract_cleanup", 0),
                               ("cleanup_complete", 1), ("native_logging_error_preserved", 1))]
        self.assertEqual(self.helper.observation_errors(value, value["case_id"], "run-1"), [])
        value["native_finish"][1]["observed_return"] = -1
        self.assertTrue(self.helper.observation_errors(value, value["case_id"], "run-1"))


if __name__ == "__main__":
    unittest.main()
