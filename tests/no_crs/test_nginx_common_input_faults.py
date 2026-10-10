"""Unit fault observations are not substitutes for real native evidence."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "runners/nginx_common_input_faults.py"


class CommonInputFaultContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("common_input_faults", PATH)
        cls.contract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.contract)

    def observation(self, case):
        transaction = "a" * 32
        return {"schema_version": 1, "case_id": case, "run_id": "unit", "operation": "common_mapper_input_fault",
                "protocol": "http1", "client_exit_code": 0, "observed_http_status": 400,
                "path": "/no-crs/input-fault/" + case,
                "transaction_id": transaction,
                "roles": {"master_uid": 0, "worker_uid": 65534, "master_pid": 123, "worker_pid": 124, "run_id": "unit"},
                "cleanup": {"verified": True, "master_running": False, "worker_running": False, "listener_open": False,
                            "master_pid": 123, "worker_pid": 124, "run_id": "unit"},
                "native_access": {"transaction_id": transaction, "uri": "/no-crs/input-fault/" + case, "status": 400},
                "native_fault": {"case_id": case, "transaction_id": transaction, "pid": 124, "ppid": 123,
                                 "uid": 65534, "validator_return": 0, "diagnostic_match": True,
                                 "body_size": 1 if case.startswith("body_") else 0,
                                 "body_data_null": True, "header_count": 1, "headers_null": case.startswith("header_")},
                "native_diagnostic": "modsecurity common request mapper validation failed: " +
                   ("missing body data" if case.startswith("body_") else "missing headers"),
                "native_events": [{"event": "protocol_error", "message_id": "MSCONN_EVENT_PROTOCOL_ERROR",
                    "connector": "nginx", "integration_mode": "native-nginx-http-module", "phase": "request_headers",
                    "transaction_id": transaction, "status": "error", "reason": "protocol_error", "rule_id": "",
                    "method": "", "uri": ""}]}

    def test_two_required_native_mapper_operations_retain_actual_host_contract(self):
        for case in self.contract.CONTRACTS:
            with self.subTest(case=case):
                self.assertEqual(self.contract.observation_errors(self.observation(case), case, "unit"), [])
                self.assertEqual(self.contract.CONTRACTS[case]["phase"], 1)
                self.assertEqual(self.contract.CONTRACTS[case]["expected_status"], 400)

    def test_wrong_transaction_foreign_worker_missing_guard_or_engine_rule_never_pass(self):
        for case in self.contract.CONTRACTS:
            for target, field, value in (("native_fault", "transaction_id", "b"*32),
                                         ("native_access", "transaction_id", "b"*32),
                                         ("native_fault", "pid", 999), ("native_fault", "ppid", 999),
                                         ("native_fault", "validator_return", 1),
                                         ("native_fault", "diagnostic_match", False),
                                         ("cleanup", "verified", False),
                                         ("cleanup", "run_id", "foreign"),
                                         ("cleanup", "master_pid", 999),
                                         ("cleanup", "worker_pid", 999),
                                         ("roles", "run_id", "foreign"),
                                         ("roles", "worker_uid", 0)):
                row = self.observation(case)
                row[target][field] = value
                with self.subTest(case=case, target=target, field=field):
                    self.assertTrue(self.contract.observation_errors(row, case, "unit"))
            row = self.observation(case)
            row["native_events"][0]["rule_id"] = "1100001"
            self.assertTrue(self.contract.observation_errors(row, case, "unit"))
            row["native_events"] = []
            self.assertTrue(self.contract.observation_errors(row, case, "unit"))
            row = self.observation(case)
            row["native_events"][0]["phase"] = True
            self.assertTrue(self.contract.observation_errors(row, case, "unit"))
            row = self.observation(case)
            row["native_events"][0]["event"] = "phase1_error"
            self.assertTrue(self.contract.observation_errors(row, case, "unit"))

    def test_identity_types_and_old_body_failure_remain_rejected(self):
        for case in self.contract.CONTRACTS:
            changes = ((None, "observed_http_status", 405), (None, "client_exit_code", False),
                       (None, "run_id", "foreign"), (None, "case_id", "foreign"),
                       (None, "path", "/different"), (None, "transaction_id", ""),
                       ("native_access", "status", 200), ("native_access", "uri", "/different"),
                       ("native_fault", "uid", 0), ("native_fault", "validator_return", False),
                       ("roles", "master_pid", True), ("roles", "worker_pid", 123),
                       ("cleanup", "listener_open", True))
            for target, field, value in changes:
                row = self.observation(case)
                (row[target] if target else row)[field] = value
                with self.subTest(case=case, target=target, field=field):
                    self.assertTrue(self.contract.observation_errors(row, case, "unit"))
            field = "body_data_null" if case.startswith("body_") else "headers_null"
            row = self.observation(case)
            row["native_fault"][field] = False
            self.assertTrue(self.contract.observation_errors(row, case, "unit"))

    def test_native_event_cause_identity_cardinality_and_diagnostic_are_exact(self):
        for case in self.contract.CONTRACTS:
            for field, value in (("transaction_id", "b" * 32), ("message_id", "OTHER"),
                                 ("connector", "apache"), ("reason", "engine_error"),
                                 ("status", "ok"), ("phase", 2),
                                 ("integration_mode", "external"), ("method", "POST"),
                                 ("uri", "/no-crs/input-fault/foreign")):
                row = self.observation(case)
                row["native_events"][0][field] = value
                with self.subTest(case=case, field=field):
                    self.assertTrue(self.contract.observation_errors(row, case, "unit"))
            row = self.observation(case)
            row["native_events"] *= 2
            self.assertTrue(self.contract.observation_errors(row, case, "unit"))
            for field in ("method", "uri"):
                row = self.observation(case)
                del row["native_events"][0][field]
                self.assertTrue(self.contract.observation_errors(row, case, "unit"))
            row = self.observation(case)
            row["native_diagnostic"] += " unrelated"
            self.assertTrue(self.contract.observation_errors(row, case, "unit"))
            for field in ("roles", "cleanup", "native_fault", "native_access", "native_events"):
                row = self.observation(case)
                row[field] = None
                with self.subTest(case=case, field=field):
                    self.assertTrue(self.contract.observation_errors(row, case, "unit"))
        self.assertTrue(self.contract.observation_errors(None, "unknown", "unit"))


if __name__ == "__main__":
    unittest.main()
