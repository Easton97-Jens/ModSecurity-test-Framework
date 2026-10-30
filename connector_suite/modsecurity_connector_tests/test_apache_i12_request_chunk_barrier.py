"""Apache request wire continuation requires a physical principal append gate."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = connector_root()
BATCH = load_source(source_path('ci/runtime/lifecycle/apache-i12/acceptance/batch.py', root=ROOT))


def blob(data):
    return {"data": base64.b64encode(data).decode(), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


class RequestChunkBarrierTest(unittest.TestCase):
    def setUp(self):
        storage = Path("/var/tmp/codex/ModSecurity-conector/request-chunk-barrier-tests")
        storage.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=storage)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.request = {"method": "POST", "path": "/main", "headers": [["X-I12-ID", "principal"]],
            "body": blob(b"onetwo"), "chunks": [blob(b"one"), blob(b"two")], "framing": "chunked",
            "barrier": {"after_chunk": 1, "release_condition": "native_append_first_chunk_observed",
                        "timeout_seconds": 5}}
        self.context = {"native_log": self.root / "native-api.jsonl", "identity": {
            "run": "run", "case": "case", "transaction_id": "principal", "host_pid": 123}}
        self.receipt = {"started_ns": 7, "request_send_operations": []}
        self.connection = Mock()
        self.head, self.chunks = BATCH.wire_request(self.request, 18123)

    def send(self):
        BATCH.send_client_request(self.connection, self.request, self.head, self.chunks,
                                 self.root, self.receipt, self.context)

    def test_second_wire_chunk_waits_for_principal_append_witness(self):
        witness = {"path": str(self.context["native_log"]), "witness": {"physical": "test-only"}}
        def observe(*args):
            self.assertEqual(self.connection.sendall.call_args_list,
                             [unittest.mock.call(self.head), unittest.mock.call(self.chunks[0])])
            self.assertNotIn("request_send_completed_ns", self.receipt)
            return witness
        with patch.object(BATCH.cancellation, "wait_for_append", side_effect=observe) as wait, patch.object(BATCH.time, "sleep"):
            self.send()
        wait.assert_called_once_with(self.context["native_log"], self.context["identity"], 7, 5)
        self.assertEqual(self.connection.sendall.call_count, 4)
        self.assertTrue(self.receipt["request_chunk_barrier"]["released"])
        self.assertEqual(self.receipt["request_chunk_barrier"]["native_append"], witness)
        self.assertIn("request_send_completed_ns", self.receipt)

    def test_gate_timeout_leaves_remaining_body_unsent_and_contract_open(self):
        with patch.object(BATCH.cancellation, "wait_for_append", side_effect=BATCH.cancellation.GateError("timeout")):
            with self.assertRaises(BATCH.cancellation.GateError):
                self.send()
        self.assertEqual(self.connection.sendall.call_count, 2)
        self.assertFalse(self.receipt["request_chunk_barrier"]["released"])
        self.assertIsNone(self.receipt["request_chunk_barrier"]["native_append"])
        self.assertNotIn("request_send_completed_ns", self.receipt)
        (self.root / "receipt.json").write_text(json.dumps(self.receipt))
        observation = {"missing_operations": []}
        BATCH.read_client_observation(self.root, "main", False, self.request, observation)
        self.assertFalse(observation["actual_principal_execution"])
        self.assertIn("actual_native_request_chunk_barrier_unproven", observation["missing_operations"])

    def test_missing_context_wrong_duplicate_principal_and_missing_host_fail_before_send(self):
        invalid = [None, {"native_log": self.root / "native", "identity": dict(self.context["identity"], transaction_id="other")},
                   {"native_log": self.root / "native", "identity": {"run": "run", "case": "case", "transaction_id": "principal"}}]
        for context in invalid:
            with self.subTest(context=context), self.assertRaises(BATCH.cancellation.GateError):
                BATCH.send_client_request(self.connection, self.request, self.head, self.chunks,
                                         self.root, self.receipt, context)
        self.request["headers"].append(["x-i12-id", "principal"])
        with self.assertRaises(BATCH.cancellation.GateError):
            self.send()
        self.connection.sendall.assert_not_called()

    def test_client_timeout_receipt_retains_only_completed_sends_and_nonzero_exit(self):
        spec_path = self.root / "request.json"
        spec_path.write_text(json.dumps(self.request))
        connection_manager = Mock()
        connection_manager.__enter__ = Mock(return_value=self.connection)
        connection_manager.__exit__ = Mock(return_value=False)
        with patch.object(BATCH.socket, "create_connection", return_value=connection_manager), patch.object(
                BATCH.cancellation, "wait_for_append", side_effect=BATCH.cancellation.GateError("timeout")):
            result = BATCH.client_main(spec_path, self.root, 18123, self.root, self.context)
        self.assertEqual(result, 1)
        receipt = json.loads((self.root / "receipt.json").read_text())
        self.assertEqual(receipt["proposed_process_exit"], 1)
        self.assertFalse(receipt["request_chunk_barrier"]["released"])
        self.assertEqual((self.root / "request.raw").read_bytes(), self.head + self.chunks[0])
        self.assertEqual(receipt["request_wire_capture_scope"], "completed_sendall_operations_only")
        self.assertNotIn("request_send_completed_ns", receipt)

    def test_invalid_gate_parameters_fail_before_send(self):
        for key, value in (("after_chunk", True), ("after_chunk", 2), ("timeout_seconds", True),
                           ("timeout_seconds", 0), ("timeout_seconds", 21), ("release_condition", "sleep")):
            original = self.request["barrier"][key]
            self.request["barrier"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.send()
            self.request["barrier"][key] = original
        self.request["framing"] = "content_length"
        with self.assertRaises(ValueError):
            self.send()
        self.connection.sendall.assert_not_called()

    def test_control_request_drops_principal_barrier(self):
        plan = {"request": self.request, "unique_main_request": {"token": "principal"}}
        control = BATCH.client_request(plan, {}, "precontrol", None)
        self.assertIsNone(control["barrier"])
        self.assertIsNotNone(self.request["barrier"])

    def test_ordinary_chunked_request_does_not_gate(self):
        self.request.pop("barrier")
        with patch.object(BATCH.cancellation, "wait_for_append") as wait, patch.object(BATCH.time, "sleep"):
            BATCH.send_client_request(self.connection, self.request, self.head, self.chunks, self.root, self.receipt)
        wait.assert_not_called()
        self.assertEqual(self.connection.sendall.call_count, 4)

    def test_main_command_and_client_mode_supply_exact_native_context(self):
        plan = {"case_id": "NEED-request-streaming"}
        argv = BATCH.client_command(plan, self.root, self.root, 18123, self.request, "main", False,
            {"MSCONNECTOR_LIFECYCLE_RUN": "run"}, {"host_identity": {"pid": 123}})
        self.assertEqual(argv[argv.index("--gate-case") + 1], "NEED-request-streaming")
        spec_path = self.root / "request.json"
        spec_path.write_text(json.dumps(self.request))
        args = argparse.Namespace(client_spec=spec_path, native_log=self.context["native_log"],
            gate_run="run", gate_case="case", gate_host_pid=123, output=self.root, port=18123, backend_root=self.root)
        with patch.object(BATCH, "client_main", return_value=0) as client:
            self.assertEqual(BATCH.run_client_mode(args, argparse.ArgumentParser()), 0)
        self.assertEqual(client.call_args.args[-1]["identity"], self.context["identity"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
