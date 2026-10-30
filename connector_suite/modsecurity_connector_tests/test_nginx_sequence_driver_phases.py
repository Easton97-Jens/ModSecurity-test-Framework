"""Controlled sequence orchestration characterization, never host/runtime proof."""
import argparse
import ast
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from modsecurity_connector_tests.test_nginx_sequence_driver import DRIVER


class SequenceDriverPhasesTests(unittest.TestCase):
    def test_domain_records_are_closed_and_keep_actual_descriptor_and_bytes(self):
        invocation = DRIVER.PreparedInvocation(19000, ["binary"], {"KEY": "value"}, 17, 0, None)
        self.assertEqual(invocation.fault_descriptor, 17)
        self.assertEqual(invocation.argv, ["binary"])
        with self.assertRaises(TypeError):
            DRIVER.PreparedInvocation(19000, [], {}, 17, 0, None, arbitrary=True)
        with self.assertRaises(AttributeError):
            invocation.fault_descriptor = 18
        context = DRIVER.ReceiptContext({"binary_sha256": "a" * 64}, b"raw config\n",
                                       Path("/projection"), Path("/projection/child"), 0)
        self.assertEqual(context.config, b"raw config\n")
        self.assertEqual(context.projection_root, Path("/projection/child"))
        outcome = DRIVER.ExecutionOutcome({}, None, None, None, "failure", False)
        self.assertEqual(outcome.failure, "failure")
        self.assertFalse(outcome.live_executed)

    def test_phase_helpers_have_at_most_seven_explicit_parameters(self):
        tree = ast.parse(Path(DRIVER.__file__).read_text())
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                with self.subTest(function=node.name):
                    parameters = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                    self.assertLessEqual(len(parameters), 7)

    def exercise(self, case="single_request_cleanup", config_failure=None,
                 client_failure=None, validation_errors=()):
        temporary = tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP"))
        self.addCleanup(temporary.cleanup)
        parent = Path(temporary.name)
        output = parent / "output"
        args = argparse.Namespace(case_id=case, run_id="controlled-run",
            parent_sha="a" * 40, framework_sha="b" * 40, mrts_sha="c" * 40,
            framework_root=str(parent / "framework"), projection_parent=str(parent / "projection"),
            library_dir=str(parent), fault_library=str(parent / "fault.so")
                if case in DRIVER.DEADLINE or case in {"transaction_begin_failure_cleanup", "finish_failure_propagation"}
                else None,
            fault_negative_control=False, engine_call_budget_ms=10)
        roles = {"master_pid": 120, "worker_pid": 121, "master_uid": 0, "worker_uid": 65534}
        cleanup = {"master_exited": True, "worker_exited": True}
        order = []
        validator = mock.Mock()
        validator.observation_errors.return_value = list(validation_errors)
        validator.WIRE.parse_http11_response.return_value = {"body": b"controlled", "observed_status": 200}
        if case in DRIVER.FRAMING and client_failure:
            validator.WIRE.parse_http11_response.side_effect = ValueError(client_failure)
        def snapshot(source, target, executable):
            target.write_bytes(b"controlled snapshot\n")
            return DRIVER.BASE.digest(target.read_bytes())
        def capture(path):
            return path.read_bytes() if path.exists() else b"controlled worker maps\n"
        def start(*args, **kwargs):
            order.append("start")
            return mock.Mock()
        def client(*args, **kwargs):
            order.append("client")
            if client_failure:
                raise ValueError(client_failure)
            return [{"observed_status": status} for status in DRIVER.SEQUENCES[case]]
        def stop(*args):
            order.append("stop")
            return cleanup
        reservation = mock.MagicMock()
        reservation.__enter__.return_value.getsockname.return_value = ("127.0.0.1", 19000)
        with mock.patch.object(DRIVER.BASE, "validate_inputs", return_value=(parent / "binary", parent / "module", output)), \
             mock.patch.object(DRIVER.BASE, "snapshot_artifact", side_effect=snapshot), \
             mock.patch.object(DRIVER.BASE, "configtest_environment", return_value={}), \
             mock.patch.object(DRIVER.BASE, "invoke", return_value=(0 if not config_failure else 1, b"out", b"err", config_failure)) as configtest, \
             mock.patch.object(DRIVER.STARTUP.PROJECTION, "prepare_projection", return_value=parent / "projection/child"), \
             mock.patch.object(DRIVER.STARTUP, "bounded_capture", side_effect=capture), \
             mock.patch.object(DRIVER.STARTUP, "observe_roles", return_value=roles), \
             mock.patch.object(DRIVER.STARTUP, "stop_owned_master", side_effect=stop), \
             mock.patch.object(DRIVER, "load", return_value=validator), \
             mock.patch.object(DRIVER, "run_sequence", side_effect=client), \
             mock.patch.object(DRIVER, "capture_http11_wire", return_value=(b"raw request", b"raw response")), \
             mock.patch.object(DRIVER, "read_access", return_value=[{"status": 200}]), \
             mock.patch.object(DRIVER.socket, "socket", return_value=reservation), \
             mock.patch.object(DRIVER.subprocess, "Popen", side_effect=start) as child, \
             mock.patch.object(DRIVER.os, "geteuid", return_value=0):
            result = DRIVER.run(args)
        self.assertEqual(configtest.call_args.kwargs, {})
        self.assertEqual(len(configtest.call_args.args), 2)
        if child.called:
            self.assertIs(child.call_args.kwargs["env"], configtest.call_args.args[1])
            descriptors = child.call_args.kwargs["pass_fds"]
            self.assertEqual(len(descriptors), 1 if args.fault_library is not None else 0)
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
        observed = json.loads((output / "sequence-observation.json").read_bytes())
        source = json.loads((output / "sequence-source.json").read_bytes())["cases"][0]
        return result, observed, source, order, output

    def test_success_receipts_are_raw_bound_without_canonical_promotion(self):
        result, observed, source, order, output = self.exercise()
        self.assertTrue(result)
        self.assertEqual(order, ["start", "client", "stop"])
        self.assertEqual(observed["client_exit_code"], 0)
        self.assertEqual(observed["cleanup"], {"master_exited": True, "worker_exited": True})
        self.assertTrue(source["live_executed"])
        self.assertTrue(source["sequence_observation_valid"])
        self.assertNotIn("status", source)
        self.assertNotIn("canonical_status", source)
        self.assertEqual(source["sequence_receipt"]["observed_sha256"],
                         DRIVER.BASE.digest((output / "sequence-observation.json").read_bytes()))

    def test_original_fault_descriptor_reaches_child_but_not_configtest(self):
        for case in ("transaction_begin_failure_cleanup", "finish_failure_propagation",
                     "engine_timeout_before_commit"):
            with self.subTest(case=case):
                result, _, source, order, _ = self.exercise(case=case)
                self.assertTrue(result)
                self.assertEqual(order, ["start", "client", "stop"])
                self.assertIn("fault_library_sha256", source["sequence_receipt"])

    def test_receipt_context_keeps_mapping_override_semantics_and_original_raw_hash(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP")) as temporary:
            output = Path(temporary)
            args = argparse.Namespace(case_id="single_request_cleanup", run_id="actual-run",
                                      parent_sha="a" * 40, framework_sha="b" * 40, mrts_sha="c" * 40)
            hashes = {"schema_version": 99, "run_id": "stale", "config_sha256": "stale"}
            context = DRIVER.ReceiptContext(hashes, b"original config", output / "parent",
                                           output / "parent/child", 7)
            raw = b'{"original":"observation"}\n'
            receipt = DRIVER.sequence_receipt(args, output, context, raw, 1)
            self.assertEqual(receipt["schema_version"], 1)
            self.assertEqual(receipt["run_id"], "actual-run")
            self.assertEqual(receipt["config_sha256"], DRIVER.BASE.digest(b"original config"))
            self.assertEqual(receipt["observed_sha256"], DRIVER.BASE.digest(raw))
            self.assertEqual(receipt["observed_exit_code"], 7)
            self.assertEqual(receipt["client_exit_code"], 1)
            self.assertIsNone(receipt["native_access_sha256"])
            self.assertEqual(hashes, {"schema_version": 99, "run_id": "stale", "config_sha256": "stale"})

    def test_config_rejection_never_starts_client_and_still_attempts_cleanup(self):
        result, observed, source, order, _ = self.exercise(config_failure="config failed")
        self.assertFalse(result)
        self.assertEqual(order, ["stop"])
        self.assertEqual(observed["requests"], [])
        self.assertEqual(observed["client_exit_code"], 1)
        self.assertFalse(source["live_executed"])
        self.assertEqual(source["errors"], ["native config acceptance is required before sequence"])

    def test_client_error_follows_validator_errors_and_retains_real_config_exit(self):
        result, observed, source, order, _ = self.exercise(client_failure="client failed",
                                                         validation_errors=("validator failed",))
        self.assertFalse(result)
        self.assertEqual(order, ["start", "client", "stop"])
        self.assertEqual(observed["client_exit_code"], 1)
        self.assertEqual(source["errors"], ["validator failed", "client failed"])
        self.assertEqual(source["sequence_receipt"]["observed_exit_code"], 0)

    def test_parser_error_preserves_captured_wire_in_observation_and_receipt(self):
        result, observed, source, order, output = self.exercise(
            case="transport_http11_content_length", client_failure="parser failed",
            validation_errors=("validator failed",))
        self.assertFalse(result)
        self.assertEqual(order, ["start", "stop"])
        self.assertEqual(observed["client_exit_code"], 1)
        self.assertEqual(observed["requests"], [])
        self.assertEqual(observed["wire"], {"request_hex": b"raw request".hex(),
                                         "response_hex": b"raw response".hex(), "eof_seen": True})
        self.assertEqual(source["errors"], ["validator failed", "parser failed"])
        receipt = source["sequence_receipt"]
        self.assertEqual(receipt["observed_exit_code"], 0)
        self.assertEqual(receipt["client_exit_code"], 1)
        for leaf, field in (("request-wire.bin", "request_wire_sha256"),
                            ("response-wire.bin", "response_wire_sha256"),
                            ("sequence-observation.json", "observed_sha256")):
            self.assertEqual(receipt[field], DRIVER.BASE.digest((output / leaf).read_bytes()))

    def test_capture_failure_does_not_fabricate_wire_facts_or_artifact_hashes(self):
        with mock.patch.object(DRIVER, "capture_sequence_wire", side_effect=ValueError("capture failed")):
            result, observed, source, order, _ = self.exercise(case="transport_http11_content_length")
        self.assertFalse(result)
        self.assertEqual(order, ["start", "stop"])
        self.assertIsNone(observed["wire"])
        self.assertEqual(observed["requests"], [])
        self.assertEqual(source["errors"], ["capture failed"])
        self.assertNotIn("request_wire_sha256", source["sequence_receipt"])
        self.assertNotIn("response_wire_sha256", source["sequence_receipt"])

    def test_run_has_explicit_bounded_execution_seam(self):
        tree = ast.parse(Path(DRIVER.__file__).read_text())
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        self.assertIn("execute_sequence", functions)
        run = ast.unparse(functions["run"])
        self.assertIn("execute_sequence(", run)
        self.assertNotIn("subprocess.Popen(", run)

    def test_fault_setup_requires_library_for_each_closed_boundary(self):
        for case in ("transaction_begin_failure_cleanup", "response_short_write_resume",
                     "response_write_would_block_resume", "finish_failure_propagation",
                     "engine_timeout_before_commit", "engine_timeout_after_commit"):
            with self.subTest(case=case):
                args = argparse.Namespace(case_id=case, fault_library=None, fault_negative_control=False)
                with self.assertRaises(ValueError):
                    DRIVER.prepare_sequence_fault(args, Path("/uncreated"), "a" * 64,
                                                  "a" * 24, 19000, {}, {})

    def test_fault_library_cannot_be_used_by_an_unrelated_case(self):
        args = argparse.Namespace(case_id="single_request_cleanup", fault_library="/fixture.so",
                                  fault_negative_control=False)
        with self.assertRaisesRegex(ValueError, "only authorized"):
            DRIVER.prepare_sequence_fault(args, Path("/uncreated"), "a" * 64, "a" * 24,
                                          19000, {}, {})

    def test_budget_partition_retains_original_rows_and_rejects_malformed_ledger(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP")) as temporary:
            output = Path(temporary)
            args = argparse.Namespace(case_id="engine_timeout_before_commit")
            native = {"native_operation": "msc_process_request_headers", "observed_return": 1}
            cleanup = {"native_operation": "msconnector_transaction_contract_cleanup", "cleanup_return": 0}
            raw = (json.dumps(native) + "\n" + json.dumps(cleanup) + "\n").encode()
            path = output / DRIVER.BUDGET_LEDGER
            path.write_bytes(raw)
            observed = {}
            DRIVER.add_native_fault_observations(args, output, observed, 10)
            self.assertEqual(observed, {"budget_ms": 10, "native_budget": [native], "native_cleanup": [cleanup]})
            self.assertEqual(path.read_bytes(), raw)
            path.write_bytes(b"not JSON\n")
            with self.assertRaises(json.JSONDecodeError):
                DRIVER.add_native_fault_observations(args, output, {}, 10)

    def test_fault_setup_keeps_exact_transaction_phase_and_private_descriptor(self):
        cases = (("finish_failure_propagation", "MSCONNECTOR_OWNED_FINISH", DRIVER.FINISH_LEDGER, None),
                 ("engine_timeout_before_commit", "MSCONNECTOR_OWNED_BUDGET", DRIVER.BUDGET_LEDGER, "1"),
                 ("engine_timeout_after_commit", "MSCONNECTOR_OWNED_BUDGET", DRIVER.BUDGET_LEDGER, "4"))
        for case, prefix, leaf, phase in cases:
            for negative in (False, True):
                with self.subTest(case=case, negative=negative), tempfile.TemporaryDirectory(
                        dir=os.environ.get("RUNNER_TEMP")) as temporary:
                    output = Path(temporary)
                    args = argparse.Namespace(case_id=case, fault_library="/fixture.so",
                                              fault_negative_control=negative)
                    environment, hashes = {}, {}
                    with mock.patch.object(DRIVER.BASE, "snapshot_artifact", return_value="d" * 64):
                        descriptor = DRIVER.prepare_sequence_fault(args, output, "a" * 64,
                            "a" * 24, 19000, environment, hashes)
                    try:
                        metadata = os.fstat(descriptor)
                        self.assertEqual(metadata.st_mode & 0o777, 0o600)
                        self.assertEqual(metadata.st_nlink, 1)
                        self.assertEqual(metadata.st_size, 0)
                        self.assertEqual(environment[prefix + "_FD"], str(descriptor))
                        self.assertEqual(environment[prefix + "_TXID"] == "a" * 32, not negative)
                        self.assertEqual(environment.get(prefix + "_PHASE"), phase)
                        self.assertEqual(hashes, {"fault_library_sha256": "d" * 64})
                        self.assertTrue((output / leaf).exists())
                    finally:
                        os.close(descriptor)

    def test_descriptor_closes_even_if_owned_master_cleanup_raises(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP")) as temporary:
            output = Path(temporary)
            descriptor = os.open(output / "ledger", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            args = argparse.Namespace(case_id="single_request_cleanup", run_id="controlled-run")
            invocation = DRIVER.PreparedInvocation(19000, [], {}, descriptor, 1, "config failed")
            validator = mock.Mock()
            with mock.patch.object(DRIVER.STARTUP, "stop_owned_master", side_effect=ValueError("cleanup failed")):
                with self.assertRaisesRegex(ValueError, "cleanup failed"):
                    DRIVER.execute_sequence(args, output, "a" * 24, None, validator, invocation)
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_descriptor_closes_when_fsync_fails_without_rewriting_failure(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP")) as temporary:
            output = Path(temporary)
            descriptor = os.open(output / "ledger", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            args = argparse.Namespace(case_id="single_request_cleanup", run_id="controlled-run")
            invocation = DRIVER.PreparedInvocation(19000, [], {}, descriptor, 1, "config failed")
            validator = mock.Mock()
            with mock.patch.object(DRIVER.STARTUP, "stop_owned_master", return_value={}), \
                 mock.patch.object(DRIVER.os, "fsync", side_effect=OSError("sync failed")):
                with self.assertRaisesRegex(OSError, "sync failed"):
                    DRIVER.execute_sequence(args, output, "a" * 24, None, validator, invocation)
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_sequence_capture_preserves_socket_reuse_and_terminal_abort_controls(self):
        for case in ("transport_sequential_requests", "transport_keep_alive",
                     "phase4_strict_http1_client_abort", "engine_timeout_after_commit",
                     "response_write_would_block_resume"):
            with self.subTest(case=case), mock.patch.object(DRIVER, "run_sequence", return_value=[{"real": "client"}]) as client:
                args = argparse.Namespace(case_id=case)
                upstream = mock.Mock()
                observed = DRIVER.capture_sequence_requests(args, 19000, "a" * 24,
                                                            upstream, mock.Mock(), None)
                self.assertEqual(observed, [{"real": "client"}])
                self.assertEqual(client.call_args.args[2], DRIVER.SEQUENCES[case])
                self.assertEqual(client.call_args.kwargs["keepalive"], case in DRIVER.KEEPALIVE)
                self.assertEqual(client.call_args.kwargs["expect_first_abort"],
                                 case in DRIVER.STRICT or case == "engine_timeout_after_commit")
                self.assertEqual(client.call_args.kwargs["backpressure"],
                                 case == "response_write_would_block_resume")
                self.assertIs(client.call_args.kwargs["headers_seen"], upstream.headers_seen)

    def test_framing_capture_retains_original_wire_bytes_and_parser_fields(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP")) as temporary:
            output = Path(temporary)
            validator = mock.Mock()
            validator.WIRE.parse_http11_response.return_value = {"body": b"actual", "observed_status": 200,
                                                               "framing": "content_length"}
            args = argparse.Namespace(case_id="transport_http11_content_length")
            with mock.patch.object(DRIVER, "capture_http11_wire", return_value=(b"request", b"response")), \
                 mock.patch.object(DRIVER, "run_sequence") as sequence:
                wire, response_wire = DRIVER.capture_sequence_wire(args, output, 19000, "a" * 24)
                observed = DRIVER.capture_sequence_requests(args, 19000, "a" * 24,
                                                            None, validator, response_wire)
            sequence.assert_not_called()
            self.assertEqual((output / "request-wire.bin").read_bytes(), b"request")
            self.assertEqual((output / "response-wire.bin").read_bytes(), b"response")
            self.assertEqual(wire, {"request_hex": b"request".hex(), "response_hex": b"response".hex(), "eof_seen": True})
            self.assertEqual(observed[0]["framing"], "content_length")
            self.assertNotIn("body", observed[0])
            validator.WIRE.parse_http11_response.assert_called_once_with(b"response")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
