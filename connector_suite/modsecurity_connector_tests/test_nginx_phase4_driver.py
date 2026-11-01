"""Contract guards for actual native observation selection and configuration."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

PATH = connector_root() / "ci/runtime/lifecycle/run-nginx-phase4-cases.py"
driver = load_source(PATH)


class NativePhase4DriverTest(unittest.TestCase):
    def test_adapter_receipt_accepts_all_closed_metadata_without_mutating_inputs(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP", "/var/tmp/codex/ModSecurity-conector")) as temp:
            output = Path(temp)
            metadata = {
                "variant": "long-query",
                "request_headers": {"X-Modsec-Smoke": "log-only"},
                "backend_contract_sha256": "a" * 64,
                "backend_omission_contract_sha256": "b" * 64,
            }
            row = {"case_id": "unit", "raw_sha256": {}}
            expected_metadata = dict(metadata, request_headers=dict(metadata["request_headers"]))
            expected_row = dict(row, raw_sha256=dict(row["raw_sha256"]))

            driver.write_source_result(output, row, receipt_metadata=metadata)

            observed = json.loads((output / "source-result.json").read_bytes())
            self.assertEqual({name: observed[name] for name in metadata}, metadata)
            self.assertEqual(metadata, expected_metadata)
            self.assertEqual(row, expected_row)

    def test_adapter_receipt_is_sealed_once_with_actual_extra_capture(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP", "/var/tmp/codex/ModSecurity-conector")) as temp:
            output = Path(temp)
            fixture = output / "response-header-fixture.json"
            fixture.write_bytes(b"actual fixture\n")
            metadata = {"backend_contract_sha256": "a" * 64}
            row = {"case_id": "unit", "raw_sha256": {}}
            driver.write_source_result(output, row, receipt_metadata=metadata,
                                       extra_capture_leaves=(fixture.name,))
            sealed = (output / "source-result.json").read_bytes()
            observed = json.loads(sealed)
            self.assertEqual(observed["backend_contract_sha256"], "a" * 64)
            self.assertEqual(observed["raw_sha256"][fixture.name], driver.HOST.BASE.digest(fixture.read_bytes()))
            with self.assertRaises(FileExistsError):
                driver.write_source_result(output, row, receipt_metadata=metadata,
                                           extra_capture_leaves=(fixture.name,))
            self.assertEqual((output / "source-result.json").read_bytes(), sealed)

    def test_adapter_metadata_and_capture_authority_are_closed(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP", "/var/tmp/codex/ModSecurity-conector")) as temp:
            output = Path(temp)
            for metadata in ({"case_id": "foreign"}, {"variant": "../foreign"},
                             {"backend_contract_sha256": "not-a-digest"},
                             {"request_headers": {"Bad": "value\nInjected"}}):
                with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                    driver.write_source_result(output, {"raw_sha256": {}}, receipt_metadata=metadata)
            for leaf in ("../outside", "nested/file", "source-result.json", "nginx.conf"):
                with self.subTest(leaf=leaf), self.assertRaises(ValueError):
                    driver.write_source_result(output, {"raw_sha256": {}}, extra_capture_leaves=(leaf,))
            with self.assertRaises(ValueError):
                driver.write_source_result(output, {"variant": "at255", "raw_sha256": {}},
                                           receipt_metadata={"variant": "over256"})
            with self.assertRaises(ValueError):
                driver.write_source_result(output, {"raw_sha256": {}},
                                           extra_capture_leaves=("response-header-fixture.json",))
            with self.assertRaises(ValueError):
                driver.write_source_result(output, {"raw_sha256": {"response-header-fixture.json": "a" * 64}},
                                           extra_capture_leaves=("response-header-fixture.json",))
            target = output / "target"
            target.write_bytes(b"foreign")
            (output / "response-header-fixture.json").symlink_to(target)
            with self.assertRaises(ValueError):
                driver.write_source_result(output, {"raw_sha256": {}},
                                           extra_capture_leaves=("response-header-fixture.json",))
            self.assertFalse((output / "source-result.json").exists())

    def test_optional_request_headers_are_bounded_literal_curl_arguments(self):
        self.assertEqual(driver.request_header_arguments({}), [])
        self.assertEqual(driver.request_header_arguments({"request_headers": {"X-Modsec-Smoke": "log-only"}}),
                         ["--header", "X-Modsec-Smoke: log-only"])
        for headers in ({"Bad\rName": "value"}, {"Good": "value\nInjected: other"},
                        {"Good": "\x00"}, {"Good": "é"}, {"Good": "v" * 257},
                        {"": "value"}, {str(index): "v" for index in range(9)}, []):
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                driver.request_header_arguments({"request_headers": headers})

    def test_actual_client_invocation_receives_header_and_header_capture_arguments(self):
        spec = {"request_headers": {"X-Modsec-Smoke": "log-only"},
                "request_path": "/unit-only", "pause_between_chunks": False}
        server = SimpleNamespace(release=mock.Mock(), finished=mock.Mock(),
                                 observations=mock.Mock(return_value={}))
        args = SimpleNamespace(port=18081)
        seen = []

        def client(command, **kwargs):
            seen.append(command)
            kwargs["stdout"].write(b"200")
            return SimpleNamespace(wait=lambda **unused: 0)

        with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP", "/var/tmp/codex/ModSecurity-conector")) as temp:
            output = Path(temp)
            with mock.patch.object(driver.subprocess, "Popen", side_effect=client):
                observed = driver.actual_request(args, spec, output, {}, server)
            command = seen[0]
            self.assertEqual(command[command.index("--header") + 1], "X-Modsec-Smoke: log-only")
            self.assertEqual(command[command.index("--dump-header") + 1], str(output / "response.headers"))
            self.assertEqual(observed["client_exit_code"], 0)
            self.assertEqual((output / "response.bin").read_bytes(), b"")

    def test_closed_phase4_entry_delegates_without_changing_spec_or_input_identity(self):
        args = SimpleNamespace(framework_root="/trusted-framework", case_id="phase4_body_at_limit")
        spec = {"source_record_id": args.case_id, "operation": "native_phase4_request"}
        inputs = SimpleNamespace(operation=mock.Mock(return_value=spec))
        with mock.patch.object(driver.HOST.BASE, "absolute_path", side_effect=Path), \
                mock.patch.object(driver, "load", return_value=inputs) as loader, \
                mock.patch.object(driver, "run_operation", return_value=True) as runtime:
            self.assertTrue(driver.run(args))
        path = Path("/trusted-framework/tests/runners/nginx_phase4_contracts.py")
        loader.assert_called_once_with("phase4_closed_inputs", path)
        inputs.operation.assert_called_once_with(args.case_id)
        runtime.assert_called_once_with(args, spec, input_path=path)

    def test_shared_operation_requires_explicit_spec_source_and_preserves_native_defaults(self):
        import inspect
        signature = inspect.signature(driver.run_operation)
        self.assertIs(signature.parameters["input_path"].default, inspect.Parameter.empty)
        self.assertIs(signature.parameters["upstream_factory"].default, driver.BoundedPhase4Upstream)
        self.assertIs(signature.parameters["configuration_factory"].default, driver.configuration)
        self.assertIs(signature.parameters["observation_factory"].default, driver.native_observations)
        self.assertEqual(signature.parameters["upstream_path"].default,
                         PATH.parent.parent / "common/nginx_phase4_upstream.py")

    def test_closed_phase4_entry_flushes_headers_only_for_immediate_body_reject(self):
        case_ids = (
            "phase4_marker_split_across_chunks", "phase4_end_of_stream_evaluation",
            "phase4_deny_after_commit_log_only_minimal", "phase4_body_at_limit",
            "phase4_body_over_limit", "phase4_body_process_partial", "phase4_body_reject",
            "full_lifecycle_event_metadata_bounded",
        )
        for case_id in case_ids:
            with self.subTest(case_id=case_id):
                args = SimpleNamespace(framework_root="/trusted-framework", case_id=case_id)
                spec = {"source_record_id": case_id, "operation": "native_phase4_request"}
                inputs = SimpleNamespace(operation=mock.Mock(return_value=spec))
                with mock.patch.object(driver.HOST.BASE, "absolute_path", side_effect=Path), \
                        mock.patch.object(driver, "load", return_value=inputs), \
                        mock.patch.object(driver, "run_operation", return_value=True) as runtime:
                    self.assertTrue(driver.run(args))
                call = runtime.call_args
                self.assertEqual(call.args, (args, spec))
                self.assertEqual(spec, {"source_record_id": case_id, "operation": "native_phase4_request"})
                self.assertEqual(call.kwargs["input_path"],
                                 Path("/trusted-framework/tests/runners/nginx_phase4_contracts.py"))
                factory = call.kwargs.get("configuration_factory", driver.configuration)
                config = factory(Path("/owned"), 18081, 18082, Path("/projection"),
                                 "/exact", "safe", "owned-case-run")
                self.assertEqual(config.count("postpone_output 0;"), int(case_id == "phase4_body_reject"))
                baseline = driver.configuration(Path("/owned"), 18081, 18082, Path("/projection"),
                                                "/exact", "safe", "owned-case-run")
                self.assertEqual(config.replace("postpone_output 0; ", ""), baseline)

    def test_header_flush_configuration_option_is_keyword_only_and_defaults_off(self):
        import inspect
        option = inspect.signature(driver.configuration).parameters["flush_response_headers"]
        self.assertIs(option.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(option.default, False)
        config = driver.configuration(Path("/owned"), 18081, 18082, Path("/projection"),
                                      "/exact", "safe", "owned-case-run", flush_response_headers=True)
        self.assertEqual(config.count("postpone_output 0;"), 1)

    def test_foreign_case_phase_or_connector_cannot_be_native_observation(self):
        actual = {"connector": "nginx", "integration_mode": "native-nginx-http-module",
                  "phase": "response_body", "method": "GET", "uri": "/exact"}
        values = [actual, dict(actual, uri="/other"), dict(actual, phase="request_headers"),
                  dict(actual, connector="apache"), dict(actual, method="POST"),
                  dict(actual, integration_mode="synthetic_harness")]
        raw = b"\n".join(json.dumps(value).encode() for value in values)
        self.assertEqual(driver.native_observations(raw, "/exact"), [actual])
        self.assertNotIn("status", driver.native_observations(raw, "/exact")[0])

    def test_existing_mode_only_and_buffering_not_enabled(self):
        for mode in ("off", "safe"):
            config = driver.configuration(Path("/owned"), 18081, 18082, Path("/projection"), "/exact", mode, "owned-case-run")
            self.assertIn("modsecurity_phase4_mode " + mode + ";", config)
            self.assertIn("proxy_buffering off;", config)
            self.assertIn("user nobody nogroup;", config)
            self.assertIn('modsecurity_transaction_id "owned-case-run-$connection-$connection_requests";', config)
        for mode in ("minimal", "unknown", "safe; off"):
            with self.assertRaises(ValueError):
                driver.configuration(Path("/owned"), 18081, 18082, Path("/projection"), "/exact", mode, "owned-case-run")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
