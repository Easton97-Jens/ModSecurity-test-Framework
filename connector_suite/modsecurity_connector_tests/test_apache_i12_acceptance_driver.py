"""Wire/protocol/configuration negatives for the isolated Apache batch driver."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import base64
from email.message import Message
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = connector_root()
ACCEPTANCE = source_path('ci/runtime/lifecycle/apache-i12/acceptance', root=ROOT)


def load(name):
    module = load_source(ACCEPTANCE / (name + '.py'))
    return module


BATCH = load("batch")
BACKEND = load("backend")


def byte_input(content):
    return {"data": base64.b64encode(content).decode(), "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(), "encoding": "base64"}


class AcceptanceDriverTest(unittest.TestCase):
    def test_prelaunch_error_retains_case_filename_without_execution_qualification(self):
        plan = {"case_id": "apache-case", "original_id": "original-apache-case"}
        base = Path("/task/unique")
        with patch.object(BATCH, "save") as save:
            result = BATCH.prelaunch_error(plan, 7, base, ValueError("fixture unavailable"))
        save.assert_called_once_with(base / "007-apache-case-prelaunch-error.json", result)
        self.assertEqual(result["case_id"], "apache-case")
        self.assertEqual(result["original_id"], "original-apache-case")
        self.assertFalse(result["actual_principal_execution"])
        self.assertFalse(result["executed_case_contract"])
        self.assertIsNone(result["outcome"])
        self.assertIsNone(result["full_lifecycle_qualification"])
        self.assertEqual(result["execution_error"],
                         {"type": "ValueError", "message": "fixture unavailable"})

    def private_workspace(self):
        temporary_root = Path(os.environ.get("CODEX_TEST_TMP_ROOT") or os.environ.get("RUNNER_TEMP")
                              or "/var/tmp/codex/ModSecurity-conector/acceptance-driver-tests")
        temporary_root.mkdir(parents=True, exist_ok=True)
        directory = tempfile.TemporaryDirectory(dir=temporary_root)
        self.addCleanup(directory.cleanup)
        return Path(directory.name)

    def host_artifacts(self, root):
        artifacts = {}
        for name in BATCH.LINK_ARTIFACTS:
            artifact = root / name
            artifact.write_bytes(("unit fixture identity only: " + name).encode())
            artifacts[name] = artifact
        return artifacts

    def request(self, **overrides):
        result = {"method": "POST", "path": "/principal", "headers": [["X-I12-ID", "test-main"]],
                  "body": byte_input(b"actual bytes"), "framing": "content_length", "chunks": []}
        result.update(overrides)
        return result

    def test_ordered_duplicate_and_empty_wire_headers_remain_distinct(self):
        request = self.request(headers=[["X-I12-ID", "test-main"], ["X-Duplicate", "one"],
                                       ["x-duplicate", "two"], ["X-Empty", ""]])
        head, chunks = BATCH.wire_request(request, 18123)
        self.assertIn(b"X-Duplicate: one\r\nx-duplicate: two\r\nX-Empty: \r\n", head)
        self.assertIn(b"Content-Length: 12\r\n", head)
        self.assertEqual(b"".join(chunks), b"actual bytes")

    def test_wire_request_rejects_nonprivate_port(self):
        request = self.request()
        with self.assertRaisesRegex(ValueError, "private loopback port"):
            BATCH.wire_request(request, 443)

    def test_raw_invalid_framing_is_not_normalized(self):
        request = self.request(framing="raw_no_normalization", headers=[["Content-Length", "1"], ["Content-Length", "2"]])
        head, _ = BATCH.wire_request(request, 18123)
        self.assertEqual(head.count(b"Content-Length:"), 2)
        self.assertNotIn(b"Content-Length: 12", head)

    def test_chunked_wire_has_actual_separate_marker_chunks(self):
        request = self.request(body=byte_input(b"abcXYZ"), chunks=[byte_input(b"abc"), byte_input(b"XYZ")], framing="chunked")
        head, chunks = BATCH.wire_request(request, 18123)
        self.assertIn(b"Transfer-Encoding: chunked", head)
        self.assertNotIn(b"Content-Length:", head)
        self.assertEqual(chunks, [b"3\r\nabc\r\n", b"3\r\nXYZ\r\n", b"0\r\n\r\n"])

    def test_request_injection_and_payload_hash_tamper_rejected(self):
        for request in (self.request(path="/bad\r\nInjected: yes"), self.request(headers=[["X-Header", "bad\nvalue"]])):
            with self.assertRaises(ValueError):
                BATCH.wire_request(request, 18123)
        item = byte_input(b"actual bytes")
        item["sha256"] = "0" * 64
        request = self.request(body=item)
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            BATCH.wire_request(request, 18123)

    def test_response_content_length_and_real_chunked_decode(self):
        fields, body, header = BATCH.response_framing(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
        self.assertEqual((fields["status"], body), (200, b"abc"))
        self.assertTrue(header.endswith(b"\r\n\r\n"))
        fields, body, _ = BATCH.response_framing(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
        self.assertEqual(body, b"abc")
        self.assertEqual(fields["framing"]["kind"], "chunked")

    def test_truncated_ambiguous_and_suffix_responses_rejected(self):
        wires = [b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc",
                 b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc",
                 b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabc",
                 b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nsuffix"]
        for wire in wires:
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                BATCH.response_framing(wire)

    def test_causal_barrier_requires_entity_byte_not_chunk_size_line(self):
        prefix = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        self.assertFalse(BATCH.entity_prefix_received(prefix))
        self.assertFalse(BATCH.entity_prefix_received(prefix + b"3\r\n"))
        self.assertTrue(BATCH.entity_prefix_received(prefix + b"3\r\na"))
        self.assertFalse(BATCH.entity_prefix_received(prefix + b"0\r\n\r\n"))
        self.assertTrue(BATCH.entity_prefix_received(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na"))

    def test_backend_principal_marker_does_not_leak_to_control(self):
        plan = {"request": {"path": "/principal"},
                "backend": {"status": 200, "headers": [["X-Modsec-Upstream", "block"]]},
                "controls": [{"path": "/neighbor", "expected_status": 200,
                              "backend_headers": [["Content-Type", "text/plain"]], "backend_body": byte_input(b"OK")} ]}
        self.assertIn(["X-Modsec-Upstream", "block"], BACKEND.response_for(plan, "/principal")["headers"])
        self.assertNotIn(["X-Modsec-Upstream", "block"], BACKEND.response_for(plan, "/neighbor")["headers"])
        self.assertIsNone(BACKEND.response_for(plan, "/unselected"))
        before = BACKEND.response_for(plan, "/i12-observer-control-before")
        self.assertEqual(before["status"], 200)
        self.assertNotIn(["X-Modsec-Upstream", "block"], before["headers"])

    def test_precontrol_has_own_benign_log_rule_and_never_mutates_principal(self):
        request = self.request()
        plan = {"request": request, "baseline_rules_required": True,
                "unique_main_request": {"token": "test-main"}}
        actual = BATCH.client_request(plan, {}, "precontrol", {"configured": True})
        self.assertEqual(actual["path"], "/i12-observer-control-before")
        self.assertEqual(actual["body"]["bytes"], 0)
        self.assertIn(["X-I12-ID", "test-main-precontrol"], actual["headers"])
        self.assertIn(["Host", "control.localhost"], actual["headers"])
        self.assertIn(["X-Modsec-Smoke", "log-only"], actual["headers"])
        self.assertEqual(plan["request"], request)
        self.assertNotIn(["X-Modsec-Smoke", "log-only"], request["headers"])

    def test_backend_reads_actual_chunked_and_rejects_short_cl(self):
        headers = Message()
        headers["Transfer-Encoding"] = "chunked"
        self.assertEqual(BACKEND.read_body(io.BytesIO(b"3\r\nabc\r\n0\r\n\r\n"), headers), b"abc")
        headers = Message()
        headers["Content-Length"] = "4"
        stream = io.BytesIO(b"abc")
        with self.assertRaisesRegex(ValueError, "truncated"):
            BACKEND.read_body(stream, headers)

    def test_fault_seam_never_becomes_normal_contract_execution(self):
        plan = {"driver_seams": ["causal_response_barrier", "physical_sink_close"],
                "fault": {"operation": "real_close_failure"}}
        missing = BATCH.missing_operations(plan)
        self.assertNotIn("causal_response_barrier", missing)
        self.assertIn("physical_sink_close", missing)
        self.assertIn("fault_operation_not_activated:real_close_failure", missing)

    def test_config_preserves_apache_reject_partial_and_private_sink(self):
        plan = {"execution_kind": "host_http", "apache": {"phase4_mode": "strict", "config_directives": []}}
        text = BATCH.config_text(plan, Path("/task/unique"), Path("/mnt/artifacts/mod_security3.so"), 18123, 18124)
        self.assertIn('modsecurity_rules_file "/task/unique/rules.conf"', text)
        self.assertIn("modsecurity_phase4_mode strict", text)
        self.assertIn('modsecurity_phase4_log "/task/unique/events.jsonl"', text)
        rules = BATCH.native_rules(dict(plan, rules="SecResponseBodyLimit 16\nSecResponseBodyLimitAction Reject\n", baseline_rules_required=False), Path("/task/unique"))
        self.assertIn("SecResponseBodyLimitAction Reject", rules)
        self.assertIn("SecAuditEngine On", rules)
        self.assertNotIn("ProcessPartial", rules)

    def test_explicit_control_vhost_host_header_has_no_duplicate(self):
        head, _ = BATCH.wire_request(self.request(headers=[["X-I12-ID", "control"],
                                                           ["Host", "control.localhost"]]), 18123)
        self.assertEqual(head.lower().count(b"host:"), 1)
        self.assertIn(b"Host: control.localhost\r\n", head)
        self.assertNotIn(b"Host: 127.0.0.1", head)

    def test_generated_id_config_omits_both_native_id_directives(self):
        plan = {"execution_kind": "host_http", "apache": {"transaction_id_expression": None}}
        text = BATCH.config_text(plan, Path("/task/case"), Path("/mnt/module.so"), 18123, 18124)
        self.assertNotIn("modsecurity_transaction_id", text)
        head, _ = BATCH.wire_request(self.request(), 18123)
        self.assertIn(b"X-I12-ID: test-main\r\n", head)
        plan["apache"]["transaction_id_expression"] = "%{req:X-I12-ID}"
        self.assertIn('modsecurity_transaction_id_expr "%{req:X-I12-ID}"',
                      BATCH.config_text(plan, Path("/task/case"), Path("/mnt/module.so"), 18123, 18124))

    def test_response_file_materializes_real_static_source_without_bucket_claim(self):
        temporary_root = Path(os.environ.get("CODEX_TEST_TMP_ROOT") or os.environ.get("RUNNER_TEMP")
                              or "/var/tmp/codex/ModSecurity-conector/acceptance-driver-tests")
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temporary_root) as temporary:
            root = Path(temporary)
            plan = {"execution_kind": "host_http", "request": {"path": "/i12/NEED-response-file"},
                    "backend": {"file": {"serving": "apache_static_file", "content": byte_input(b"real file bytes")}}}
            result = BATCH.materialize_response_file(plan, root)
            self.assertEqual(Path(result["path"]).read_bytes(), b"real file bytes")
            self.assertEqual(Path(result["path"]).stat().st_mode & 0o777, 0o600)
            self.assertIsNone(result["actual_APR_FILE_bucket_observed"])
            text = BATCH.config_text(plan, root, Path("/mnt/module.so"), 18123, 18124)
            self.assertLess(text.index('ProxyPass "/i12/NEED-response-file" "!"'), text.index('ProxyPass "/"'))
            self.assertIn("ForceType text/plain", text)
            self.assertIn('DocumentRoot "' + str(root / "static") + '"', text)
            for path in ("/../outside", "/i12/file?query", '/i12/"bad', "/i12/%2e%2e/outside"):
                plan["request"]["path"] = path
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unsafe static"):
                    BATCH.materialize_response_file(plan, root)

    def test_gate_failure_receipts_cannot_become_normal_success(self):
        temporary_root = Path(os.environ.get("CODEX_TEST_TMP_ROOT") or os.environ.get("RUNNER_TEMP")
                              or "/var/tmp/codex/ModSecurity-conector/acceptance-driver-tests")
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temporary_root) as temporary:
            root = Path(temporary)
            observation = {"clients": [{}], "missing_operations": [], "actual_principal_execution": False}
            (root / "termination.json").write_text(json.dumps({
                "actual_termination": {"actual_signal": 15}, "requested_action_performed": False,
                "wrapper_exit": 1}))
            (root / "send-ready.json").write_text(json.dumps({"progress": {"request_send_completed_ns": 100}}))
            # A valid send and cleanup SIGTERM cannot satisfy a failed native gate.
            BATCH.read_client_observation(root, "main", False, self.request(), observation)
            self.assertTrue(observation["actual_principal_execution"])
            self.assertIn("actual_native_gated_client_cancellation_unproven", observation["missing_operations"])
            self.assertTrue(observation["clients"][-1]["wrapper_exit_is_not_wire_client_exit"])
            (root / "termination.json").unlink()
            (root / "receipt.json").write_text(json.dumps({"request_send_completed_ns": 100, "error": {"type": "GateError"}}))
            observation["missing_operations"] = []
            request = self.request(peer_action="SO_LINGER_zero_RST_after_first_native_append")
            BATCH.read_client_observation(root, "main", False, request, observation)
            self.assertIn("actual_native_gated_client_reset_unproven", observation["missing_operations"])

    def test_sink_virtual_hosts_keep_control_physical_sink_healthy(self):
        plan = {"execution_kind": "host_http", "request": {"path": "/sink-disruptive"},
                "apache": {"phase4_mode": "safe", "config_directives": []}}
        text = BATCH.config_text(plan, Path("/task/case"), Path("/mnt/artifacts/module.so"),
                                 18123, 18124, Path("/task/case/missing/events.jsonl"))
        self.assertEqual(text.count("<VirtualHost 127.0.0.1:18123>"), 2)
        self.assertIn('ServerName control.localhost\nmodsecurity_phase4_log "/task/case/events.jsonl"', text)
        self.assertIn('ServerName 127.0.0.1\nmodsecurity_phase4_log "/task/case/missing/events.jsonl"', text)

    def test_five_sink_modes_configure_real_paths_guarded_env_without_rule_changes(self):
        temporary_root = Path(os.environ.get("CODEX_TEST_TMP_ROOT") or os.environ.get("RUNNER_TEMP")
                              or "/var/tmp/codex/ModSecurity-conector/acceptance-driver-tests")
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temporary_root) as temporary:
            root = Path(temporary)
            helper = root / "test-helper.so"
            helper.write_bytes(b"fixture binary identity; not loaded by this unit test")
            for mode in BATCH.SINK_MODES:
                case_root = root / mode
                case_root.mkdir(mode=0o700)
                plan = {"rules": "120001 then120016 retained", "fault": {"kind": mode, "boundary": "physical_event_sink"}}
                previous = json.dumps(plan, sort_keys=True)
                result = BATCH.prepare_sink(plan, case_root, helper)
                self.assertTrue(result["configured"])
                self.assertIsNone(result["actual_fault_observed"])
                self.assertIsNone(result["apr_calls"])
                self.assertTrue(result["native_rule_order_unchanged"])
                self.assertEqual(json.dumps(plan, sort_keys=True), previous)
                self.assertEqual(result["environment"]["I12_SINK_FAULT"],
                                 mode if mode in ("closed-descriptor", "physical-enospc") else "observe")
                self.assertEqual(Path(result["environment"]["I12_SINK_MARKER"]).read_text(), "I12_APACHE_SINK_FAULT_V1\n")
                if mode == "devfull":
                    self.assertEqual(result["principal_sink"], "/dev/full")
                elif mode == "badpath":
                    self.assertFalse(Path(result["principal_sink"]).parent.exists())
                elif mode == "unwritable":
                    self.assertEqual(Path(result["principal_sink"]).parent.stat().st_mode & 0o777, 0o500)
                    # Restore only this task-owned test directory for cleanup.
                    Path(result["principal_sink"]).parent.chmod(0o700)
                else:
                    self.assertEqual(Path(result["principal_sink"]).stat().st_mode & 0o777, 0o600)

    def test_physical_sink_collection_requires_exact_apr_failure(self):
        with tempfile.TemporaryDirectory(dir=self.private_workspace()) as temporary:
            root = Path(temporary)
            observation = {"executed_case_contract": True, "missing_operations": [],
                           "fault_not_activated": None}
            sink = {"configured": True, "requested_mode": "closed-descriptor"}
            row = {"stage": "apr_file_write_full", "action": "closed-descriptor",
                   "result": 9, "operation_result": 0}
            (root / "error.log").write_text("host I12_APACHE_APR " + json.dumps(row) + "\n")
            BATCH.collect_sink_observation(root, sink, observation)
            self.assertTrue(sink["actual_fault_observed"])
            self.assertFalse(observation["fault_not_activated"])
            self.assertTrue(observation["executed_case_contract"])

            row["operation_result"] = -1
            (root / "error.log").write_text("host I12_APACHE_APR " + json.dumps(row) + "\n")
            observation.update(executed_case_contract=True, fault_not_activated=None)
            BATCH.collect_sink_observation(root, sink, observation)
            self.assertFalse(sink["actual_fault_observed"])
            self.assertTrue(observation["fault_not_activated"])
            self.assertFalse(observation["executed_case_contract"])

    def test_enospc_and_pre_apr_sink_collection_remain_distinct(self):
        with tempfile.TemporaryDirectory(dir=self.private_workspace()) as temporary:
            root = Path(temporary)
            row = {"stage": "apr_file_write_full", "action": "physical-enospc",
                   "result": 28, "operation_result": 1}
            (root / "error.log").write_text("I12_APACHE_APR " + json.dumps(row) + "\n")
            observation = {"executed_case_contract": True, "missing_operations": [],
                           "fault_not_activated": None}
            sink = {"configured": True, "requested_mode": "physical-enospc"}
            BATCH.collect_sink_observation(root, sink, observation)
            self.assertTrue(sink["actual_fault_observed"])
            self.assertTrue(observation["executed_case_contract"])

            observation = {"executed_case_contract": True, "missing_operations": [],
                           "fault_not_activated": None}
            sink = {"configured": True, "requested_mode": "devfull"}
            BATCH.collect_sink_observation(root, sink, observation)
            self.assertFalse(observation["executed_case_contract"])
            self.assertIn("independent_Common_POSIX_first_cause_and_native120016_join",
                          observation["missing_operations"])

    def test_host_io_optin_is_private_and_only_modifies_apache_environment(self):
        temporary_root = Path(os.environ.get("CODEX_TEST_TMP_ROOT") or os.environ.get("RUNNER_TEMP")
                              or "/var/tmp/codex/ModSecurity-conector/acceptance-driver-tests")
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temporary_root) as temporary:
            root = Path(temporary)
            helper = root / "host-io.so"
            environment = {"LD_PRELOAD": "/mnt/artifacts/apr-sink-fault.so"}
            inherited = dict(os.environ)
            missing = BATCH.configure_io_environment(root, environment, helper)
            self.assertFalse(missing["configured"])
            self.assertNotIn("I12_APACHE_IO_ROOT", environment)
            helper.write_bytes(b"fixture helper identity only")
            observation = BATCH.configure_io_environment(root, environment, helper)
            self.assertTrue(observation["configured"])
            self.assertEqual(environment["I12_APACHE_IO_ROOT"], str(root))
            self.assertEqual(environment["LD_PRELOAD"], "/mnt/artifacts/apr-sink-fault.so:" + str(helper))
            self.assertEqual((root / "host-io.enable").read_text(), "I12_APACHE_HOST_IO_V1\n")
            self.assertEqual((root / "host-io.enable").stat().st_mode & 0o777, 0o600)
            self.assertEqual(dict(os.environ), inherited)

    def test_batch_requires_explicit_link_artifacts_but_client_mode_does_not(self):
        arguments = ["batch.py", "--plan", "/mnt/fixtures/plan.json", "--module", "/mnt/artifacts/module.so",
                     "--helper-dir", "/mnt/fixtures", "--output", "/task/output"]
        with patch.object(BATCH.sys, "argv", arguments), patch("sys.stderr", new_callable=io.StringIO) as error:
            with self.assertRaises(SystemExit) as raised:
                BATCH.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--host-bucket-object --multipart-object --fault-boundary-object --fault-boundary-header", error.getvalue())
        root = self.private_workspace()
        specification = root / "request.json"
        specification.write_text(json.dumps(self.request()))
        arguments = ["batch.py", "--client-spec", str(specification), "--output", str(root),
                     "--port", "18123", "--backend-root", str(root)]
        with patch.object(BATCH.sys, "argv", arguments), patch.object(BATCH, "client_main", return_value=37) as client:
            self.assertEqual(BATCH.main(), 37)
        client.assert_called_once()

    def test_batch_port_converter_accepts_cli_text_and_rejects_ambiguous_values(self):
        self.assertEqual(BATCH.private_loopback_port("18123"), 18123)
        self.assertEqual(BATCH.private_loopback_port(18123), 18123)
        for value in (443, "443", True, "18123 ", "١٨١٢٣", object()):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "private loopback port"):
                BATCH.private_loopback_port(value)

    def test_bucket_and_multipart_private_admission_do_not_claim_runtime_wiring(self):
        root = self.private_workspace()
        (root / "uploads").mkdir(mode=0o700)
        artifacts = self.host_artifacts(root)
        plan = {"case_id": "NEED-request-file", "execution_kind": "host_http", "rules": "",
                "baseline_rules_required": False, "apache": {}, "request": self.request()}
        environment = BATCH.case_environment(plan, root)
        inherited = dict(os.environ)
        original_plan = json.dumps(plan, sort_keys=True)
        result = BATCH.configure_host_helpers(plan, root, environment, artifacts)
        self.assertTrue(result["host_bucket"]["configured"])
        self.assertTrue(result["multipart"]["configured"])
        self.assertEqual(environment["I12_APACHE_BUCKET_CASE"], plan["case_id"])
        self.assertEqual(environment["I12_APACHE_BUCKET_RUN"], environment["MSCONNECTOR_LIFECYCLE_RUN"])
        self.assertEqual(environment["I12_APACHE_MULTIPART_ROOT"], str(root / "uploads"))
        self.assertEqual((root / "host-bucket.enable").read_bytes(), b"I12_APACHE_HOST_BUCKET_V1\n")
        self.assertEqual((root / "uploads/multipart.enable").read_bytes(), b"I12_APACHE_MULTIPART_V1\n")
        for marker in (root / "host-bucket.enable", root / "uploads/multipart.enable"):
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        self.assertIsNone(result["actual_link_wiring_observed"])
        self.assertIsNone(result["multipart"]["actual_collection_observed"])
        self.assertIsNone(result["multipart"]["actual_cleanup_observed"])
        self.assertNotIn("LD_PRELOAD", {key: value for key, value in environment.items() if key not in os.environ})
        self.assertEqual(json.dumps(plan, sort_keys=True), original_plan)
        self.assertEqual(dict(os.environ), inherited, "process environment changed")
        rules = BATCH.native_rules(plan, root)
        self.assertIn("SecTmpSaveUploadedFiles On", rules)
        self.assertIn("SecUploadKeepFiles Off", rules)
        self.assertIn('SecUploadDir "' + str(root / "uploads") + '"', rules)
        ordinary = dict(plan, case_id="NEED-request-body")
        self.assertNotIn("SecTmpSaveUploadedFiles", BATCH.native_rules(ordinary, root))
        other = root / "other"
        other.mkdir(mode=0o700)
        other_env = BATCH.case_environment(ordinary, other)
        other_result = BATCH.configure_host_helpers(ordinary, other, other_env, artifacts)
        self.assertFalse(other_result["multipart"]["configured"])
        self.assertNotIn("I12_APACHE_MULTIPART_ROOT", other_env)

    def test_fault_markers_keep_actual_activation_unknown_and_missing_operations(self):
        root = self.private_workspace()
        artifacts = self.host_artifacts(root)
        for case, mode in BATCH.FAULT_MODES.items():
            case_root = root / case
            case_root.mkdir(mode=0o700)
            plan = {"case_id": case, "execution_kind": "host_http", "request": self.request(),
                    "unique_main_request": {"token": "test-main"},
                    "driver_seams": ["real_callback_and_failure_observation"],
                    "fault": {"operation": "original_operation_retained"}}
            before = BATCH.missing_operations(plan)
            environment = BATCH.case_environment(plan, case_root)
            result = BATCH.configure_host_helpers(plan, case_root, environment, artifacts)
            boundary = result["fault_boundary"]
            self.assertTrue(boundary["configured"])
            self.assertEqual(environment["I12_APACHE_FAULT_MODE"], mode)
            self.assertEqual(environment["I12_APACHE_FAULT_ID"], "test-main")
            self.assertEqual((case_root / "fault-boundary.enable").read_bytes(), b"I12_APACHE_FAULT_BOUNDARY_V1\n")
            self.assertIsNone(boundary["actual_activation_observed"])
            self.assertIsNone(boundary["actual_sdk_result"])
            self.assertIsNone(boundary["actual_host_result"])
            self.assertFalse(boundary["elapsed_budget_enforcement_claimed"])
            self.assertEqual(BATCH.missing_operations(plan), before)

    def test_unimplemented_fault_or_missing_artifacts_cannot_configure_callback(self):
        root = self.private_workspace()
        artifacts = self.host_artifacts(root)
        for case, selected in (("transaction_begin_failure_cleanup", artifacts),
                               ("NEED-invalid-native-return", {})):
            plan = {"case_id": case, "execution_kind": "host_http", "fault": {"operation": "required"}}
            environment = BATCH.case_environment(plan, root)
            result = BATCH.configure_host_helpers(plan, root, environment, selected)
            self.assertFalse(result["fault_boundary"]["configured"])
            self.assertIsNone(result["fault_boundary"]["actual_activation_observed"])
            self.assertNotIn("I12_APACHE_FAULT_MODE", environment)

    def test_fault_admission_rejects_duplicate_or_mismatched_principal(self):
        root = self.private_workspace()
        artifacts = self.host_artifacts(root)
        for headers in ([["X-I12-ID", "test-main"], ["x-i12-id", "test-main"]], [["X-I12-ID", "other"]]):
            case_root = root / str(len(list(root.iterdir())))
            case_root.mkdir(mode=0o700)
            plan = {"case_id": "NEED-invalid-native-return", "execution_kind": "host_http",
                    "request": self.request(headers=headers), "unique_main_request": {"token": "test-main"}}
            environment = BATCH.case_environment(plan, case_root)
            with self.assertRaisesRegex(ValueError, "exactly one bounded principal"):
                BATCH.configure_host_helpers(plan, case_root, environment, artifacts)

    def test_selected_missing_rules_path_has_real_enoent_receipt_and_null_hash(self):
        root = self.private_workspace()
        plan = {"case_id": "missing_rules_file", "execution_kind": "configtest",
                "config": {"directives": ["modsecurity_rules_file @@CASE_ROOT@@/absent.rules"], "setup": []}}
        (root / "rules.conf").write_text("unselected valid fixture\n")
        receipt = BATCH.selected_rules_observation(plan, root)
        self.assertEqual(receipt["path"], str(root / "absent.rules"))
        self.assertEqual((receipt["result"], receipt["errno"], receipt["exists"]), (-1, 2, False))
        self.assertIsNone(receipt["sha256"])
        self.assertEqual(json.loads((root / "selected-rules-path.json").read_text()), receipt)
        text = BATCH.config_text(plan, root, Path("/mnt/artifacts/module.so"), 18123, 18124)
        self.assertEqual(text.count("modsecurity_rules_file"), 1)
        self.assertIn('modsecurity_rules_file "' + str(root / "absent.rules") + '"', text)
        self.assertNotIn('modsecurity_rules_file "' + str(root / "rules.conf") + '"', text)
        (root / "absent.rules").touch()
        (root / "selected-rules-path.json").unlink()
        with self.assertRaisesRegex(ValueError, "genuinely be absent"):
            BATCH.selected_rules_observation(plan, root)

    def test_helper_artifact_symlink_and_hardlink_are_rejected(self):
        root = self.private_workspace()
        target = root / "artifact"
        target.write_bytes(b"fixture")
        symlink = root / "alias"
        symlink.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "nonsymlink"):
            BATCH.artifact_identity(symlink)
        hardlink = root / "hardlink"
        os.link(target, hardlink)
        with self.assertRaisesRegex(ValueError, "one-link"):
            BATCH.artifact_identity(hardlink)

    def test_digest_and_cli_mount_paths_reject_escape_and_aliases(self):
        root = self.private_workspace()
        artifact_root = root / "artifacts"
        artifact_root.mkdir(mode=0o700)
        physical = artifact_root / "module.so"
        physical.write_bytes(b"admitted fixture")
        with patch.dict(os.environ, CODEX_TEMP_ROOT=str(root)):
            self.assertEqual(BATCH.admitted_mount_path(physical, artifact_root), physical)
            self.assertEqual(BATCH.digest(physical), hashlib.sha256(b"admitted fixture").hexdigest())
            alias = artifact_root / "alias.so"
            alias.symlink_to(physical)
            ancestor = root / "artifact-alias"
            ancestor.symlink_to(artifact_root, target_is_directory=True)
            nested = artifact_root / "nested"
            nested.mkdir(mode=0o700)
            traversal = nested / ".." / physical.name
            sibling = root.parent / (root.name + "-prefix-sibling")
            sibling.write_bytes(b"outside configured root")
            self.addCleanup(sibling.unlink)
            for supplied in (alias, ancestor / physical.name, traversal, sibling, Path("relative")):
                with self.subTest(path=supplied), self.assertRaises(ValueError):
                    BATCH.digest(supplied)
            for supplied in (alias, ancestor / physical.name, traversal, sibling, Path("relative")):
                with self.subTest(cli_path=supplied), self.assertRaises(ValueError):
                    BATCH.admitted_mount_path(supplied, artifact_root)

    def test_private_admission_requires_each_runtime_preload_binding(self):
        root = self.private_workspace()
        helper_dir = root / "helpers"
        helper_dir.mkdir(mode=0o700)
        module = root / "module.so"
        sink_helper = root / "sink-helper.so"
        io_helper = root / "io-helper.so"
        admission_file = root / "admission.json"
        admission_file.write_text(json.dumps({"outside_namespaces": {}}))
        required = (module, Path("/usr/sbin/apache2"),
                    Path("/usr/lib/x86_64-linux-gnu/libmodsecurity.so.3.0.14"),
                    sink_helper, io_helper)
        for omitted in (sink_helper, io_helper):
            binding = {"input_sha256": {str(path): "0" * 64 for path in required if path != omitted}}
            (helper_dir / "batch-binding.json").write_text(json.dumps(binding))
            direct = Mock()
            with self.subTest(omitted=omitted), patch.object(
                    BATCH, "Path", side_effect=lambda value: admission_file
                    if value == "/opt/controller/admission.json" else Path(value)):
                with self.assertRaisesRegex(ValueError, "binding omits"):
                    BATCH.private_admission(
                        direct, module, helper_dir,
                        runtime_helpers={"sink_helper": sink_helper, "io_helper": io_helper})
            direct.admission.assert_not_called()

    def test_inherited_fault_environment_is_not_carried_into_another_case(self):
        root = self.private_workspace()
        inherited = {"I12_APACHE_FAULT_MODE": "technical-precommit", "I12_APACHE_FAULT_ID": "other-principal",
                     "I12_APACHE_FAULT_ROOT": "/other/private", "I12_APACHE_BUCKET_CASE": "other-case",
                     "I12_APACHE_MULTIPART_ROOT": "/other/upload"}
        with patch.dict(os.environ, inherited):
            environment = BATCH.case_environment({"case_id": "current"}, root)
            self.assertTrue(all(os.environ[name] == value for name, value in inherited.items()))
        self.assertTrue(all(name not in environment for name in inherited))
        self.assertEqual(environment["MSCONNECTOR_LIFECYCLE_CASE"], "current")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
