"""Boundary and verdict controls for stock-native supplementary diagnostics."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import json
import hashlib
from pathlib import Path
import tempfile
import socket
import shutil
import subprocess
import threading
import unittest
from unittest import mock


DIAGNOSTIC = load_source(source_path('ci/runtime/lifecycle/i12/lighttpd/diagnostic_capture.py'))
NATIVE = load_source(source_path('ci/runtime/lifecycle/i12/lighttpd/diagnostic_native.py'))
PACKETS = load_source(source_path('ci/runtime/lifecycle/i12/lighttpd/diagnostic_packets.py'))


class DiagnosticTests(unittest.TestCase):
    def backend_module(self):
        return load_source(source_path("ci/runtime/common/response-header-test-backend.py"))

    def exchange_backend(self, directory, case, method="GET", peer="127.0.0.1"):
        handler = NATIVE.backend_handler(self.backend_module(), directory, case)
        with NATIVE.NumericLoopbackFixtureServer(0, handler) as server:
            self.assertEqual(server.socket.getsockname()[0], "127.0.0.1")
            server.timeout = 3
            worker = threading.Thread(target=server.handle_request)
            worker.start()
            try:
                with socket.socket() as connection:
                    connection.settimeout(3)
                    connection.bind((peer, 0))
                    connection.connect(server.server_address)
                    entity = b"actual-post" if method == "POST" else b""
                    request = (f"{method} /diagnostic/test HTTP/1.1\r\nHost: private-fixture\r\n"
                               f"Content-Length: {len(entity)}\r\nConnection: close\r\n\r\n").encode() + entity
                    connection.sendall(request)
                    received = bytearray()
                    while True:
                        try:
                            chunk = connection.recv(4096)
                        except ConnectionResetError:
                            break
                        if not chunk:
                            break
                        received.extend(chunk)
            finally:
                worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            return bytes(received)

    def assert_backend_response(self, root, case, method, expected_events):
        body = b"diagnostic-native-response"
        transport = root / "backend-transport.jsonl"
        if transport.exists():
            transport.unlink()
        raw = self.exchange_backend(root, case, method)
        header, _, entity = raw.partition(b"\r\n\r\n")
        self.assertTrue(header.startswith(b"HTTP/1.0 200 "))
        self.assertEqual(entity, body)
        declared = len(body) + (9 if case.get("backend_short_length") else 0)
        self.assertIn(f"Content-Length: {declared}".encode(), header)
        events = [json.loads(line) for line in transport.read_text().splitlines()] if transport.exists() else []
        self.assertEqual(len(events), expected_events)
        self.assertEqual(sum(event["actual_body_write_return"] for event in events), len(body) if expected_events else 0)
        self.assertTrue(all(event["actual_flush_returned"] for event in events))

    def test_numeric_backend_real_get_post_delay_and_short_response(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for case, expected_events in (({}, 0), ({"backend_chunk_delay_seconds": 0.01}, 2), ({"backend_short_length": True}, 1)):
                for method in ("GET", "POST"):
                    with self.subTest(case=case, method=method):
                        self.assert_backend_response(root, case, method, expected_events)

    def test_numeric_backend_rejects_remote_identity_and_invalid_bind_port(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(self.exchange_backend(Path(temporary), {}, peer="127.0.0.2"), b"")
        with NATIVE.NumericLoopbackFixtureServer(0, object) as server:
            request = mock.Mock()
            request.getpeername.return_value = ("192.0.2.1", 1234)
            self.assertFalse(server.verify_request(request, ("127.0.0.1", 1234)))
            request.getpeername.return_value = ("127.0.0.1", 1234)
            self.assertFalse(server.verify_request(request, ("192.0.2.1", 1234)))
            request.getpeername.side_effect = OSError(107, "Transport endpoint is not connected")
            self.assertFalse(server.verify_request(request, ("127.0.0.1", 1234)))
        for port in (-1, 65536, "80", True):
            with self.subTest(port=port), self.assertRaisesRegex(ValueError, "integer loopback TCP port"):
                NATIVE.NumericLoopbackFixtureServer(port, object)

    def test_numeric_backend_service_loop_is_bounded_and_signal_stoppable(self):
        server = mock.Mock()
        server.handle_request.side_effect = (None, SystemExit(0))
        with self.assertRaises(SystemExit):
            NATIVE.serve_numeric_loopback(server)
        self.assertEqual(server.timeout, 0.05)
        self.assertEqual(server.handle_request.call_count, 2)

    def test_rule_oracle_uses_exact_main_transaction_event_or_audit_token(self):
        def audit_record(boundary, transaction_id, rule_id, extra=""):
            return (f"---{boundary}---A--\n[date] {transaction_id} 127.0.0.1\n"
                    f"---{boundary}---H--\n{extra}[id \"{rule_id}\"]\n"
                    f"---{boundary}---Z--\n")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = {"rule_id": 1100001, "event_fields": []}
            (root / "audit.log").write_text(
                audit_record("main", "tx-main", 1100001)
                + audit_record("neighbor", "tx-neighbor", 1100202))
            matched = PACKETS._matching_oracle_events(root, [], expected, "tx-main")
            self.assertTrue(matched[2])
            expected["rule_id"] = 1100202
            self.assertFalse(PACKETS._matching_oracle_events(root, [], expected, "tx-main")[2])
            (root / "audit.log").write_text("unrelated-neighbor-metadata=1100001\n")
            expected["rule_id"] = 1100001
            self.assertFalse(PACKETS._matching_oracle_events(root, [], expected, "tx-main")[2])
            event = {"transaction_id": "tx-main", "rule_id": "1100001"}
            self.assertTrue(PACKETS._matching_oracle_events(root, [event], expected, "tx-main")[2])

    def test_parser_first_cause_preserves_first_physical_diagnostic_without_case_inference(self):
        self.assertIsNone(DIAGNOSTIC.parser_first_cause("dlopen failed: missing module\nConfiguration of plugins failed."))
        stderr = ("source.c.242: msconnector runtime config check failed: invalid enabled value\n"
                  "source.c.242: msconnector runtime config check failed: later diagnostic\n")
        self.assertEqual(DIAGNOSTIC.parser_first_cause(stderr), "invalid enabled value")

    def test_case_sources_reject_directory_escape_duplicates_and_parent_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = root / "cases.json"
            for names in (("../escape",), ("same", "same")):
                cases.write_text(json.dumps({"cases": [{"case_id": name} for name in names]}))
                with self.assertRaisesRegex(ValueError, "unique physical-directory-safe"):
                    NATIVE.declared_cases(cases)
            cases.write_text(json.dumps({"cases": [{"case_id": "NEED-precommit-error"}]}))
            self.assertEqual(len(NATIVE.declared_cases(cases)), 1)
            (root / "alias").symlink_to(root, target_is_directory=True)
            alias = root / "alias/cases.json"
            with self.assertRaisesRegex(ValueError, "physical single-link"):
                NATIVE.declared_cases(alias)

    def test_waited_parser_receipt_preserves_exact_exit_and_real_rules_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            host = root / "lighttpd"
            shutil.copyfile("/bin/sh", host)
            host.chmod(0o500)
            directory = root / "parser"
            directory.mkdir()
            argv = ["rtk", "proxy", str(host), "-c", "exit 255"]
            actual = subprocess.run(argv, capture_output=True, timeout=5)
            self.assertEqual(actual.returncode, 255)
            record = {"argv": argv, "cwd": str(Path.cwd()), "exitcode": actual.returncode,
                      "waited_signal": None, "host_config_sha256": hashlib.sha256(b"test config").hexdigest()}
            missing = root / "absent.conf"
            case = ("missing_rules_file", "rules_file", str(missing))
            identity = {"run_id": "independent-receipt-unit", "parent_sha": "fixture-test"}
            DIAGNOSTIC.parser_process_receipt(directory, case, record, actual, host, missing, identity)
            receipt = json.loads((directory / "parser-process.json").read_text())
            absence = json.loads((directory / "rules-absence.json").read_text())
            self.assertEqual(receipt["waited_exit"], 255)
            self.assertIsNone(receipt["rules_sha256"])
            self.assertEqual((absence["measurement"], absence["errno"], absence["exists"]), ("lstat", 2, False))
            self.assertEqual(receipt["rules_path"], str(missing))
            self.assertEqual(receipt["rules_absence_sha256"], hashlib.sha256((directory / "rules-absence.json").read_bytes()).hexdigest())
            record["exitcode"] = 1
            with self.assertRaisesRegex(ValueError, "actually waited"):
                DIAGNOSTIC.parser_process_receipt(directory, case, record, actual, host, missing, identity)

    def test_cli_artifacts_reject_relative_wrong_name_and_symlink_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            physical = root / "lighttpd"
            physical.write_text("fixture")
            self.assertEqual(DIAGNOSTIC.approved_input(physical, "lighttpd"), physical)
            with self.assertRaisesRegex(ValueError, "artifact name"):
                DIAGNOSTIC.approved_input(physical, "mod_msconnector.so")
            (root / "alias").symlink_to(physical)
            with self.assertRaisesRegex(ValueError, "physical absolute"):
                DIAGNOSTIC.approved_input(root / "alias")
            with self.assertRaisesRegex(ValueError, "physical absolute"):
                DIAGNOSTIC.approved_input(Path("lighttpd"))

    def test_real_peer_response_over_bound_is_rejected_and_socket_closes(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            server.settimeout(3)
            def peer():
                with server.accept()[0] as client:
                    client.recv(65536)
                    try:
                        client.sendall(b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 140000)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
            thread = threading.Thread(target=peer)
            thread.start()
            port = server.getsockname()[1]
            try:
                with self.assertRaisesRegex(ValueError, "128 KiB"):
                    DIAGNOSTIC.request(port)
            finally:
                thread.join(timeout=5)
            self.assertFalse(thread.is_alive())

    def test_negative_parser_acceptance_and_signals_cannot_succeed(self):
        receipt = {"configuration_probes": [{"exitcode": code} for code in [0] + [255] * 7],
                   "clients": [{"status": code} for code in [200, 403, 200]]}
        self.assertTrue(DIAGNOSTIC.controls_match(receipt))
        for code in (0, -9):
            receipt["configuration_probes"][3]["exitcode"] = code
            self.assertFalse(DIAGNOSTIC.controls_match(receipt))
        receipt["configuration_probes"][3]["exitcode"] = 255
        receipt["clients"][2]["status"] = 500
        self.assertFalse(DIAGNOSTIC.controls_match(receipt))

    def test_output_parent_alias_existing_and_private_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "alias").symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "physical"):
                DIAGNOSTIC.fresh_output(root / "alias/child")
            actual = DIAGNOSTIC.fresh_output(root / "physical")
            self.assertEqual(actual.stat().st_mode & 0o777, 0o700)
            with self.assertRaisesRegex(ValueError, "Fresh"):
                DIAGNOSTIC.fresh_output(actual)

    def test_numeric_loopback_client_keeps_origin_form_contract(self):
        source = (connector_root()
                  / "ci/runtime/lifecycle/i12/lighttpd/stock_raw_client.py").read_text()
        generated = NATIVE.numeric_loopback_client(source)
        self.assertNotIn("urlsplit", generated)
        self.assertIn("socket.create_connection(('127.0.0.1',port)", generated)
        self.assertEqual(NATIVE.loopback_target(8080, "/diagnostic?case=p1"),
                         ["--i12-port", "8080", "--i12-path", "/diagnostic?case=p1"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
