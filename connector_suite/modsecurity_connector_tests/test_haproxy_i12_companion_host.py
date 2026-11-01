"""Safety and evidence boundaries for the HAProxy-only companion runner."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import sys
from pathlib import Path
import tempfile
import json
import ssl
import os
import socket
import subprocess
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import unittest

SOURCE = connector_root() / "connectors/haproxy/harness/i12_companion_host.py"

runner = load_source(SOURCE)


def prepare_component_certificate(root):
    configuration = root / "openssl.cnf"
    configuration.write_text("[req]\ndistinguished_name=dn\nprompt=no\nx509_extensions=ext\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\n")
    argv = ["rtk", "proxy", "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(root / runner.TLS_KEY), "-out", str(root / runner.TLS_CERT),
            "-days", "1", "-config", str(configuration)]
    result = subprocess.run(argv, capture_output=True, timeout=20)
    if result.returncode:
        raise AssertionError(result.stderr.decode())
    return argv


def serve_component_tls(listener, root, errors):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / runner.TLS_CERT, root / runner.TLS_KEY)
        with listener:
            peer, _address = listener.accept()
            peer.settimeout(5)
            with context.wrap_socket(peer, server_side=True) as stream:
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    chunk = stream.recv(4096)
                    if not chunk:
                        raise EOFError("component peer closed before request headers")
                    request.extend(chunk)
                head, body = request.split(b"\r\n\r\n", 1)
                length = int(next(line.split(b":", 1)[1] for line in head.split(b"\r\n")[1:] if line.lower().startswith(b"content-length:")))
                while len(body) < length:
                    chunk = stream.recv(4096)
                    if not chunk:
                        raise EOFError("component peer closed before request body")
                    body += chunk
                stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                with stream.unwrap() as raw:
                    raw.shutdown(socket.SHUT_WR)
                    raw.recv(1)
    except Exception as exc:
        errors.append(repr(exc))


class CompanionCaptureTests(unittest.TestCase):
    def setUp(self):
        from modsecurity_connector_ci.lib.active_test_inventory import validate_output_root

        storage = validate_output_root(SOURCE.parents[3], Path(
            os.environ.get("I12_TEST_ROOT") or os.environ["RUNNER_TEMP"]))
        self.temporary = tempfile.TemporaryDirectory(prefix="companion-", dir=storage)
        self.addCleanup(self.temporary.cleanup)
        selected_root = patch.object(runner, "ROOT", Path(self.temporary.name))
        selected_root.start()
        self.addCleanup(selected_root.stop)

    def test_source_oracle_rejects_mixed_parallel_responses(self):
        fixture = runner.cases.fixture_profile(runner.cases.PREFIX + "HIST-SPOP-HTX-CORRELATION-CLEANUP")
        expected = runner.cases.source_expectation(fixture)
        for wire in (b"HTTP/1.1 502 Bad Gateway\r\n\r\n", b"HTTP/1.1 503 Unavailable\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 33\r\n\r\n"):
            observed = runner.cases.response_measurements(wire)
            self.assertFalse(all(runner.cases.compare_response(expected, observed).values()))
        healthy = b"HTTP/1.1 200 OK\r\nContent-Length: 33\r\n\r\n" + runner.cases.BODY
        self.assertTrue(all(runner.cases.compare_response(expected, runner.cases.response_measurements(healthy)).values()))

    def test_strict_forbids_complete_large_body_and_preserves_safe_oracle(self):
        fixture = dict(runner.cases.fixture_profile(runner.cases.PREFIX + "NEED-response-file"), mode="strict")
        expected = runner.cases.source_expectation(fixture)
        complete = f"HTTP/1.1 200 OK\r\nContent-Length: {len(runner.cases.body_for(fixture))}\r\n\r\n".encode() + runner.cases.body_for(fixture)
        self.assertFalse(runner.cases.compare_response(expected, runner.cases.response_measurements(complete))["complete_body_absent"])
        fixture["mode"] = "safe"
        self.assertTrue(all(runner.cases.compare_response(runner.cases.source_expectation(fixture), runner.cases.response_measurements(complete)).values()))

    def test_mrc_negative_controls_preserve_input_and_mutate_actual_forwarding(self):
        original = runner.cases.mrc_frame(8, bytes((1, 0, 1, 147)))
        missing = runner.cases.mutate_outcome(original, "missing")
        self.assertEqual(missing, runner.cases.mrc_frame(7))
        self.assertEqual(runner.cases.mutate_outcome(original, "wrong")[-2:], bytes((0, 200)))
        self.assertEqual(runner.cases.mutate_outcome(runner.cases.mrc_frame(8, bytes((1, 0, 1, 195))), "stale")[-2:], bytes((1, 147)))
        self.assertEqual(original[-2:], bytes((1, 147)))
        self.assertEqual(runner.cases.mutate_outcome(runner.cases.mrc_frame(4), "wrong"), runner.cases.mrc_frame(4))

    def test_fragmented_mrc_frame_and_oversized_or_invalid_headers(self):
        frame = runner.cases.mrc_frame(8, bytes((1, 0, 1, 147)))
        pending = bytearray(frame[:13])
        self.assertEqual(runner.cases.complete_mrc_frames(pending), [])
        pending.extend(frame[13:] + runner.cases.mrc_frame(7))
        self.assertEqual(runner.cases.complete_mrc_frames(pending), [frame, runner.cases.mrc_frame(7)])
        self.assertEqual(pending, bytearray())
        with self.assertRaisesRegex(ValueError, "unexpected MRC1"):
            runner.cases.complete_mrc_frames(bytearray(b"BAD!" + frame[4:]))
        with self.assertRaisesRegex(ValueError, "unbounded"):
            runner.cases.complete_mrc_frames(bytearray(frame[:8] + bytes((127, 255, 255, 255))))

    def test_relay_records_physical_error_instead_of_silent_timeout(self):
        import threading
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            path = Path(directory) / "spop-1-notify.bin"
            source, target = MagicMock(), MagicMock()
            source.recv.side_effect = [b"actual", TimeoutError("inherited timeout")]
            runner.relay_bytes(threading.Event(), source, target, path)
            report = json.loads(path.with_suffix(".relay.json").read_text())
            self.assertIn("inherited timeout", report["error"])
            self.assertEqual(report["received_bytes"], 6)
            self.assertEqual(report["forwarded_bytes"], 6)
            self.assertEqual(path.read_bytes(), b"actual")
            self.assertEqual(path.with_suffix(".forwarded.bin").read_bytes(), b"actual")

    def test_fixture_rejects_changed_original_or_expected_oracle(self):
        import hashlib
        contract = {"run_scoped_case_id": runner.cases.PREFIX + "NEED-allow"}
        fixture = runner.cases.fixture_profile(contract["run_scoped_case_id"])
        fixture.update(schema="i12-companion-source-fixture-v2", original_contract=contract,
                       original_contract_sha256=hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        fixture["expected"] = runner.cases.source_expectation(fixture)
        runner.cases.validate_fixture(fixture, fixture["case_id"])
        fixture["expected"]["status"] = 502
        with self.assertRaisesRegex(ValueError, "source prediction"):
            runner.cases.validate_fixture(fixture, fixture["case_id"])
        fixture["original_contract"]["changed"] = True
        with self.assertRaisesRegex(ValueError, "contract hash"):
            runner.cases.validate_fixture(fixture, fixture["case_id"])

    def test_tap_rewrites_wire_and_retains_original_frame_bytes(self):
        import threading
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            (root / "fixture.json").write_text(json.dumps({"mrc_fault": "missing"}))
            path = root / "mrc1-1-host.bin"
            original = runner.cases.mrc_frame(8, bytes((1, 0, 1, 147)))
            source, target = MagicMock(), MagicMock()
            source.recv.side_effect = [original[:9], original[9:], b""]
            runner.relay_bytes(threading.Event(), source, target, path)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(path.with_suffix(".forwarded.bin").read_bytes(), runner.cases.mrc_frame(7))
            target.sendall.assert_called_once_with(runner.cases.mrc_frame(7))
            self.assertEqual(json.loads(path.with_suffix(".relay.json").read_text())["trailing_frame_bytes"], 0)

    def test_connect_deadline_cannot_become_persistent_spop_relay_timeout(self):
        import threading
        stop = threading.Event()
        upstream, downstream, listener = MagicMock(), MagicMock(), MagicMock()
        listener.accept.return_value = downstream, None
        started = []
        def start(_target, _args, _registry):
            upstream.settimeout.assert_called_once_with(None)
            started.append(True)
            if len(started) == 2:
                stop.set()
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            with patch.object(runner, "start_capture_thread", side_effect=start):
                runner.capture_accept_loop(listener, lambda: upstream, "spop", ("notify", "ack"), stop, [], Path(directory), [])
        self.assertEqual(len(started), 2)

    def test_native_limit_fixtures_predict_actual_limit_paths(self):
        reject = runner.cases.fixture_profile(runner.cases.PREFIX + "phase4_body_reject")
        partial = runner.cases.fixture_profile(runner.cases.PREFIX + "phase4_body_process_partial")
        at_limit = runner.cases.fixture_profile(runner.cases.PREFIX + "phase4_body_at_limit")
        self.assertEqual(len(runner.cases.body_for(at_limit)), at_limit["native_limit"])
        self.assertGreater(len(runner.cases.body_for(reject)), reject["native_limit"])
        self.assertFalse(runner.cases.source_expectation(reject)["native_eos_required"])
        self.assertTrue(runner.cases.source_expectation(partial)["native_eos_required"])
        self.assertTrue(runner.cases.source_expectation(partial)["complete_body_required"])
        self.assertEqual(partial["limit_action"], "ProcessPartial")
        self.assertEqual(reject["limit_action"], "Reject")

    def test_claim_replay_runs_only_after_successful_legitimate_claim_ack(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            path = root / "mrc1-1-owner.bin"
            good = runner.cases.mrc_frame(128, bytes((1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)))
            bad = runner.cases.mrc_frame(128, bytes((1, 1, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0)))
            record = {}
            with patch.object(runner, "probe_claim_once") as probe:
                runner.observe_claim_replay(path, bad, "claim-owner", record)
                probe.assert_not_called()
                record = {}
                runner.observe_claim_replay(path, good, "claim-owner", record)
                runner.observe_claim_replay(path, good, "claim-owner", record)
                probe.assert_called_once_with(root, root / "mrc1-1-claim.frame", "mrc1-1")

    def test_claim_replay_records_real_result_code_and_first_cause(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            claim = root / "mrc1-1-claim.frame"
            original = runner.cases.mrc_frame(1, b"x" * 64)
            claim.write_bytes(original)
            rejected = runner.cases.mrc_frame(128, bytes((1, 1, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0)))
            peer = MagicMock()
            peer.__enter__.return_value = peer
            peer.recv.side_effect = [rejected[:15], rejected[15:]]
            with patch.object(runner, "connect_mrc", return_value=peer):
                runner.probe_claim_once(root, claim, "mrc1-1")
            peer.sendall.assert_called_once_with(original)
            report = json.loads((root / "mrc1-1-claim-replay.json").read_text())
            self.assertEqual(report["actual_result_code"], 1)
            self.assertEqual(report["actual_error_code"], 19)
            self.assertEqual((root / "mrc1-1-claim-replay.owner.bin").read_bytes(), rejected)
            self.assertIsNone(report["qualification"])

    def test_canonical_rules_retain_original_marker_and_rule_identity(self):
        fixture = runner.cases.fixture_profile(runner.cases.PREFIX + "phase4_rule_observed")
        self.assertEqual(runner.cases.body_for(fixture), b"no-crs-response-body-marker")
        self.assertIn("@contains no-crs-response-body-marker", runner.fixture_rules(fixture))
        self.assertIn("id:1100301,phase:4", runner.fixture_rules(fixture))
        self.assertIn("SecResponseBodyMimeType text/plain text/html application/json", runner.fixture_rules(fixture))
        custom = runner.cases.fixture_profile(runner.cases.PREFIX + "NEED-response-csv")
        self.assertIn("SecResponseBodyMimeType text/plain text/csv", runner.fixture_rules(custom))
        self.assertIn("SecResponseBodyLimit 4194304", runner.fixture_rules(custom))
        p3 = runner.cases.fixture_profile(runner.cases.PREFIX + "phase3_deny_before_commit")
        self.assertIn("RESPONSE_HEADERS:X-Modsec-Upstream", runner.fixture_rules(p3))
        self.assertIn("@streq block", runner.fixture_rules(p3))
        self.assertIn("id:1100201,phase:3,deny,status:403", runner.fixture_rules(p3))

    def test_every_implemented_negative_fixture_has_a_clean_small_neighbor(self):
        import io
        from types import SimpleNamespace
        names = ("NEED-cancel", "NEED-incomplete-framing", "NEED-missing-eos", "NEED-expired-correlation", "NEED-missing-correlation", "phase3_deny_before_commit", "phase3_redirect_before_commit", "phase4_body_reject")
        fixtures = [runner.cases.fixture_profile(runner.cases.PREFIX + name) for name in names]
        base = runner.cases.fixture_profile(runner.cases.PREFIX + "NEED-response-commit-order")
        fixtures.extend(runner.cases.outcome_negative_fixture(base, mode) for mode in ("missing", "wrong", "stale"))
        for fixture in fixtures:
            with self.subTest(case=fixture["case_id"], fault=fixture.get("mrc_fault")), tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
                args = SimpleNamespace(case=fixture["scenario"], fixture_data=fixture, root=Path(directory))
                handler = object.__new__(runner.backend_handler(args, lambda _row: None))
                handler.path, handler.headers = "/neighbor", {"Content-Length": "0"}
                handler.rfile, handler.wfile = io.BytesIO(), io.BytesIO()
                handler.send_response, handler.send_header, handler.end_headers = MagicMock(), MagicMock(), MagicMock()
                with patch.object(runner.time, "sleep") as sleep, patch.object(runner, "wait_for_first_body") as barrier:
                    handler.do_POST()
                sleep.assert_not_called()
                barrier.assert_not_called()
                headers = dict(call.args for call in handler.send_header.call_args_list)
                self.assertEqual(headers["Content-Length"], str(len(runner.cases.NEIGHBOR)))
                self.assertEqual(headers["X-Modsec-Upstream"], "allow")
                self.assertEqual(headers["X-Companion"], "allow")
                self.assertEqual(headers["Content-Type"], "text/plain")
                self.assertEqual(handler.wfile.getvalue(), runner.cases.NEIGHBOR)
                self.assertLessEqual(len(runner.cases.NEIGHBOR), 16)
                self.assertFalse(runner.cases.native_rejects(fixture, runner.cases.NEIGHBOR, True))
                self.assertTrue(runner.cases.source_expectation(fixture, True)["complete_body_required"])

    def test_negative_client_and_mrc_controls_do_not_target_neighbor(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            (root / "fixture.json").write_text(json.dumps({"transport": "cancel"}))
            self.assertTrue(runner.selected_client_cancel(root, "safe"))
            self.assertFalse(runner.selected_client_cancel(root, "neighbor"))
            path = root / "mrc1-2-host.bin"
            self.assertEqual(runner.relay_frame_mode({"mrc_fault": "wrong"}, path), "wrong")
            (root / "neighbor-stage").touch()
            for fault in ("missing", "wrong", "stale", "claim-replay"):
                self.assertIsNone(runner.relay_frame_mode({"mrc_fault": fault}, path))
            self.assertIn("if { path -m str /neighbor }", runner.request_spoe_directive("missing"))
            self.assertNotIn(" if ", runner.request_spoe_directive("safe"))

    def test_strict_requires_independent_abort_and_does_not_infer_reset(self):
        fixture = dict(runner.cases.fixture_profile(runner.cases.PREFIX + "NEED-client-response-bytes"), mode="strict")
        empty = runner.cases.response_measurements(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        self.assertTrue(empty["complete_length_framing"])
        self.assertEqual(empty["declared_body_bytes"], 0)
        clean = {"tls_eof": "close_notify", "error_type": None, "kernel_tcp_eof": True, "kernel_tcp_reset": False}
        for transport in (None, clean, {"tls_eof": "exception", "error_type": "SSLEOFError", "kernel_tcp_eof": None, "kernel_tcp_reset": None}):
            checks = runner.cases.compare_response(runner.cases.source_expectation(fixture), empty, runner.cases.body_for(fixture), transport)
            self.assertFalse(checks["transport_abort_observed"])
        fixture["pause_after_first"] = True
        full = runner.cases.response_measurements(b"HTTP/1.1 200 OK\r\nContent-Length: 33\r\n\r\n" + runner.cases.BODY)
        self.assertFalse(all(runner.cases.compare_response(runner.cases.source_expectation(fixture), full, runner.cases.BODY, clean).values()))
        prefix = runner.cases.response_measurements(b"HTTP/1.1 200 OK\r\nContent-Length: 33\r\n\r\n" + runner.cases.BODY[:8])
        reset = {"tls_eof": "exception", "error_type": "ConnectionResetError", "kernel_tcp_eof": None, "kernel_tcp_reset": True}
        self.assertTrue(all(runner.cases.compare_response(runner.cases.source_expectation(fixture), prefix, runner.cases.BODY, reset).values()))
        timeout = {"tls_eof": "exception", "error_type": "TimeoutError", "kernel_tcp_eof": None, "kernel_tcp_reset": False}
        self.assertFalse(runner.cases.transport_abort_observed(timeout))

    def test_kernel_terminal_read_distinguishes_reset_from_eof(self):
        import errno
        for event, eof, reset in ((b"", True, False), (ConnectionResetError(errno.ECONNRESET, "peer reset"), None, True)):
            raw, tls = MagicMock(), MagicMock()
            raw.__enter__.return_value = raw
            raw.recv.side_effect = event if isinstance(event, Exception) else [event]
            with patch.object(runner.socket, "socket", return_value=raw):
                observed = runner.capture_kernel_terminal(tls)
            self.assertEqual(observed["kernel_tcp_eof"], eof)
            self.assertEqual(observed["kernel_tcp_reset"], reset)
            tls.detach.assert_called_once()

    def test_main_backend_faults_remain_active_after_neighbor_isolation(self):
        import io
        from types import SimpleNamespace
        for name in ("NEED-cancel", "NEED-incomplete-framing", "NEED-expired-correlation", "phase3_deny_before_commit"):
            fixture = runner.cases.fixture_profile(runner.cases.PREFIX + name)
            with self.subTest(case=name), tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
                args = SimpleNamespace(case=fixture["scenario"], fixture_data=fixture, root=Path(directory))
                handler = object.__new__(runner.backend_handler(args, lambda _row: None))
                handler.path, handler.headers = "/i12/0", {"Content-Length": "0"}
                handler.rfile, handler.wfile = io.BytesIO(), io.BytesIO()
                handler.send_response, handler.send_header, handler.end_headers = MagicMock(), MagicMock(), MagicMock()
                with patch.object(runner.time, "sleep") as sleep:
                    handler.do_POST()
                headers = dict(call.args for call in handler.send_header.call_args_list)
                body = runner.cases.body_for(fixture)
                self.assertEqual(int(headers["Content-Length"]), len(body) + int(name == "NEED-incomplete-framing"))
                if name in ("NEED-cancel", "NEED-expired-correlation"):
                    sleep.assert_called_once_with(.4)
                if name == "phase3_deny_before_commit":
                    self.assertEqual(headers["X-Modsec-Upstream"], "block")

    def test_tls_unclean_eof_is_an_abort_observation_but_not_a_tcp_reset(self):
        observed = {"tls_eof": "exception", "error_type": "SSLEOFError", "kernel_tcp_eof": True, "kernel_tcp_reset": False}
        self.assertTrue(runner.cases.transport_abort_observed(observed))
        self.assertFalse(observed["kernel_tcp_reset"])
        observed["kernel_tcp_eof"] = None
        self.assertFalse(runner.cases.transport_abort_observed(observed))

    def test_response_framing_keeps_unknown_or_conflicting_lengths_unproved(self):
        for headers in (b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2", b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0"):
            self.assertIsNone(runner.cases.response_framing(headers, b"")["complete_length_framing"])
        actual = runner.cases.response_framing(b"HTTP/1.1 200 OK\r\nContent-Length: 33", b"prefix")
        self.assertTrue(actual["body_length_underflow"])
        self.assertFalse(actual["complete_length_framing"])

    def test_complete_source_body_with_wrong_declared_length_fails(self):
        fixture = runner.cases.fixture_profile(runner.cases.PREFIX + "NEED-client-response-bytes")
        body = runner.cases.body_for(fixture)
        for length in (0, len(body) - 1, len(body) + 1):
            response = f"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n".encode() + body
            observed = runner.cases.response_measurements(response)
            checks = runner.cases.compare_response(runner.cases.source_expectation(fixture), observed, body)
            self.assertTrue(checks["body_matches"])
            self.assertFalse(checks["declared_framing_matches"])
            self.assertFalse(checks["length_framing_complete"])
        observed = runner.cases.response_measurements(b"HTTP/1.1 200 OK\r\n\r\n" + body)
        self.assertFalse(all(runner.cases.compare_response(runner.cases.source_expectation(fixture), observed, body).values()))

    def test_mrc_wire_version_matches_primary_c_header_and_product_aliases(self):
        import subprocess
        product = SOURCE.parents[3]
        header = product / "common/runtime/response_companion_transport.h"
        self.assertIn("MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_PROTOCOL_VERSION 2U", header.read_text())
        client = (product / "common/runtime/response_companion_client.c").read_text()
        transport = (product / "common/runtime/response_companion_transport.c").read_text()
        self.assertIn("#define MRC1_VERSION MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_PROTOCOL_VERSION", client)
        self.assertIn("MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_PROTOCOL_VERSION", transport.split("#define RESPONSE_COMPANION_VERSION", 1)[1].split("\n", 2)[1])
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            cfile, binary = Path(directory) / "version.c", Path(directory) / "version"
            cfile.write_text("#include \"response_companion_transport.h\"\n_Static_assert(MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_PROTOCOL_VERSION == " + str(runner.cases.MRC_PROTOCOL_VERSION) + "U, \"fixture wire version must equal primary product contract\");\nint main(void) { return 0; }\n")
            command = ["cc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-I", str(product / "common/runtime"), "-I", str(product / "common/include"), str(cfile), "-o", str(binary)]
            compiled = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        actual_retained_header = bytes.fromhex("4d5243310201000000000040")
        pending = bytearray(actual_retained_header + b"x" * 64)
        self.assertEqual(runner.cases.complete_mrc_frames(pending)[0][:12], actual_retained_header)
        pending = bytearray(b"MRC1\x01" + actual_retained_header[5:] + b"x" * 64)
        with self.assertRaisesRegex(ValueError, "unexpected MRC1"):
            runner.cases.complete_mrc_frames(pending)

    def test_tls_truncation_preserves_physical_bytes(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            context = MagicMock()
            stream = context.wrap_socket.return_value.__enter__.return_value
            stream.recv.side_effect = [b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nabc", ssl.SSLEOFError("no close_notify")]
            with patch.object(runner.ssl, "create_default_context", return_value=context), patch.object(runner.socket, "create_connection"), patch.object(runner, "capture_kernel_terminal", return_value={"kernel_tcp_eof": True, "kernel_tcp_reset": False, "kernel_error": None}):
                runner.capture_client(root, 19000, 0, False)
            report = json.loads((root / "client-0.json").read_text())
            self.assertEqual(report["tls_eof"], "exception")
            self.assertIn("SSLEOFError", report["error"])
            self.assertTrue(report["kernel_tcp_eof"])
            stream.unwrap.assert_not_called()
            self.assertTrue((root / "client-0.response").read_bytes().endswith(b"abc"))
            context.wrap_socket.assert_called_once()
            self.assertFalse(context.wrap_socket.call_args.kwargs["suppress_ragged_eofs"])

    def test_tls_close_notify_is_distinct_from_client_cancel(self):
        for cancel, expected in ((False, "close_notify"), (True, "client_cancel")):
            with self.subTest(cancel=cancel), tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
                root = Path(directory)
                context = MagicMock()
                stream = context.wrap_socket.return_value.__enter__.return_value
                stream.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\nbody", b""]
                stream.unwrap.return_value.recv.return_value = b""
                with patch.object(runner.ssl, "create_default_context", return_value=context), patch.object(runner.socket, "create_connection"):
                    runner.capture_client(root, 19000, 0, cancel)
                report = json.loads((root / "client-0.json").read_text())
                self.assertEqual(report["tls_eof"], expected)
                self.assertIsNone(report["error"])
                self.assertEqual(report["kernel_tcp_eof"], None if cancel else True)

    def test_client_report_has_physical_wall_and_monotonic_window(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            context = MagicMock()
            stream = context.wrap_socket.return_value.__enter__.return_value
            stream.recv.side_effect = [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", b""]
            stream.unwrap.return_value.recv.return_value = b""
            with patch.object(runner.ssl, "create_default_context", return_value=context), patch.object(runner.socket, "create_connection"):
                runner.capture_client(root, 19000, 0, False)
            report = json.loads((root / "client-0.json").read_text())
            for key in ("started_wall_ns", "started_monotonic_ns", "completed_wall_ns", "completed_monotonic_ns"):
                self.assertIs(type(report[key]), int)
                self.assertGreater(report[key], 0)
            self.assertLessEqual(report["started_monotonic_ns"], report["completed_monotonic_ns"])
            self.assertEqual(report["time_ns"], report["completed_wall_ns"])

    def test_actual_harmless_tls_client_process_records_window_endpoints_and_wait(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            prepare_component_certificate(root)
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)
            port = listener.getsockname()[1]
            errors = []
            server = threading.Thread(target=serve_component_tls, args=(listener, root, errors), daemon=True)
            server.start()
            commands, observations = [], []
            try:
                runner.run_capture_client(root, port, SimpleNamespace(fixture_data={}, case="safe"), commands,
                                          threading.Lock(), observations.append, 0)
            finally:
                server.join(6)
                listener.close()
            self.assertFalse(server.is_alive())
            self.assertEqual(errors, [])
            client = json.loads((root / "client-0.json").read_text())
            process = json.loads((root / "client-0.process.json").read_text())
            self.assertEqual(process["schema"], "i12-companion-client-process-v1")
            self.assertEqual(client["schema"], "i12-companion-client-capture-v2")
            self.assertEqual(process["argv"], [sys.executable, str(SOURCE), "--client-capture", str(root), str(port), "0", "safe"])
            self.assertEqual(process["pid"], client["pid"])
            self.assertEqual(process["exit"], 0)
            self.assertIsNone(process["signal"])
            self.assertTrue(process["reaped"])
            self.assertEqual(commands, [process])
            self.assertEqual(client["connection_peer"], ["127.0.0.1", port])
            self.assertEqual(client["connection_local"][0], "127.0.0.1")
            self.assertLessEqual(process["started_monotonic_ns"], client["started_monotonic_ns"])
            self.assertLessEqual(client["started_monotonic_ns"], client["request_send_started_monotonic_ns"])
            self.assertLessEqual(client["request_send_started_monotonic_ns"], client["request_send_completed_monotonic_ns"])
            self.assertLessEqual(client["request_send_completed_monotonic_ns"], client["completed_monotonic_ns"])
            self.assertLessEqual(client["completed_monotonic_ns"], process["completed_monotonic_ns"])
            self.assertTrue((root / "client-0.response").read_bytes().endswith(b"ok"))

    def test_actual_refused_client_preserves_error_window_and_unknown_endpoints(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            prepare_component_certificate(root)
            # A bound but non-listening TCP socket deterministically rejects
            # connect without racing another process for a released port.
            with socket.socket() as reserved:
                reserved.bind(("127.0.0.1", 0))
                port = reserved.getsockname()[1]
                commands = []
                args, lock = SimpleNamespace(fixture_data={}, case="safe"), threading.Lock()
                with self.assertRaisesRegex(RuntimeError, "client-1 failed"):
                    runner.run_capture_client(root, port, args, commands, lock, lambda _row: None, 1)
            client = json.loads((root / "client-1.json").read_text())
            process = json.loads((root / "client-1.process.json").read_text())
            self.assertEqual(client["error_type"], "ConnectionRefusedError")
            self.assertEqual(client["error_stage"], "connect")
            self.assertIsNone(client["connection_local"])
            self.assertIsNone(client["connection_peer"])
            self.assertIsNone(client["request_send_started_wall_ns"])
            self.assertIsNone(client["request_send_completed_wall_ns"])
            self.assertLessEqual(client["started_monotonic_ns"], client["completed_monotonic_ns"])
            self.assertEqual(process["exit"], 1)
            self.assertTrue(process["reaped"])
            self.assertEqual((root / "client-1.response").read_bytes(), b"")

    def test_actual_signal_wait_is_separate_from_missing_child_completion(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            argv = [sys.executable, "-c", "import os,signal;os.kill(os.getpid(),signal.SIGTERM)"]
            receipt = runner.capture_client_process(root, 7, argv)
            self.assertEqual(receipt["argv"], argv)
            self.assertEqual(receipt["exit"], -runner.signal.SIGTERM)
            self.assertEqual(receipt["signal"], runner.signal.SIGTERM)
            self.assertTrue(receipt["reaped"])
            self.assertFalse((root / "client-7.json").exists())
            self.assertLessEqual(receipt["started_monotonic_ns"], receipt["completed_monotonic_ns"])

    def test_cancel_and_send_failure_keep_windows_without_fabricated_completion(self):
        for cancel in (False, True):
            with self.subTest(cancel=cancel), tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
                root = Path(directory)
                context = MagicMock()
                stream = context.wrap_socket.return_value.__enter__.return_value
                stream.recv.return_value = b"partial-response"
                if not cancel:
                    stream.sendall.side_effect = BrokenPipeError("actual send boundary")
                with patch.object(runner.ssl, "create_default_context", return_value=context), patch.object(runner.socket, "create_connection"):
                    if cancel:
                        runner.capture_client(root, 19000, 0, True)
                    else:
                        with self.assertRaises(BrokenPipeError):
                            runner.capture_client(root, 19000, 0, False)
                report = json.loads((root / "client-0.json").read_text())
                self.assertLessEqual(report["started_monotonic_ns"], report["completed_monotonic_ns"])
                self.assertEqual(report["cancel_requested"], cancel)
                if cancel:
                    self.assertEqual(report["tls_eof"], "client_cancel")
                    self.assertIsNotNone(report["request_send_completed_wall_ns"])
                else:
                    self.assertEqual(report["error_type"], "BrokenPipeError")
                    self.assertIsNone(report["request_send_completed_wall_ns"])

    def test_timeout_receipt_records_kill_and_wait_without_inventing_child_times(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            process = MagicMock(pid=123, returncode=-9)
            timeout = subprocess.TimeoutExpired(["component"], 12)
            process.communicate.side_effect = [timeout, (b"partial-output", b"timeout-detail")]
            with patch.object(runner.subprocess, "Popen", return_value=process), self.assertRaises(subprocess.TimeoutExpired) as caught:
                runner.capture_client_process(root, 9, ["component"])
            self.assertIs(caught.exception, timeout)
            process.kill.assert_called_once_with()
            self.assertEqual(process.communicate.call_count, 2)
            receipt = json.loads((root / "client-9.process.json").read_text())
            self.assertTrue(receipt["timed_out"])
            self.assertTrue(receipt["reaped"])
            self.assertEqual(receipt["signal"], 9)
            self.assertEqual((root / "client-9.stdout").read_bytes(), b"partial-output")
            self.assertFalse((root / "client-9.json").exists())

    def test_started_child_is_reaped_before_arbitrary_communication_exception_returns(self):
        actual_popen = subprocess.Popen
        for exception_type in (KeyboardInterrupt, SystemExit, RuntimeError):
            with self.subTest(exception=exception_type.__name__), tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
                root = Path(directory)
                interruption = exception_type("component communication interruption")
                children = []
                def start(*args, **kwargs):
                    process = actual_popen(*args, **kwargs)
                    children.append(process)
                    communicate = process.communicate
                    calls = []
                    def interrupted(*args, **kwargs):
                        if not calls:
                            calls.append(True)
                            raise interruption
                        return communicate(*args, **kwargs)
                    process.communicate = interrupted
                    return process
                argv = [sys.executable, "-c", "import time;time.sleep(30)"]
                try:
                    with patch.object(runner.subprocess, "Popen", side_effect=start), self.assertRaises(exception_type) as caught:
                        runner.capture_client_process(root, 12, argv)
                    self.assertIs(caught.exception, interruption)
                    self.assertIsNotNone(children[0].returncode, "started child was not waited by its owner")
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(children[0].pid, os.WNOHANG)
                    receipt = json.loads((root / "client-12.process.json").read_text())
                    self.assertTrue(receipt["reaped"])
                    self.assertEqual(receipt["pid"], children[0].pid)
                    self.assertEqual(receipt["exit"], children[0].returncode)
                    self.assertEqual(receipt["communication_error"], repr(interruption))
                    self.assertFalse((root / "client-12.json").exists())
                finally:
                    # The before-fix negative control must also leave no child.
                    for process in children:
                        if process.poll() is None:
                            process.kill()
                        process.communicate(timeout=5)

    def test_close_notify_without_tcp_eof_remains_distinct(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            context = MagicMock()
            stream = context.wrap_socket.return_value.__enter__.return_value
            stream.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n", b""]
            stream.unwrap.return_value.recv.return_value = b"unexpected"
            with patch.object(runner.ssl, "create_default_context", return_value=context), patch.object(runner.socket, "create_connection"):
                runner.capture_client(root, 19000, 100, False, neighbor=True)
            report = json.loads((root / "client-100.json").read_text())
            self.assertEqual(report["tls_eof"], "close_notify")
            self.assertFalse(report["kernel_tcp_eof"])
            self.assertIn(b"POST /neighbor HTTP/1.1", (root / "client-100.request").read_bytes())

    def test_unstarted_relay_is_never_published_to_concurrent_cleanup(self):
        registry = []
        thread = MagicMock()
        thread.start.side_effect = lambda: self.assertEqual(registry, [])
        with patch.object(runner.threading, "Thread", return_value=thread):
            runner.start_capture_thread(lambda: None, (), registry)
        self.assertEqual(registry, [thread])
        thread.start.side_effect = RuntimeError("start failed")
        registry.clear()
        with patch.object(runner.threading, "Thread", return_value=thread), self.assertRaisesRegex(RuntimeError, "start failed"):
            runner.start_capture_thread(lambda: None, (), registry)
        self.assertEqual(registry, [])

    def test_live_accept_worker_prevents_relay_snapshot(self):
        class UnstableRegistry:
            def __iter__(self):
                raise AssertionError("relay ownership read before accept worker stopped")
        worker = MagicMock()
        worker.ident = 123
        worker.is_alive.return_value = True
        registry = UnstableRegistry()
        with self.assertRaisesRegex(RuntimeError, "accept worker did not stop"):
            runner.stop_capture_threads((worker,), [], registry)
        worker.join.assert_called_once_with(timeout=4)

    def test_live_relay_is_a_reported_cleanup_failure(self):
        worker = MagicMock()
        worker.ident = 123
        worker.is_alive.return_value = False
        relay = MagicMock()
        relay.is_alive.return_value = True
        with self.assertRaisesRegex(RuntimeError, "relay did not stop"):
            runner.stop_capture_threads((worker,), [], [relay])
        relay.join.assert_called_once_with(timeout=1)

    def test_backend_accept_backlog_covers_the_parallel_fixture(self):
        self.assertEqual(runner.BACKEND_LISTEN_BACKLOG, 32)
        self.assertGreaterEqual(runner.CaptureBackendServer.request_queue_size, 16)

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            sentinel = root / "sentinel"
            sentinel.write_text("retain")
            with self.assertRaises(FileExistsError):
                runner.fresh_root(root)
            self.assertEqual(sentinel.read_text(), "retain")

    def test_cli_input_cannot_read_outside_boundary_or_through_symlinks(self):
        outside = Path("/etc/passwd")
        with self.assertRaises(ValueError):
            runner.sha(outside)
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            original = root / "input"
            original.write_bytes(b"physical")
            self.assertEqual(runner.sha(original), "4b60d190e95e576933967e0a1bb4255ebdf98bd6a990e631b23a91902d6a11a0")
            link = root / "link"
            link.symlink_to(root, target_is_directory=True)
            linked_input = link / "input"
            with self.assertRaises(ValueError):
                runner.sha(linked_input)
            traversal = root / ".." / root.name / "input"
            with self.assertRaises(ValueError):
                runner.sha(traversal)
            escaped_child = root / "escaped"
            widened_boundary = Path("/")
            with self.assertRaises(ValueError):
                runner.fresh_root(escaped_child, widened_boundary)
            self.assertFalse(escaped_child.exists())

    def test_publicly_writable_boundary_and_client_cli_escape_are_rejected(self):
        outside = Path("/etc")
        with patch.object(runner.ssl, "create_default_context") as tls:
            with self.assertRaises(ValueError):
                runner.capture_client(outside, 19000, 0, False)
            tls.assert_not_called()
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            child = root / "child"
            root.chmod(0o777)
            try:
                with self.assertRaises(ValueError):
                    runner.fresh_root(child, root)
                self.assertFalse(child.exists())
            finally:
                root.chmod(0o700)

    def test_escape_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                runner.fresh_root(root.parent / "escape", root)
            link = root / "link"
            link.symlink_to(root / "new")
            with self.assertRaises(ValueError):
                runner.fresh_root(link, root)

    def test_controller_child_is_explicit_and_fresh(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT) as directory:
            root = Path(directory)
            child = runner.fresh_root(root / "child", root)
            self.assertEqual(child.stat().st_mode & 0o777, 0o700)


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
