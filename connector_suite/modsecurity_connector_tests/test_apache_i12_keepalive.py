"""Real-frame parser and original sequence-contract regressions; no Apache host."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
from pathlib import Path
import socket
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = connector_root()
PATH = source_path('ci/runtime/lifecycle/apache-i12/acceptance/keepalive.py', root=ROOT)
KEEPALIVE = load_source(PATH)


class CapturedSocket:
    """Feed exact captured-like TCP fragments without opening a listener."""
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def recv(self, _size):
        return self.chunks.pop(0) if self.chunks else b""


class KeepaliveTest(unittest.TestCase):
    def plan(self, case_id):
        return {"case_id": case_id, "request": {"method": "GET", "path": "/principal",
            "headers": [["X-I12-ID", "unique-main"]], "body": {"bytes": 0}, "chunks": []},
            "backend": {"body": None}, "driver_seams": ["raw_connection_sequence_transaction_join"]}

    def test_private_loopback_port_accepts_cli_text_and_rejects_ambiguous_values(self):
        self.assertEqual(KEEPALIVE.private_loopback_port("18124"), 18124)
        self.assertEqual(KEEPALIVE.private_loopback_port(18124), 18124)
        for value in (443, "443", True, "18124 ", "١٨١٢٤", object()):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "private loopback port"):
                KEEPALIVE.private_loopback_port(value)

    def test_exact_original_allow_deny_allow_families_have_three_unique_transactions(self):
        for case_id in KEEPALIVE.DENY_SEQUENCES:
            steps = KEEPALIVE.sequence_requests(self.plan(case_id))
            self.assertEqual([x["label"] for x in steps], ["main", "sequence-deny", "sequence-followup"])
            self.assertIn(["X-Modsec-Smoke", "block"], steps[1]["request"]["headers"])
            ids = [next(v for k, v in x["request"]["headers"] if k == "X-I12-ID") for x in steps]
            self.assertEqual(len(ids), len(set(ids)))

    def test_content_length_response_is_drained_without_waiting_for_eof(self):
        reader = KEEPALIVE.ResponseReader(CapturedSocket([
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na", b"bc"]))
        response, raw, body = reader.read_response()
        self.assertEqual(body, b"abc")
        self.assertTrue(response["framing_complete"])
        self.assertFalse(response["tcp_eof_observed"])
        self.assertTrue(response["connection_reusable_by_headers"])
        self.assertTrue(raw.endswith(b"abc"))

    def test_real_kernel_stream_reads_two_frames_while_peer_remains_open(self):
        # A socketpair exercises actual kernel reads without starting a host
        # or a network listener; this is parser evidence, not Apache evidence.
        first = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none"
        second = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\ntwo\r\n0\r\n\r\n"
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        left.settimeout(1)
        right.sendall(first + second)
        reader = KEEPALIVE.ResponseReader(left)
        response, raw, body = reader.read_response()
        self.assertEqual((raw, body), (first, b"one"))
        self.assertFalse(response["tcp_eof_observed"])
        response, raw, body = reader.read_response()
        self.assertEqual((raw, body), (second, b"two"))
        self.assertFalse(response["tcp_eof_observed"])

    def test_two_distinct_responses_buffered_correctly_not_concatenated_bodies(self):
        first = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none"
        second = b"HTTP/1.1 403 Denied\r\nContent-Length: 3\r\n\r\ntwo"
        reader = KEEPALIVE.ResponseReader(CapturedSocket([first + second]))
        response, raw, body = reader.read_response()
        self.assertEqual((response["status"], raw, body), (200, first, b"one"))
        response, raw, body = reader.read_response()
        self.assertEqual((response["status"], raw, body), (403, second, b"two"))

    def test_chunked_response_trailers_are_consumed_before_next_status_line(self):
        first = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-End: yes\r\n\r\n"
        second = b"HTTP/1.1 204 No Content\r\n\r\n"
        reader = KEEPALIVE.ResponseReader(CapturedSocket([first + second]))
        response, raw, body = reader.read_response()
        self.assertEqual((response["framing"], raw, body), ("chunked", first, b"abc"))
        response, raw, body = reader.read_response()
        self.assertEqual((response["status"], raw, body), (204, second, b""))

    def test_interim100_is_not_the_final_request_response(self):
        wire = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        result, _, body = KEEPALIVE.ResponseReader(CapturedSocket([wire])).read_response()
        self.assertEqual(result["status"], 200)
        self.assertEqual(len(result["interim_responses"]), 1)
        self.assertEqual(body, b"")

    def test_eof_mid_content_length_keeps_error_and_real_eof(self):
        reader = KEEPALIVE.ResponseReader(CapturedSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc"]))
        with self.assertRaisesRegex(KEEPALIVE.IncompleteResponse, "EOF"):
            reader.read_response()
        self.assertTrue(reader.exchange["tcp_eof_observed"])
        self.assertFalse(reader.exchange["framing_complete"])

    def test_chunk_size_without_body_cannot_release_streaming_barrier(self):
        state = []
        class ObservedSocket(CapturedSocket):
            def recv(self, size):
                state.append("recv")
                return super().recv(size)
        reader = KEEPALIVE.ResponseReader(ObservedSocket([
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n", b"abc\r\n0\r\n\r\n"]),
            lambda: state.append("body-prefix"))
        reader.read_response()
        self.assertEqual(state, ["recv", "recv", "body-prefix"])

    def test_ambiguous_unframed_and_invalid_chunk_responses_fail(self):
        wires = [b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
                 b"HTTP/1.1 200 OK\r\n\r\nunframed",
                 b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n"]
        for wire in wires:
            reader = KEEPALIVE.ResponseReader(CapturedSocket([wire]))
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                reader.read_response()

    def test_sequence_socket_rejects_nonprivate_port_before_connect(self):
        with self.assertRaisesRegex(ValueError, "private loopback port"):
            KEEPALIVE.open_sequence_connection({}, Path("/owned"), 443, Path("/backend"), {})

    def test_strict_new_socket_contract_needs_actual_server_close(self):
        plan = self.plan("keepalive_after_strict_new_connection")
        summary = {"steps": [{"request_send_completed_ns": 1, "error": {"type": "IncompleteResponse"}, "response": {}},
                             {"request_send_completed_ns": 2, "error": None, "response": {"framing_complete": True}}],
                   "server_close_before_fresh_socket": False}
        self.assertFalse(KEEPALIVE.sequence_complete(plan, summary))
        summary["server_close_before_fresh_socket"] = True
        self.assertTrue(KEEPALIVE.sequence_complete(plan, summary))

    def test_strict_first_response_retains_close_and_allows_fresh_socket_step(self):
        summary = {}
        result = {"response": {"tcp_reset_observed": True}, "error": {"type": "ConnectionResetError"}}
        self.assertFalse(KEEPALIVE.stop_sequence(result, True, 0, summary))
        self.assertTrue(summary["server_close_before_fresh_socket"])
        self.assertTrue(KEEPALIVE.stop_sequence(result, True, 1, summary))

    def test_non_strict_sequence_stops_on_error_or_close_header(self):
        summary = {}
        self.assertTrue(KEEPALIVE.stop_sequence({"response": {}, "error": {"type": "OSError"}},
                                               False, 0, summary))
        self.assertNotIn("sequence_stopped_reason", summary)
        self.assertTrue(KEEPALIVE.stop_sequence({"response": {}, "error": None}, False, 0, summary))
        self.assertEqual(summary["sequence_stopped_reason"], "server response forbids connection reuse")
        self.assertFalse(KEEPALIVE.stop_sequence(
            {"response": {"connection_reusable_by_headers": True}, "error": None}, False, 1, {}))

    def test_strict_second_step_closes_first_socket_before_opening_new_one(self):
        connection, reader = mock.Mock(), object()
        args = SimpleNamespace(output=Path("/owned"), port=12345, backend_root=Path("/backend"))
        selected = (object(), object())
        with mock.patch.object(KEEPALIVE, "open_sequence_connection", return_value=selected) as opened:
            self.assertEqual(KEEPALIVE.select_sequence_connection(
                connection, reader, False, {}, args, {}), (connection, reader))
            opened.assert_not_called()
            connection.close.assert_not_called()
            def after_close(*_args):
                connection.close.assert_called_once_with()
                return selected
            opened.side_effect = after_close
            self.assertEqual(KEEPALIVE.select_sequence_connection(
                connection, reader, True, {}, args, {}), selected)

    def test_neighbor_case_has_real_backend_pause_and_keeps_original_input(self):
        original = self.plan("NEED-neighbor-connection-stream")
        result = KEEPALIVE.prepare_plan(original)
        self.assertIsNone(original["backend"]["body"])
        self.assertEqual(result["backend"]["barrier"]["release_condition"],
                         "independent_neighbor_process_completed_after_main_prefix")
        self.assertEqual(len(KEEPALIVE.sequence_requests(result)), 1)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
