"""Regression coverage for bounded local runtime-smoke request bodies."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import http.client
import importlib.util
import io
from email.message import Message
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from types import SimpleNamespace


SCRIPT_PATH = connector_root() / "common/scripts/run_local_runtime_smoke.py"
SMOKE = load_source(SCRIPT_PATH)


class RecordingBackend:
    decision_backend = "test"

    def __init__(self) -> None:
        self.last_error: str | None = None
        self.bodies: list[bytes] = []

    def decide(
        self,
        headers: http.client.HTTPMessage,
        path: str,
        method: str = "GET",
        body: bytes = b"",
    ) -> dict[str, object]:
        del headers, path, method
        self.bodies.append(body)
        return {"status": 200, "body": b"ok\n"}


class RequestBodyReader:
    def __init__(self, headers: Message, body: bytes) -> None:
        self.headers = headers
        self.rfile = io.BytesIO(body)


class LocalRuntimeSmokeRequestBodyTest(unittest.TestCase):
    def test_lighttpd_artifacts_are_isolated_by_validated_scenario(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = SMOKE.RuntimeOutputPaths(
                root,
                root / "evidence",
                root / "results",
                root / "tmp",
                root / "logs",
                root / "logs" / "shared",
                root / "config",
            )
            targeted = SMOKE.lighttpd_artifacts(
                SimpleNamespace(
                    modsecurity_ruleset="targeted",
                    modsecurity_smoke_case="targeted",
                    crs_smoke_case="minimal",
                ),
                paths,
            )
            request_body = SMOKE.lighttpd_artifacts(
                SimpleNamespace(
                    modsecurity_ruleset="targeted",
                    modsecurity_smoke_case="request_body",
                    crs_smoke_case="minimal",
                ),
                paths,
            )
            crs = SMOKE.lighttpd_artifacts(
                SimpleNamespace(
                    modsecurity_ruleset="crs",
                    modsecurity_smoke_case="targeted",
                    crs_smoke_case="secondary",
                ),
                paths,
            )

        self.assertEqual(len({targeted.log_dir, request_body.log_dir, crs.log_dir}), 3)
        self.assertEqual(
            {targeted.log_dir.name, request_body.log_dir.name, crs.log_dir.name},
            {"lighttpd-targeted", "lighttpd-request_body", "lighttpd-crs-secondary"},
        )

    def test_shared_http_literals_preserve_the_smoke_contract(self) -> None:
        self.assertEqual(SMOKE.DEFAULT_TEXT_CONTENT_TYPE, "text/plain")
        self.assertEqual(SMOKE.DEFAULT_ALLOWED_PATH, "/allowed")
        self.assertEqual(SMOKE.DEFAULT_BLOCKED_PATH, "/blocked")

    def test_explicit_loopback_ports_reject_zero_and_out_of_range_values(self) -> None:
        self.assertEqual(SMOKE.require_loopback_port(8080), 8080)
        self.assertEqual(SMOKE.require_loopback_port(0, allow_ephemeral=True), 0)
        for value in (0, -1, 65536):
            with self.subTest(value=value), self.assertRaises(SMOKE.RequestBodyError):
                SMOKE.require_loopback_port(value)

    def test_loopback_url_builder_rejects_authority_and_preserves_origin_form(self) -> None:
        self.assertEqual(
            SMOKE.local_smoke_url(8080, "/allowed?case=control"),
            "http://127.0.0.1:8080/allowed?case=control",
        )
        for target in ("http://example.test/", "//example.test/", "/allowed#fragment"):
            with self.subTest(target=target), self.assertRaises(SMOKE.RequestBodyError):
                SMOKE.require_local_request_target(target)

    def test_handlers_reject_absolute_form_requests_without_backend_or_upstream_processing(self) -> None:
        request = b"POST http://example.test/ HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\n\r\n"
        self.assert_handlers_reject_without_processing(request)

    def test_modsecurity_evaluator_accepts_only_smoke_protocol_arguments(self) -> None:
        backend = SMOKE.ModSecurityDecisionBackend(
            Path("/tmp/helper"),
            Path("/tmp/rules.conf"),
            Path("/tmp/decision.log"),
            {},
            "targeted",
            "minimal",
            "request_body",
        )
        headers = Message()
        accepted = backend._evaluator_request(
            headers, "/allowed", "POST", SMOKE.REQUEST_BODY_ALLOW_BODY
        )
        self.assertEqual(accepted.path, "/allowed")
        self.assertEqual(accepted.content_type, SMOKE.REQUEST_BODY_CONTENT_TYPE)
        for target, body in (
            ("http://example.test/", SMOKE.REQUEST_BODY_ALLOW_BODY),
            ("/allowed", b"unexpected=body"),
        ):
            with self.subTest(target=target, body=body), self.assertRaises(SMOKE.RequestBodyError):
                backend._evaluator_request(headers, target, "POST", body)

    def start_server(self, handler: type[SMOKE.QuietHandler]) -> SMOKE.LocalSmokeHTTPServer:
        server = SMOKE.start_http_server(handler, 0)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def post(self, port: int, body: bytes) -> int:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            connection.request("POST", "/", body=body, headers={"Content-Length": str(len(body))})
            response = connection.getresponse()
            response.read()
            return int(response.status)
        finally:
            connection.close()

    def raw_status(self, port: int, request: bytes) -> int:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            response = bytearray()
            while b"\r\n" not in response:
                received = connection.recv(4096)
                if not received:
                    break
                response.extend(received)
        status_line = bytes(response).split(b"\r\n", 1)[0].split()
        self.assertGreaterEqual(len(status_line), 2, response)
        return int(status_line[1])

    def assert_handlers_reject_without_processing(self, request: bytes) -> None:
        decision_backend = RecordingBackend()
        decision_server = self.start_server(SMOKE.make_decision_handler(decision_backend))
        self.assertEqual(self.raw_status(decision_server.server_port, request), 400)
        self.assertEqual(decision_backend.bodies, [])

        forwarded_methods: list[str] = []

        class RecordingUpstream(SMOKE.QuietHandler):
            def do_POST(self) -> None:
                forwarded_methods.append(self.command)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        with tempfile.TemporaryDirectory() as temporary:
            sidecar_backend = RecordingBackend()
            upstream_server = self.start_server(RecordingUpstream)
            sidecar_server = self.start_server(
                SMOKE.make_sidecar_proxy_handler(
                    sidecar_backend,
                    upstream_server.server_port,
                    Path(temporary) / "sidecar.jsonl",
                ),
            )
            self.assertEqual(self.raw_status(sidecar_server.server_port, request), 400)
            self.assertEqual(sidecar_backend.bodies, [])
            self.assertEqual(forwarded_methods, [])

    def test_decision_and_sidecar_handlers_accept_exact_content_length_limit(self) -> None:
        body = b"a" * SMOKE.MAX_REQUEST_BODY_BYTES
        decision_backend = RecordingBackend()
        decision_server = self.start_server(SMOKE.make_decision_handler(decision_backend))
        self.assertEqual(self.post(decision_server.server_port, body), 200)
        self.assertEqual(decision_backend.bodies, [body])

        with tempfile.TemporaryDirectory() as temporary:
            sidecar_backend = RecordingBackend()
            upstream_server = self.start_server(SMOKE.UpstreamHandler)
            transcript = Path(temporary) / "sidecar.jsonl"
            sidecar_server = self.start_server(
                SMOKE.make_sidecar_proxy_handler(sidecar_backend, upstream_server.server_port, transcript),
            )
            self.assertEqual(self.post(sidecar_server.server_port, body), 200)
            self.assertEqual(sidecar_backend.bodies, [body])

    def test_decision_and_sidecar_handlers_reject_oversized_content_length(self) -> None:
        request = (
            b"POST / HTTP/1.1\r\nHost: local\r\nContent-Length: "
            + str(SMOKE.MAX_REQUEST_BODY_BYTES + 1).encode("ascii")
            + b"\r\n\r\n"
        )
        decision_backend = RecordingBackend()
        decision_server = self.start_server(SMOKE.make_decision_handler(decision_backend))
        self.assertEqual(self.raw_status(decision_server.server_port, request), 413)
        self.assertEqual(decision_backend.bodies, [])

        with tempfile.TemporaryDirectory() as temporary:
            sidecar_backend = RecordingBackend()
            sidecar_server = self.start_server(
                SMOKE.make_sidecar_proxy_handler(sidecar_backend, 1, Path(temporary) / "sidecar.jsonl"),
            )
            self.assertEqual(self.raw_status(sidecar_server.server_port, request), 413)
            self.assertEqual(sidecar_backend.bodies, [])

    def test_decision_and_sidecar_handlers_reject_conflicting_body_framing(self) -> None:
        request = (
            b"POST / HTTP/1.1\r\n"
            b"Host: local\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n"
            b"0\r\n\r\n"
        )
        self.assert_handlers_reject_without_processing(request)

    def test_decision_and_sidecar_handlers_reject_duplicate_content_length(self) -> None:
        for first, second in ((b"0", b"0"), (b"0", b"5")):
            with self.subTest(first=first, second=second):
                request = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: local\r\n"
                    b"Content-Length: "
                    + first
                    + b"\r\nContent-Length: "
                    + second
                    + b"\r\n\r\n"
                )
                self.assert_handlers_reject_without_processing(request)

    def test_decision_and_sidecar_handlers_reject_duplicate_transfer_encoding(self) -> None:
        request = (
            b"POST / HTTP/1.1\r\n"
            b"Host: local\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"0\r\n\r\n"
        )
        self.assert_handlers_reject_without_processing(request)

    def test_reader_rejects_zero_content_length_with_transfer_encoding(self) -> None:
        headers = Message()
        headers["transfer-encoding"] = "chunked"
        headers["content-length"] = "0"
        reader = RequestBodyReader(headers, b"0\r\n\r\n")
        with self.assertRaises(SMOKE.RequestBodyError):
            SMOKE.read_request_body(reader)

    def test_chunked_reader_accepts_exact_limit_and_rejects_cumulative_overflow(self) -> None:
        headers = Message()
        headers["Transfer-Encoding"] = "chunked"
        exact_body = b"a" * SMOKE.MAX_REQUEST_BODY_BYTES
        exact_request = (
            f"{len(exact_body):X}\r\n".encode("ascii")
            + exact_body
            + b"\r\n0\r\n\r\n"
        )
        self.assertEqual(
            SMOKE.read_request_body(RequestBodyReader(headers, exact_request)),
            exact_body,
        )
        overflow_request = exact_request[:-5] + b"1\r\nb\r\n0\r\n\r\n"
        overflow_reader = RequestBodyReader(headers, overflow_request)
        with self.assertRaises(SMOKE.RequestBodyTooLarge):
            SMOKE.read_request_body(overflow_reader)

    def test_reader_rejects_malformed_and_incomplete_request_bodies(self) -> None:
        chunked_headers = Message()
        chunked_headers["Transfer-Encoding"] = "chunked"
        malformed_chunk_reader = RequestBodyReader(chunked_headers, b"not-hex\r\n")
        with self.assertRaises(SMOKE.RequestBodyError):
            SMOKE.read_request_body(malformed_chunk_reader)
        length_headers = Message()
        length_headers["Content-Length"] = "2"
        incomplete_length_reader = RequestBodyReader(length_headers, b"x")
        with self.assertRaises(SMOKE.RequestBodyError):
            SMOKE.read_request_body(incomplete_length_reader)

    def test_reader_rejects_non_ascii_content_length_digits(self) -> None:
        headers = Message()
        headers["Content-Length"] = "١"
        reader = RequestBodyReader(headers, b"x")

        with self.assertRaises(SMOKE.RequestBodyError):
            SMOKE.read_request_body(reader)

    def test_accepted_connections_receive_a_finite_socket_deadline(self) -> None:
        observed: list[float | None] = []

        class DeadlineHandler(SMOKE.QuietHandler):
            def do_GET(self) -> None:
                observed.append(self.connection.gettimeout())
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        server = self.start_server(DeadlineHandler)
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        try:
            connection.request("GET", "/")
            response = connection.getresponse()
            response.read()
            self.assertEqual(response.status, 200)
        finally:
            connection.close()
        self.assertEqual(observed, [SMOKE.SERVER_SOCKET_TIMEOUT_SECONDS])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
