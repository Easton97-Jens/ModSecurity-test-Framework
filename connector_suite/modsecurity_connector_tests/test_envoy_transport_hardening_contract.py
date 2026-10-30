from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import http.client
import http.server
import importlib.util
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = connector_root()
HELPER_PATH = source_path('connectors/envoy/harness/envoy_smoke_helper.py', root=ROOT)
RUNTIME_PATH = source_path('connectors/envoy/harness/run_envoy_ext_proc_runtime.sh', root=ROOT)
EXT_AUTHZ_RUNTIME_PATH = source_path('connectors/envoy/harness/run_envoy_connector_runtime.sh', root=ROOT)
EXT_AUTHZ_START_PATH = source_path('connectors/envoy/harness/start_envoy_connector.sh', root=ROOT)
EXT_AUTHZ_TEMPLATE = source_path('connectors/envoy/config/envoy-ext-authz-smoke.yaml.in', root=ROOT)
EXT_PROC_CONFIG_MATERIALIZER = (
    source_path('connectors/envoy/config/prepare_envoy_ext_proc_config.sh', root=ROOT)
)
TLS_YAML_RENDERER = source_path('connectors/envoy/config/lib/tls_yaml_render.sh', root=ROOT)


def load_helper() -> object:
    module = load_source(HELPER_PATH)
    return module


def create_loopback_tls_material(root: Path) -> tuple[Path, Path]:
    certificate = root / "loopback.crt"
    private_key = root / "loopback.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", str(private_key), "-out", str(certificate),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return certificate, private_key


def configure_loopback_tls(server: http.server.ThreadingHTTPServer, root: Path) -> Path:
    certificate, private_key = create_loopback_tls_material(root)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certificate, keyfile=private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return certificate


class EnvoyTransportHardeningContractTest(unittest.TestCase):
    def test_ext_proc_runtime_uses_canonical_p1_p4_traffic_vectors(self) -> None:
        source = RUNTIME_PATH.read_text(encoding="utf-8")

        for marker in (
            "/vector/p1",
            'X-Msconnector-Vector: msconnector-p1-only',
            "/vector/p2",
            'P2_REQUEST_BODY_MARKER=msconnector-p2-only',
            "/vector/p2-body-limit",
            "P2_BODY_LIMIT_BODY=",
            "phase2_body_limit_status=",
            "phase2_body_limit_upstream_reached=false",
            "/vector/p3",
            "/vector/p3-redirect",
            "P3_REDIRECT_TARGET=/msconnector-p3-redirect-target",
            "phase3_redirect_status=",
            "/vector/p4",
            "/vector/p4-safe",
            "PHASE4_ONLY_TRANSACTION_ID=envoy-ext-proc-phase4-only",
            "phase4_only_status=",
            "phase4_only_completion=PASS",
            "missing bounded P4-only completion evidence",
            '"rule_id":"1101001"',
            '"rule_id":"1102001"',
            '"rule_id":"1103001"',
            '"rule_id":"1103002"',
            '"rule_id":"1104002"',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)

        for obsolete in (
            "/phase1-deny",
            "/phase2-deny",
            "/phase3-block",
            "/phase3-redirect",
            "/phase4-marker",
            "X-Modsec-Smoke: block",
            "no-crs-request-body-marker",
            "no-crs-response-body-marker",
            '"rule_id":"1100001"',
            '"rule_id":"1100101"',
            '"rule_id":"1100201"',
            '"rule_id":"1100202"',
            '"rule_id":"1100301"',
        ):
            with self.subTest(obsolete=obsolete):
                self.assertNotIn(obsolete, source)

        raw_gate = source[source.index("raw_event_ready=0"):source.index('if [ "$raw_event_ready" -ne 1 ]')]
        self.assertNotIn('"rule_id":"1104001"', raw_gate)
        self.assertIn('"rule_id":"1104002"', raw_gate)

    def test_ext_authz_runtime_does_not_claim_host_owned_response_body_verification(self) -> None:
        source = EXT_AUTHZ_RUNTIME_PATH.read_text(encoding="utf-8")

        self.assertIn("printf 'response_body_verified=false\\n'", source)
        self.assertNotIn("printf 'response_body_verified=true\\n'", source)
        self.assertIn("printf 'response_phase_events_verified=true\\n'", source)

    def test_runtime_harness_cleanup_is_bounded_and_pid_identity_bound(self) -> None:
        source = RUNTIME_PATH.read_text(encoding="utf-8")

        self.assertIn("owned_process_start_token()", source)
        self.assertIn("owned_process_stat_value()", source)
        self.assertIn('close = line.rfind(")")', source)
        self.assertIn('post_comm[19]', source)
        self.assertNotIn("awk '{ print $22 }'", source)
        self.assertNotIn("awk '{ print $3 }'", source)
        self.assertIn("owned_process_is_current()", source)
        self.assertIn("CHILD_STOP_ATTEMPTS=${ENVOY_CHILD_STOP_ATTEMPTS:-20}", source)
        self.assertIn("CHILD_STOP_DELAY=${ENVOY_CHILD_STOP_DELAY_SECONDS:-0.1}", source)
        self.assertIn('kill -TERM "$owned_pid"', source)
        self.assertIn('kill -KILL "$owned_pid"', source)
        self.assertIn('wait_for_owned_process_stop "$owned_pid" "$expected_token"', source)
        self.assertIn('refusing to signal changed $process_label PID $owned_pid', source)
        self.assertIn('refusing to signal unverified $process_label PID $owned_pid', source)
        self.assertIn('upstream_start_token=$(owned_process_start_token "$upstream_pid")', source)
        self.assertIn('service_start_token=$(owned_process_start_token "$service_pid")', source)
        self.assertIn('envoy_start_token=$(owned_process_start_token "$envoy_pid")', source)

    def test_envoy_v138_template_avoids_deprecated_protocol_and_admin_fields(self) -> None:
        template = (
            source_path('connectors/envoy/config/envoy-ext-proc-streaming.yaml.in', root=ROOT)
        ).read_text(encoding="utf-8")

        self.assertIn("typed_extension_protocol_options:", template)
        self.assertIn("envoy.extensions.upstreams.http.v3.HttpProtocolOptions:", template)
        self.assertIn(
            "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
            template,
        )
        self.assertIn("explicit_http_config:", template)
        self.assertNotIn("\n    http2_protocol_options: {}", template)
        self.assertIn("\n          http2_protocol_options: {}", template)
        self.assertNotIn("access_log_path:", template)
        self.assertIn("envoy.access_loggers.file", template)
        self.assertIn(
            "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog",
            template,
        )
        self.assertIn("path: /dev/null", template)
        self.assertIn("log_format:", template)
        self.assertIn("text_format_source:", template)
        self.assertIn('inline_string: ""', template)
        self.assertIn("type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext", template)
        self.assertIn("validation_context:", template)
        self.assertIn("trusted_ca:", template)
        self.assertIn('filename: "@TLS_CERTIFICATE@"', template)

    def test_first_body_byte_is_read_once_without_header_remainder(self) -> None:
        helper = load_helper()

        class Connection:
            def __init__(self) -> None:
                self.recv_limits: list[int] = []
                self.timeouts: list[float] = []
                self.responses = [
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n",
                    b"x",
                ]

            def settimeout(self, timeout: float) -> None:
                self.timeouts.append(timeout)

            def recv(self, limit: int) -> bytes:
                self.recv_limits.append(limit)
                return self.responses.pop(0)

        connection = Connection()

        self.assertEqual(helper._read_chunked_first_body(connection, timeout=1.0), (200, 1))
        self.assertEqual(connection.recv_limits, [4096, 1])
        self.assertTrue(all(timeout > 0 for timeout in connection.timeouts))

    def test_client_cancel_waits_for_one_real_body_byte_then_closes(self) -> None:
        helper = load_helper()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            class FastCancelHandler(helper.UpstreamHandler):
                client_cancel_delay_seconds = 0.05

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FastCancelHandler)
            server.handle_error = lambda request, client_address: None
            certificate = configure_loopback_tls(server, root)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                observation = helper.client_cancel(
                    str(root), str(certificate), "127.0.0.1", server.server_port,
                    "/client-cancel", ["X-Request-Id: cancel-test"],
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

        self.assertEqual(observation["http_status"], 200)
        self.assertTrue(observation["first_body_byte_received"])
        self.assertTrue(observation["client_closed"])

    def test_client_cancel_rejects_non_ascii_wire_headers(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate = root / "loopback.crt"
            certificate.write_text("placeholder", encoding="utf-8")
            runtime_root = str(root)
            certificate_path = str(certificate)
            non_ascii_header = ["X-Test: snowman-☃"]
            with self.assertRaises(ValueError):
                helper.client_cancel(
                    runtime_root, certificate_path, "127.0.0.1", 18080,
                    "/client-cancel", non_ascii_header,
                )

    def test_probe_requires_verified_loopback_tls_and_root_confined_evidence(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), helper.UpstreamHandler)
            certificate = configure_loopback_tls(server, root)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            evidence = root / "probe.json"
            try:
                self.assertEqual(
                    helper.probe(
                        str(root), str(certificate), f"https://127.0.0.1:{server.server_port}/allowed",
                        [], "GET", None, False, str(evidence),
                    ),
                    0,
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            observation = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(observation["http_status"], 200)
            self.assertFalse(observation["composite_lease_header_present"])
            self.assertFalse(observation["redirect_location_verified"])
            for unsafe_url in (
                f"http://127.0.0.1:{server.server_port}/allowed",
                f"https://example.invalid:{server.server_port}/allowed",
                f"https://user@127.0.0.1:{server.server_port}/allowed",
            ):
                with self.assertRaises(ValueError):
                    helper.checked_loopback_https_url(unsafe_url)

            outside = root.parent / "envoy-probe-outside.json"
            with self.assertRaises(ValueError):
                helper.runtime_artifact(root, outside, "probe evidence output")
            escaped_parent = root / "escaped"
            escaped_parent.symlink_to(root.parent, target_is_directory=True)
            with self.assertRaises(ValueError):
                helper.runtime_artifact(root, escaped_parent / "probe.json", "probe evidence output")

    def test_probe_rejects_a_forbidden_response_header_without_retaining_its_value(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            class MarkerHandler(helper.UpstreamHandler):
                def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                    body = b"ok\n"
                    self.send_response(403)
                    self.send_header("X-Msconnector-Terminal-Authz", "1")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MarkerHandler)
            certificate = configure_loopback_tls(server, root)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with self.assertRaisesRegex(RuntimeError, "forbidden response header"):
                    helper.probe(
                        str(root), str(certificate),
                        f"https://127.0.0.1:{server.server_port}/blocked",
                        [], "GET", None, False, None,
                        ["x-msconnector-terminal-authz"],
                    )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_probe_requires_exact_response_header_without_retaining_its_value(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            class RedirectHandler(helper.UpstreamHandler):
                def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                    self.send_response(302)
                    self.send_header("Location", "/msconnector-p3-redirect-target")
                    self.send_header("Content-Length", "0")
                    self.end_headers()

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
            certificate = configure_loopback_tls(server, root)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            evidence = root / "probe.json"
            try:
                self.assertEqual(
                    helper.probe(
                        str(root), str(certificate),
                        f"https://127.0.0.1:{server.server_port}/redirect",
                        [], "GET", None, True, str(evidence), [],
                        ["Location: /msconnector-p3-redirect-target"],
                    ),
                    0,
                )
                with self.assertRaisesRegex(RuntimeError, "required response header"):
                    helper.probe(
                        str(root), str(certificate),
                        f"https://127.0.0.1:{server.server_port}/redirect",
                        [], "GET", None, True, None, [],
                        ["Location: /incorrect-target"],
                    )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            observation = json.loads(evidence.read_text(encoding="utf-8"))
            serialized = json.dumps(observation, sort_keys=True)
            self.assertTrue(observation["redirect_location_verified"])
            self.assertNotIn("msconnector-p3-redirect-target", serialized)
            with self.assertRaises(ValueError):
                helper.parse_headers(["X-Test: safe\x00unsafe"])

    def test_probe_rejects_duplicate_required_response_header_without_retaining_values(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            class DuplicateRedirectHandler(helper.UpstreamHandler):
                def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                    self.send_response(302)
                    self.send_header("Location", "/msconnector-p3-redirect-target")
                    self.send_header("Location", "/other-target")
                    self.send_header("Content-Length", "0")
                    self.end_headers()

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), DuplicateRedirectHandler)
            certificate = configure_loopback_tls(server, root)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with self.assertRaisesRegex(RuntimeError, "required response header"):
                    helper.probe(
                        str(root), str(certificate),
                        f"https://127.0.0.1:{server.server_port}/redirect",
                        [], "GET", None, True, None, [],
                        ["Location: /msconnector-p3-redirect-target"],
                    )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_probe_records_only_a_boolean_when_a_composite_lease_header_reaches_the_client(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            class LeaseHeaderHandler(helper.UpstreamHandler):
                def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                    body = b"ok\n"
                    self.send_response(200)
                    self.send_header("X-Msconnector-Composite-Lease", "opaque-test-marker")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), LeaseHeaderHandler)
            certificate = configure_loopback_tls(server, root)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            evidence = root / "probe.json"
            try:
                self.assertEqual(
                    helper.probe(
                        str(root), str(certificate),
                        f"https://127.0.0.1:{server.server_port}/lease-header",
                        [], "GET", None, False, str(evidence),
                    ),
                    0,
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            observation = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertTrue(observation["composite_lease_header_present"])
            self.assertNotIn("opaque-test-marker", json.dumps(observation, sort_keys=True))

    def test_upstream_fixture_requires_runtime_confined_tls_files(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate, private_key = create_loopback_tls_material(root)
            server = mock.MagicMock()
            with mock.patch.object(helper, "Phase4TrackingHTTPSServer", return_value=server) as constructor:
                self.assertEqual(
                    helper.serve_upstream(
                        18081, 5.0, str(root), str(certificate), str(private_key),
                    ),
                    0,
                )

            arguments, keywords = constructor.call_args
            self.assertEqual(arguments[0], (helper.LOOPBACK_HOST, 18081))
            self.assertTrue(issubclass(arguments[1], helper.UpstreamHandler))
            self.assertEqual(keywords["certfile"], str(certificate))
            self.assertEqual(keywords["keyfile"], str(private_key))
            self.assertEqual(server.socket.context.minimum_version, ssl.TLSVersion.TLSv1_2)
            server.serve_forever.assert_called_once_with()
            server.server_close.assert_called_once_with()

            outside_key = root.parent / "outside-loopback.key"
            outside_key.write_text("not a key", encoding="utf-8")
            private_key.unlink()
            private_key.symlink_to(outside_key)
            with self.assertRaisesRegex(ValueError, "below the runtime root|private key must be a regular file"):
                helper.loopback_tls_server_files(root, str(certificate), str(private_key))

    def test_phase4_marker_default_and_plain_text_headers_remain_stable(self) -> None:
        helper = load_helper()
        with mock.patch.object(sys, "argv", [
            "envoy_smoke_helper.py",
            "phase4-first-byte",
            "--host", "127.0.0.1",
            "--port", "18080",
            "--runtime-root", "/var/tmp/envoy-phase4-runtime",
            "--tls-certificate", "/var/tmp/envoy-phase4-runtime/loopback.crt",
            "--barrier-dir", "/tmp/phase4-barrier",
        ]):
            arguments = helper.parse_args()

        self.assertEqual(helper.PHASE4_MARKER_PATH, "/vector/p4-safe")
        self.assertEqual(arguments.path, "/vector/p4-safe")
        self.assertEqual(helper.TEXT_PLAIN_CONTENT_TYPE, "text/plain")

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), helper.UpstreamHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        try:
            connection.request("GET", arguments.path)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader("content-type"), "text/plain")
            self.assertEqual(response.read(), b"p4-safe-response-msconnector-p4-safe")
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        source = HELPER_PATH.read_text(encoding="utf-8")
        self.assertIn('later_chunk = b"p4-safe-response-msconnector-p4-safe"', source)
        self.assertNotIn('later_chunk = b"no-crs-response-body-marker\\n"', source)
        self.assertEqual(
            source.count('self.send_header("content-type", TEXT_PLAIN_CONTENT_TYPE)'), 3,
        )

    def test_response_phase_smoke_target_selects_companion_rules_without_changing_default(self) -> None:
        makefile = (source_path('connectors/envoy/Makefile', root=ROOT)).read_text(encoding="utf-8")

        self.assertIn(
            "RULES_FILE ?= $(abspath $(CURDIR)/../../common/rules/modsecurity_targeted_smoke.conf)",
            makefile,
        )
        self.assertIn("response-phase-smoke-envoy", makefile)
        self.assertIn(
            "response-phase-smoke-envoy: override RULES_FILE := $(abspath $(CURDIR)/../../common/rules/modsecurity_response_companion_smoke.conf)",
            makefile,
        )
        self.assertIn(
            "response-phase-smoke-envoy: override export MSCONNECTOR_RESPONSE_PHASE_SMOKE := 1",
            makefile,
        )
        self.assertIn("response-phase-smoke-envoy: runtime-smoke-envoy", makefile)

        companion_rules = (source_path('common/rules/modsecurity_response_companion_smoke.conf', root=ROOT)).resolve()
        dry_run = subprocess.run(
            [
                "make",
                "-n",
                "-s",
                "-C",
                str(source_path('connectors/envoy', root=ROOT)),
                "RULES_FILE=/tmp/nonmatching.conf",
                "MSCONNECTOR_RESPONSE_PHASE_SMOKE=0",
                "--eval",
                "response-phase-smoke-envoy: ; @printf 'RULES_FILE=%s MSCONNECTOR_RESPONSE_PHASE_SMOKE=%s\\n' '$(RULES_FILE)' '$(MSCONNECTOR_RESPONSE_PHASE_SMOKE)'",
                "response-phase-smoke-envoy",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(dry_run.returncode, 0, dry_run.stdout + dry_run.stderr)
        self.assertIn(f'RULES_FILE="{companion_rules}"', dry_run.stdout)
        self.assertIn(
            f"'{companion_rules}' '1'",
            dry_run.stdout,
        )

        default_dry_run = subprocess.run(
            [
                "make",
                "-n",
                "-s",
                "-C",
                str(source_path('connectors/envoy', root=ROOT)),
                "RULES_FILE=/tmp/caller-selected.conf",
                "MSCONNECTOR_RESPONSE_PHASE_SMOKE=1",
                "--eval",
                "print-default-response-phase-values: runtime-smoke-envoy ; @printf 'RULES_FILE=%s MSCONNECTOR_RESPONSE_PHASE_SMOKE=%s\\n' '$(RULES_FILE)' '$(MSCONNECTOR_RESPONSE_PHASE_SMOKE)'",
                "print-default-response-phase-values",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            default_dry_run.returncode,
            0,
            default_dry_run.stdout + default_dry_run.stderr,
        )
        self.assertIn('RULES_FILE="/tmp/caller-selected.conf"', default_dry_run.stdout)
        self.assertIn(
            "'/tmp/caller-selected.conf' '1'",
            default_dry_run.stdout,
        )

    def test_response_phase_fixture_matches_companion_p3_and_p4_rules_only(self) -> None:
        helper = load_helper()
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), helper.UpstreamHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        try:
            connection.request("GET", "/phase3-block")
            p3_response = connection.getresponse()
            self.assertEqual(p3_response.status, 200)
            self.assertEqual(p3_response.getheader("X-Modsec-Upstream"), "block")
            self.assertNotIn(b"no-crs-response-body-marker", p3_response.read())

            connection.request("GET", "/phase4-marker")
            p4_response = connection.getresponse()
            self.assertEqual(p4_response.status, 200)
            self.assertIsNone(p4_response.getheader("X-Modsec-Upstream"))
            self.assertIn(b"no-crs-response-body-marker", p4_response.read())
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_phase4_barrier_confirms_first_byte_before_upstream_eos(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as temporary:
            barrier_dir = Path(temporary) / "phase4-barrier"
            root = Path(temporary)

            class BarrierHandler(helper.UpstreamHandler):
                phase4_barrier_timeout_seconds = 2.0

            BarrierHandler.phase4_barrier_dir = barrier_dir
            BarrierHandler.runtime_root = root
            server = helper.Phase4TrackingHTTPServer(("127.0.0.1", 0), BarrierHandler)
            certificate = configure_loopback_tls(server, root)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                observation = helper.phase4_first_byte(
                    str(root),
                    str(certificate),
                    "127.0.0.1",
                    server.server_port,
                    "/vector/p4-safe",
                    ["X-Request-Id: phase4-first-byte-test"],
                    str(barrier_dir),
                    2.0,
                )
            finally:
                server.shutdown()
                helper.wait_for_phase4_handlers(server, 2.0)
                server.server_close()
                thread.join(timeout=2)

            self.assertEqual(observation["http_status"], 200)
            self.assertTrue(observation["client_first_byte_received"])
            self.assertTrue(observation["first_byte_before_response_end"])
            self.assertGreater(observation["first_chunk_size"], 0)
            self.assertTrue(observation["upstream_paused"])
            self.assertFalse(observation["upstream_eos_sent_at_first_byte"])
            self.assertFalse(observation["upstream_response_finished_at_first_byte"])
            self.assertTrue(observation["upstream_eos_sent_after_release"])
            self.assertFalse(observation["body_payload_persisted"])

            paused = json.loads((barrier_dir / "upstream-paused.json").read_text(encoding="utf-8"))
            completed = json.loads(
                (barrier_dir / "upstream-completed.json").read_text(encoding="utf-8")
            )
            self.assertTrue(paused["upstream_paused"])
            self.assertFalse(paused["upstream_eos_sent"])
            self.assertTrue(completed["upstream_eos_sent"])
            self.assertNotIn("no-crs-response-body-marker", json.dumps(observation))
            self.assertNotIn("no-crs-response-body-marker", json.dumps(paused))
            self.assertNotIn("no-crs-response-body-marker", json.dumps(completed))

    def test_phase4_lifecycle_waits_for_exceptional_handler_exit(self) -> None:
        helper = load_helper()
        lifecycle = helper.Phase4HandlerLifecycle()
        lifecycle.begin()
        completed = threading.Event()

        def fail_and_release() -> None:
            try:
                raise RuntimeError("synthetic phase-4 handler failure")
            except RuntimeError:
                pass
            finally:
                lifecycle.end()
                completed.set()

        thread = threading.Thread(target=fail_and_release)
        thread.start()
        helper.wait_for_phase4_handlers(type("Server", (), {
            "phase4_handler_lifecycle": lifecycle,
        })(), 2.0)
        thread.join(timeout=2)
        self.assertTrue(completed.is_set())

    def test_phase4_first_byte_evidence_binds_to_the_common_safe_event(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            observation_path = root / "observation.json"
            event_path = root / "events.jsonl"
            evidence_path = root / "first-byte-evidence.json"
            helper.write_json_atomic(root, observation_path,
                {
                    "schema_version": 1,
                    "evidence_type": "envoy_phase4_first_byte_observation",
                    "http_status": 200,
                    "client_first_byte_received": True,
                    "first_byte_before_response_end": True,
                    "first_chunk_size": 17,
                    "upstream_paused": True,
                    "upstream_eos_sent_at_first_byte": False,
                    "upstream_response_finished_at_first_byte": False,
                    "upstream_eos_sent_after_release": True,
                    "body_payload_persisted": False,
                    "transport_protocol": "http1",
                    "outcome": "PASS",
                }, "phase-4 first-byte observation",
            )
            common_safe_event = {
                "connector": "envoy",
                "integration_mode": "ext_proc",
                "event": "MSCONN_EVENT_RULE",
                "message_id": "MSCONN_EVENT_RULE",
                "transaction_id": "envoy-ext-proc-phase4-safe",
                "rule_id": "1104002",
                "phase": "response_body",
                "status": "blocked",
                "http_status": 451,
                "original_http_status": 200,
                "visible_http_status": 200,
                "requested_action": "deny",
                "actual_action": "log_only",
                "late_intervention": True,
                "late_intervention_mode": "safe",
                "headers_sent": True,
                "body_started": True,
                "response_committed": True,
                "connection_aborted": False,
                "transport_result": "log_only",
                "body_bytes_seen": 42,
                "body_bytes_inspected": 42,
            }
            event_path.write_text(json.dumps(common_safe_event) + "\n", encoding="utf-8")

            result = helper.write_phase4_first_byte_evidence(
                runtime_root=str(root),
                event_log=str(event_path),
                observation_path=str(observation_path),
                transaction_id="envoy-ext-proc-phase4-safe",
                evidence_output=str(evidence_path),
                run_id="run-phase4-first-byte",
            )

            self.assertTrue(result["event_appended"])
            self.assertTrue(result["evidence_written"])
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["evidence_type"], "synchronized_first_byte")
            self.assertEqual(evidence["evidence_origin"], "real_host")
            self.assertTrue(evidence["promotion_eligible"])
            self.assertTrue(evidence["first_byte_before_response_end"])
            self.assertTrue(evidence["no_full_response_buffering"])
            self.assertFalse(evidence["connector_owned_full_response_buffer"])
            self.assertEqual(evidence["transport_protocol"], "http1")

            records = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines()]
            barrier_event = records[-1]
            self.assertEqual(barrier_event["event"], "phase4_first_byte_barrier")
            self.assertEqual(barrier_event["transaction_id"], "envoy-ext-proc-phase4-safe")
            self.assertEqual(barrier_event["rule_id"], "1104002")
            self.assertEqual(barrier_event["phase"], 4)
            self.assertEqual(barrier_event["late_intervention_mode"], "safe")
            self.assertEqual(barrier_event["actual_action"], "log_only")
            self.assertTrue(barrier_event["end_of_stream_evaluation"])
            self.assertTrue(barrier_event["eos_seen"])
            self.assertEqual(barrier_event["cleanup_reason"], "normal")
            self.assertTrue(barrier_event["first_byte_before_response_end"])
            self.assertFalse(barrier_event["upstream_eos_sent_at_first_byte"])
            self.assertTrue(barrier_event["no_full_response_buffering"])
            self.assertNotIn("no-crs-response-body-marker", json.dumps(evidence))
            self.assertNotIn("no-crs-response-body-marker", json.dumps(barrier_event))

            repeated = helper.write_phase4_first_byte_evidence(
                runtime_root=str(root),
                event_log=str(event_path),
                observation_path=str(observation_path),
                transaction_id="envoy-ext-proc-phase4-safe",
                evidence_output=str(evidence_path),
                run_id="run-phase4-first-byte",
            )
            self.assertFalse(repeated["event_appended"])
            self.assertEqual(len(event_path.read_text(encoding="utf-8").splitlines()), 2)

            unexpected_status = dict(common_safe_event)
            unexpected_status["http_status"] = 403
            event_path.write_text(json.dumps(unexpected_status) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected status metadata"):
                helper.write_phase4_first_byte_evidence(
                    runtime_root=str(root),
                    event_log=str(event_path),
                    observation_path=str(observation_path),
                    transaction_id="envoy-ext-proc-phase4-safe",
                )

    def test_ext_authz_response_phase_validator_binds_p3_and_p4_records_without_payloads(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_path = root / "events.jsonl"
            records = [
                {
                    "connector": "envoy",
                    "integration_mode": "ext_authz",
                    "transaction_id": "envoy-p3-block-1",
                    "rule_id": "1000003",
                    "phase": "response_headers",
                    "status": "blocked",
                    "actual_action": "deny",
                    "response_committed": False,
                },
                {
                    "connector": "envoy",
                    "integration_mode": "ext_authz",
                    "transaction_id": "envoy-p4-safe-1",
                    "rule_id": "1000004",
                    "phase": "response_body",
                    "status": "blocked",
                    "actual_action": "log_only",
                    "response_committed": True,
                    "body_bytes_seen": 28,
                },
            ]
            event_path.write_text(
                "\n".join(json.dumps(record) for record in records) + "\n",
                encoding="utf-8",
            )
            helper.verify_response_phase_events(
                runtime_root=str(root),
                event_log=str(event_path),
                p3_rule_id="1000003",
                p3_transaction_id="envoy-p3-block-1",
                p4_rule_id="1000004",
                p4_transaction_id="envoy-p4-safe-1",
            )

            records[1]["response_body"] = "must-not-appear"
            event_path.write_text(
                "\n".join(json.dumps(record) for record in records) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "forbidden body payload"):
                helper.verify_response_phase_events(
                    runtime_root=str(root),
                    event_log=str(event_path),
                    p3_rule_id="1000003",
                    p3_transaction_id="envoy-p3-block-1",
                    p4_rule_id="1000004",
                    p4_transaction_id="envoy-p4-safe-1",
                )

            records[1].pop("response_body")
            records.append(dict(records[0]))
            event_path.write_text(
                "\n".join(json.dumps(record) for record in records) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "exactly one P3 deny and P4 Safe record"):
                helper.verify_response_phase_events(
                    runtime_root=str(root),
                    event_log=str(event_path),
                    p3_rule_id="1000003",
                    p3_transaction_id="envoy-p3-block-1",
                    p4_rule_id="1000004",
                    p4_transaction_id="envoy-p4-safe-1",
                )

    def test_allow_event_binds_client_http200_to_one_normal_ext_proc_completion(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events.jsonl"
            probe = root / "allow-probe.json"
            completions = root / "completion-events.jsonl"
            events.write_text(
                json.dumps({
                    "connector": "envoy",
                    "integration_mode": "ext_proc",
                    "event": "phase4_first_byte_barrier",
                    "message_id": "MSCONN_EVENT_P4_FIRST_BYTE_BARRIER",
                    "transaction_id": "envoy-ext-proc-phase4-safe",
                    "rule_id": "1104002",
                    "phase": 4,
                    "status": "observed",
                    "http_status": 403,
                    "visible_http_status": 200,
                    "requested_action": "deny",
                    "actual_action": "log_only",
                    "late_intervention": True,
                    "late_intervention_mode": "safe",
                    "headers_sent": True,
                    "body_started": True,
                    "response_committed": True,
                    "connection_aborted": False,
                    "transport_result": "log_only",
                    "end_of_stream_evaluation": True,
                    "eos_seen": True,
                }) + "\n",
                encoding="utf-8",
            )
            helper.write_json_atomic(root, probe, {
                "schema_version": 1,
                "evidence_type": "envoy_http_client_probe",
                "http_status": 200,
                "response_bytes": 27,
                "body_payload_persisted": False,
            }, "allow probe evidence")
            completions.write_text(
                json.dumps({
                    "event": "ext_proc_stream_complete",
                    "integration_mode": "ext_proc",
                    "evaluation_mode": "common_libmodsecurity_nonpromoted",
                    "rule_evaluation": "libmodsecurity",
                    "transaction_id": "envoy-ext-proc-allow-1",
                    "response_body_bytes": 27,
                    "late_action": "none",
                    "close_reason": "response_end_of_stream",
                }) + "\n",
                encoding="utf-8",
            )

            result = helper.write_allow_event(
                runtime_root=str(root),
                event_log=str(events),
                probe_evidence_path=str(probe),
                completion_log=str(completions),
                transaction_id="envoy-ext-proc-allow-1",
            )

            self.assertTrue(result["event_appended"])
            allow_event = json.loads(events.read_text(encoding="utf-8").splitlines()[-1])
            self.assertEqual(allow_event["message_id"], "ENVOY_EXT_PROC_NATIVE_P1_ALLOW")
            self.assertEqual(allow_event["transaction_id"], "envoy-ext-proc-allow-1")
            self.assertEqual(allow_event["phase"], 1)
            self.assertEqual(allow_event["visible_http_status"], 200)
            self.assertNotIn("requested_action", allow_event)
            self.assertNotIn("actual_action", allow_event)
            self.assertNotIn("no-crs-response-body-marker", json.dumps(allow_event))

    def test_allow_event_rejects_noncausal_client_or_completion_metadata(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events.jsonl"
            probe = root / "allow-probe.json"
            completions = root / "completion-events.jsonl"
            events.write_text("{}\n", encoding="utf-8")
            helper.write_json_atomic(root, probe, {
                "schema_version": 1,
                "evidence_type": "envoy_http_client_probe",
                "http_status": 403,
                "response_bytes": 27,
                "body_payload_persisted": False,
            }, "allow probe evidence")
            completions.write_text(
                json.dumps({
                    "event": "ext_proc_stream_complete",
                    "integration_mode": "ext_proc",
                    "evaluation_mode": "common_libmodsecurity_nonpromoted",
                    "rule_evaluation": "libmodsecurity",
                    "transaction_id": "envoy-ext-proc-allow-1",
                    "response_body_bytes": 27,
                    "late_action": "none",
                    "close_reason": "response_end_of_stream",
                }) + "\n",
                encoding="utf-8",
            )
            event_log = str(events)
            probe_evidence_path = str(probe)
            completion_log = str(completions)
            runtime_root = str(root)
            with self.assertRaisesRegex(ValueError, "HTTP 200"):
                helper.write_allow_event(
                    runtime_root=runtime_root,
                    event_log=event_log,
                    probe_evidence_path=probe_evidence_path,
                    completion_log=completion_log,
                    transaction_id="envoy-ext-proc-allow-1",
                )

            helper.write_json_atomic(root, probe, {
                "schema_version": 1,
                "evidence_type": "envoy_http_client_probe",
                "http_status": 200,
                "response_bytes": 27,
                "body_payload_persisted": False,
            }, "allow probe evidence")
            completions.write_text("\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exactly one ext_proc completion"):
                helper.write_allow_event(
                    runtime_root=runtime_root,
                    event_log=event_log,
                    probe_evidence_path=probe_evidence_path,
                    completion_log=completion_log,
                    transaction_id="envoy-ext-proc-allow-1",
                )

    def test_tls_path_materializer_keeps_paths_data_in_yaml_and_sed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "generated.yaml"
            marker = root / "unexpected-command-marker"
            injected_certificate = (
                f"{root}/benign|; s|{root}/benign|touch {marker}|e; #"
            )
            private_key = root / 'key with spaces&pipe|quote"backslash\\.key'
            environment = dict(os.environ)
            environment.update({
                "TLS_CERTIFICATE": injected_certificate,
                "TLS_PRIVATE_KEY": str(private_key),
                "OUTPUT_CONFIG": str(output),
            })

            completed = subprocess.run(
                ["sh", str(EXT_PROC_CONFIG_MATERIALIZER)],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(marker.exists())
            rendered = output.read_text(encoding="utf-8")
            self.assertIn(f'filename: "{injected_certificate}"', rendered)
            self.assertIn(
                "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                rendered,
            )
            self.assertGreaterEqual(rendered.count(f'filename: "{injected_certificate}"'), 2)
            expected_private_key = str(private_key).replace("\\", "\\\\").replace('"', '\\"')
            self.assertIn(f'filename: "{expected_private_key}"', rendered)

            for label, control in (("newline", "\n"), ("carriage-return", "\r")):
                with self.subTest(control=label):
                    rejected_output = root / f"{label}-generated.yaml"
                    environment["TLS_CERTIFICATE"] = f"{root}/certificate{control}with-control.crt"
                    environment["OUTPUT_CONFIG"] = str(rejected_output)
                    rejected = subprocess.run(
                        ["sh", str(EXT_PROC_CONFIG_MATERIALIZER)],
                        cwd=ROOT,
                        env=environment,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(rejected.returncode, 2, rejected.stderr)
                    self.assertIn("TLS certificate path contains an unsupported control character", rejected.stderr)
                    self.assertFalse(rejected_output.exists())

    def test_tls_renderer_explicitly_accepts_control_free_paths(self) -> None:
        renderer = TLS_YAML_RENDERER.read_text(encoding="utf-8")

        self.assertIn('        *) : ;;\n', renderer)

    def test_ext_authz_compat_runtime_uses_private_loopback_tls(self) -> None:
        source = EXT_AUTHZ_RUNTIME_PATH.read_text(encoding="utf-8")
        start_source = EXT_AUTHZ_START_PATH.read_text(encoding="utf-8")
        template = EXT_AUTHZ_TEMPLATE.read_text(encoding="utf-8")

        self.assertIn("prepare-runtime-root --runtime-root \"$RUNTIME_ROOT\"", source)
        self.assertIn("serve-upstream --port \"$upstream_port\" \\", source)
        self.assertIn("--runtime-root \"$RUNTIME_ROOT\"", source)
        self.assertIn("--tls-certificate \"$TLS_CERTIFICATE\"", source)
        self.assertIn("--tls-private-key \"$TLS_PRIVATE_KEY\"", source)
        self.assertEqual(
            source.count("--runtime-root \"$RUNTIME_ROOT\" --tls-certificate \"$TLS_CERTIFICATE\""),
            4,
        )
        self.assertEqual(source.count("https://127.0.0.1:$listen_port"), 4)
        self.assertNotIn("http://127.0.0.1:$listen_port", source)
        self.assertIn('RESPONSE_PHASE_SMOKE=${MSCONNECTOR_RESPONSE_PHASE_SMOKE:-0}', source)
        self.assertIn('P3_TRANSACTION_ID=envoy-p3-block-1', source)
        self.assertIn('P4_TRANSACTION_ID=envoy-p4-safe-1', source)
        self.assertIn('--forbid-response-header x-msconnector-terminal-authz', source)
        self.assertIn('rm -f "$TLS_CERTIFICATE" "$TLS_PRIVATE_KEY"', source)
        self.assertIn("prepare-runtime-root --runtime-root \"$START_ROOT\"", start_source)
        self.assertIn("create_private_loopback_tls", start_source)
        self.assertIn('rm -f "$TLS_CERTIFICATE" "$TLS_PRIVATE_KEY"', start_source)
        self.assertIn("name: envoy.transport_sockets.tls", template)
        self.assertIn('filename: "@TLS_CERTIFICATE@"', template)
        self.assertIn('filename: "@TLS_PRIVATE_KEY@"', template)
        self.assertIn("type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext", template)
        self.assertIn("trusted_ca:", template)
        self.assertIn("uri: http://127.0.0.1:@AUTHZ_PORT@", template)
        self.assertNotIn("access_log_path:", template)
        self.assertIn("failure_mode_allow: false\n              allowed_headers:", template)
        self.assertNotIn("authorization_request:", template)
        self.assertIn("authorization_response:", template)
        self.assertIn("allowed_upstream_headers:", template)
        self.assertIn("- exact: x-msconnector-response-handle", template)
        self.assertIn("name: envoy.filters.http.ext_proc", template)
        self.assertIn("cluster_name: msconnector_ext_authz_response_observer", template)
        self.assertIn("request_body_mode: NONE", template)
        self.assertIn("response_body_mode: STREAMED", template)
        self.assertIn("response_trailer_mode: SEND", template)
        self.assertIn('path: "@RESPONSE_OBSERVER_SOCKET@"', template)

    def test_envoy_smokes_reject_unsafe_root_without_tls_cleanup(self) -> None:
        true_binary = shutil.which("true")
        self.assertIsNotNone(true_binary)

        cases = (
            (
                EXT_AUTHZ_START_PATH,
                "START_ROOT",
                {
                    "ENVOY_BIN": true_binary,
                    "SERVICE_BIN": true_binary,
                    "RESPONSE_OBSERVER_BIN": true_binary,
                },
                "START_ROOT is unsafe for private runtime artifacts",
            ),
            (
                EXT_AUTHZ_RUNTIME_PATH,
                "RUNTIME_ROOT",
                {
                    "ENVOY_BIN": true_binary,
                    "SERVICE_BIN": true_binary,
                    "RESPONSE_OBSERVER_BIN": true_binary,
                },
                "RUNTIME_ROOT is unsafe for private runtime artifacts",
            ),
            (
                RUNTIME_PATH,
                "RUNTIME_ROOT",
                {
                    "ENVOY_BIN": true_binary,
                    "EXT_PROC_BIN": true_binary,
                    "MSCONNECTOR_RULES_FILE": str(
                        source_path('common/rules/modsecurity_targeted_smoke.conf', root=ROOT)
                    ),
                },
                "RUNTIME_ROOT is unsafe for private runtime artifacts",
            ),
        )

        for script, root_variable, extra_environment, expected_error in cases:
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = root / "target"
                target.mkdir()
                certificate = target / "envoy-loopback.crt"
                private_key = target / "envoy-loopback.key"
                certificate.write_text("certificate marker", encoding="utf-8")
                private_key.write_text("private key marker", encoding="utf-8")
                unsafe_root = root / "unsafe-root"
                unsafe_root.symlink_to(target, target_is_directory=True)
                environment = dict(os.environ)
                environment.update(extra_environment)
                environment.update({
                    root_variable: str(unsafe_root),
                    "PYTHON": sys.executable,
                })

                completed = subprocess.run(
                    ["sh", str(script)],
                    cwd=ROOT,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )

                self.assertEqual(completed.returncode, 1, completed.stderr)
                self.assertIn(expected_error, completed.stderr)
                self.assertEqual(certificate.read_text(encoding="utf-8"), "certificate marker")
                self.assertEqual(private_key.read_text(encoding="utf-8"), "private key marker")

    def test_runtime_probe_keeps_cancellation_unattributed_and_nonpromoting(self) -> None:
        source = RUNTIME_PATH.read_text(encoding="utf-8")
        self.assertIn("ENVOY_TRANSPORT_CANCEL_PROBE", source)
        self.assertIn("grpc_context_canceled_unattributed", source)
        self.assertIn("grpc_peer_eof", source)
        self.assertIn("expected exactly one unattributed ext_proc terminal completion", source)
        self.assertIn("client_disconnect_after_first_response_chunk", source)
        self.assertIn("transport-observations.diagnostic.json", source)
        self.assertIn('"capability_promotion": "not_permitted"', source)
        self.assertIn('"state": "NOT_EXECUTED"', source)
        self.assertIn('"diagnostic_only": True', source)
        self.assertNotIn('"transport_case_id":', source)
        self.assertIn("client-cancel", source)
        self.assertIn("FULL_LIFECYCLE_EVIDENCE_OUTPUT", source)
        self.assertIn("phase4-first-byte", source)
        self.assertIn("phase4_first_byte_before_response_end_status", source)
        self.assertIn("phase4_no_full_response_buffering_status", source)
        self.assertIn("phase4_end_of_stream_evaluation_status", source)
        self.assertIn("phase4_rule_observed_status", source)
        self.assertIn("write-allow-event", source)
        self.assertIn("prepare-runtime-root", source)
        self.assertIn("envoy.transport_sockets.tls", source)
        self.assertIn('https://127.0.0.1:$listen_port', source)

    def test_runtime_uses_an_unambiguous_allow_transaction(self) -> None:
        source = RUNTIME_PATH.read_text(encoding="utf-8")

        self.assertIn("READINESS_TRANSACTION_ID=envoy-ext-proc-readiness-1", source)
        self.assertIn("ALLOW_TRANSACTION_ID=envoy-ext-proc-allow-1", source)
        self.assertIn('X-Request-Id: $READINESS_TRANSACTION_ID', source)
        self.assertIn('X-Request-Id: $ALLOW_TRANSACTION_ID', source)
        self.assertIn('READINESS_PROBE_EVIDENCE="$RUNTIME_ROOT/readiness-probe.json"', source)
        self.assertIn('ALLOW_PROBE_EVIDENCE="$RUNTIME_ROOT/allow-probe.json"', source)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
