"""Parent-owned regression coverage for HAProxy HTX transaction-ID bounds."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import importlib.util
import http.server
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.parse


HELPER_PATH = (
    connector_root()
    / "connectors/haproxy/harness/haproxy_htx_smoke_helper.py"
)
HELPER = load_source(HELPER_PATH)


class _LoopbackTLSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"tls-ok\n"
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args


class HAProxyHTXTransactionIdTest(unittest.TestCase):
    def test_runtime_artifacts_stay_in_private_root_and_clients_stay_loopback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canonical = root / "canonical.conf"
            canonical.write_text(
                "\n".join(HELPER.CANONICAL_RULE_SNIPPETS) + "\n",
                encoding="utf-8",
            )
            certificate = root / "loopback-tls.pem"
            certificate.write_text("private test certificate", encoding="utf-8")
            config = root / "haproxy.cfg"
            outside = root.parent / f"{root.name}-outside.conf"
            runtime_root = str(root)
            outside_path = str(outside)
            canonical_path = str(canonical)
            certificate_path = str(certificate)
            engine_policy = {
                "request_body_limit": 32,
                "request_body_no_files_limit": 32,
                "request_body_limit_action": "Reject",
                "response_body_limit": 1048576,
                "response_body_limit_action": "Reject",
            }
            with self.assertRaisesRegex(ValueError, "below the runtime root"):
                HELPER.write_rules(runtime_root, outside_path, canonical_path, **engine_policy)
            self.assertFalse(outside.exists())

            redirected = root / "redirected.conf"
            redirected.symlink_to(outside)
            redirected_path = str(redirected)
            with self.assertRaisesRegex(ValueError, "below the runtime root|symbolic link"):
                HELPER.write_rules(runtime_root, redirected_path, canonical_path, **engine_policy)
            self.assertFalse(outside.exists())

            self.assertEqual(
                HELPER.checked_loopback_https_url("https://127.0.0.1:18080/no-crs/allow"),
                ("127.0.0.1", 18080, "/no-crs/allow"),
            )
            non_loopback_url = "https://example.invalid/"
            with self.assertRaisesRegex(ValueError, "127.0.0.1"):
                HELPER.checked_loopback_https_url(non_loopback_url)
            credential_url = "https://user@127.0.0.1:18080/"
            with self.assertRaisesRegex(ValueError, "credential-free"):
                HELPER.checked_loopback_https_url(credential_url)
            plaintext_url = urllib.parse.urlunsplit(("http", "127.0.0.1:18080", "/", "", ""))
            with self.assertRaisesRegex(ValueError, "https"):
                HELPER.checked_loopback_https_url(plaintext_url)

            self.assertEqual(
                HELPER.write_config(
                    runtime_root, str(config), 18080, 18081, canonical_path, certificate_path,
                ),
                0,
            )
            self.assertIn("bind 127.0.0.1:18080 ssl crt", config.read_text(encoding="utf-8"))

        runtime = (
            connector_root()
            / "connectors/haproxy/harness/run_haproxy_htx_runtime.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("helper prepare-runtime-root", runtime)
        self.assertIn('"$@" --runtime-root "$RUNTIME_ROOT"', runtime)
        self.assertIn("generate_loopback_tls_certificate", runtime)
        self.assertIn('--tls-certificate "$TLS_CA_CERTIFICATE_PATH"', runtime)

    def test_probe_requires_verified_loopback_tls_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / "loopback.key"
            certificate = root / "loopback.crt"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
                    "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-keyout", str(key), "-out", str(certificate),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LoopbackTLSHandler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=str(certificate), keyfile=str(key))
            server.socket = context.wrap_socket(server.socket, server_side=True)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                url = f"https://127.0.0.1:{server.server_port}/tls"
                runtime_root = str(root)
                certificate_path = str(certificate)
                self.assertEqual(HELPER.probe(runtime_root, url, [], "GET", None, certificate_path), 0)
            finally:
                server.shutdown()
                worker.join()
                server.server_close()

    def test_native_128_byte_buffer_limit_applies_to_allow_and_evidence_writers(self) -> None:
        accepted = "a" * HELPER.HTX_TRANSACTION_ID_MAX_LENGTH
        rejected = "b" * (HELPER.HTX_TRANSACTION_ID_MAX_LENGTH + 1)
        self.assertEqual(HELPER.safe_htx_transaction_id(accepted), accepted)
        with self.assertRaisesRegex(ValueError, "invalid HTX transaction id"):
            HELPER.safe_htx_transaction_id(rejected)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events.jsonl"
            probe = root / "client-probe.json"
            upstream = root / "upstream-requests.jsonl"
            host_evidence = root / "host-runtime-evidence.jsonl"
            decision_log = root / "haproxy.stderr.log"
            events_path = str(events)
            probe_path = str(probe)
            upstream_path = str(upstream)
            host_evidence_path = str(host_evidence)
            decision_log_path = str(decision_log)
            runtime_root = str(root)
            probe.write_text(
                json.dumps({"status": 200, "response_bytes": 24, "content_type": "text/plain"}),
                encoding="utf-8",
            )
            upstream.write_text(
                json.dumps({"profile": "ordinary", "request_id": accepted}) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(
                HELPER.write_allow_event(
                    str(root), events_path, probe_path, upstream_path, accepted,
                ),
                0,
            )
            self.assertEqual(
                json.loads(events.read_text(encoding="utf-8"))["transaction_id"],
                accepted,
            )
            with self.assertRaisesRegex(ValueError, "invalid HTX transaction id"):
                HELPER.write_allow_event(
                    runtime_root, events_path, probe_path, upstream_path, rejected,
                )

            probe.write_text(
                json.dumps({"status": 403, "response_bytes": 24, "content_type": "text/plain"}),
                encoding="utf-8",
            )
            decision_log.write_text(
                "modsecurity-htx: request intervention observed; "
                f"transaction_id={accepted} phase=1 status=403 rule_id=1100001 action=deny\n",
                encoding="utf-8",
            )
            self.assertEqual(
                HELPER.write_host_evidence(
                    str(root), host_evidence_path, "phase1_403", 1, 1100001, probe_path, 0,
                    "enforced_reply", decision_log_path,
                ),
                0,
            )
            self.assertEqual(
                json.loads(host_evidence.read_text(encoding="utf-8"))["transaction_id"],
                accepted,
            )
            decision_log.write_text(
                "modsecurity-htx: request intervention observed; "
                f"transaction_id={rejected} phase=1 status=403 rule_id=1100001 action=deny\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "invalid HTX transaction id"):
                HELPER.write_host_evidence(
                    runtime_root, host_evidence_path, "phase1_403", 1, 1100001, probe_path, 0,
                    "enforced_reply", decision_log_path,
                )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
