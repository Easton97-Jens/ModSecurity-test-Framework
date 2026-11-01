from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest


ROOT = connector_root()
HARNESS = source_path('connectors/nginx/harness/run_nginx_smoke.sh', root=ROOT)


class NginxProtocolHarnessContractTest(unittest.TestCase):
    def test_tls_chain_listener_inventory_and_0rtt_boundary_are_explicit(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        for required in (
            "ModSecurity local test CA",
            "-CA \"$NGINX_TLS_CA_CERT\"",
            "-CAkey \"$NGINX_TLS_CA_KEY\"",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            '"tcp_listener"',
            '"udp_listener"',
            '"http3_0rtt"',
            '"$NGINX_TLS_CA_KEY"',
            '"${NGINX_TLS_CA_CERT:-}.srl"',
        ):
            self.assertIn(required, source)

    def test_optional_forced_client_probe_is_live_but_non_promoting(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        for required in (
            "run_nginx_protocol_client_if_requested()",
            "NO_CRS_PROTOCOL_CLIENT_ARTIFACT_DIR",
            'https://127.0.0.1:$PORT/no-crs/allow',
            "--cacert \"$NGINX_TLS_CA_CERT\"",
            'protocol_probe_token="nginx-${protocol}-live-probe"',
            '--header "X-Modsec-Smoke: allow"',
            '--transport-case-id "$protocol_probe_token"',
            "protocol-client status=%s exit=%s (non-promoting without stream/case correlation)",
            "no synthetic stream ID or ALPN sidecar",
            'value.get("reason") != "incomplete_protocol_provenance"',
            'value.get("fallback_used") is not False',
            'value.get("http_status") != 200',
            'value.get("curl_exit_code") != 0',
            'value.get("response_committed") is not True',
            'if protocol == "h2" and value.get("transport") != "tls_tcp":',
            'if "stream_id" in value or "alpn" in value:',
            'wait_tcp_port "$PORT" || fail "NGINX protocol listener did not become TCP-ready',
        ):
            self.assertIn(required, source)
        self.assertNotIn("--stream-id 1", source)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
