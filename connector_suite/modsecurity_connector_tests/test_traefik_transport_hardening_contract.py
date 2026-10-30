from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source

import http.server
import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from modsecurity_connector_tests.framework_test_trust import trusted_framework_root


ROOT = connector_root()
RUNTIME_SCRIPT = source_path('connectors/traefik/scripts/runtime_native_smoke.py', root=ROOT)
STANDALONE_RULES = source_path('connectors/traefik/config/traefik-native-engine-rules.conf', root=ROOT)
FRAMEWORK_ROOT = Path(
    os.environ.get("PARENT_TEST_FRAMEWORK_ROOT", source_path('modules/ModSecurity-test-Framework', root=ROOT))
)


def load_runtime_module() -> object:
    module = load_source(RUNTIME_SCRIPT)
    return module


def load_trusted_framework_baseline(test_case: unittest.TestCase) -> object:
    framework_root, error = trusted_framework_root(ROOT, FRAMEWORK_ROOT)
    if framework_root is None:
        test_case.skipTest(error)
    assert framework_root is not None
    module = load_source(framework_root / 'ci' / 'checks' / 'catalog' / 'no_crs_baseline.py')
    return module


class _KeepAliveHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - http.server callback shape
        size = int(self.headers.get("Content-Length", "0"))
        if size:
            self.rfile.read(size)
        body = b"payload-free-test-body\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class TraefikTransportHardeningContractTest(unittest.TestCase):
    def test_safe_followup_requires_the_same_http11_connection(self) -> None:
        runtime = load_runtime_module()
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _KeepAliveHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            observation = runtime.keepalive_safe_followup(
                server.server_port,
                b"request-body",
                "safe-transaction",
                "followup-transaction",
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertTrue(observation["connection_reused"])
        self.assertEqual(observation["safe_status"], 200)
        self.assertEqual(observation["followup_status"], 200)
        self.assertTrue(observation["safe_first_byte_received"])
        self.assertTrue(observation["followup_first_byte_received"])

    def test_synchronized_safe_followup_observes_a_byte_before_upstream_eos(self) -> None:
        runtime = load_runtime_module()
        state = runtime.UpstreamState()
        server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), runtime.upstream_handler(state)
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            observation = runtime.synchronized_safe_followup(
                server.server_port,
                state,
                b"request-body",
                "safe-barrier-transaction",
                "safe-barrier-followup",
            )
        finally:
            state.barrier_release.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertTrue(observation["safe_first_byte_received"])
        self.assertTrue(observation["upstream_paused"])
        self.assertFalse(observation["upstream_eos_sent_at_first_byte"])
        self.assertGreater(observation["first_chunk_size"], 0)

    def test_real_barrier_sidecar_and_strict_boundary_are_explicit(self) -> None:
        source = RUNTIME_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"artifact_profile": "native-http1-barrier-observation"', source)
        self.assertIn('"diagnostic_case": "phase4_safe_first_byte_barrier"', source)
        self.assertIn('"canonical_evidence": True', source)
        self.assertIn('"diagnostic_only": False', source)
        self.assertIn('"transport_case_id": "phase4-first-byte-traefik"', source)
        self.assertIn('"evidence_origin": "real_host"', source)
        self.assertIn('"connection_reused": bool(results.keepalive_observation["connection_reused"])', source)
        self.assertIn('"phase4_rule_observed_status": results.p4_safe_status', source)
        self.assertIn('"state": "NOT_EXECUTED"', source)
        self.assertIn('"client_visible_abort": False', source)

    def test_p1_alternative_status_is_bound_to_a_real_host_transaction(self) -> None:
        runtime = load_runtime_module()
        source = RUNTIME_SCRIPT.read_text(encoding="utf-8")
        rules = STANDALONE_RULES.read_text(encoding="utf-8")
        self.assertEqual(runtime.CANONICAL_RULE_IDS["p1_alternative"], "1100002")
        self.assertEqual(runtime.STANDALONE_RULE_IDS["p1_alternative"], "1000005")
        self.assertIn("http.HTTPStatus.TOO_MANY_REQUESTS", source)
        self.assertIn('"X-Modsec-Smoke": "alternative-status"', source)
        self.assertIn('"phase1_alternative_status_client_status": results.p1_alternative_status', source)
        self.assertIn('"traefik-native-p1-alternative"', source)
        self.assertIn("P1 alternative outcome is not bound to its host transaction", source)
        self.assertIn("id:1000005,phase:1,deny,status:429", rules)

    def test_p1_allow_event_is_payload_free_and_selected_after_the_p4_barrier(self) -> None:
        runtime = load_runtime_module()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            phase4_event = {
                "connector": "traefik",
                "integration_mode": "native-traefik-middleware",
                "transaction_id": "traefik-native-p4-safe",
                "rule_id": 1100301,
                "phase": 4,
                "requested_action": "deny",
                "actual_action": "log_only",
                "late_intervention": True,
                "late_intervention_mode": "safe",
                "http_status": 403,
                "visible_http_status": 200,
                "headers_sent": True,
                "body_started": True,
                "response_committed": True,
                "connection_aborted": False,
                "transport_result": "log_only",
            }
            runtime.append_jsonl(path, phase4_event)
            runtime.append_allow_host_event(
                path,
                200,
                17,
                "traefik-native-p1-allow",
                1,
                "core-run-1",
            )
            events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

        allow_event = events[-1]
        self.assertEqual(allow_event["connector"], "traefik")
        self.assertEqual(allow_event["integration_mode"], "native-traefik-middleware")
        self.assertEqual(allow_event["run_id"], "core-run-1")
        self.assertEqual(allow_event["transaction_id"], "traefik-native-p1-allow")
        self.assertEqual(allow_event["phase"], 1)
        self.assertEqual(allow_event["http_status"], 200)
        self.assertEqual(allow_event["visible_http_status"], 200)
        self.assertEqual(allow_event["transport_result"], "http_status")
        self.assertNotIn("requested_action", allow_event)
        self.assertNotIn("actual_action", allow_event)
        self.assertNotIn("rule_id", allow_event)
        self.assertNotIn("negotiated_protocol", allow_event)
        self.assertTrue(allow_event["headers_sent"])
        self.assertTrue(allow_event["response_committed"])
        selected = load_trusted_framework_baseline(self).event_for_case(
            events,
            None,
            {"phase": 1, "expected_status": 200},
            transaction_ids=(),
            integration_mode="native-traefik-middleware",
        )
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected["transaction_id"], "traefik-native-p1-allow")
        self.assertEqual(selected["phase"], 1)

    def test_p1_allow_event_rejects_noncausal_client_or_upstream_observation(self) -> None:
        runtime = load_runtime_module()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            with self.assertRaisesRegex(RuntimeError, "HTTP 200"):
                runtime.append_allow_host_event(
                    path, 403, 17, "traefik-native-p1-allow", 1, "core-run-1"
                )
            with self.assertRaisesRegex(RuntimeError, "HTTP 200"):
                runtime.append_allow_host_event(
                    path, 200, 0, "traefik-native-p1-allow", 1, "core-run-1"
                )
            with self.assertRaisesRegex(RuntimeError, "exactly once upstream"):
                runtime.append_allow_host_event(
                    path, 200, 17, "traefik-native-p1-allow", 0, "core-run-1"
                )

    def test_first_byte_host_event_carries_the_exact_canonical_run_id(self) -> None:
        runtime = load_runtime_module()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            phase4_event = {
                "connector": "traefik",
                "integration_mode": "native-traefik-middleware",
                "transaction_id": "traefik-native-p4-safe",
                "rule_id": 1100301,
                "phase": 4,
                "requested_action": "deny",
                "actual_action": "log_only",
                "late_intervention": True,
                "late_intervention_mode": "safe",
                "http_status": 403,
                "original_http_status": 200,
                "visible_http_status": 200,
                "headers_sent": True,
                "body_started": True,
                "response_committed": True,
                "connection_aborted": False,
                "transport_result": "log_only",
            }
            observation = {
                "safe_first_byte_received": True,
                "upstream_paused": True,
                "upstream_eos_sent_at_first_byte": False,
                "first_chunk_size": 27,
            }
            runtime.append_first_byte_host_event(
                path,
                phase4_event,
                observation,
                "traefik-native-p4-safe",
                "1100301",
                55,
                "core-run-1",
            )
            barrier_event = json.loads(path.read_text(encoding="utf-8").strip())

        self.assertEqual(barrier_event["run_id"], "core-run-1")
        self.assertEqual(barrier_event["transaction_id"], "traefik-native-p4-safe")
        self.assertEqual(barrier_event["rule_id"], 1100301)
        self.assertEqual(barrier_event["phase"], 4)
        self.assertTrue(barrier_event["eos_seen"])
        self.assertTrue(barrier_event["end_of_stream_evaluation"])
        self.assertTrue(barrier_event["first_byte_before_response_end"])
        self.assertTrue(barrier_event["no_full_response_buffering"])
        self.assertEqual(barrier_event["negotiated_protocol"], "http1")
        self.assertEqual(barrier_event["transport_case_id"], "phase4-first-byte-traefik")
        record = {
            "connector": "traefik",
            "phase": 4,
            "transaction_ids": ["traefik-native-p4-safe"],
            "expected_rule_id": 1100301,
            "requested_action": "deny",
            "actual_action": "log_only",
            "run_id": "core-run-1",
            "integration_mode": "native-traefik-middleware",
            "negotiated_protocol": "http1",
            "transport_case_id": "phase4-first-byte-traefik",
        }
        self.assertEqual(
            load_trusted_framework_baseline(self).protocol_pass_errors(
                record,
                barrier_event,
                expected_run_id="core-run-1",
                expected_integration_mode="native-traefik-middleware",
            ),
            [],
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
