"""Regression contracts for stateful HAProxy SPOP response processing."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition


ROOT = connector_root()
SOURCE = (
    source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
).read_text(encoding="utf-8")
HARNESS = (
    source_path('connectors/haproxy/harness/run_haproxy_spop_cache_miss.sh', root=ROOT)
).read_text(encoding="utf-8")


class HAProxySPOPTransactionCacheContractTests(unittest.TestCase):
    """Keep a cache eviction/mismatch from becoming an implicit allow."""

    def test_missing_stateful_response_transaction_is_fail_closed(self) -> None:
        response = SOURCE.split(
            "static void process_production_response_notify", 1
        )[1].split("static void build_modsecurity_request_from_notify", 1)[0]

        self.assertIn("transaction = transaction_cache_take(state, request->request_id)", response)
        self.assertIn(
            "set_response_correlation_failure(decision, phase)", response
        )
        self.assertIn('"canonical response transaction correlation is missing or expired"', SOURCE)
        self.assertIn('"correlation-failure"', SOURCE)
        self.assertIn('runtime_init_decision(decision, phase, "error", 502', SOURCE)
        self.assertIn("protocol_failure_requires_enforcement(decision_text)", SOURCE)
        self.assertIn('"response_transaction_correlation_missing_closed"', SOURCE)
        self.assertIn("decision_log_write(state, request, decision, 0, *decision_text)", response)
        self.assertNotIn('"pass", 200, "transaction_resumed=false"', response)

    def test_response_processing_remains_bound_to_a_live_cache_entry(self) -> None:
        response = SOURCE.split(
            "static void process_production_response_notify", 1
        )[1].split("static void build_modsecurity_request_from_notify", 1)[0]

        # Legitimate controls must still process response headers/body and
        # finish or re-store the same transaction after successful processing.
        self.assertIn(
            "haproxy_modsecurity_transaction_process_response_headers(", response
        )
        self.assertIn(
            "haproxy_modsecurity_transaction_append_response_body_chunk(", response
        )
        self.assertIn("transaction_cache_store(state, request->request_id, transaction)", response)
        self.assertIn("finish_production_response_transaction(state, request, transaction,", response)
        finish = function_definition(SOURCE, "finish_production_response_transaction")
        self.assertIn("haproxy_modsecurity_transaction_finish_with_decision(transaction, decision) != 0", finish)
        self.assertIn("set_processing_failure(state, decision, phase,", finish)
        self.assertIn("decision_log_write(state, request, decision, 0, *decision_text)", finish)
        self.assertIn("decision, decision_origin, decision_text, modsec_rc)", response)
        self.assertIn("const int phase = request->http_metadata.is_response_body ? 4 : 3;", finish)
        self.assertIn("if (modsec_rc != 0)", finish)
        self.assertIn("haproxy_modsecurity_transaction_abort_with_error(transaction, decision->error_class)", finish)

    def test_request_only_harness_exercises_peer_local_response_guard(self) -> None:
        self.assertIn("set_response_phase_disabled_failure(decision, phase)", SOURCE)
        self.assertIn('runtime_init_decision(decision, phase, "deny", 503', SOURCE)
        self.assertIn('"response_phase_disabled_closed"', SOURCE)
        self.assertIn('"malformed_notify_closed"', SOURCE)
        self.assertIn('"--max-transactions", "1"', HARNESS)
        self.assertNotIn('"--enable-response-headers"', HARNESS)
        self.assertIn('"response-disabled-phase"', HARNESS)
        self.assertIn('"response_phase_disabled_closed"', HARNESS)
        self.assertIn('"request-block"', HARNESS)
        self.assertIn('"request-C-fresh-allow"', HARNESS)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
