"""Focused regressions for Apache P1–P4 terminal contract failures."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest


ROOT = connector_root()
MODULE = source_path('connectors/apache/src/mod_security3.c', root=ROOT)
FILTERS = source_path('connectors/apache/src/msc_filters.c', root=ROOT)
HARNESS = source_path('connectors/apache/harness/run_apache_smoke.sh', root=ROOT)


def c_function(source: str, signature: str) -> str:
    """Return one C function body, skipping a declaration when present."""
    start = source.index(signature)
    while True:
        opening_brace = source.index("{", start)
        semicolon = source.index(";", start)
        if opening_brace < semicolon:
            break
        start = source.index(signature, semicolon)

    depth = 0
    for offset, character in enumerate(source[opening_brace:], opening_brace):
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[start : offset + 1]
    raise AssertionError(f"unterminated function: {signature}")


class ApacheTerminalContractFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module_source = MODULE.read_text(encoding="utf-8")
        cls.filters_source = FILTERS.read_text(encoding="utf-8")
        cls.harness_source = HARNESS.read_text(encoding="utf-8")

    def test_p1_metadata_admission_precedes_uri_intervention(self) -> None:
        phase1 = c_function(
            self.module_source,
            "static int process_request_headers(request_rec *r, msc_t *msr)",
        )

        metadata = phase1.index("msc_apache_contract_record_request_metadata(msr, r)")
        begin = phase1.index(
            "msc_apache_contract_begin(msr, MSCONNECTOR_PHASE_REQUEST_HEADERS)"
        )
        uri = phase1.index("msc_process_uri(msr->t,")

        self.assertLess(metadata, begin)
        self.assertLess(begin, uri)
        self.assertGreaterEqual(
            phase1.count("apache_emit_contract_failure_event(msr, r,"), 5
        )

    def test_p2_to_p4_failures_preserve_phase_and_error_class(self) -> None:
        phase2 = c_function(
            self.filters_source,
            "int msc_finalize_request_body(msc_t *msr, request_rec *r)",
        )
        phase3 = c_function(
            self.filters_source,
            "static apr_status_t apache_output_filter_process_headers(",
        )
        phase4 = c_function(
            self.filters_source,
            "static apr_status_t apache_phase4_finish_response_body(",
        )
        fail_closed = c_function(
            self.filters_source,
            "static apr_status_t apache_phase4_fail_closed(",
        )
        failure_event = c_function(
            self.filters_source,
            "static msconnector_error_code apache_emit_contract_failure_event_with_action(",
        )
        failure_name = c_function(
            self.filters_source,
            "static const char *apache_contract_failure_event_name(",
        )

        for phase_source, phase in (
            (phase2, "MSCONNECTOR_PHASE_REQUEST_BODY"),
            (phase3, "MSCONNECTOR_PHASE_RESPONSE_HEADERS"),
            (phase4, "MSCONNECTOR_PHASE_RESPONSE_BODY"),
        ):
            with self.subTest(phase=phase):
                self.assertIn("msr->native_event_phase = " + phase, phase_source)
                self.assertIn("msr->native_event_phase_active = 1;", phase_source)
                self.assertIn("msr->native_event_phase_active = 0;", phase_source)

        # Genuine engine BODY_LIMIT is retained through the canonical first
        # cause; a connector truncation flag must not invent that cause.
        self.assertIn("error_class = msr->contract.error_class;", fail_closed)
        self.assertIn("error_class = MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR;", fail_closed)
        self.assertNotIn("response_body_truncated", fail_closed)
        self.assertIn("msc_apache_contract_fail(msr, error_class)", fail_closed)
        self.assertIn('return "body_limit";', failure_name)
        self.assertIn('return "invalid_engine_response";', failure_name)
        self.assertIn("msr->contract_failure_event_emitted", failure_event)
        self.assertIn('msr->last_intervention_log = "";', failure_event)

    def test_committed_p4_failure_records_abort_and_never_renders_error_document(self) -> None:
        precommit = c_function(
            self.filters_source,
            "static apr_status_t apache_send_precommit_terminal_error(",
        )
        release = c_function(
            self.filters_source,
            "static apr_status_t apache_phase4_release_response_brigade(",
        )
        fail_closed = c_function(
            self.filters_source,
            "static apr_status_t apache_phase4_fail_closed(",
        )
        failure_event = c_function(
            self.filters_source,
            "static msconnector_error_code apache_emit_contract_failure_event_with_action(",
        )

        guard = "if (apache_phase4_response_committed(msr, r))"
        self.assertIn(guard, precommit)
        self.assertLess(precommit.index(guard), precommit.index("ap_die(status, r);"))
        for source in (release, fail_closed):
            with self.subTest(source=source[:64]):
                self.assertIn(
                    "apache_emit_contract_failure_event_with_action(msr, r,", source
                )
                self.assertIn('"abort_connection"', source)
        self.assertIn("apache_phase4_abort_response_connection(f)", release)
        self.assertIn("msr->response_status_snapshot", failure_event)
        self.assertIn("input.response_already_committed = msr->response.committed;", failure_event)

    def test_downstream_failure_harness_requires_a_bounded_transport_abort(self) -> None:
        start = self.harness_source.index("send_phase4_downstream_error_request() {")
        end = self.harness_source.index(
            "\nsend_phase4_upstream_error_request() {", start
        )
        downstream = self.harness_source[start:end]

        self.assertIn('[ "$curl_rc" -ne 0 ]', downstream)
        self.assertIn('[ ! -s "$RESPONSE_HEADERS" ]', downstream)
        self.assertIn('[ ! -s "$RESPONSE_BODY" ]', downstream)
        self.assertIn('"actual_action":"abort_connection"', downstream)
        self.assertIn('"connection_aborted":true', downstream)
        self.assertIn('"transport_result":"connection_aborted"', downstream)
        self.assertIn('grep -F "$HTTP2_PROTOCOL_LABEL"', downstream)
        self.assertIn('grep -E "$CURL_H2_ALPN_ACCEPT_PATTERN"', downstream)
        self.assertNotIn("did not negotiate HTTP/2", downstream)
        self.assertNotIn("downstream_error_expected", downstream)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
