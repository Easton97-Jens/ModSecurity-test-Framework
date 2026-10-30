"""Focused static contracts for HTX/MRC1 correlation and fail-closed paths."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest


SOURCE = Path(__file__).with_name("haproxy_modsecurity_htx_filter.c")
HARNESS = source_path('connectors/haproxy') / "harness" / "run_haproxy_smoke.sh"


class ResponseHandleContractTest(unittest.TestCase):
    def test_response_handle_is_bounded_and_lower_hex_only(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("HAPROXY_MODSECURITY_HTX_RESPONSE_HANDLE_LENGTH 64U", source)
        self.assertIn('txn.modsec.response_handle', source)
        self.assertIn("length != HAPROXY_MODSECURITY_HTX_RESPONSE_HANDLE_LENGTH", source)
        self.assertIn("character >= 'a' && character <= 'f'", source)
        self.assertIn("ctx->response.handle_present", source)


    def test_companion_path_uses_the_typed_mrc1_client(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('#include "response_companion_client.h"', source)
        self.assertIn("response-companion-socket", source)
        self.assertIn("msconnector_response_companion_client_claim", source)
        self.assertIn("msconnector_response_companion_client_response_headers", source)
        self.assertIn("msconnector_response_companion_client_commit", source)
        self.assertIn("msconnector_response_companion_client_body_chunk", source)
        self.assertIn("msconnector_response_companion_client_body_eos", source)
        self.assertIn("msconnector_response_companion_client_outcome", source)
        self.assertIn("msconnector_response_companion_client_release", source)
        self.assertIn(
            "msconnector_response_companion_client_cancel_with_cause", source
        )
        self.assertIn(
            "MSCONNECTOR_RESPONSE_COMPANION_CANCEL_CONNECTOR_ERROR", source
        )
        self.assertNotIn(
            "msconnector_response_companion_client_cancel(\n", source
        )

    def test_companion_error_mapping_preserves_supported_failure_classes(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn(
            "haproxy_modsecurity_htx_companion_cancel_cause_from_error", source
        )
        self.assertIn("MSCONNECTOR_ERROR_TIMEOUT", source)
        self.assertIn("MSCONNECTOR_ERROR_RUNTIME_UNAVAILABLE", source)
        self.assertIn("MSCONNECTOR_ERROR_PROTOCOL", source)
        self.assertIn("MSCONNECTOR_ERROR_PHASE_SEQUENCE", source)
        self.assertIn("MSCONNECTOR_ERROR_CORRELATION_EXPIRED", source)
        self.assertIn(
            "return MSCONNECTOR_RESPONSE_COMPANION_CANCEL_CONNECTOR_ERROR;",
            source,
        )
        self.assertIn(
            "haproxy_modsecurity_htx_companion_cancel_and_close(ctx, &error);",
            source,
        )

    def test_typed_cancel_preserves_the_source_error_while_using_a_separate_io_error(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index(
            "static int haproxy_modsecurity_htx_companion_cancel_and_close("
        )
        end = source.index("\n}\n", start) + 3
        helper = source[start:end]
        self.assertIn("const msconnector_error *error", helper)
        self.assertIn("msconnector_error cancel_error;", helper)
        self.assertIn(
            "haproxy_modsecurity_htx_companion_cancel_cause_from_error(error)",
            helper,
        )
        self.assertIn("&result, &cancel_error", helper)
        self.assertNotIn("msconnector_error error;", helper)

    def test_companion_path_does_not_copy_mrc1_framing(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("MRC1_RESPONSE_", source)
        self.assertNotIn("MRC1_CLAIM", source)
        self.assertNotIn("socket(", source)
        self.assertNotIn("send(", source)
        self.assertNotIn("recv(", source)

    def test_companion_never_creates_a_second_direct_request_transaction(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("SPOP owns P1/P2 in companion mode", source)
        self.assertIn("would split one logical transaction across two engines", source)
        self.assertIn("if (ctx->companion.mode) {\n        /* SPOP owns P1/P2", source)

    def test_header_and_body_failures_have_host_actions(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("haproxy_modsecurity_htx_fail_closed_precommit", source)
        self.assertIn("haproxy_modsecurity_htx_fail_closed_postcommit", source)
        self.assertIn('"request headers"', source)
        self.assertIn('"request body"', source)
        self.assertIn('"response body"', source)
        self.assertIn("http_reply_and_close(s, 503", source)
        self.assertIn("stream_shutdown(s, SF_ERR_KILLED)", source)

    def test_missing_phase_endings_and_direct_p3_fail_closed(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("response headers without request transaction", source)
        self.assertIn("request body eos without request phase", source)
        self.assertIn("response body eos without response phase", source)
        self.assertIn(
            "response-companion body eos without response phase", source
        )
        self.assertIn("duplicate request body eos", source)
        self.assertIn("duplicate response body eos", source)
        self.assertIn("duplicate response-companion body eos", source)

    def test_direct_disruptive_precommit_decisions_never_disable_and_forward(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn(
            "haproxy_modsecurity_htx_apply_precommit_decision_or_fail_closed",
            source,
        )
        self.assertIn('"request disruptive decision"', source)
        self.assertIn('"request-body disruptive decision"', source)
        self.assertIn('"response-header disruptive decision"', source)
        self.assertIn(
            "every other disruptive precommit decision to the deterministic 503 path",
            source,
        )

    def test_direct_phase4_safe_is_log_only_and_strict_requests_abort(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('host_action = action == MSCONNECTOR_LATE_INTERVENTION_LOG_ONLY', source)
        self.assertIn('? "log_only" : "abort_connection"', source)
        self.assertIn("if (late_action != MSCONNECTOR_LATE_INTERVENTION_LOG_ONLY)", source)
        self.assertIn("MSCONNECTOR_PHASE4_MODE_STRICT", source)
        self.assertIn("stream_shutdown(s, SF_ERR_KILLED)", source)

    def test_direct_headers_use_common_limits_and_reject_embedded_nuls(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("MSCONNECTOR_MAX_HEADER_NAME_LENGTH", source)
        self.assertIn("MSCONNECTOR_MAX_HEADER_VALUE_LENGTH", source)
        self.assertIn("MSCONNECTOR_MAX_TOTAL_HEADER_BYTES", source)
        self.assertIn("total_header_bytes", source)
        self.assertIn("memchr(name.ptr, '\\0', name.len)", source)
        self.assertIn("memchr(value.ptr, '\\0', value.len)", source)
        self.assertNotIn("HAPROXY_MODSECURITY_HTX_MAX_HEADER_BYTES", source)

    def test_request_phase_is_single_and_uses_host_generated_identity(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('"duplicate request headers"', source)
        self.assertIn('"haproxy-htx-%u"', source)
        self.assertNotIn('strcasecmp(header->name, "x-request-id")', source)

    def test_companion_request_callbacks_require_one_local_p1_then_p2(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("!ctx->request.headers_seen || ctx->request.finished", source)
        self.assertIn(
            "response-companion request payload outside active request phase",
            source,
        )
        self.assertIn(
            "response-companion request body eos without request phase", source
        )
        self.assertIn("duplicate request headers", source)
        self.assertIn("duplicate request body eos", source)

    def test_legitimate_bounded_body_path_remains_forward_first(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_MAX_BODY_CHUNK", source)
        self.assertIn("while (data_size != 0U)", source)
        self.assertIn("return (int)len;", source)

    def test_postcommit_body_failure_never_reports_borrowed_slice_as_forwarded(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn(
            'haproxy_modsecurity_htx_fail_closed_postcommit(s, ctx,\n'
            '                "response-companion body");\n            return -1;',
            source,
        )
        self.assertIn('haproxy_modsecurity_htx_fail_closed_postcommit(s, ctx, ', source)
        self.assertIn('"response body");', source)
        self.assertGreaterEqual(source.count("if (ctx->lifecycle.disabled)"), 4)

    def test_normal_terminal_path_releases_without_a_host_outcome(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("Allow and ordinary log-only results have no host action", source)
        self.assertIn("if (record_host_action)", source)
        self.assertIn("msconnector_response_companion_client_release", source)

    def test_companion_strict_p4_uses_native_stream_shutdown(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("static int haproxy_modsecurity_htx_finish_companion_response(")
        end = source.index("static int haproxy_modsecurity_htx_filter_init(", start)
        companion_finish = source[start:end]
        self.assertIn("strict_mode", companion_finish)
        self.assertIn("MSCONNECTOR_PHASE4_MODE_STRICT", companion_finish)
        self.assertIn("DECISION_ACTION_ABORT_CONNECTION", companion_finish)
        self.assertIn("connection_aborted = actual_action ==", companion_finish)
        self.assertIn("record_host_action", companion_finish)
        self.assertIn("if (connection_aborted)", companion_finish)
        self.assertIn("haproxy_modsecurity_htx_fail_closed_postcommit(s, ctx,", companion_finish)
        start = source.index("static void haproxy_modsecurity_htx_fail_closed_postcommit(")
        end = source.index("\n}\n", start) + 3
        self.assertIn("stream_shutdown(s, SF_ERR_KILLED)", source[start:end])


    def test_spop_ack_registers_response_handle(self) -> None:
        harness = HARNESS.read_text(encoding="utf-8")
        self.assertIn(
            "register-var-names blocked action status redirect_url rule_id phase error response_handle",
            harness,
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
