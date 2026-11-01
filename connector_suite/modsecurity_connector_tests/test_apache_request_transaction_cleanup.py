"""Regression contract for Apache request-owned ModSecurity transactions."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest


ROOT = connector_root()
MODULE = source_path('connectors/apache/src/mod_security3.c', root=ROOT)
HEADER = source_path('connectors/apache/src/mod_security3.h', root=ROOT)
UTILS = source_path('connectors/apache/src/msc_utils.c', root=ROOT)
FILTERS = source_path('connectors/apache/src/msc_filters.c', root=ROOT)
C17_CHECK = (
    source_path('ci/checks/connectors/apache/check-apache-c-standards.sh', root=ROOT)
)
AUTOTOOLS_BOOTSTRAP = (
    source_path('ci/checks/connectors/apache/check-apache-autotools-bootstrap.sh', root=ROOT)
)


def c_function(source: str, signature: str) -> str:
    """Return one complete C function body without matching nearby tokens."""
    start = source.index(signature)
    while True:
        body_start = start + len(signature)
        while body_start < len(source) and source[body_start].isspace():
            body_start += 1
        if body_start < len(source) and source[body_start] == "{":
            break
        start = source.index(signature, body_start)
    opening_brace = source.index("{", start)
    depth = 0
    for index in range(opening_brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"incomplete C function: {signature}")


class ApacheRequestTransactionCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = MODULE.read_text(encoding="utf-8")
        self.header = HEADER.read_text(encoding="utf-8")
        self.utils = UTILS.read_text(encoding="utf-8")
        self.filters = FILTERS.read_text(encoding="utf-8")
        self.create_context = c_function(
            self.module,
            "static apache_tx_context_result create_tx_context(request_rec *r, msc_t **out,\n"
            "    const char **failure_reason)",
        )
        self.store_transaction_id = c_function(
            self.module,
            "static int apache_store_transaction_id(msc_t *msr, request_rec *r,\n"
            "    const char *transaction_id, const char **failure_reason)",
        )
        self.transaction_id_expression = c_function(
            self.module,
            "static int apache_transaction_id_from_expression(request_rec *r,\n"
            "    const msc_conf_t *config, const char **transaction_id)",
        )
        self.transaction_id_resolution = c_function(
            self.module,
            "static int apache_resolve_transaction_id(request_rec *r, const msc_conf_t *config,\n"
            "    const char **transaction_id, const char **failure_reason)",
        )
        self.request_headers = c_function(
            self.module,
            "static int process_request_headers(request_rec *r, msc_t *msr)",
        )
        phase1_start = self.module.index(
            "static int apache_emit_phase1_intervention_event"
        )
        phase1_end = self.module.index(
            "static int process_request_headers", phase1_start
        )
        self.phase1_intervention = self.module[phase1_start:phase1_end]
        self.cleanup = c_function(
            self.utils, "apr_status_t msc_cleanup_request_transaction(void *data)"
        )
        self.output_filter = c_function(
            self.filters,
            "apr_status_t output_filter(ap_filter_t *f, apr_bucket_brigade *bb_in)",
        )

    def test_failed_native_transaction_is_never_published(self) -> None:
        failure_check = self.create_context.index("if (msr->t == NULL)")
        publish = self.create_context.index("store_tx_context(msr, r);")

        self.assertLess(failure_check, publish)
        self.assertIn(
            "return APACHE_TX_CONTEXT_RESULT_ERROR;",
            self.create_context[failure_check:publish],
        )

    def test_contract_initialization_precedes_native_transaction_allocation(self) -> None:
        contract_init = self.create_context.index(
            "msconnector_transaction_contract_init("
        )
        native_with_id = self.create_context.index("msc_new_transaction_with_id(")
        native_without_id = self.create_context.index("msc_new_transaction(")
        validated_copy = self.create_context.index(
            "modsecurity_transaction_id = apr_pstrdup(r->pool,\n"
            "            msr->event_transaction_id);"
        )
        registration = self.create_context.index("apr_pool_cleanup_register(r->pool, msr,")

        self.assertLess(contract_init, validated_copy)
        self.assertLess(contract_init, native_with_id)
        self.assertLess(contract_init, native_without_id)
        self.assertLess(native_with_id, registration)
        self.assertLess(native_without_id, registration)

    def test_request_derived_identifier_is_bounded_before_apr_pool_copy(self) -> None:
        bound_check = self.store_transaction_id.index(
            "transaction_id[length] != '\\0'"
        )
        pool_copy = self.store_transaction_id.index(
            "msr->event_transaction_id = apr_pstrdup(r->pool, transaction_id);"
        )
        contract_init = self.create_context.index(
            "msconnector_transaction_contract_init("
        )
        store_helper = self.create_context.index(
            "if (!apache_store_transaction_id(msr, r, transaction_id, failure_reason))"
        )

        self.assertIn(
            "MSCONNECTOR_MAX_TRANSACTION_ID_LENGTH", self.store_transaction_id
        )
        self.assertIn(
            "transaction identifier exceeds canonical limit", self.store_transaction_id
        )
        self.assertLess(bound_check, pool_copy)
        self.assertLess(store_helper, contract_init)

    def test_unpublished_contract_is_cleaned_when_native_allocation_cannot_continue(self) -> None:
        native_failure = self.create_context.index("if (msr->t == NULL)")
        contract_cleanup = self.create_context.index(
            "msconnector_transaction_contract_cleanup(&msr->contract,", native_failure
        )
        initialized_clear = self.create_context.index(
            "msr->contract_initialized = 0;", contract_cleanup
        )
        failure_return = self.create_context.index(
            "return APACHE_TX_CONTEXT_RESULT_ERROR;", initialized_clear
        )
        registration = self.create_context.index("apr_pool_cleanup_register(r->pool, msr,")

        self.assertLess(native_failure, contract_cleanup)
        self.assertLess(contract_cleanup, initialized_clear)
        self.assertLess(initialized_clear, failure_return)
        self.assertLess(failure_return, registration)

    def test_successful_context_is_registered_once_on_owner_request_pool(self) -> None:
        publish = self.create_context.index("store_tx_context(msr, r);")
        registration = self.create_context.index("apr_pool_cleanup_register(r->pool, msr,")

        self.assertLess(publish, registration)
        self.assertEqual(self.create_context.count("apr_pool_cleanup_register("), 1)
        self.assertIn(
            "msc_cleanup_request_transaction, apr_pool_cleanup_null);",
            self.create_context[registration:],
        )
        self.assertIn("*out = msr;", self.create_context[registration:])
        self.assertIn(
            "return APACHE_TX_CONTEXT_RESULT_READY;", self.create_context[registration:]
        )

    def test_context_creation_distinguishes_disabled_from_enabled_failures(self) -> None:
        late_hook = c_function(self.module, "static int hook_request_late(request_rec *r)")

        self.assertIn("APACHE_TX_CONTEXT_RESULT_DISABLED", self.module)
        self.assertIn("APACHE_TX_CONTEXT_RESULT_READY", self.module)
        self.assertIn("APACHE_TX_CONTEXT_RESULT_ERROR", self.module)
        self.assertIn(
            "context_result = create_tx_context(r, &msr, &context_failure);",
            late_hook,
        )
        disabled = late_hook.index("APACHE_TX_CONTEXT_RESULT_DISABLED")
        fail_closed = late_hook.index("return apache_fail_closed(r, context_failure);")
        self.assertLess(disabled, fail_closed)

    def test_context_creation_clears_an_output_pointer_before_input_rejection(self) -> None:
        output_clear = self.create_context.index("if (out != NULL) {\n        *out = NULL;")
        input_rejection = self.create_context.index(
            "if (out == NULL || failure_reason == NULL || r == NULL)"
        )

        self.assertLess(output_clear, input_rejection)

    def test_expression_errors_are_terminal_but_empty_results_keep_fallback(self) -> None:
        expression_failure = self.transaction_id_expression.index("if (expr_error != NULL)")
        expression_return = self.transaction_id_expression.index(
            "return 0;", expression_failure
        )
        fallback = self.transaction_id_resolution.index(
            "if (resolved == NULL || resolved[0] == '\\0')"
        )

        self.assertNotIn("ap_log_rerror", self.transaction_id_expression)
        self.assertIn(
            "failed to evaluate transaction identifier expression",
            self.transaction_id_resolution,
        )
        self.assertLess(expression_failure, expression_return)
        self.assertIn("resolved = getenv(\"UNIQUE_ID\");", self.transaction_id_resolution[fallback:])

    def test_context_failures_log_once_through_the_fail_closed_gate(self) -> None:
        late_hook = c_function(self.module, "static int hook_request_late(request_rec *r)")

        for source in (
            self.transaction_id_expression,
            self.transaction_id_resolution,
            self.store_transaction_id,
            self.create_context,
        ):
            self.assertNotIn("ap_log_rerror", source)
        self.assertEqual(
            late_hook.count("return apache_fail_closed(r, context_failure);"), 1
        )

    def test_native_bootstrap_exercises_transaction_identifier_boundaries(self) -> None:
        bootstrap = AUTOTOOLS_BOOTSTRAP.read_text(encoding="utf-8")

        self.assertIn("HTTP_STATUS_FORMAT='%{http_code}'", bootstrap)
        self.assertEqual(bootstrap.count('-w "$HTTP_STATUS_FORMAT"'), 6)
        self.assertNotIn("-w '%{http_code}'", bootstrap)
        self.assertIn("TXID_127_PATH=$(txid_path_for_length 127)", bootstrap)
        self.assertIn("TXID_128_PATH=$(txid_path_for_length 128)", bootstrap)
        self.assertIn("TXID_LONG_PATH=$(txid_path_for_length 192)", bootstrap)
        self.assertIn('modsecurity_transaction_id_expr "%{REQUEST_URI}"', bootstrap)
        self.assertIn("txid_128_status", bootstrap)
        self.assertIn("Connection: close", bootstrap)
        self.assertIn("reached the Apache document handler", bootstrap)
        self.assertIn("txid_failure_count", bootstrap)

    def test_cleanup_invalidates_native_and_owner_context_before_destroy(self) -> None:
        self.assertIn("request_rec *owner_request;", self.header)
        self.assertIn("owner_request = msr->owner_request;", self.cleanup)
        self.assertIn("msr->owner_request = NULL;", self.cleanup)
        self.assertIn("transaction = msr->t;", self.cleanup)
        self.assertIn("msr->t = NULL;", self.cleanup)
        self.assertIn("ap_set_module_config(owner_request->request_config, &security3_module,", self.cleanup)
        self.assertIn("if (transaction != NULL)", self.cleanup)
        self.assertIn("msc_transaction_cleanup(transaction);", self.cleanup)
        self.assertNotIn("msr->r", self.cleanup)

        pointer_clear = self.cleanup.index("msr->t = NULL;")
        owner_clear = self.cleanup.index("ap_set_module_config(owner_request->request_config, &security3_module,")
        native_destroy = self.cleanup.index("msc_transaction_cleanup(transaction);")
        self.assertLess(pointer_clear, native_destroy)
        self.assertLess(owner_clear, native_destroy)

    def test_primary_request_ownership_preserves_existing_redirect_and_subrequest_rules(self) -> None:
        late_hook = c_function(self.module, "static int hook_request_late(request_rec *r)")
        retrieve = c_function(self.module, "static msc_t *retrieve_tx_context(request_rec *r)")

        self.assertIn("if ((r->main != NULL) || (r->prev != NULL))", late_hook)
        self.assertIn("apache_request_context(r->main)", retrieve)
        self.assertIn("rx = r->prev;", retrieve)
        self.assertIn("msr->r = r;", retrieve)

    def test_c17_check_compiles_the_cleanup_helper(self) -> None:
        source_list = C17_CHECK.read_text(encoding="utf-8")
        self.assertIn("connectors/apache/src/msc_utils.c", source_list)

    def test_unread_request_body_failure_returns_before_response_headers(self) -> None:
        drain = self.output_filter.index(
            "apr_status_t request_body_rc = apache_finish_unread_request_body(f);"
        )
        failure_check = self.output_filter.index(
            "if (request_body_rc != APR_SUCCESS)", drain
        )
        failure_return = self.output_filter.index("return request_body_rc;", failure_check)
        response_headers = self.output_filter.index(
            "rc = apache_output_filter_process_headers(msr, r, f, bb_in);"
        )

        self.assertNotIn(
            "apr_status_t rc = apache_finish_unread_request_body(f);",
            self.output_filter,
        )
        self.assertLess(drain, failure_check)
        self.assertLess(failure_check, failure_return)
        self.assertLess(failure_return, response_headers)

    def test_phase1_intervention_logging_shares_one_bounded_event_writer(self) -> None:
        self.assertEqual(
            self.phase1_intervention.count("apache_emit_intervention_event("), 1
        )
        self.assertIn(
            'event_input.event_name = "phase1_intervention";',
            self.phase1_intervention,
        )
        self.assertIn(
            "event_input.phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;",
            self.phase1_intervention,
        )
        self.assertIn(
            '"request_uri_before_request_headers"', self.request_headers
        )
        self.assertIn('"request_headers_before_handler"', self.request_headers)
        self.assertEqual(
            self.request_headers.count(
                "apache_emit_phase1_intervention_event(msr, r, it,"
            ),
            2,
        )

    def test_contract_records_apache_lifecycle_timestamps_without_inferring_order(self) -> None:
        clock = c_function(self.module, "static uint64_t apache_contract_now_ms(void)")
        self.assertIn("apr_time_now()", clock)
        self.assertIn("APR_USEC_PER_SEC / 1000", clock)
        self.assertIn("if (now <= 0)", clock)
        self.assertIn("Common FSM", clock)
        self.assertNotIn("return 0U;\n}", clock)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
