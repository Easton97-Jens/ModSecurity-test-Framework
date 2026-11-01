"""Source-contract regression for Apache intervention-owned values."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import re
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()
MODULE = source_path('connectors/apache/src/mod_security3.c', root=ROOT)
FILTERS = source_path('connectors/apache/src/msc_filters.c', root=ROOT)
C17_CHECK = (
    source_path('ci/checks/connectors/apache/check-apache-c-standards.sh', root=ROOT)
)


def c_function(source: str, signature: str) -> str:
    """Return a complete definition, accounting for braces in comments/text."""
    name = signature.split("(", 1)[0].split()[-1].lstrip("*")
    return function_definition(source, name)


class ApacheInterventionCleanupTests(unittest.TestCase):
    def test_request_body_has_full_chunk_accounting_without_policy_defaults(self) -> None:
        bucket = c_function(FILTERS.read_text(encoding="utf-8"),
            "static apr_status_t apache_input_filter_process_bucket(")
        self.assertIn("SIZE_MAX - len", bucket)
        self.assertIn("len > 0 && data == NULL", bucket)
        self.assertIn("msc_apache_contract_record_body(msr, 0, len)", bucket)
        self.assertIn("(const unsigned char *)data, len)", bucket)
        self.assertIn("pending_request_intervention", bucket)
        self.assertLess(bucket.index("msc_apache_contract_record_body"), bucket.index("msc_append_request_body"))
        self.assertLess(bucket.index("process_intervention"), bucket.index("APR_BRIGADE_INSERT_TAIL"))
        self.assertNotIn("body_limit_plan", bucket)
        self.assertNotIn("request_body_limit", bucket)
        self.assertNotIn("body_limit_action", bucket)

    def test_request_metadata_has_no_connector_body_limit(self) -> None:
        metadata = c_function(MODULE.read_text(encoding="utf-8"),
            "int msc_apache_contract_record_request_metadata(")
        self.assertIn("content_type, header_count, header_bytes)", metadata)
        self.assertNotIn("request_body_limit", metadata)
        self.assertNotIn("MSCONNECTOR_MAX_BODY_BUFFER_SIZE", metadata)

    def setUp(self) -> None:
        self.module_source = MODULE.read_text(encoding="utf-8")
        self.filters_source = FILTERS.read_text(encoding="utf-8")
        self.source = function_definition(self.module_source, "process_intervention")
        self.storage = function_definition(self.module_source, "apache_store_native_intervention")
        self.cleanup_helper = function_definition(self.module_source, "msc_release_intervention_buffers")

    def test_successful_interventions_funnel_through_one_cleanup(self) -> None:
        cleanup_call = "msc_release_intervention_buffers(&intervention);"
        self.assertEqual(self.source.count(cleanup_call), 1)
        native = self.source.index("native_result = msc_intervention(t, &intervention);")
        cleanup = self.source.index(cleanup_call)
        self.assertNotIn("return ", self.source[native:cleanup])
        self.assertNotIn("intervention.url", self.source[cleanup:])
        self.assertNotIn("intervention.log", self.source[cleanup:])
        self.assertLess(cleanup, self.source.index("return result;"))
        self.assertLess(self.source.index("apache_store_native_intervention(msr, r, &intervention)"), cleanup)

    def test_cleanup_uses_only_the_legacy_public_intervention_contract(self) -> None:
        self.assertNotIn("msc_intervention_cleanup(&", self.module_source)
        self.assertEqual(self.cleanup_helper.count("free(intervention->url);"), 1)
        self.assertEqual(self.cleanup_helper.count("free(intervention->log);"), 1)
        self.assertIn("intervention->url = NULL;", self.cleanup_helper)
        self.assertIn("intervention->log = NULL;", self.cleanup_helper)
        self.assertIn("intervention->status = N_INTERVENTION_STATUS;", self.cleanup_helper)
        self.assertIn("intervention->pause = 0;", self.cleanup_helper)
        self.assertIn("intervention->disruptive = 0;", self.cleanup_helper)
        self.assertIn("memset(&intervention, 0, sizeof(intervention));", self.source)
        self.assertLess(self.source.index("memset(&intervention"), self.source.index("msc_intervention(t,"))

    def test_log_fallback_does_not_overwrite_the_cleanup_owned_field(self) -> None:
        self.assertIn("log = apr_pstrdup(r->pool, intervention->log == NULL", self.storage)
        self.assertIn('"(no log message was specified)" : intervention->log', self.storage)
        self.assertNotIn('intervention->log = "', self.storage)
        self.assertIn("if (log == NULL)", self.storage)
        self.assertLess(self.storage.index("if (log == NULL)"),
                        self.storage.index("msr->last_intervention_log = log;"))

    def test_no_intervention_preserves_allow_and_now_releases_owned_buffers(self) -> None:
        no_intervention = self.source.index("native_result == 0 && !intervention.disruptive")
        cleanup = self.source.index("msc_release_intervention_buffers(&intervention);")
        self.assertLess(no_intervention, cleanup)
        self.assertIn("result = N_INTERVENTION_STATUS;", self.source[no_intervention:cleanup])
        self.assertNotIn("return N_INTERVENTION_STATUS;", self.source)

    def test_redirect_url_is_request_owned_before_native_cleanup(self) -> None:
        copy = "location = apr_pstrdup(r->pool, intervention->url);"
        assign = 'apr_table_setn(r->headers_out, "Location", location);'
        self.assertIn(copy, self.storage)
        self.assertIn(assign, self.storage)
        self.assertNotIn('apr_table_setn(r->headers_out, "Location", intervention->url);', self.storage)
        self.assertLess(self.storage.index(copy), self.storage.index(assign))
        self.assertIn("location == NULL || r->headers_out == NULL", self.storage)
        self.assertIn("!msr->response.committed && r->bytes_sent == 0", self.storage)
        self.assertIn("return status;", self.storage)
        self.assertNotIn("return HTTP_MOVED_TEMPORARILY;", self.storage)

    def test_native_intervention_status_is_normalized_before_contract_or_sink(self) -> None:
        mapper = function_definition(self.module_source, "msc_apache_contract_record_intervention_decision")
        decision_kind_mapper = function_definition(self.module_source, "apache_intervention_decision_kind")
        self.assertIn('#include "msconnector/intervention.h"', self.module_source)
        normalize = self.storage.index("msconnector_intervention_normalize_status(")
        retained_status = self.storage.index("msr->last_intervention_status =")
        sink = self.storage.index('apr_table_setn(r->headers_out, "Location", location);')
        self.assertLess(normalize, retained_status)
        self.assertLess(retained_status, sink)
        self.assertNotIn("apache_intervention_status_is_valid", self.module_source)
        self.assertIn("status >= HTTP_MULTIPLE_CHOICES", decision_kind_mapper)
        self.assertIn("status < HTTP_BAD_REQUEST", decision_kind_mapper)
        self.assertNotIn("case 301:", mapper)
        self.assertLess(mapper.index("msr->contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE"),
                        mapper.index("msconnector_rule_id_extract_from_message"))
        self.assertIn("native_result != 0 && native_result != 1", self.source)

    def test_p3_intervention_records_a_canonical_terminal_decision_before_sink(self) -> None:
        phase3 = c_function(
            self.filters_source,
            "static apr_status_t apache_output_filter_process_headers(",
        )
        mapper = c_function(
            self.module_source,
            "int msc_apache_contract_record_intervention_decision(msc_t *msr)",
        )
        decision_kind_mapper = c_function(
            self.module_source,
            "static msconnector_transaction_decision_kind apache_intervention_decision_kind(",
        )
        decision_wrapper = c_function(
            self.module_source,
            "int msc_apache_contract_record_decision(",
        )
        failure_wrapper = c_function(
            self.module_source,
            "int msc_apache_contract_fail(",
        )

        complete = phase3.index("msc_apache_contract_complete(msr,")
        record = phase3.index("msc_apache_contract_record_intervention_decision(msr)")
        failure = phase3.index(
            "MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE", record
        )
        event = phase3.index("apache_phase3_log_event(msr, r, wanted, wanted, original_status)")
        sink = phase3.index(
            "apache_send_precommit_terminal_error(msr, filter, brigade,", event
        )
        self.assertLess(complete, record)
        self.assertLess(record, event)
        self.assertLess(event, sink)
        self.assertLess(record, failure)
        self.assertLess(failure, sink)
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE", phase3)
        self.assertIn("char rule_id[MSCONNECTOR_MAX_RULE_ID_LENGTH]", mapper)
        self.assertIn("msconnector_rule_id_extract_from_message", mapper)
        self.assertIn("MSCONNECTOR_TRANSACTION_DECISION_REDIRECT", decision_kind_mapper)
        self.assertIn("MSCONNECTOR_TRANSACTION_DECISION_RATE_LIMIT", decision_kind_mapper)
        self.assertIn("MSCONNECTOR_TRANSACTION_DECISION_BLOCK", decision_kind_mapper)
        self.assertIn("HTTP_TOO_MANY_REQUESTS", decision_kind_mapper)
        self.assertIn("status >= HTTP_MULTIPLE_CHOICES", decision_kind_mapper)
        self.assertIn("status < HTTP_BAD_REQUEST", decision_kind_mapper)
        self.assertNotIn("case 301:", decision_kind_mapper)
        self.assertIn("apache_intervention_decision_kind", mapper)
        self.assertIn("msc_apache_contract_record_decision(msr, kind, rule_id)", mapper)
        self.assertIn("msconnector_transaction_contract_record_decision", decision_wrapper)
        self.assertIn("apache_contract_now_ms()", decision_wrapper)
        self.assertIn("msconnector_transaction_contract_fail", failure_wrapper)
        self.assertIn("apache_contract_now_ms()", failure_wrapper)

    def test_changed_translation_unit_and_regression_are_in_required_wiring(self) -> None:
        source_list = C17_CHECK.read_text(encoding="utf-8")
        makefile = (source_path('Makefile', root=ROOT)).read_text(encoding="utf-8")
        lint_match = re.search(
            r"^lint:[^\n]*\n(?P<body>(?:\t.*\n)+)", makefile, re.MULTILINE
        )

        self.assertIn("connectors/apache/src/mod_security3.c", source_list)
        self.assertIn("check-apache-intervention-cleanup:", makefile)
        self.assertIsNotNone(lint_match)
        self.assertIn(
            "$(MAKE) check-apache-intervention-cleanup", lint_match.group("body")
        )



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
