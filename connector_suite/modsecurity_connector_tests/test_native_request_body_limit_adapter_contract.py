"""Regression contract for native P2 body-limit host translations."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition


ROOT = connector_root()
APACHE = source_path('connectors/apache/src/mod_security3.c', root=ROOT)
APACHE_FILTERS = source_path('connectors/apache/src/msc_filters.c', root=ROOT)
NGINX = source_path('connectors/nginx/src/ngx_http_modsecurity_module.c', root=ROOT)
NGINX_ACCESS = source_path('connectors/nginx/src/ngx_http_modsecurity_access.c', root=ROOT)
HAPROXY = source_path('connectors/haproxy/src/haproxy_modsecurity_binding.c', root=ROOT)
HAPROXY_SPOP = (
    source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
)


class NativeRequestBodyLimitAdapterContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.apache = APACHE.read_text(encoding="utf-8")
        cls.apache_filters = APACHE_FILTERS.read_text(encoding="utf-8")
        cls.nginx = NGINX.read_text(encoding="utf-8")
        cls.nginx_access = NGINX_ACCESS.read_text(encoding="utf-8")
        cls.haproxy = HAPROXY.read_text(encoding="utf-8")
        cls.haproxy_spop = HAPROXY_SPOP.read_text(encoding="utf-8")

    def test_apache_classifies_before_rule_id_correlation(self) -> None:
        collector = function_definition(self.apache, "process_intervention")
        intervention = function_definition(self.apache, "apache_store_native_intervention")
        self.assertIn("apache_store_native_intervention(msr, r, &intervention)", collector)
        mapper = function_definition(
            self.apache, "msc_apache_contract_record_intervention_decision"
        )
        phase2 = function_definition(self.apache_filters, "msc_finalize_request_body")

        classifier = intervention.index(
            "msconnector_intervention_is_request_body_limit_rejection"
        )
        normalize = intervention.index("msconnector_intervention_normalize_status")
        self.assertLess(classifier, normalize)
        self.assertIn("status = msconnector_intervention_normalize_status(intervention->url,", intervention)
        self.assertIn("intervention->status, default_block_status)", intervention)
        self.assertIn("msr->last_intervention_body_limit = body_limit ||", intervention)
        self.assertNotIn("HTTP_REQUEST_ENTITY_TOO_LARGE", intervention)
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT", mapper)
        self.assertLess(
            mapper.index("MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT"),
            mapper.index("msconnector_rule_id_extract_from_message"),
        )
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT", phase2)
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT,\n                msr->last_intervention_status)", phase2)
        self.assertNotIn("HTTP_REQUEST_ENTITY_TOO_LARGE", phase2)

    def test_nginx_classifies_before_rule_id_correlation_and_emits_body_limit(self) -> None:
        intervention = function_definition(
            self.nginx, "ngx_http_modsecurity_process_intervention"
        )
        mapper = function_definition(
            self.nginx, "ngx_http_modsecurity_contract_record_intervention"
        )
        event = function_definition(
            self.nginx_access, "ngx_http_modsecurity_request_intervention_log_event"
        )

        classifier = intervention.index(
            "msconnector_intervention_is_request_body_limit_rejection"
        )
        normalize = intervention.index("msconnector_intervention_normalize_status")
        retained = intervention.index(
            "ctx->native_request_body_limit_rejection =", classifier
        )
        self.assertLess(classifier, normalize)
        self.assertLess(retained, normalize)
        self.assertIn("intervention.status = msconnector_intervention_normalize_status(intervention.url,", intervention)
        self.assertIn("ctx->last_intervention_status = intervention.status;", intervention)
        self.assertNotIn("NGX_HTTP_REQUEST_ENTITY_TOO_LARGE", intervention)
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT", mapper)
        self.assertLess(
            mapper.index("MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT"),
            mapper.index("ctx->last_intervention_rule_id"),
        )
        self.assertIn("MSCONN_EVENT_BODY_LIMIT", event)
        self.assertIn('"body_limit"', event)
        self.assertIn('event.body.limit_outcome = body_limit ? "reject" : NULL;', event)

    def test_haproxy_preserves_the_exact_marker_through_legacy_spop(self) -> None:
        capture = function_definition(self.haproxy, "capture_intervention")
        mapper = function_definition(self.haproxy, "record_contract_decision")
        native_self_test = function_definition(
            self.haproxy, "haproxy_modsecurity_request_body_limit_self_test"
        )
        request_body_self_test = function_definition(
            self.haproxy, "haproxy_modsecurity_request_body_self_test"
        )
        legacy_ack = function_definition(self.haproxy_spop, "send_legacy_decision_ack")

        self.assertIn("msconnector_intervention_is_request_body_limit_rejection", capture)
        self.assertIn("decision->body_limit", capture)
        self.assertIn("decision->status = intervention.status;", capture)
        self.assertNotIn("decision->status = 413;", capture)
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT", mapper)
        self.assertLess(
            mapper.index("MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT"),
            mapper.index("msconnector_decision_init(&common)"),
        )
        self.assertIn("SecRequestBodyLimit 8", native_self_test)
        self.assertIn("SecRequestBodyLimitAction Reject", native_self_test)
        self.assertIn("decision->body_limit != 0", native_self_test)
        self.assertIn("decision->status == 403", native_self_test)
        self.assertIn("decision->rule_id == 0", native_self_test)
        self.assertIn(
            "return haproxy_modsecurity_request_body_limit_self_test(decision);",
            request_body_self_test,
        )
        self.assertIn("decision->body_limit == 0", legacy_ack)
        self.assertIn("build_set_var_blocked_payload", legacy_ack)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
