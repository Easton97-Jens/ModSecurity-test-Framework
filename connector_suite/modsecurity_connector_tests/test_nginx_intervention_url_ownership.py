from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import re
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition


ROOT = connector_root()
MODULE = source_path('connectors/nginx/src/ngx_http_modsecurity_module.c', root=ROOT)


class NginxInterventionUrlOwnershipTests(unittest.TestCase):
    def setUp(self) -> None:
        module = MODULE.read_text(encoding="utf-8")
        self.intervention = function_definition(
            module, "ngx_http_modsecurity_process_intervention"
        )
        self.redirect = function_definition(
            module, "ngx_http_modsecurity_process_redirect_intervention"
        )

    def test_intervention_ownership_transfer_and_final_cleanup(self) -> None:
        self.assertIn("ngx_memzero(&intervention, sizeof(intervention));", self.intervention)
        self.assertIn("intervention.status = 200;", self.intervention)
        self.assertNotIn("free(intervention.log)", self.intervention)
        # EOS may replace its result with the previously captured native owner.
        # That result is released before the move; only the moved owner reaches
        # the final cleanup after all extraction and host delivery decisions.
        transfer = """if (ctx->native_event_phase == MSCONNECTOR_PHASE_REQUEST_BODY &&
        ctx->request_intervention_pending) {
        msc_intervention_cleanup(&intervention);
        intervention = ctx->pending_request_intervention;
        ngx_memzero(&ctx->pending_request_intervention,
            sizeof(ctx->pending_request_intervention));
        ctx->request_intervention_pending = 0;
        native_result = 1;
    }"""
        self.assertIn(transfer, self.intervention)
        self.assertEqual(
            self.intervention.count("msc_intervention_cleanup(&intervention);"), 2
        )
        self.assertEqual(
            self.intervention.replace(transfer, "").count("msc_intervention_cleanup(&intervention);"), 1
        )

        cleanup = self.intervention.rindex("msc_intervention_cleanup(&intervention);")
        self.assertNotIn("intervention.url", self.intervention[cleanup:])
        self.assertNotIn("intervention.log", self.intervention[cleanup:])
        self.assertEqual(
            re.findall(r"\breturn\s+[^;]+;", self.intervention),
            ["return result;"],
        )

    def test_redirect_location_is_owned_before_the_wrapper_cleans_up(self) -> None:
        self.assertIn(
            "if (msconnector_intervention_has_redirect_url(intervention.url))",
            self.intervention,
        )
        call = self.intervention.index(
            "result = ngx_http_modsecurity_process_redirect_intervention"
        )
        cleanup = self.intervention.rindex("msc_intervention_cleanup(&intervention);")
        self.assertLess(call, cleanup)
        self.assertIn("goto cleanup;", self.intervention[call:cleanup])

        self.assertIn("location_value.len = ngx_strlen(intervention->url);", self.redirect)
        self.assertIn(
            "redirect_url = (const u_char *) intervention->url;", self.redirect
        )
        self.assertIn(
            "if (redirect_url[i] == '\\r' || redirect_url[i] == '\\n')",
            self.redirect,
        )
        self.assertIn("if (location_value.len > NGX_MAX_SIZE_T_VALUE - 1U)", self.redirect)
        self.assertIn(
            "location_value.data = ngx_pnalloc(r->pool, location_value.len + 1U);",
            self.redirect,
        )
        self.assertIn(
            "ngx_memcpy(location_value.data, intervention->url, location_value.len);",
            self.redirect,
        )
        self.assertIn("location_value.data[location_value.len] = '\\0';", self.redirect)
        self.assertIn("location->value = location_value;", self.redirect)
        self.assertNotIn("location->value = a;", self.redirect)
        self.assertNotIn("(unsigned char *)intervention.url", self.redirect)

        self.assertLess(
            self.redirect.index("location_value.data = ngx_pnalloc"),
            self.redirect.index("location->value = location_value;"),
        )
        crlf_rejection = self.redirect.index(
            "if (redirect_url[i] == '\\r' || redirect_url[i] == '\\n')"
        )
        self.assertIn("return NGX_HTTP_BAD_REQUEST;", self.redirect[crlf_rejection:])
        self.assertLess(
            crlf_rejection, self.redirect.index("location_value.data = ngx_pnalloc")
        )
        self.assertLess(
            crlf_rejection, self.redirect.index("location->value = location_value;")
        )

    def test_redirect_helper_reports_failures_to_the_cleanup_wrapper(self) -> None:
        expected_returns = {
            "if (r->header_sent)": "return -1;",
            "if (location_value.len > NGX_MAX_SIZE_T_VALUE - 1U)": (
                "return NGX_HTTP_INTERNAL_SERVER_ERROR;"
            ),
            "if (redirect_url[i] == '\\r' || redirect_url[i] == '\\n')": (
                "return NGX_HTTP_BAD_REQUEST;"
            ),
            "if (location_value.data == NULL)": "return NGX_HTTP_INTERNAL_SERVER_ERROR;",
            "if (location == NULL)": "return NGX_HTTP_INTERNAL_SERVER_ERROR;",
        }
        for condition, result in expected_returns.items():
            with self.subTest(condition=condition):
                start = self.redirect.index(condition)
                self.assertIn(result, self.redirect[start:])

        self.assertIn("ngx_http_clear_location(r);", self.redirect)
        self.assertIn("return intervention->status;", self.redirect)

    def test_native_intervention_status_is_normalized_before_host_delivery(self) -> None:
        self.assertIn('#include "msconnector/intervention.h"', MODULE.read_text(encoding="utf-8"))
        normalize = self.intervention.index("msconnector_intervention_normalize_status(")
        retained_status = self.intervention.index("ctx->last_intervention_status =")
        redirect = self.intervention.index(
            "if (msconnector_intervention_has_redirect_url(intervention.url))"
        )
        status = self.intervention.index("ngx_http_modsecurity_process_status_intervention")
        self.assertLess(normalize, retained_status)
        self.assertLess(retained_status, redirect)
        self.assertLess(redirect, status)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
