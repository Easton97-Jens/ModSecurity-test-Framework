"""Regression contract for native HAProxy HTX payload-failure handling."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import unittest
from pathlib import Path
from modsecurity_connector_tests.c_source_contract import function_definition


ROOT = connector_root()
SOURCE = (source_path('connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c', root=ROOT)).read_text(
    encoding="utf-8",
)


class HAProxyHTXPayloadFailClosedContractTest(unittest.TestCase):
    def test_request_append_failure_closes_the_affected_stream_before_forwarding(self) -> None:
        request_branch = SOURCE.split(
            "static int haproxy_modsecurity_htx_filter_request_payload(", 1
        )[1].split("static int haproxy_modsecurity_htx_filter_response_payload(", 1)[0]
        precommit = function_definition(SOURCE, "haproxy_modsecurity_htx_fail_closed_precommit")

        self.assertIn("haproxy_modsecurity_htx_append_request_payload", request_branch)
        self.assertIn(
            'haproxy_modsecurity_htx_fail_closed_request_phase(s, ctx, "request body");',
            request_branch,
        )
        self.assertIn("return (int)len;", request_branch)
        self.assertIn("haproxy_modsecurity_htx_abort_context(ctx);", precommit)
        self.assertIn("s->txn->status = 503;", precommit)
        self.assertIn("http_reply_and_close(s, 503, http_error_message(s));", precommit)

    def test_response_append_failure_stops_only_affected_stream(self) -> None:
        response_branch = SOURCE.split(
            "static int haproxy_modsecurity_htx_filter_response_payload(", 1
        )[1].split("static int haproxy_modsecurity_htx_filter_http_payload(", 1)[0]
        postcommit = SOURCE.split(
            "static void haproxy_modsecurity_htx_fail_closed_postcommit(", 1
        )[1].split(
            "static void haproxy_modsecurity_htx_fail_closed_request_phase(", 1
        )[0]

        self.assertIn("haproxy_modsecurity_htx_append_response_payload", response_branch)
        self.assertIn(
            'haproxy_modsecurity_htx_fail_closed_postcommit(s, ctx, "response body");',
            response_branch,
        )
        self.assertIn("return -1;", response_branch)
        self.assertIn("ctx->response.headers_committed = 1;", response_branch)
        self.assertIn("haproxy_modsecurity_htx_abort_context(ctx);", postcommit)
        self.assertIn("haproxy_modsecurity_htx_abort_response_stream(s);", postcommit)
        abort = SOURCE.split(
            "static void haproxy_modsecurity_htx_abort_response_stream(", 1
        )[1].split("static void haproxy_modsecurity_htx_fail_closed_postcommit(", 1)[0]
        self.assertIn("channel_htx_erase(&s->res, htxbuf(&s->res.buf));", abort)
        self.assertIn("stream_abort(s);", abort)
        self.assertIn("sc_abort(s->scf);", abort)
        self.assertIn("sc_shutdown(s->scf);", abort)
        self.assertIn("stream_shutdown(s, SF_ERR_KILLED);", abort)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
