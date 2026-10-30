"""Cross-connector response-limit ownership and wiring checks; no hosted runtime claim."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()
BODY = source_path('connectors/nginx/src/ngx_http_modsecurity_body_filter.c', root=ROOT)
APACHE = source_path('connectors/apache/src/msc_filters.c', root=ROOT)
RUNTIME = source_path('common/runtime/msconnector_runtime.c', root=ROOT)
BINDING = source_path('connectors/haproxy/src/haproxy_modsecurity_binding.c', root=ROOT)
HTX = source_path('connectors/haproxy/htx-overlay/haproxy_modsecurity_htx_filter.c', root=ROOT)

def function(path: Path, name: str) -> str:
    return function_definition(path.read_text(encoding="utf-8"), name)


class Phase4BudgetWiringTests(unittest.TestCase):
    def test_no_response_budget_policy_survives_in_adapters(self) -> None:
        for path in (BODY, APACHE, RUNTIME, BINDING, HTX):
            text = path.read_text()
            self.assertNotIn("msconnector_phase4_effective_body_limit", text)
            self.assertNotIn("config.response_body_limit", text)

    def test_common_direct_and_companion_append_full_chunks(self) -> None:
        text = function(RUNTIME, "append_response_body_chunk_internal")
        self.assertIn("append_size = size", text)
        self.assertIn("SIZE_MAX - transaction->response_body.bytes_seen", text)
        self.assertNotIn("apply_body_limit_plan", text)
        self.assertNotIn("msconnector_body_limit_plan_chunk", text)
        self.assertNotIn("phase4_mode", text)
        for name in ("msconnector_runtime_transaction_append_response_body_chunk",
                     "append_companion_response_body_chunk"):
            self.assertIn("append_response_body_chunk_internal(", function(RUNTIME, name))

    def test_envoy_traefik_lighttpd_route_body_to_common_runtime(self) -> None:
        paths = (
            "connectors/envoy/ext_proc/internal/processor/common_runtime_bridge.c",
            "connectors/traefik/src/traefik_engine_service.c",
            "connectors/lighttpd/module/mod_msconnector.c",
            "connectors/lighttpd/stock_sidecar/stock_sidecar.c",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertIn("msconnector_runtime_transaction_append_response_body_chunk(",
                              (ROOT / path).read_text(encoding="utf-8"))

    def test_nginx_null_guards_precede_configuration_use(self) -> None:
        for name in ("ngx_http_modsecurity_phase4_log_event",
                     "ngx_http_modsecurity_phase4_handle_intervention"):
            text = function(BODY, name)
            self.assertLess(text.index("if (mcf == NULL)"), text.index("mcf->"))
            guard = text[text.index("if (mcf == NULL)"):text.index("mcf->")]
            self.assertIn("return NGX_ERROR;", guard)

    def test_apache_null_guards_precede_bucket_and_request_use(self) -> None:
        text = function(APACHE, "apache_phase4_append_bucket")
        self.assertLess(text.index("msr == NULL"), text.index("APR_BUCKET_IS_EOS"))
        for token in ("conf == NULL", "bucket == NULL", "msr->t == NULL"):
            self.assertIn(token, text[:text.index("APR_BUCKET_IS_EOS")])
        text = function(APACHE, "apache_phase4_handle_intervention")
        self.assertLess(text.index("conf == NULL"), text.index("conf->"))
        self.assertLess(text.index("f == NULL"), text.index("r = f->r;"))
        text = function(APACHE, "apache_phase4_log_event")
        self.assertLess(text.index("r == NULL"), text.index("r->status"))

    def test_shared_event_writer_guards_before_dereference(self) -> None:
        text = function(RUNTIME, "write_event_jsonl")
        self.assertLess(text.index("runtime == NULL"), text.index("runtime->"))
        self.assertLess(text.index("event == NULL"), text.index("msconnector_allocator_init"))
        self.assertIn("runtime->event_file == NULL", text)
        self.assertIn("SIZE_MAX - 2U", text)

    def test_traefik_checks_service_before_policy(self) -> None:
        path = source_path('connectors/traefik/src/traefik_engine_service.c', root=ROOT)
        text = function(path, "traefik_engine_handle_response_chunk")
        self.assertLess(text.index("session->service == NULL"),
                        text.index("session->service->response_body_mode"))

    def test_existing_envoy_body_bridge_null_checks_remain(self) -> None:
        path = source_path('connectors/envoy/ext_proc/internal/processor/common_runtime_bridge.c', root=ROOT)
        text = function(path, "msc_envoy_ext_proc_transaction_process_body")
        self.assertLess(text.index("msc_envoy_ext_proc_check_transaction("), text.index("transaction->"))
        self.assertLess(text.index("body == NULL"), text.index("body->"))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
