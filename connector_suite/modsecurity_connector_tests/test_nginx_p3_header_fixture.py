"""Contracts for the separately built native NGINX P3-header fixture."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import ast
from pathlib import Path
import unittest


ROOT = connector_root()
OBSERVER = source_path('tests/nginx_p3_header_observer_fixture', root=ROOT)
INJECTOR = source_path('tests/nginx_p3_header_injector_fixture', root=ROOT)
RUNNER = source_path('tests/run_nginx_p3_header_fixture.py', root=ROOT)
PRODUCT_HEADER = source_path('connectors/nginx/src/ngx_http_modsecurity_header_filter.c', root=ROOT)


class NginxP3HeaderFixtureContractTests(unittest.TestCase):
    def test_static_modules_surround_the_real_connector_in_filter_order(self) -> None:
        observer_config = (OBSERVER / "config").read_text(encoding="utf-8")
        injector_config = (INJECTOR / "config").read_text(encoding="utf-8")

        self.assertIn("ngx_http_p3_header_observer_fixture_module", observer_config)
        self.assertIn("ngx_http_p3_header_injector_fixture_module", injector_config)
        self.assertIn("ngx_http_modsecurity_module", injector_config)
        self.assertIn("requires static ngx_http_modsecurity_module ordering", injector_config)
        self.assertIn(
            "ngx_http_p3_header_observer_fixture_module $module "
            "ngx_http_p3_header_injector_fixture_module",
            injector_config,
        )

    def test_injector_is_test_only_and_covers_zero_negative_and_reinvocation(self) -> None:
        source = (INJECTOR / "ngx_http_p3_header_injector_fixture_module.c").read_text(
            encoding="utf-8"
        )

        for mode in ("success", "zero", "negative", "zero-reinvoke"):
            with self.subTest(mode=mode):
                self.assertIn(f'"{mode}"', source)
        self.assertIn("__wrap_msc_process_response_headers", source)
        self.assertIn("__real_msc_process_response_headers", source)
        self.assertIn("P3_HEADER_FIXTURE_ZERO_REINVOKE", source)
        self.assertIn("response_headers_processing_failed", source)
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE", source)
        self.assertIn("cleanup-complete=%ui", source)
        self.assertIn("transaction-null=%ui", source)
        self.assertNotIn("getenv(", source)
        self.assertNotIn("setenv(", source)
        self.assertNotIn(
            "P3_HEADER_FIXTURE", PRODUCT_HEADER.read_text(encoding="utf-8")
        )

    def test_observer_can_only_mark_a_reached_downstream_filter(self) -> None:
        source = (OBSERVER / "ngx_http_p3_header_observer_fixture_module.c").read_text(
            encoding="utf-8"
        )

        self.assertIn("X-P3-Header-Fixture-Downstream", source)
        self.assertIn("p3-header-observer downstream=1", source)
        self.assertIn("ngx_http_p3_header_observer_next_filter(r)", source)

    def test_runner_rebuilds_exact_head_and_records_only_bounded_evidence(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")

        ast.parse(source, filename=str(RUNNER))
        self.assertIn("assert_exact_checkout", source)
        self.assertIn("SHARED_RUNNER", source)
        self.assertIn("--wrap=msc_process_response_headers", source)
        self.assertIn("nginx_p3_header_observer_fixture", source)
        self.assertIn("nginx_p3_header_injector_fixture", source)
        self.assertIn("require_static_fixture_filter_order", source)
        self.assertIn("zero-reinvoke", source)
        self.assertIn("cleanup-complete", source)
        self.assertIn("error_log_sha256", source)
        self.assertIn("must run as an unprivileged user", source)
        self.assertNotIn("LD_PRELOAD", source)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
