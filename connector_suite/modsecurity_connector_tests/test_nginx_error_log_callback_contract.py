"""Source contract for the native NGINX ModSecurity log callback."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition


ROOT = connector_root()
LOG_SOURCE = source_path('connectors/nginx/src/ngx_http_modsecurity_log.c', root=ROOT)


class NginxErrorLogCallbackContractTest(unittest.TestCase):
    def setUp(self) -> None:
        source = LOG_SOURCE.read_text(encoding="utf-8")
        self.callback = function_definition(source, "ngx_http_modsecurity_log")

    def test_callback_guards_null_inputs_and_context(self) -> None:
        self.assertIn("if (log == NULL || data == NULL)", self.callback)
        self.assertIn(
            "if (r == NULL || r->connection == NULL || r->connection->log == NULL)",
            self.callback,
        )
        self.assertIn(
            "if (mcf == NULL)",
            self.callback,
        )

    def test_jsonl_rule_match_precedes_effective_error_log_guard(self) -> None:
        emission = self.callback.index("ngx_http_modsecurity_log_rule_match_event")
        guard = self.callback.index(
            "if (mcf->common_config.use_error_log != MSCONNECTOR_BOOL_ON)"
        )
        host_log = self.callback.index("ngx_log_error(NGX_LOG_INFO")
        self.assertLess(emission, guard)
        self.assertLess(guard, host_log)
        self.assertIn("mcf->common_config.use_error_log", self.callback)

    def test_error_log_setting_does_not_change_waf_callback_processing(self) -> None:
        self.assertIn("ctx->native_event_phase_active", self.callback)
        self.assertIn("msconnector_rule_id_extract_from_message", self.callback)
        self.assertIn("ngx_http_modsecurity_log_rule_match_event(r,", self.callback)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
