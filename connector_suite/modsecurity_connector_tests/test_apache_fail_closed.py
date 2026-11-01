"""Regression contracts for Apache native request-processing failures."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import re
import unittest


ROOT = connector_root()
MODULE = source_path('connectors/apache/src/mod_security3.c', root=ROOT)


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    while True:
        opening = source.find("{", start + len(signature))
        semicolon = source.find(";", start + len(signature), opening)
        if opening >= 0 and (semicolon < 0 or opening < semicolon):
            break
        start = source.index(signature, start + len(signature))
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


class ApacheFailClosedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = MODULE.read_text(encoding="utf-8")
        self.headers = function_body(self.source, "static int process_request_headers(request_rec *r, msc_t *msr)")
        self.late_hook = function_body(self.source, "static int hook_request_late(request_rec *r)")

    def test_each_native_failure_returns_before_intervention_or_handler(self) -> None:
        for operation in ("msc_process_uri", "msc_add_request_header", "msc_process_request_headers"):
            with self.subTest(operation=operation):
                call = self.headers.index(f"{operation}(")
                failure = self.headers.index(f'return apache_native_failed(r, "{operation}");', call)
                self.assertLess(call, failure)
                self.assertRegex(self.headers[call:failure + len(f'return apache_native_failed(r, "{operation}");')],
                    re.compile(rf"{operation}\([^;]*?\)\s*!=\s*1\)\s*\{{\s*(?:msr->native_event_phase_active = 0;\s*)?return apache_native_failed\(r, \"{operation}\"\);", re.DOTALL))

    def test_connection_failure_is_fail_closed_in_the_late_hook(self) -> None:
        call = self.late_hook.index("msc_process_connection(")
        failure = self.late_hook.index('return apache_native_failed(r, "msc_process_connection");', call)
        self.assertLess(call, failure)
        self.assertLess(failure, self.late_hook.index("process_request_headers"))

    def test_all_checked_native_api_calls_require_the_success_value(self) -> None:
        for operation in ("msc_process_connection", "msc_process_uri", "msc_add_request_header", "msc_process_request_headers"):
            with self.subTest(operation=operation):
                self.assertRegex(self.source, re.compile(rf"{operation}\([^;]*?\)\s*!=\s*1", re.DOTALL))

    def test_fail_closed_keeps_connection_close_and_owner_cleanup_contract(self) -> None:
        connector_helper = function_body(self.source, "static int apache_fail_closed(")
        native_helper = function_body(self.source, "static int apache_native_failed(")
        for wrapper, cause in ((connector_helper, "CONNECTOR"), (native_helper, "INVALID_ENGINE_RESPONSE")):
            self.assertRegex(wrapper, re.compile(
                rf"return apache_fail_closed_with_cause\(r, operation,\s*MSCONNECTOR_TRANSACTION_ERROR_{cause}\);"))
        helper = function_body(self.source, "static int apache_fail_closed_with_cause(")
        self.assertIn("apache_record_failure(msr, r, cause)", helper)
        self.assertIn("return HTTP_INTERNAL_SERVER_ERROR;", helper)
        self.assertIn("r->connection->keepalive = AP_CONN_CLOSE;", helper)
        native = function_body(self.source, "static int apache_native_failed(")
        self.assertIn("return apache_fail_closed_with_cause(r, operation,", native)
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE", native)
        connector = function_body(self.source, "static int apache_fail_closed(")
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR", connector)
        self.assertIn("apr_pool_cleanup_register(r->pool, msr,", self.source)
        self.assertIn("msc_cleanup_request_transaction, apr_pool_cleanup_null);", self.source)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
