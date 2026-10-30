"""Regression contract for Apache's connection-phase failure gates."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest


ROOT = connector_root()
MODULE = source_path('connectors/apache/src/mod_security3.c', root=ROOT)


def function_region(source: str, marker: str) -> str:
    start = source.index(marker)
    end = source.find("\nstatic ", start + len(marker))
    return source[start:] if end < 0 else source[start:end]


class ApacheConnectionPhaseContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = MODULE.read_text(encoding="utf-8")
        self.early = function_region(
            self.source, "static int hook_request_early(request_rec *r) {"
        )
        self.late = function_region(
            self.source, "static int hook_request_late(request_rec *r)\n{"
        )

    def test_both_connection_branches_require_exact_success(self) -> None:
        self.assertEqual(self.source.count("msc_process_connection(msr->t,"), 2)
        for branch in (self.early, self.late):
            call = branch.index("msc_process_connection(msr->t,")
            gate = branch.index(") != 1)", call)
            intervention = branch.index("it = process_intervention(msr->t, r);")
            self.assertLess(call, gate)
            self.assertLess(gate, intervention)
            self.assertIn("return apache_native_failed", branch[gate:intervention])

    def test_failure_gate_logs_and_precedes_normal_request_processing(self) -> None:
        fail_closed = function_region(self.source, "static int apache_fail_closed_with_cause(")
        self.assertIn("ModSecurity: operation failed: %s", fail_closed)
        self.assertIn("HTTP_INTERNAL_SERVER_ERROR", fail_closed)
        native = function_region(self.source, "static int apache_native_failed(")
        self.assertIn("return apache_fail_closed_with_cause(r, operation,", native)
        self.assertIn("MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE", native)
        for branch in (self.early, self.late):
            gate = branch.index(") != 1)")
            intervention = branch.index("it = process_intervention(msr->t, r);")
            failure_path = branch[gate:intervention]
            self.assertIn("apache_native_failed", failure_path)
            self.assertIn("return apache_native_failed", failure_path)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
