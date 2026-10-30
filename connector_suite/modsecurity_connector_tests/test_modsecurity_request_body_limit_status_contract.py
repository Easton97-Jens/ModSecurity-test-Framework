"""Exact native limit classification preserves the actual engine status."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import unittest
from pathlib import Path
ROOT = connector_root()
class NativeRequestLimitStatusContractTest(unittest.TestCase):
    def test_exact_signature_preserves_403_and_413(self):
        source = (source_path('common/src/intervention.c', root=ROOT)).read_text()
        runtime = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text()
        for condition in ("phase == MSCONNECTOR_PHASE_REQUEST_BODY", "intervention->disruptive != 0", "intervention->status == 403", "intervention->status == 413", "intervention->redirect_url == 0", "intervention->log_message != 0", "MSCONNECTOR_REQUEST_BODY_LIMIT_REJECTION_LOG"):
            self.assertIn(condition, source)
        self.assertNotIn("strstr(", source)
        self.assertNotIn("native_intervention_status(", runtime)
        self.assertIn("msconnector_decision_set_body_limit(decision, intervention.status, native->reason)", runtime)
        self.assertIn("return transaction->native_body_limit_status;", runtime)
        self.assertIn("visible_http_status != decision->http_status", runtime)
    def test_append_rejection_survives_native_eos_reset(self):
        runtime = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text()
        self.assertIn("pending_request_decision", runtime)
        self.assertIn("msc_process_request_body(native->transaction)", runtime)

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__": unittest.main()
