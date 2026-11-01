"""Static contract checks for the payload-free Common transaction snapshot."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import unittest


ROOT = connector_root()
HEADER = source_path('common/runtime/msconnector_runtime.h', root=ROOT)
IMPLEMENTATION = source_path('common/runtime/msconnector_runtime.c', root=ROOT)


class RuntimeTransactionSnapshotContractTest(unittest.TestCase):
    def test_snapshot_is_bounded_value_state(self) -> None:
        source = HEADER.read_text(encoding="utf-8")
        start = source.index("typedef struct msconnector_runtime_transaction_snapshot")
        end = source.index("} msconnector_runtime_transaction_snapshot;", start)
        snapshot = source[start:end]
        self.assertIn("msconnector_transaction_contract contract;", snapshot)
        self.assertIn("msconnector_runtime_body_progress request_body;", snapshot)
        self.assertIn("msconnector_runtime_body_progress response_body;", snapshot)
        self.assertNotIn("*", snapshot)
        self.assertIn("msconnector_runtime_transaction_snapshot_get", source)

    def test_accessor_copies_only_bounded_members(self) -> None:
        source = IMPLEMENTATION.read_text(encoding="utf-8")
        start = source.index("int msconnector_runtime_transaction_snapshot_get")
        end = source.index("int msconnector_runtime_transaction_process_response", start)
        function = source[start:end]
        self.assertIn("snapshot->contract = transaction->contract;", function)
        self.assertIn("snapshot->request_body = transaction->request_body;", function)
        self.assertIn("snapshot->response_body = transaction->response_body;", function)
        self.assertNotIn("event_file", function)
        self.assertNotIn("body.data", function)

    def test_finalizer_captures_only_the_completed_cleanup_state(self) -> None:
        source = IMPLEMENTATION.read_text(encoding="utf-8")
        start = source.index("int msconnector_runtime_transaction_finalize_and_snapshot")
        end = source.index("int msconnector_runtime_transaction_process_response", start)
        function = source[start:end]
        self.assertIn("runtime_transaction_cleanup_checked(transaction, error)", function)
        self.assertIn("msconnector_runtime_transaction_snapshot_get(transaction, snapshot)", function)
        self.assertIn("snapshot->contract.cleanup_complete", function)
        self.assertIn("MSCONNECTOR_TRANSACTION_STATUS_CLEANED", function)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
