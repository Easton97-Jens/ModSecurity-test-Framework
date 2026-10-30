"""Pure BEGIN descriptor/event capture checks; not native runtime proof."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import ast
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = connector_root()
PATH = source_path('ci/runtime/lifecycle/run-nginx-lifecycle-sequences.py', root=ROOT)

DRIVER = load_source(PATH)


class BeginDriverEvidenceTests(unittest.TestCase):
    def test_root_descriptor_is_private_fresh_and_bound_to_target(self):
        with tempfile.TemporaryDirectory(prefix="begin-driver-", dir="/var/tmp/codex/ModSecurity-conector") as temporary:
            output = Path(temporary)
            for negative in (False, True):
                child = output / str(negative)
                child.mkdir(mode=0o700)
                environment = {}
                descriptor = DRIVER.begin_ledger_environment(child, environment, "a" * 32, negative)
                try:
                    metadata = os.fstat(descriptor)
                    self.assertTrue(stat.S_ISREG(metadata.st_mode))
                    self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
                    self.assertEqual(metadata.st_uid, os.geteuid())
                    self.assertEqual(metadata.st_nlink, 1)
                    self.assertEqual(metadata.st_size, 0)
                    self.assertEqual(environment["MSCONNECTOR_OWNED_BEGIN_FD"], str(descriptor))
                    self.assertEqual(environment["MSCONNECTOR_OWNED_BEGIN_FAULT"], "one-native-allocation-failure")
                    self.assertEqual(environment["MSCONNECTOR_OWNED_BEGIN_TXID"] == "a" * 32, not negative)
                    with self.assertRaises(FileExistsError):
                        DRIVER.begin_ledger_environment(child, {}, "a" * 32, False)
                finally:
                    os.fsync(descriptor)
                    os.close(descriptor)

    def test_all_original_events_and_begin_rows_are_retained(self):
        with tempfile.TemporaryDirectory(prefix="begin-driver-", dir="/var/tmp/codex/ModSecurity-conector") as temporary:
            output = Path(temporary)
            events = [{"event": "connector_error", "phase": "request_headers"},
                      {"event": "transaction_cleanup", "phase": "logging"}]
            begin = {"native_operation": "msc_new_transaction_with_id", "observed_return": None,
                     "worker_pid": 123, "worker_uid": 65534, "master_pid": 122,
                     "transaction_id": "a" * 32, "injected": True}
            raw = b"".join((json.dumps(row) + "\n").encode() for row in events)
            begin_raw = (json.dumps(begin) + "\n").encode()
            (output / "phase1-events.jsonl").write_bytes(raw)
            (output / "native-begin-observations.jsonl").write_bytes(begin_raw)
            for case in ("single_request_cleanup", "early_mapping_failure_cleanup",
                         "finish_failure_propagation", "transaction_begin_failure_cleanup"):
                observed = DRIVER.native_source_observations(output, case)
                self.assertEqual(observed["native_events"], events)
                self.assertEqual(observed.get("native_begin"), [begin] if case.startswith("transaction_begin") else None)
            self.assertEqual((output / "phase1-events.jsonl").read_bytes(), raw)
            self.assertEqual((output / "native-begin-observations.jsonl").read_bytes(), begin_raw)
            (output / "native-begin-observations.jsonl").unlink()
            with self.assertRaises(FileNotFoundError):
                DRIVER.native_source_observations(output, "transaction_begin_failure_cleanup")

    def test_actual_host_call_and_finally_preserve_descriptor_and_hash_contract(self):
        tree = ast.parse(PATH.read_text())
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run")
        self.assertIn("execute_sequence(", ast.unparse(run))
        execution = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "execute_sequence")
        calls = [node for node in ast.walk(execution) if isinstance(node, ast.Call)]
        popen = next(node for node in calls if isinstance(node.func, ast.Attribute) and node.func.attr == "Popen")
        forwarded = next(keyword.value for keyword in popen.keywords if keyword.arg == "pass_fds")
        self.assertIn("write_fd", ast.unparse(forwarded))
        finalizers = [node for node in ast.walk(execution) if isinstance(node, ast.Try)]
        self.assertTrue(any("os.fsync(write_fd)" in ast.unparse(node) and "os.close(write_fd)" in ast.unparse(node)
                            for attempt in finalizers for node in attempt.finalbody))
        self.assertIn('"native_begin_sha256": BEGIN_LEDGER', PATH.read_text())
        self.assertEqual(DRIVER.BEGIN_LEDGER, "native-begin-observations.jsonl")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
