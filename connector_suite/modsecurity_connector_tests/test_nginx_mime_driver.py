"""Pure adapter controls; unit observations are not native runtime evidence."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = connector_root()


class MimeDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("mime_driver", source_path('ci/runtime/lifecycle/run-nginx-mime-cases.py', root=ROOT))
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_self_contained_type_safe_and_real_sink_for_each_closed_case(self):
        cases = {"phase4_in_scope_content_type": "text/plain",
                 "phase4_content_type_with_charset": "text/plain; charset=utf-8",
                 "phase4_out_of_scope_content_type": "image/png", "phase4_missing_content_type": ""}
        for case, content_type in cases.items():
            with self.subTest(case=case):
                config = self.driver.configuration(Path("/var/tmp/codex/owned"), 32123, 32124,
                    "/var/tmp/codex/projection/child", "/no-crs/content-type/" + case, "safe", "unit")
                self.assertIn(f'default_type "{content_type}";', config)
                self.assertIn("types { }", config)
                self.assertIn('modsecurity_phase4_log "/var/tmp/codex/owned/phase4-events.jsonl";', config)
                self.assertIn('modsecurity_transaction_id "unit-$connection-$connection_requests";', config)
                self.assertIn("user nobody nogroup;", config)
                self.assertNotIn("include ", config)

    def test_foreign_mode_uri_run_and_body_are_rejected_before_listening(self):
        path = "/no-crs/content-type/phase4_missing_content_type"
        for uri, mode, run in ((path, "off", "unit"), ("/foreign", "safe", "unit"),
                               (path, "safe", 'unit";bad')):
            with self.assertRaises(ValueError):
                self.driver.configuration(Path("/var/tmp/codex/owned"), 1, 2, "projection", uri, mode, run)
        for body, pause in (([b"foreign"], False), ([b"no-crs-response-body-marker"], True)):
            with self.assertRaises(ValueError):
                self.driver.MimeUpstream(body, pause=pause, spec={}, output=Path("/var/tmp/codex/owned"))

    def test_adapter_delegates_runtime_and_authenticates_actual_backend_dependencies(self):
        args = SimpleNamespace(framework_root=str(ROOT), output_root="/var/tmp/codex/owned", case_id="mime-case")
        operation = {"backend_fixture": {"headers": [], "omit_headers": ["Content-Type"], "status": 200}}
        runtime = SimpleNamespace(run_operation=Mock(return_value=True))
        contract = SimpleNamespace(operation=lambda case: operation)
        with patch.object(self.driver, "load", side_effect=[contract, runtime]), \
             patch.object(Path, "is_file", return_value=True), \
             patch.object(self.driver.HOST, "write_json") as writer, \
             patch.object(self.driver.HOST.BASE, "digest", side_effect=lambda value: "a" * 64):
            self.assertTrue(self.driver.run(args))
        writer.assert_not_called()
        observed = runtime.run_operation.call_args.kwargs["receipt_metadata"]
        self.assertIs(runtime.run_operation.call_args.args[0], args)
        self.assertIs(runtime.run_operation.call_args.args[1], operation)
        self.assertIs(runtime.run_operation.call_args.kwargs["upstream_factory"], self.driver.MimeUpstream)
        self.assertIs(runtime.run_operation.call_args.kwargs["configuration_factory"], self.driver.configuration)
        self.assertEqual(runtime.run_operation.call_args.kwargs["extra_capture_leaves"],
                         ("response-header-fixture.json",))
        self.assertEqual(observed["backend_contract_sha256"], "a" * 64)
        self.assertEqual(observed["backend_omission_contract_sha256"], "a" * 64)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
