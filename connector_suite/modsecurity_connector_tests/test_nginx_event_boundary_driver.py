"""Pure E-adapter controls; no native host or listener is started."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = connector_root()


class EventDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("event_driver", source_path('ci/runtime/lifecycle/run-nginx-event-boundary-cases.py', root=ROOT))
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_two_separate_fixed_boundary_variants_and_no_invented_directive(self):
        self.assertEqual(self.driver.variants_for("event_json_limit"), ("at255", "over256"))
        self.assertEqual(self.driver.variants_for("event_metadata_truncation"), ("long-query",))
        text = self.driver.configuration(Path("/var/tmp/codex/owned"), 123, 124, "projection",
                                         "/no-crs/events/long-query/xxx?probe=non-sensitive", "safe", "unit-long-query")
        self.assertIn('modsecurity_transaction_id "unit-long-query-$connection-$connection_requests";', text)
        self.assertIn('modsecurity_phase4_log "/var/tmp/codex/owned/phase4-events.jsonl";', text)
        self.assertNotIn("event_json_limit", text)
        self.assertIn("location /no-crs/events/", text)

    def test_unknown_or_injected_inputs_rejected(self):
        with self.assertRaises(ValueError):
            self.driver.variants_for("foreign")
        for path, mode, run in (("/foreign", "safe", "unit"),
                                ("/no-crs/events/at255/xxx", "off", "unit"),
                                ("/no-crs/events/at255/xxx", "safe", 'unit";bad')):
            with self.assertRaises(ValueError):
                self.driver.configuration(Path("/var/tmp/codex/owned"), 123, 124, "projection", path, mode, run)

    def test_only_actual_phase1_rule_callback_is_selected(self):
        row = b'{"event":"rule_match","connector":"nginx","phase":"request_headers","integration_mode":"native-nginx-http-module","method":"GET","rule_id":"1100402","action":"allow"}\n'
        self.assertEqual(len(self.driver.native_callbacks(row, "/actual")), 1)
        self.assertEqual(self.driver.native_callbacks(row.replace(b"rule_match", b"request_rule_match"), "/actual"), [])
        self.assertEqual(self.driver.native_callbacks(row.replace(b"1100402", b"1100401"), "/actual"), [])
        with self.assertRaises(ValueError):
            self.driver.native_callbacks(b"[]\n", "/actual")

    def test_variant_metadata_is_written_once_and_exact_receipt_bytes_are_sealed(self):
        shared = load_source(source_path('ci/runtime/lifecycle/run-nginx-phase4-cases.py', root=ROOT))
        with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP", "/var/tmp/codex/ModSecurity-conector")) as temp:
            output = Path(temp) / "event"
            args = SimpleNamespace(output_root=str(output), framework_root=str(ROOT),
                run_id="unit", case_id="event_json_limit", parent_sha="p", framework_sha="f", mrts_sha="m")
            contracts = SimpleNamespace(operation=lambda case, variant: {"request_headers": {"X-Test": variant}},
                                        URI_BUFFER_BYTES=256, WRITER_BUFFER_BYTES=4096)
            retained = {}

            def run_operation(child, operation, **kwargs):
                child_output = Path(child.output_root)
                child_output.mkdir(mode=0o700)
                shared.write_source_result(child_output, {"raw_sha256": {}, "run_id": child.run_id},
                                           receipt_metadata=kwargs["receipt_metadata"])
                retained[child_output.name] = (child_output / "source-result.json").read_bytes()
                return True

            runtime = SimpleNamespace(run_operation=Mock(side_effect=run_operation))
            read_bytes = Path.read_bytes
            with patch.object(self.driver.HOST.BASE, "validate_inputs", return_value=(None, None, output)), \
                 patch.object(self.driver, "load", side_effect=[contracts, runtime]), \
                 patch.object(Path, "read_bytes", autospec=True, side_effect=lambda path: read_bytes(path)
                     if path.name == "source-result.json" else b"source dependency"):
                self.assertTrue(self.driver.run(args))
            aggregate = json.loads((output / "source-result.json").read_bytes())
            self.assertEqual(runtime.run_operation.call_count, 2)
            for child in aggregate["children"]:
                variant = child["variant"]
                raw = (output / variant / "source-result.json").read_bytes()
                self.assertEqual(raw, retained[variant])
                self.assertEqual(child["receipt_sha256"], self.driver.HOST.BASE.digest(raw))
                self.assertEqual(json.loads(raw)["variant"], variant)
                self.assertEqual(json.loads(raw)["request_headers"], {"X-Test": variant})



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
