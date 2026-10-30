"""Protect original-ID fixture identity and abnormal transport observations."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool, load_source
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace


PATH = connector_root() / "ci/runtime/lifecycle/i12/lighttpd/patched_qualification.py"
producer = load_source(PATH)


class PatchedQualificationTests(unittest.TestCase):
    def test_original_ids_unique_and_chunks_cover_declared_bodies(self):
        rows = producer.definitions()
        self.assertEqual(len({row["original_id"] for row in rows}), len(rows))
        for row in rows:
            self.assertEqual(row["original_id"], "I12::lighttpd-patched-native::" + row["case"])
            self.assertEqual(sum(row["request_chunks"]), len(bytes.fromhex(row["request_hex"])))
            self.assertEqual(sum(row["response_chunks"]), len(bytes.fromhex(row["response_hex"])))
            self.assertTrue(row["oracle_basis"])

    def test_short_content_length_preserves_received_body_and_marks_incomplete(self):
        row, _, body = producer.response_decode(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc")
        self.assertEqual(row["status"], 200)
        self.assertEqual(body, b"abc")
        self.assertFalse(row["framing"]["complete"])
        self.assertEqual(row["entity_sha256"], producer.digest(b"abc"))

    def test_real_chunked_response_requires_terminal_chunk(self):
        row, _, body = producer.response_decode(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1\r\nc\r\n0\r\n\r\n")
        self.assertEqual(body, b"abc")
        self.assertTrue(row["framing"]["complete"])
        with self.assertRaises(ValueError):
            producer.response_decode(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\na")

    def test_no_fabricated_allow_or_eos_in_preallocation_failure_spec(self):
        row = next(r for r in producer.definitions() if r["case"] == "NEED-invalid-metadata")
        self.assertIsNone(row["oracle_proposal"]["visible_status"])
        self.assertIsNone(row["expectations"]["response_eos"])
        self.assertIsNone(row["expectations"]["native_cleanup"])

    def test_canonical_early_deny_keeps_original_oracle_and_no_response_phase(self):
        expected = {"native_result": "deny", "visible_status": 429,
            "phase": 1, "rule_id": 1100002, "event_fields": ["rule_id"]}
        selected = {"case_id": "deny_with_alternative_status", "expected_oracle": expected}
        original = {"run_scoped_case_id": "I12::lighttpd-patched-native::deny_with_alternative_status",
            "selected_requirement": selected}
        contract = {"request": {"method": "GET", "path": "/no-crs/deny-alternative",
            "headers": {"X-Modsec-Smoke": "alternative-status"}}}
        row = producer.canonical_spec(producer.definitions()[0], original, contract, "# independent baseline")
        self.assertEqual(row["oracle_proposal"], expected)
        self.assertEqual(row["path"], "/no-crs/deny-alternative")
        self.assertEqual(row["method"], "GET")
        self.assertEqual(row["request_chunks"], [])
        self.assertEqual(row["expectations"]["backend_main_count"], 0)
        self.assertEqual(row["expectations"]["native_request_body_process"], 0)
        self.assertEqual(row["expectations"]["native_response_body_process"], 0)
        self.assertIsNone(row["expectations"]["response_entity_sha256"])

    def test_complete_native_response_rejects_spliced_missing_entity_bytes(self):
        context = SimpleNamespace(spec={"response_hex": (b"x" * 1050657).hex(),
            "expectations": {"response_eos": 1, "native_response_body_process": 1}},
            main=[{"function": "native_append_response_body", "edge": "enter", "input_size": 10105}],
            hooks=[{"kind": "patched_response_body_hook", "stream_offset": 0, "input_size": 10105}])
        checks = {}
        producer.response_entity_assertions(context, checks)
        self.assertFalse(any(checks.values()))
        context.main[0]["input_size"] = 1050657
        context.hooks[0]["input_size"] = 1050657
        producer.response_entity_assertions(context, checks)
        self.assertTrue(all(checks.values()))
        context.hooks[0]["stream_offset"] = 1
        producer.response_entity_assertions(context, checks)
        self.assertFalse(checks["complete_response_host_contiguous_bytes"])

    def test_neighbor_fixture_is_below_limit_and_has_no_disruptive_marker(self):
        self.assertLess(len(producer.NEIGHBOR_RESPONSE), 16)
        self.assertNotIn(b"response-marker", producer.NEIGHBOR_RESPONSE)
        self.assertNotIn(b"no-crs-response-body-marker", producer.NEIGHBOR_RESPONSE)

    def test_observation_rebase_preserves_new_product_lines(self):
        temporary_root = producer.EXTERNAL_ROOT / "tmp"
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="patched-observation-", dir=temporary_root) as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = source / "connectors/lighttpd/module/mod_msconnector.c"
            destination.parent.mkdir(parents=True)
            destination.write_text("historical full module must be replaced\n")
            (source / ".i12-disposable-source-copy.json").write_text(json.dumps({"path": str(source), "disposable": True}))
            current = root / "current_module.c"
            text = ('#include "first.h"\n/* new product fix preserved */\n'
                '    if (r->reqbody_length == 0) {\n'
                '    ctx->request_body_next_offset += length;\n'
                '    if (length > 0 && !lighttpd_modsecurity_visit_body_range(\n'
                '    msconnector_error_init(&runtime_error);\n'
                '    if (length > 0U && msconnector_runtime_transaction_append_response_body_chunk(\n')
            current.write_text(text)
            result = producer.rebase_host_observation(source, current)
            self.assertEqual(result["current_product_module_sha256"], producer.digest(text.encode()))
            self.assertEqual(result["current_product_module_sha256"], result["stripped_observation_product_sha256"])
            self.assertIn("new product fix preserved", destination.read_text())
            self.assertNotIn("historical full module", destination.read_text())



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
