#!/usr/bin/env python3
"""Source contract tests for the HAProxy libmodsecurity phase binding."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import re
import unittest


SOURCE = (
    connector_root()
    / "connectors/haproxy/src/haproxy_modsecurity_binding.c"
).read_text(encoding="utf-8")


class HaproxyBindingPhaseContractTests(unittest.TestCase):
    def test_direct_request_phase_calls_require_exact_success(self):
        calls = (
            "msc_process_connection",
            "msc_process_uri",
            "msc_add_request_header",
            "msc_process_request_headers",
            "msc_append_request_body",
            "msc_process_request_body",
        )
        for call in calls:
            with self.subTest(call=call):
                if call in ("msc_process_request_headers", "msc_process_request_body"):
                    self.assertRegex(SOURCE, re.compile(rf"msconnector_native_phase_succeeded\({call}\(", re.DOTALL))
                elif call == "msc_append_request_body":
                    self.assertRegex(SOURCE, re.compile(r"msconnector_native_body_append_can_continue\(\s*msc_append_request_body\(", re.DOTALL))
                else:
                    self.assertRegex(SOURCE, re.compile(rf"{call}\(.*?\)\s*!=\s*1", re.DOTALL))

    def test_direct_response_phase_calls_require_exact_success(self):
        calls = ("msc_add_response_header",)
        for call in calls:
            with self.subTest(call=call):
                if call == "msc_process_response_headers":
                    self.assertRegex(SOURCE, re.compile(r"msconnector_native_phase_succeeded\(\s*msc_process_response_headers\(", re.DOTALL))
                else:
                    self.assertRegex(SOURCE, re.compile(rf"{call}\(.*?\)\s*!=\s*1", re.DOTALL))

        self.assertRegex(
            SOURCE,
            re.compile(r"!msconnector_native_phase_succeeded\(\s*msc_process_response_headers\(", re.DOTALL),
        )

    def test_shared_body_helpers_keep_native_phase_and_byte_contracts(self):
        append_helper = re.search(
            r"static int append_body_chunk\(.*?^}\n\nstatic int finish_body",
            SOURCE,
            re.DOTALL | re.MULTILINE,
        )
        finish_helper = re.search(
            r"static int finish_body\(.*?^}\n\nstatic int load_rules_file",
            SOURCE,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(append_helper)
        self.assertIsNotNone(finish_helper)
        self.assertRegex(
            append_helper.group(0),
            re.compile(r"!msconnector_native_body_append_can_continue\(\s*phase->append_body\(", re.DOTALL),
        )
        self.assertRegex(
            finish_helper.group(0),
            re.compile(r"!msconnector_native_phase_succeeded\(\s*phase->finish_body\(", re.DOTALL),
        )

    def test_rule_loading_keeps_its_distinct_negative_error_contract(self):
        rules = re.search(
            r"static int load_rules_file\(.*?^}\n\nstatic int load_rules_text",
            SOURCE,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(rules)
        self.assertRegex(rules.group(0), r"msc_rules_add_file\(")
        self.assertRegex(rules.group(0), r"if \(rc\s*<\s*0\)")

    def test_no_legacy_negative_phase_checks_remain(self):
        phase_calls = (
            "msc_process_connection",
            "msc_process_uri",
            "msc_add_request_header",
            "msc_process_request_headers",
            "msc_append_request_body",
            "msc_process_request_body",
            "msc_add_response_header",
            "msc_process_response_headers",
        )
        for call in phase_calls:
            with self.subTest(call=call):
                self.assertNotRegex(
                    SOURCE,
                    re.compile(rf"{call}\(.*?\)\s*<\s*0", re.DOTALL),
                )

    def test_body_chunks_are_bounded_before_the_libmodsecurity_sink(self):
        helper = re.search(
            r"static int append_body_chunk\(.*?^}\n\nstatic int finish_body",
            SOURCE,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(helper)
        body = helper.group(0)
        self.assertIn("SIZE_MAX - (size_t)body_len", body)
        self.assertNotIn("body_limit -", body)
        self.assertLess(
            body.index("SIZE_MAX - (size_t)body_len"),
            body.index("phase->append_body("),
        )

    def test_neither_direction_has_connector_body_limit_policy(self):
        self.assertNotIn("common_config.request_body_limit", SOURCE)
        self.assertNotIn("contract.response_body_limit", SOURCE)
        self.assertNotIn("common_config.response_body_limit", SOURCE)
        self.assertIn("capture_pending_body_intervention(transaction, decision, phase->phase)", SOURCE)
        self.assertIn("SIZE_MAX - (size_t)body_len", SOURCE)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
