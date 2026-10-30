"""Source-level fail-closed contracts for Apache native request processing."""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import re
import unittest
from pathlib import Path


ROOT = connector_root()
FILTERS = source_path('connectors/apache/src/msc_filters.c', root=ROOT)
EVENT_JSONL = source_path('common/src/event_jsonl.c', root=ROOT)


class ApacheNativeSecurityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = FILTERS.read_text(encoding="utf-8")
        cls.event_jsonl = EVENT_JSONL.read_text(encoding="utf-8")

    def test_request_body_append_uses_operation_specific_result_contract(self) -> None:
        self.assertRegex(
            self.source,
            re.compile(
                r"!msconnector_native_body_append_can_continue\("
                r"msc_append_request_body\(msr->t,\s*"
                r"\(const unsigned char \*\)data, len\)\)",
                re.DOTALL,
            ),
        )

    def test_final_request_body_processing_requires_exact_success(self) -> None:
        self.assertIn(
            "if (!msconnector_native_phase_succeeded(msc_process_request_body(msr->t)))",
            self.source,
        )

    def test_response_header_append_failure_enters_precommit_terminal_path(self) -> None:
        helper = self.source[self.source.index("static int apache_add_response_headers"):]
        self.assertIn("msc_add_response_header(msr->t,", helper)
        self.assertIn("!= 1)", helper[:helper.index("static int apache_response_header_metrics")])
        self.assertIn("return 0;", helper[:helper.index("static int apache_response_header_metrics")])
        response_path = self.source[self.source.index(
            "error_headers_added = apache_add_response_headers"):]
        response_path = response_path[:response_path.index(
            "original_status = r->status")]
        self.assertIn("apache_add_response_headers(msr, r->err_headers_out)", response_path)
        self.assertIn("apache_add_response_headers(msr, r->headers_out)", response_path)
        self.assertIn("return apache_send_precommit_terminal_error(msr, filter, brigade,", response_path)
        self.assertIn("HTTP_INTERNAL_SERVER_ERROR);", response_path)

    def test_response_content_type_append_failure_enters_precommit_terminal_path(self) -> None:
        self.assertRegex(
            self.source,
            re.compile(
                r"content_type != NULL && content_type\[0\] != '\\0'.*?"
                r"msc_add_response_header\(msr->t,\s*"
                r"\(const unsigned char \*\)\"Content-Type\",\s*"
                r"\(const unsigned char \*\)content_type\) != 1\).*?"
                r"return apache_send_precommit_terminal_error\(msr, filter, brigade,\s*"
                r"HTTP_INTERNAL_SERVER_ERROR\);",
                re.DOTALL,
            ),
        )

    def test_event_path_walk_is_fail_closed_and_descriptor_backed(self) -> None:
        self.assertIn("msconnector_open_private_event_file(path, &fd)", self.source)
        self.assertIn("apr_os_file_put", self.source)
        self.assertIn("openat(directory_fd, component", self.event_jsonl)
        self.assertIn("O_DIRECTORY | O_NOFOLLOW", self.event_jsonl)
        self.assertIn("strcmp(component, \"..\") == 0", self.event_jsonl)
        self.assertIn("strcmp(component, \".\") == 0", self.event_jsonl)
        self.assertIn("!S_ISREG(file_status.st_mode)", self.event_jsonl)
        self.assertIn("file_status.st_uid != geteuid()", self.event_jsonl)
        self.assertIn("fchmod(fd, (mode_t)0600)", self.event_jsonl)

    def test_event_path_rejects_empty_double_and_trailing_components(self) -> None:
        self.assertIn("path[path_length - 1U] == '/'", self.event_jsonl)
        self.assertIn("component[0] == '\\0'", self.event_jsonl)
        self.assertIn("path[0] == '/' ? \"/\" : \".\"", self.event_jsonl)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
