"""Focused source contracts for Common event output hardening.

The test is deliberately network- and runtime-independent.  It verifies that
the event writer keeps its JSONL and filesystem boundary controls in the
shared implementation without emitting request or response body payloads.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import unittest
from pathlib import Path


ROOT = connector_root()
EVENT_SOURCE = source_path('common/src/event.c', root=ROOT)
EVENT_JSONL_SOURCE = source_path('common/src/event_jsonl.c', root=ROOT)
RUNTIME_SOURCE = source_path('common/runtime/msconnector_runtime.c', root=ROOT)
APACHE_SOURCE = source_path('connectors/apache/src/msc_filters.c', root=ROOT)
EVENT_HEADER = source_path('common/include/msconnector/event.h', root=ROOT)
INTEGRITY_HEADER = source_path('common/include/msconnector/integrity_event.h', root=ROOT)
PRIVATE_EVENT_SMOKE = source_path('tests/private_event_file_smoke.c', root=ROOT)


class EventRuntimeSecurityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.event_source = EVENT_SOURCE.read_text(encoding="utf-8")
        cls.event_jsonl_source = EVENT_JSONL_SOURCE.read_text(encoding="utf-8")
        cls.runtime_source = RUNTIME_SOURCE.read_text(encoding="utf-8")
        cls.apache_source = APACHE_SOURCE.read_text(encoding="utf-8")
        cls.private_event_smoke = PRIVATE_EVENT_SMOKE.read_text(encoding="utf-8")

    def test_protocol_metadata_is_json_escaped_and_null_safe(self) -> None:
        escaping_writer = self.event_source.split(
            "static void escape_field(", 1
        )[1].split("/* Callers supply bounded JSON-escaped text", 1)[0]
        protocol_writer = self.event_source.split(
            "static int append_escaped_protocol_string(", 1
        )[1].split("static int append_protocol_bool(", 1)[0]
        metadata_probe = self.event_source.split(
            "static int protocol_metadata_present(", 1
        )[1].split("static int append_protocol_metadata(", 1)[0]
        event_writer = self.event_source.split(
            "int msconnector_event_write_json_ex(", 1
        )[1]

        self.assertIn("msconnector_json_escape_n(", escaping_writer)
        self.assertLess(
            event_writer.index("escape_field(event->protocol.requested_protocol"),
            event_writer.index("append_safe_event_provenance(")
        )
        self.assertIn("value == NULL", protocol_writer)
        self.assertIn("values[index] != NULL", metadata_probe)

    def test_event_file_open_is_no_follow_regular_and_private(self) -> None:
        secure_open = self.event_jsonl_source.split(
            "int msconnector_open_private_event_file(", 1
        )[1]

        for token in (
            "O_APPEND",
            "O_CREAT",
            "O_NOFOLLOW",
            "O_DIRECTORY",
            "S_ISREG",
            "0600",
            "fchmod",
            "O_CLOEXEC",
            "FD_CLOEXEC",
        ):
            self.assertIn(token, secure_open)
        self.assertIn("msconnector_open_private_event_file(path, &fd)", self.runtime_source)
        self.assertNotIn('fopen(runtime->config.phase4_log_path, "a")', self.runtime_source)
        self.assertIn("errno = ENOTSUP", secure_open)
        self.assertIn("(void)path;", secure_open)
        self.assertNotIn("_open(", secure_open)

    def test_event_path_walk_rejects_ancestor_and_normalization_escapes(self) -> None:
        secure_open = self.event_jsonl_source.split(
            "int msconnector_open_private_event_file(", 1
        )[1]
        path_validation = self.runtime_source.split(
            "static int validate_runtime_event_path(", 1
        )[1].split("static int validate_runtime_config", 1)[0]

        for token in ("openat", "O_DIRECTORY", "O_NOFOLLOW", "directory_fd",
                      "next_directory_fd", "strcmp(component, \"..\")",
                      "strcmp(component, \".\")", "directory_status.st_uid",
                      "directory_status.st_mode", "S_IWGRP", "S_IWOTH",
                      "geteuid()", "file_status.st_uid"):
            self.assertIn(token, secure_open)
        for token in ("path[path_length - 1U] == '/'", "path[index] == '\\\\'",
                      "strstr(path, \"/./\")", "strncmp(path, \"./\", 2U)"):
            self.assertIn(token, path_validation)

    def test_event_parent_accepts_only_trusted_root_or_effective_user(self) -> None:
        secure_open = self.event_jsonl_source.split(
            "int msconnector_open_private_event_file(", 1
        )[1]

        self.assertIn(
            "directory_status.st_uid != geteuid() &&\n"
            "            directory_status.st_uid != 0",
            secure_open,
        )
        self.assertIn("S_IWGRP | S_IWOTH", secure_open)
        self.assertIn("file_status.st_uid != geteuid()", self.event_jsonl_source)

    def test_root_owned_smoke_fixture_preserves_descriptor_bound_controls(self) -> None:
        root_parent_control = self.private_event_smoke.split(
            "static int check_root_owned_parent_controls(", 1
        )[1].split("static int initialize_test_paths", 1)[0]

        for token in (
            "TEST_ROOT_DIRECTORY_MODE ((mode_t)0750)",
            "TEST_ROOT_PARENT_SAFE_MODE ((mode_t)0750)",
            "TEST_ROOT_PARENT_WRITABLE_MODE ((mode_t)0770)",
            "mkdirat(*root_fd, \"root-owned\", 0700)",
            "open_test_directory_at(*root_fd, \"root-owned\")",
            "fchown(*parent_fd, TEST_UNPRIVILEGED_UID,",
            "fchmod(parent_fd, TEST_ROOT_PARENT_WRITABLE_MODE)",
            "openat(parent_fd, \"root-owned.jsonl\"",
        ):
            self.assertIn(token, self.private_event_smoke)
        for unsafe_path_operation in (
            "\n    if (chmod(",
            "\n    if (chown(",
            "\n    if (mkdir(",
        ):
            self.assertNotIn(unsafe_path_operation, self.private_event_smoke)
        self.assertNotIn("if (chmod(parent", root_parent_control)
        self.assertNotIn("if (chown(parent", root_parent_control)

    def test_apache_uses_the_common_private_descriptor_before_apr_ownership(self) -> None:
        opener = self.apache_source.split(
            "static apr_status_t apache_open_event_file(", 1
        )[1].split("/* Kept private", 1)[0]

        self.assertIn("msconnector_open_private_event_file(path, &fd)", opener)
        self.assertIn("apr_os_file_put", opener)
        self.assertIn("close(fd)", opener)

    def test_integrity_fields_document_non_cryptographic_correlation_only(self) -> None:
        event_header = EVENT_HEADER.read_text(encoding="utf-8")
        integrity_header = INTEGRITY_HEADER.read_text(encoding="utf-8")

        self.assertIn("not\n     * cryptographic signatures", event_header)
        self.assertIn("do not authenticate event records", integrity_header)
        self.assertIn("tamper-resistant audit", integrity_header)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
