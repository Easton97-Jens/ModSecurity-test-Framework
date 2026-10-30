"""Compile both actual NGX event writers against the real strict Common JSONL.

Only the final file-descriptor write and NGX logging are controlled seams.
The Common serializer is not relaxed; other oversized fields must still fail.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()
NATIVE = source_path('connectors/nginx/src', root=ROOT)
PREAMBLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "msconnector/event_jsonl.h"
#include "ngx_http_modsecurity_event_uri.h"
typedef unsigned char u_char;
typedef long ngx_int_t;
typedef struct { int fd; } ngx_open_file_t;
typedef struct { void *log; unsigned long number; unsigned long requests; } connection_t;
typedef struct { connection_t *connection; } ngx_http_request_t;
typedef struct { ngx_open_file_t *phase4_log_file; } ngx_http_modsecurity_conf_t;
enum { NGX_OK = 0, NGX_ERROR = -1, NGX_LOG_WARN = 5 };
#define ngx_inline inline
#define ngx_strlen strlen
#define ngx_errno 5
static int writes;
static int write_failure;
static char captured[4096];
static void ngx_log_error(int level, void *log, int error, const char *format, ...) {
    (void)level; (void)log; (void)error; (void)format;
}
static ssize_t ngx_write_fd(int fd, u_char *line, size_t length) {
    if (fd != 7 || length >= sizeof(captured)) { abort(); }
    ++writes;
    if (write_failure == 1) { return write(-1, line, length); }
    if (write_failure == 2) { return (ssize_t)length - 1; }
    memcpy(captured, line, length);
    captured[length] = '\0';
    return (ssize_t)length;
}
'''
MAIN = r'''
int main(int argc, char **argv) {
    char uri[700], method[80];
    connection_t connection = {NULL, 42, 1};
    ngx_http_request_t request = {&connection};
    ngx_open_file_t file = {7};
    ngx_http_modsecurity_conf_t conf = {&file};
    msconnector_event event;
    int result, phase;
    msconnector_event original;
    if (argc != 3) return 2;
    phase = strcmp(argv[1], "phase") == 0;
    msconnector_event_init(&event);
    event.meta.connector = "nginx";
    event.meta.integration_mode = "native-nginx-http-module";
    event.meta.message_id = "MSCONN_PHASE4_APPEND";
    event.meta.event = "phase4_append";
    event.request.method = "GET";
    event.request.uri = "/unit-control";
    memset(uri, 'a', sizeof(uri));
    uri[0] = '/'; uri[sizeof(uri)-1] = '\0';
    if (strcmp(argv[2], "long") == 0) event.request.uri = uri;
    else if (strcmp(argv[2], "escaped") == 0) {
        memset(uri+1, '"', 400); uri[401] = '\0'; event.request.uri = uri;
    } else if (strcmp(argv[2], "query") == 0) {
        event.request.uri = "/unit-control?token=unit-test-sensitive-value";
    } else if (strcmp(argv[2], "long-query") == 0 ||
               strcmp(argv[2], "escaped-query") == 0) {
        if (strcmp(argv[2], "escaped-query") == 0) memset(uri+1, '"', 400);
        strcpy(uri+401, "?token=unit-test-sensitive-value");
        event.request.uri = uri;
    } else if (strcmp(argv[2], "source-flags") == 0) {
        event.flags.truncated = 1;
        event.flags.redacted = 1;
    } else if (strcmp(argv[2], "oversized-method") == 0) {
        memset(method, 'M', sizeof(method)-1); method[sizeof(method)-1]='\0';
        event.request.method = method;
    } else if (strcmp(argv[2], "write-error") == 0) {
        write_failure = 1;
    } else if (strcmp(argv[2], "short-write") == 0) {
        write_failure = 2;
    } else if (strcmp(argv[2], "control") != 0 && strcmp(argv[2], "reuse") != 0) return 2;
    if (strcmp(argv[2], "reuse") == 0) connection.requests = 2;
    original = event;
    result = phase ? ngx_http_modsecurity_write_phase_event_jsonl(&request, &conf, &event, "phase4")
        : ngx_http_modsecurity_write_event_jsonl(&request, &conf, &event, "serialize", "write");
    if (memcmp(&original, &event, sizeof(event)) != 0) return 3;
    printf("%d %d\n", result, writes);
    fputs(captured, stdout);
    return 0;
}
'''


class BoundedEventUriTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or not shutil.which(compiler[0]):
            raise RuntimeError("a real C17 compiler is required")
        temp = tempfile.TemporaryDirectory(prefix="nginx-bounded-event-uri-",
                                           dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temp.cleanup)
        directory = Path(temp.name)
        source = (NATIVE / "ngx_http_modsecurity_common.h").read_text()
        writers = "\n".join("static " + kind + "\n" + function_definition(source, name)
                            for kind, name in (("int", "ngx_http_modsecurity_write_event_jsonl"),
                                               ("ngx_int_t", "ngx_http_modsecurity_write_phase_event_jsonl")))
        fixture = directory / "writer.c"
        phase = function_definition((source_path('common/src/transaction_state.c', root=ROOT)).read_text(),
                                    "msconnector_phase_name")
        helpers = "\n".join("static int\n" + function_definition(source, name)
                            for name in ("ngx_http_modsecurity_event_token_valid",
                                         "ngx_http_modsecurity_apply_event_provenance"))
        fixture.write_text(PREAMBLE + helpers + phase + "\n" + writers + MAIN)
        cls.binaries = []
        for sanity in (0, 1):
            binary = directory / f"writer-{sanity}"
            command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                                  f"-DMODSECURITY_SANITY_CHECKS={sanity}",
                                  "-I", str(NATIVE), "-I", str(source_path('common/include', root=ROOT)), str(fixture)]
            command += [str(source_path('common/src', root=ROOT) / name) for name in
                        ("event.c", "event_jsonl.c", "json_escape.c", "http_status.c", "status.c")]
            command += ["-o", str(binary)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
            if result.returncode:
                raise AssertionError(result.stderr[-6000:])
            cls.binaries.append(binary)

    def observe(self, binary: Path, writer: str, scenario: str, provenance=None):
        env = {key: value for key, value in os.environ.items()
               if key not in ("MSCONNECTOR_NGINX_EVENT_RUN_ID",
                              "MSCONNECTOR_NGINX_EVENT_TRANSPORT_CASE_ID")}
        env.update(provenance or {})
        result = subprocess.run([str(binary), writer, scenario], env=env, capture_output=True,
                                text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        header, _, raw = result.stdout.partition("\n")
        code, writes = map(int, header.split())
        return code, writes, json.loads(raw) if raw else None, raw

    def test_long_and_escaped_uri_have_bounded_real_json_and_source_truncation(self):
        for binary in self.binaries:
            for writer in ("request", "phase"):
                for scenario in ("long", "escaped"):
                    with self.subTest(sanity=binary.name, writer=writer, scenario=scenario):
                        code, writes, event, raw = self.observe(binary, writer, scenario)
                        self.assertEqual(code, 0 if writer == "phase" else 1)
                        self.assertEqual(writes, 1)
                        self.assertIs(event["truncated"], True)
                        self.assertLessEqual(len(json.dumps(event["uri"])[1:-1]), 255)
                        self.assertLess(len(raw), 4096)

    def test_control_and_query_keep_exact_truncation_redaction_semantics(self):
        for binary in self.binaries:
            for writer in ("request", "phase"):
                for scenario in ("control", "query"):
                    code, writes, event, raw = self.observe(binary, writer, scenario)
                    self.assertEqual(code, 0 if writer == "phase" else 1)
                    self.assertEqual(writes, 1)
                    self.assertIs(event["truncated"], False)
                    self.assertIs(event["redacted"], scenario == "query")
                    self.assertEqual(event["uri"], "/unit-control" if scenario == "control"
                                     else "/unit-control?<redacted>")
                    self.assertNotIn("unit-test-sensitive-value", raw)

    def test_other_oversized_field_is_not_hidden_by_uri_projection(self):
        for binary in self.binaries:
            for writer in ("request", "phase"):
                code, writes, event, _ = self.observe(binary, writer, "oversized-method")
                self.assertEqual(code, -1 if writer == "phase" else 0)
                self.assertEqual(writes, 0)
                self.assertIsNone(event)

    def test_long_query_preserves_marker_after_byte_and_escape_projection(self):
        for binary in self.binaries:
            for writer in ("request", "phase"):
                for scenario in ("long-query", "escaped-query"):
                    code, writes, event, raw = self.observe(binary, writer, scenario)
                    self.assertEqual(code, 0 if writer == "phase" else 1)
                    self.assertEqual(writes, 1)
                    self.assertIs(event["truncated"], True)
                    self.assertIs(event["redacted"], True)
                    self.assertTrue(event["uri"].endswith("?<redacted>"))
                    self.assertLessEqual(len(json.dumps(event["uri"])[1:-1]), 255)
                    self.assertNotIn("unit-test-sensitive-value", raw)

    def test_preexisting_source_flags_are_never_cleared(self):
        for binary in self.binaries:
            for writer in ("request", "phase"):
                _, writes, event, _ = self.observe(binary, writer, "source-flags")
                self.assertEqual(writes, 1)
                self.assertIs(event["truncated"], True)
                self.assertIs(event["redacted"], True)

    def test_failed_and_incomplete_physical_writes_never_report_success(self):
        for binary in self.binaries:
            for writer in ("request", "phase"):
                for scenario in ("write-error", "short-write"):
                    with self.subTest(sanity=binary.name, writer=writer, scenario=scenario):
                        code, writes, event, _ = self.observe(binary, writer, scenario)
                        self.assertEqual(code, -1 if writer == "phase" else 0)
                        self.assertEqual(writes, 1)
                        self.assertIsNone(event)

    def test_trusted_process_provenance_is_physical_and_does_not_mutate_source(self):
        for binary in self.binaries:
            for writer in ("request", "phase"):
                for scenario in ("control", "reuse"):
                    _, writes, event, _ = self.observe(binary, writer, scenario, {
                        "MSCONNECTOR_NGINX_EVENT_RUN_ID": "run.20261022:trusted",
                        "MSCONNECTOR_NGINX_EVENT_TRANSPORT_CASE_ID": "timeout-before_commit",
                    })
                    self.assertEqual(writes, 1)
                    self.assertEqual(event.get("run_id"), "run.20261022:trusted")
                    self.assertEqual(event.get("transport_case_id"), "timeout-before_commit")
                    self.assertEqual(event.get("connection_id"), "nginx-42")
                    self.assertEqual(event.get("connection_reused"), scenario == "reuse")

    def test_absent_trusted_configuration_keeps_provenance_optional(self):
        for binary in self.binaries:
            for writer in ("request", "phase"):
                _, writes, event, _ = self.observe(binary, writer, "control")
                self.assertEqual(writes, 1)
                self.assertIsNone(event.get("run_id"))
                self.assertIsNone(event.get("transport_case_id"))
                self.assertIsNone(event.get("connection_id"))

    def test_partial_invalid_or_oversized_provenance_never_writes(self):
        run_key = "MSCONNECTOR_NGINX_EVENT_RUN_ID"
        case_key = "MSCONNECTOR_NGINX_EVENT_TRANSPORT_CASE_ID"
        invalid = [{run_key: "run"}, {case_key: "case"}]
        invalid += [{run_key: value, case_key: "case"} for value in
                    ("", "a" * 129, "space value", "line\nbreak", "caf\u00e9", "slash/value")]
        invalid += [{run_key: "run", case_key: value} for value in ("", "a" * 129, "bad value")]
        for binary in self.binaries:
            for writer in ("request", "phase"):
                for provenance in invalid:
                    with self.subTest(writer=writer, provenance=provenance):
                        code, writes, event, _ = self.observe(binary, writer, "control", provenance)
                        self.assertEqual(code, -1 if writer == "phase" else 0)
                        self.assertEqual(writes, 0)
                        self.assertIsNone(event)

    def test_maximum_valid_provenance_is_accepted_by_real_serializer(self):
        for binary in self.binaries:
            for writer in ("request", "phase"):
                _, writes, event, _ = self.observe(binary, writer, "control", {
                    "MSCONNECTOR_NGINX_EVENT_RUN_ID": "A" * 128,
                    "MSCONNECTOR_NGINX_EVENT_TRANSPORT_CASE_ID": "z" * 128,
                })
                self.assertEqual(writes, 1)
                self.assertEqual(event.get("run_id"), "A" * 128)
                self.assertEqual(event.get("transport_case_id"), "z" * 128)

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
