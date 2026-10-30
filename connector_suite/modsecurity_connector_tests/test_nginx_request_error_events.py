"""Compile the actual NGINX request error boundary and Common JSONL writer.

NGINX scheduling/native calls and the file descriptor are controlled seams.
The producer, access-result gate, initializer and serializer are real source.
This is not a live NGINX, transport, or ten-route integration result.
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
from tests import test_nginx_request_native_results as native_fixture

ROOT = connector_root()
ACCESS = source_path('connectors/nginx/src/ngx_http_modsecurity_access.c', root=ROOT)
COMMON = source_path('connectors/nginx/src/ngx_http_modsecurity_common.h', root=ROOT)
FUNCTIONS = (
    ("int", "ngx_http_modsecurity_request_has_rule_decision"),
    ("void", "ngx_http_modsecurity_request_intervention_log_event"),
    ("msconnector_transaction_error_class", "ngx_http_modsecurity_request_error_cause"),
    ("const char *", "ngx_http_modsecurity_request_error_message_id"),
    ("void", "ngx_http_modsecurity_request_error_log_event"),
    ("ngx_int_t", "ngx_http_modsecurity_request_terminal_status"),
    ("ngx_int_t", "ngx_http_modsecurity_request_result"),
    ("ngx_int_t", "ngx_http_modsecurity_initialize_request"),
)
PREAMBLE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "msconnector/config.h"
#include "msconnector/event.h"
#include "msconnector/event_jsonl.h"
#include "msconnector/phase.h"
#include "msconnector/transaction_state.h"
#include "msconnector/transaction_contract.h"
#include "connectors/nginx/src/ngx_http_modsecurity_event_uri.h"
#define ngx_strlen strlen
#define ngx_errno 5
typedef unsigned char u_char;
typedef long ngx_int_t;
typedef unsigned long ngx_uint_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int fd; } ngx_open_file_t;
typedef struct { int error; void *log; } connection_t;
typedef struct { connection_t *connection; int header_sent; } ngx_http_request_t;
typedef struct {
    int enable;
    ngx_uint_t phase4_mode;
    ngx_open_file_t *phase4_log_file;
} ngx_http_modsecurity_conf_t;
typedef struct {
    msconnector_transaction_contract contract;
    int intervention_triggered, native_request_body_limit_rejection;
    int request_body_processed, request_error_event_attempted;
    ngx_int_t request_error_status, last_intervention_status;
    ngx_str_t event_transaction_id;
    size_t request_body_bytes_seen;
    char last_intervention_rule_id[MSCONNECTOR_MAX_RULE_ID_LENGTH + 1U];
} ngx_http_modsecurity_ctx_t;
typedef struct { const char *method, *uri, *content_type; }
    ngx_http_modsecurity_event_request_metadata_t;
enum { NGX_OK = 0, NGX_ERROR = -1, NGX_AGAIN = -2, NGX_DONE = -4,
    NGX_DECLINED = -5, NGX_INVALID_FILE = -1, NGX_LOG_WARN = 5,
    NGX_HTTP_BAD_REQUEST = 400, NGX_HTTP_FORBIDDEN = 403,
    NGX_HTTP_REQUEST_ENTITY_TOO_LARGE = 413, NGX_HTTP_INTERNAL_SERVER_ERROR = 500,
    NGX_HTTP_GATEWAY_TIME_OUT = 504 };
static ngx_http_modsecurity_ctx_t context;
static ngx_http_modsecurity_conf_t configuration;
static int present, header_case, allocation_failure;
static int writes, diagnostics, initialization_calls, body_calls;
static const char *sink;
static ngx_int_t selected_result;
static char attempted[8192];
static void dd(const char *format, ...) { (void)format; }
static void ngx_log_error(int level, void *log, int error, const char *format, ...) {
    (void)level; (void)log; (void)error; (void)format; ++diagnostics;
}
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_get_module_ctx(
    ngx_http_request_t *r) { (void)r; return present ? &context : NULL; }
static ngx_http_modsecurity_ctx_t *ngx_http_get_module_ctx(
    ngx_http_request_t *r, int module) {
    (void)r; (void)module; return present ? &context : NULL;
}
static ngx_http_modsecurity_conf_t *ngx_http_get_module_loc_conf(
    ngx_http_request_t *r, int module) { (void)r; (void)module; return &configuration; }
static const int ngx_http_modsecurity_module = 0;
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_create_ctx(ngx_http_request_t *r) {
    (void)r; ++initialization_calls;
    present = !allocation_failure; return present ? &context : NULL;
}
static ngx_int_t ngx_http_modsecurity_validate_common_request_mapper(ngx_http_request_t *r) {
    (void)r; return NGX_OK;
}
static ngx_int_t ngx_http_modsecurity_set_request_hostname(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx) { (void)r; (void)ctx; return NGX_OK; }
static ngx_int_t ngx_http_modsecurity_process_connection(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx) { (void)r; (void)ctx; return NGX_OK; }
static ngx_int_t ngx_http_modsecurity_process_request_uri(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx) {
    (void)r; (void)ctx; return header_case ? selected_result : NGX_OK;
}
static ngx_int_t ngx_http_modsecurity_process_request_headers(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx, const ngx_http_modsecurity_conf_t *mcf) {
    (void)r; (void)ctx; (void)mcf; return NGX_OK;
}
static ngx_http_modsecurity_event_request_metadata_t
ngx_http_modsecurity_event_request_metadata(ngx_http_request_t *r) {
    (void)r;
    return (ngx_http_modsecurity_event_request_metadata_t){
        "POST", "/case?token=private-value", "text/plain"};
}
int msconnector_transaction_contract_fail(msconnector_transaction_contract *contract,
    msconnector_transaction_error_class cause, uint64_t now) {
    (void)now; contract->error_class = cause;
    contract->status = MSCONNECTOR_TRANSACTION_STATUS_TERMINAL;
    return MSCONNECTOR_TRANSACTION_TRANSITION_OK;
}
const char *msconnector_transaction_error_class_name(msconnector_transaction_error_class cause) {
    (void)cause; return "fixture_cause";
}
static ssize_t ngx_write_fd(int fd, u_char *line, size_t length) {
    if (fd < 0 || length >= sizeof(attempted)) { abort(); }
    ++writes;
    memcpy(attempted, line, length); attempted[length] = '\0';
    if (strcmp(sink, "write-error") == 0) { return -1; }
    if (strcmp(sink, "short-write") == 0) { return (ssize_t)length - 1; }
    return (ssize_t)length;
}
"""
BODY_SEAM = r"""
static ngx_int_t ngx_http_modsecurity_process_request_body(ngx_http_request_t *r,
    const ngx_http_modsecurity_conf_t *mcf) {
    ++body_calls;
    if (context.contract.engine_decision != MSCONNECTOR_TRANSACTION_DECISION_ALLOW) {
        ngx_http_modsecurity_request_intervention_log_event(r, mcf,
            MSCONNECTOR_PHASE_REQUEST_BODY, "request_body_before_handler");
    }
    return selected_result;
}
"""
MAIN = r"""
int main(int argc, char **argv) {
    connection_t connection = {0};
    ngx_open_file_t logfile = {3};
    ngx_http_request_t request = {&connection, 0};
    ngx_int_t first, retry;
    size_t content_size;
    if (argc != 9) { return 2; }
    header_case = strcmp(argv[1], "headers") == 0;
    allocation_failure = strcmp(argv[1], "allocation") == 0;
    present = !header_case && !allocation_failure;
    selected_result = (ngx_int_t)strtol(argv[3], NULL, 10);
    configuration.enable = 1;
    configuration.phase4_mode = (ngx_uint_t)strtoul(argv[4], NULL, 10);
    configuration.phase4_log_file = &logfile;
    sink = argv[5];
    request.header_sent = strtol(argv[7], NULL, 10) == 1;
    context.last_intervention_status = (ngx_int_t)strtol(argv[8], NULL, 10);
    context.contract.error_class = MSCONNECTOR_TRANSACTION_ERROR_NONE;
    if (strcmp(argv[2], "engine") == 0) {
        context.contract.error_class = MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE;
    } else if (strcmp(argv[2], "limit") == 0) {
        context.contract.error_class = MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT;
    } else if (strcmp(argv[2], "protocol") == 0) {
        context.contract.error_class = MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL;
    } else if (strcmp(argv[2], "connector") == 0) {
        context.contract.error_class = MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR;
    } else if (strcmp(argv[2], "timeout") == 0) {
        context.contract.error_class = MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT;
    }
    context.contract.engine_decision = MSCONNECTOR_TRANSACTION_DECISION_ALLOW;
    if (strcmp(argv[6], "block") == 0) {
        context.contract.engine_decision = MSCONNECTOR_TRANSACTION_DECISION_BLOCK;
    } else if (strcmp(argv[6], "redirect") == 0) {
        context.contract.engine_decision = MSCONNECTOR_TRANSACTION_DECISION_REDIRECT;
    }
    strcpy(context.contract.transaction_id, "request-error-test");
    strcpy(context.contract.request_method, "POST");
    strcpy(context.contract.request_uri, "/case?token=private-value");
    strcpy(context.last_intervention_rule_id, "999");
    context.event_transaction_id.data = (u_char *)context.contract.transaction_id;
    context.event_transaction_id.len = strlen(context.contract.transaction_id);
    context.request_body_bytes_seen = 3;
    if (strcmp(sink, "disabled") == 0) { configuration.phase4_log_file = NULL; }
    if (strcmp(sink, "invalid-fd") == 0) { logfile.fd = NGX_INVALID_FILE; }
    if (strcmp(sink, "serialization") == 0) {
        content_size = sizeof(context.contract.request_content_type) - 1U;
        memset(context.contract.request_content_type, 'A', content_size);
        context.contract.request_content_type[content_size] = '\0';
    }
    first = ngx_http_modsecurity_access_handler(&request);
    if (strtol(argv[7], NULL, 10) == 2) { request.header_sent = 1; }
    retry = ngx_http_modsecurity_access_handler(&request);
    printf("{\"first\":%ld,\"retry\":%ld,\"writes\":%d,\"diagnostics\":%d,"
        "\"initializations\":%d,\"body_calls\":%d,\"attempted\":%d,\"cause\":%d,"
        "\"connection_error\":%d,\"attempted_event\":%s}\n",
        first, retry, writes, diagnostics, initialization_calls, body_calls,
        context.request_error_event_attempted, context.contract.error_class,
        connection.error, attempted[0] != '\0' ? attempted : "null");
    return 0;
}
"""


def compile_fixture(directory: Path, stem: str, source: str,
                    *, common_writer: bool = True) -> Path:
    compiler = shlex.split(os.environ.get("CC", "cc"))
    if not compiler or shutil.which(compiler[0]) is None:
        raise RuntimeError("a C compiler is required for request-error regressions")
    fixture = directory / (stem + ".c")
    fixture.write_text(source, encoding="utf-8")
    binary = directory / stem
    command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror",
                          "-I", str(source_path('common/include', root=ROOT)), "-I", str(ROOT), str(fixture)]
    if common_writer:
        phase_source = (source_path('common/src/transaction_state.c', root=ROOT)).read_text(encoding="utf-8")
        phase = directory / "phase.c"
        phase.write_text('#include "msconnector/transaction_state.h"\n' +
                         function_definition(phase_source, "msconnector_phase_name"),
                         encoding="utf-8")
        command.append(str(phase))
        command += [str(source_path('common/src', root=ROOT) / name) for name in
                    ("event.c", "event_jsonl.c", "http_status.c", "json_escape.c", "status.c")]
    command += ["-o", str(binary)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise AssertionError("request-error fixture compilation failed:\n" +
                             result.stderr[-6000:])
    return binary


PROVENANCE_SEAM = r'''
/* Provenance is independently exercised by the exact-writer fixture. */
static int ngx_http_modsecurity_apply_event_provenance(ngx_http_request_t *r,
    msconnector_event *event, char *connection_id, size_t capacity) {
    (void)r; (void)event; (void)connection_id; (void)capacity; return 1;
}
'''


class NginxRequestErrorEventsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        temporary = tempfile.TemporaryDirectory(
            prefix="nginx-request-events-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        access = ACCESS.read_text(encoding="utf-8")
        common = COMMON.read_text(encoding="utf-8")
        writers = "\n".join("static " + result + "\n" +
                           function_definition(common, name) for result, name in (
                               ("int", "ngx_http_modsecurity_write_event_jsonl"),
                               ("ngx_int_t", "ngx_http_modsecurity_write_phase_event_jsonl")))
        functions = "\n".join("static " + result + "\n" +
                              function_definition(access, name) for result, name in FUNCTIONS)
        handler = "ngx_int_t\n" + function_definition(access, "ngx_http_modsecurity_access_handler")
        fixture = PREAMBLE + PROVENANCE_SEAM + writers + functions + BODY_SEAM + handler + MAIN
        cls.binary = compile_fixture(directory, "request-events", fixture)
        guard = """    if (!ngx_http_modsecurity_request_has_rule_decision(ctx)) {
        return;
    }
"""
        if fixture.count(guard) != 1:
            raise AssertionError("the producer guard must have exactly one mutation anchor")
        cls.unguarded = compile_fixture(
            directory, "unguarded-events", fixture.replace(guard, "", 1))

    def run_case(self, side: str = "body", cause: str = "engine", result: int = 500,
                 mode: int = 0, sink: str = "ok", rule: str = "none",
                 header_sent: int = 0, last_status: int = 0,
                 *, binary: Path | None = None) -> dict:
        run = subprocess.run(
            [str(binary or self.binary), side, cause, str(result), str(mode),
             sink, rule, str(header_sent), str(last_status)],
            capture_output=True, text=True, timeout=5, check=True)
        return json.loads(run.stdout)

    def test_uri_native_failure_emits_one_typed_error_not_a_rule_block(self) -> None:
        for mode in (0, 1, 2):
            with self.subTest(mode=mode):
                evidence = self.run_case(side="headers", mode=mode)
                self.assertEqual((evidence["first"], evidence["retry"]), (500, 500))
                self.assertEqual(evidence["writes"], 1)
                self.assertEqual(evidence["initializations"], 1)
                self.assertEqual(evidence["body_calls"], 0)
                event = evidence["attempted_event"]
                self.assertEqual(event["message_id"], "MSCONN_EVENT_INVALID_ENGINE_RESPONSE")
                self.assertEqual(event["status"], "error")
                self.assertEqual(event["rule_id"], "")
                self.assertEqual(event["actual_action"], "")
                self.assertEqual(event["visible_http_status"], 0)
                self.assertFalse(event["eos_seen"])
                self.assertNotIn("private-value", json.dumps(event))

    def test_previous_unguarded_uri_producer_is_detected_by_duplicate_evidence(self) -> None:
        evidence = self.run_case(side="headers", binary=self.unguarded)
        self.assertEqual(evidence["writes"], 2)

    def test_unclassified_host_error_is_not_mistaken_for_a_rule(self) -> None:
        evidence = self.run_case(side="headers", cause="none")
        self.assertEqual(evidence["writes"], 1)
        self.assertEqual(evidence["attempted_event"]["message_id"], "MSCONN_EVENT_CONNECTOR_ERROR")

    def test_body_budget_and_protocol_failures_remain_distinct(self) -> None:
        for status, identifier in ((413, "MSCONN_EVENT_BODY_LIMIT"),
                                   (400, "MSCONN_EVENT_PROTOCOL_ERROR")):
            with self.subTest(status=status):
                evidence = self.run_case(cause="none", result=status)
                self.assertEqual((evidence["first"], evidence["retry"]), (status, status))
                self.assertEqual(evidence["attempted_event"]["message_id"], identifier)
                self.assertEqual(evidence["attempted_event"]["rule_id"], "")
                self.assertEqual(evidence["body_calls"], 1)

    def test_failed_log_sinks_never_replace_the_cause_or_retry(self) -> None:
        for mode in (0, 1, 2):
            for sink in ("write-error", "short-write", "serialization"):
                with self.subTest(mode=mode, sink=sink):
                    evidence = self.run_case(mode=mode, sink=sink)
                    self.assertEqual((evidence["first"], evidence["retry"]), (500, 500))
                    self.assertEqual(evidence["attempted"], 1)
                    self.assertEqual(evidence["writes"], 0 if sink == "serialization" else 1)
                    self.assertEqual(evidence["diagnostics"], 1)
                    self.assertEqual(evidence["cause"], self.run_case()["cause"])
                    self.assertEqual(evidence["body_calls"], 1)

    def test_disabled_and_invalid_sinks_are_not_accessed(self) -> None:
        for sink in ("disabled", "invalid-fd"):
            with self.subTest(sink=sink):
                evidence = self.run_case(sink=sink)
                self.assertEqual((evidence["first"], evidence["retry"]), (500, 500))
                self.assertEqual(evidence["writes"], 0)
                self.assertEqual(evidence["body_calls"], 1)

    def test_real_rule_status_500_and_redirect_are_not_technical_errors(self) -> None:
        for rule, status in (("block", 500), ("block", 403), ("redirect", 302)):
            with self.subTest(rule=rule, status=status):
                evidence = self.run_case(side="headers", cause="none", rule=rule,
                                         result=status, last_status=status)
                self.assertEqual(evidence["first"], status)
                self.assertEqual(evidence["cause"], 0)
                self.assertEqual(evidence["attempted"], 0)
                self.assertEqual(evidence["attempted_event"]["message_id"],
                                 "MSCONN_EVENT_ENGINE_DECISION")
                self.assertEqual(evidence["attempted_event"]["visible_http_status"], 0)
                self.assertEqual(evidence["attempted_event"]["actual_action"], "")

    def test_failed_redirect_host_result_cannot_borrow_the_rule_status(self) -> None:
        evidence = self.run_case(cause="none", rule="redirect", result=500, last_status=302)
        self.assertEqual(evidence["first"], 500)
        self.assertNotEqual(evidence["cause"], 0)
        self.assertEqual(evidence["attempted_event"]["message_id"], "MSCONN_EVENT_CONNECTOR_ERROR")

    def test_nginx_control_values_do_not_use_native_append_semantics(self) -> None:
        for result in (0, -2, -4, -5):
            with self.subTest(result=result):
                evidence = self.run_case(cause="none", result=result)
                self.assertEqual((evidence["first"], evidence["retry"]), (result, result))
                self.assertEqual(evidence["writes"], 0)
                self.assertEqual(evidence["cause"], 0)

    def test_existing_error_cannot_become_a_successful_control_return(self) -> None:
        for result in (0, -2, -4, -5):
            with self.subTest(result=result):
                evidence = self.run_case(result=result)
                self.assertEqual((evidence["first"], evidence["retry"]), (500, 500))
                self.assertEqual(evidence["writes"], 1)

    def test_late_request_error_never_requests_a_second_http_response(self) -> None:
        evidence = self.run_case(header_sent=1)
        self.assertEqual((evidence["first"], evidence["retry"]), (-1, -1))
        self.assertEqual(evidence["connection_error"], 1)
        self.assertEqual(evidence["attempted_event"]["visible_http_status"], 0)
        self.assertFalse(evidence["attempted_event"]["connection_aborted"])

    def test_error_reentry_after_headers_never_reuses_the_unsent_http_result(self) -> None:
        evidence = self.run_case(header_sent=2)
        self.assertEqual((evidence["first"], evidence["retry"]), (500, -1))
        self.assertEqual(evidence["connection_error"], 1)
        self.assertEqual(evidence["writes"], 1)
        self.assertEqual(evidence["body_calls"], 1)

    def test_allocation_failure_has_no_invented_transaction_event(self) -> None:
        evidence = self.run_case(side="allocation")
        self.assertEqual((evidence["first"], evidence["retry"]), (500, 500))
        self.assertEqual(evidence["writes"], 0)


class NginxMissingRequestBodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        temporary = tempfile.TemporaryDirectory(
            prefix="nginx-absent-body-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        access = ACCESS.read_text(encoding="utf-8")
        functions = "\n".join("static ngx_int_t\n" + function_definition(access, name)
                              for name in native_fixture.FUNCTIONS)
        anchor = '        if (strcmp(argv[1], "empty") == 0) { body.bufs = NULL; }'
        if native_fixture.MAIN.count(anchor) != 1:
            raise AssertionError("the missing-body fixture requires the exact empty-body anchor")
        main = native_fixture.MAIN.replace(
            anchor, anchor + '\n        if (strcmp(argv[1], "absent") == 0) { request.request_body = NULL; }', 1)
        cls.binary = compile_fixture(Path(temporary.name), "absent-body",
                                     native_fixture.PREAMBLE + functions + main,
                                     common_writer=False)

    def test_absent_storage_still_finalizes_an_empty_body_once(self) -> None:
        result = subprocess.run([str(self.binary), "absent", "1", "1", "1"],
                                capture_output=True, text=True, timeout=5, check=True)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence["result"], -5)
        self.assertEqual(evidence["append_calls"], 0)
        self.assertEqual(evidence["completions"], 1)
        self.assertEqual(evidence["processed"], 1)

    def test_absent_storage_does_not_hide_a_failed_native_finalization(self) -> None:
        for native in (-1, 0, 2):
            with self.subTest(native=native):
                result = subprocess.run([str(self.binary), "absent", "1", str(native), "1"],
                                        capture_output=True, text=True, timeout=5, check=True)
                evidence = json.loads(result.stdout)
                self.assertEqual(evidence["result"], 500)
                self.assertEqual(evidence["completions"], 0)
                self.assertEqual(evidence["processed"], 0)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
