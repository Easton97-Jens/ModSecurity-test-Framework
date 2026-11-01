"""Actual full P3 caller with real Common transitions and JSONL, not runtime.

Only NGINX host/header plumbing, native APIs and CLOCK_MONOTONIC are controlled.
ROOT defaults to this checkout; a test loader may override it for integration.
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
PREAMBLE = r'''
#define _POSIX_C_SOURCE 200809L
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include "msconnector/event_jsonl.h"
#include "msconnector/transaction_contract.h"
#include "msconnector/transaction_state.h"
#include "connectors/profile_registry.h"
#include "ngx_http_modsecurity_engine_call_budget.h"
#include "ngx_http_modsecurity_event_uri.h"
typedef long ngx_int_t;
typedef unsigned long ngx_uint_t;
typedef int ngx_flag_t;
typedef unsigned char u_char;
typedef void ngx_pool_t;
typedef ngx_pool_t *ngx_http_modsecurity_pcre_pool_snapshot_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int error; void *log; } connection_t;
typedef struct { unsigned status; ngx_str_t content_type, status_line; void *location; long content_length_n; } headers_t;
typedef struct { connection_t *connection; int header_sent, err_status, error_page, filter_need_in_memory, header_only; headers_t headers_out; ngx_pool_t *pool; } ngx_http_request_t;
typedef struct { int fd; } ngx_open_file_t;
typedef ngx_http_modsecurity_engine_call_budget ngx_http_modsecurity_engine_call_measurement;
typedef struct { ngx_uint_t engine_call_budget_ms; ngx_open_file_t *phase4_log_file; int phase4_mode; } ngx_http_modsecurity_conf_t;
typedef struct {
    msconnector_transaction_contract contract;
    int contract_initialized, native_response_body_eos, native_event_phase_active;
    enum msconnector_phase native_event_phase;
    int response_headers_processing_failed, intervention_triggered, common_response_validated, processed, response_headers_seen;
    int intervention_redirect_location_installed, response_replaced, last_intervention_status;
    char last_intervention_rule_id[64];
    ngx_str_t event_transaction_id;
    void *modsec_transaction;
} ngx_http_modsecurity_ctx_t;
typedef struct { const char *method, *uri, *content_type; } ngx_http_modsecurity_event_request_metadata_t;
typedef enum { MSCONNECTOR_NGINX_INTERVENTION_FAILURE, MSCONNECTOR_NGINX_INTERVENTION_BYPASS, MSCONNECTOR_NGINX_INTERVENTION_ACTIVE, MSCONNECTOR_NGINX_INTERVENTION_ALLOW } msconnector_nginx_intervention_disposition;
enum { NGX_OK=0, NGX_ERROR=-1, NGX_LOG_ERR=4, NGX_LOG_WARN=5, NGX_INVALID_FILE=-1, NGX_HTTP_GATEWAY_TIME_OUT=504, NGX_HTTP_INTERNAL_SERVER_ERROR=500, NGX_HTTP_FORBIDDEN=403 };
#define NGX_CONF_UNSET_UINT ((ngx_uint_t)-1)
#define NGX_HTTP_MODSECURITY_RESPONSE_MAPPER_DIAGNOSTIC_HEADER 0
#define dd(...) ((void)0)
#define ngx_strlen strlen
#define ngx_errno 0
#define ngx_str_null(s) do { (s)->len=0; (s)->data=NULL; } while (0)
static int ngx_http_modsecurity_module, clock_calls, clock_failure, native_return, native_calls, downstream_calls, intervention_calls, writes;
static uint64_t end_ns;
static ngx_http_modsecurity_ctx_t context;
static ngx_http_modsecurity_conf_t config;
static char jsonl[16384];
static int controlled_clock(int clock, struct timespec *value) {
    int ordinal=++clock_calls;
    uint64_t ns=ordinal == 1 ? UINT64_C(1000000000) : end_ns;
    if (clock != CLOCK_MONOTONIC || clock_failure == ordinal) return -1;
    value->tv_sec=(time_t)(ns / UINT64_C(1000000000));
    value->tv_nsec=(long)(ns % UINT64_C(1000000000));
    return 0;
}
#define clock_gettime controlled_clock
static void ngx_log_error(int level, void *log, int number, const char *format, ...) {
    (void)level; (void)log; (void)number; (void)format;
}
static ssize_t ngx_write_fd(int fd, u_char *data, size_t size) {
    size_t used=strlen(jsonl);
    if (fd != 7 || size >= sizeof(jsonl)-used) return -1;
    memcpy(jsonl+used,data,size); jsonl[used+size]='\0'; ++writes;
    return (ssize_t)size;
}
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_get_module_ctx(ngx_http_request_t *r) { (void)r; return &context; }
static ngx_http_modsecurity_conf_t *ngx_http_get_module_loc_conf(ngx_http_request_t *r, int module) { (void)r; (void)module; return &config; }
static ngx_http_modsecurity_event_request_metadata_t ngx_http_modsecurity_event_request_metadata(ngx_http_request_t *r) { (void)r; return (ngx_http_modsecurity_event_request_metadata_t){"GET","/p3-source-control","text/plain"}; }
static void ngx_http_modsecurity_validate_response_mapper(ngx_http_modsecurity_ctx_t *ctx, ngx_http_request_t *r, int mode) { (void)ctx; (void)r; (void)mode; }
static ngx_int_t ngx_http_modsecurity_add_response_headers(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx) { (void)r; (void)ctx; return NGX_OK; }
static ngx_int_t ngx_http_modsecurity_response_header_metrics(ngx_http_request_t *r, size_t *count, size_t *bytes) { (void)r; *count=0; *bytes=0; return NGX_OK; }
static char *ngx_str_to_char(ngx_str_t value, ngx_pool_t *pool) { (void)pool; return (char *)value.data; }
static ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool) { return pool; }
static void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *pool) { (void)pool; }
static int msc_process_response_headers(void *tx, unsigned status, const char *version) {
    if (tx != &context || status != 200 || strcmp(version,"HTTP 1.1")) abort();
    ++native_calls; return native_return;
}
static int ngx_http_modsecurity_process_intervention(void *tx, ngx_http_request_t *r, int early) { (void)r; (void)early; if (tx != &context) abort(); ++intervention_calls; return 0; }
static ngx_int_t ngx_http_next_header_filter(ngx_http_request_t *r) { (void)r; ++downstream_calls; return NGX_OK; }
static ngx_int_t ngx_http_filter_finalize_request(ngx_http_request_t *r, int *module, int status) { (void)r; (void)module; (void)status; abort(); }
'''

MAIN = r'''
int main(int argc, char **argv) {
    connection_t connection={0};
    ngx_http_request_t request={0};
    ngx_open_file_t file={7};
    int first, retry;
    if (argc != 5) return 2;
    native_return=atoi(argv[1]); clock_failure=atoi(argv[2]);
    config.engine_call_budget_ms=strtoul(argv[3],NULL,10);
    end_ns=strtoull(argv[4],NULL,10);
    config.phase4_log_file=&file;
    request.connection=&connection; request.headers_out.status=200;
    context.event_transaction_id=(ngx_str_t){9,(u_char *)"actual-tx"};
    context.modsec_transaction=&context;
    if (msconnector_transaction_contract_init(&context.contract,
        msconnector_profile_registry_find("nginx"),"actual-tx","nginx","p3-control",
        MSCONNECTOR_TRANSACTION_MODE_SAFE,100U) != 0) return 3;
    context.contract_initialized=1;
    for (enum msconnector_phase phase=MSCONNECTOR_PHASE_REQUEST_HEADERS; phase<MSCONNECTOR_PHASE_RESPONSE_HEADERS; ++phase) {
        if (msconnector_transaction_contract_begin_phase(&context.contract,phase,0U) != 0 ||
            msconnector_transaction_contract_complete_phase(&context.contract,phase,0U) != 0) return 4;
    }
    first=ngx_http_modsecurity_header_filter(&request);
    retry=first == NGX_ERROR ? ngx_http_modsecurity_header_filter(&request) : 99;
    printf("{\"return\":%d,\"retry\":%d,\"native_calls\":%d,\"downstream_calls\":%d,\"intervention_calls\":%d,\"clock_calls\":%d,\"writes\":%d,\"failed\":%d,\"headers_seen\":%d,\"phase_mask\":%u,\"last_phase\":\"%s\",\"error_class\":\"%s\"}\n",
        first,retry,native_calls,downstream_calls,intervention_calls,clock_calls,writes,
        context.response_headers_processing_failed,context.response_headers_seen,
        (unsigned)context.contract.completed_phase_mask,msconnector_phase_name(context.contract.last_completed_phase),
        msconnector_transaction_error_class_name(context.contract.error_class));
    fputs(jsonl,stdout);
    return 0;
}
'''


PROVENANCE_SEAM = r'''
/* Provenance is independently exercised by the exact-writer fixture. */
static int ngx_http_modsecurity_apply_event_provenance(ngx_http_request_t *r,
    msconnector_event *event, char *connection_id, size_t capacity) {
    (void)r; (void)event; (void)connection_id; (void)capacity; return 1;
}
'''


class P3TechnicalSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or not shutil.which(compiler[0]):
            raise RuntimeError("real C17 compiler is required")
        temporary = tempfile.TemporaryDirectory(prefix="nginx-p3-source-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        native = source_path('connectors/nginx/src', root=ROOT)
        module = (native / "ngx_http_modsecurity_module.c").read_text()
        common = (native / "ngx_http_modsecurity_common.h").read_text()
        header = (native / "ngx_http_modsecurity_header_filter.c").read_text()
        selections = (
            (common, "static ngx_int_t", "ngx_http_modsecurity_write_phase_event_jsonl"),
            (common, "static msconnector_nginx_intervention_disposition", "ngx_http_modsecurity_intervention_disposition"),
            (module, "", "ngx_http_modsecurity_contract_begin"),
            (module, "", "ngx_http_modsecurity_contract_complete"),
            (module, "static ngx_int_t", "ngx_http_modsecurity_engine_call_log_budget"),
            (module, "ngx_int_t", "ngx_http_modsecurity_engine_call_begin"),
            (module, "ngx_int_t", "ngx_http_modsecurity_engine_call_finish"),
            (module, "ngx_int_t", "ngx_http_modsecurity_log_technical_failure"),
            (header, "static ngx_int_t", "ngx_http_modsecurity_phase3_log_event"),
            (header, "static ngx_int_t", "ngx_http_modsecurity_handle_response_header_intervention"),
            (header, "ngx_int_t", "ngx_http_modsecurity_header_filter"),
        )
        functions = "\n".join(kind + "\n" + function_definition(source, name)
                              for source, kind, name in selections)
        fixture = directory / "p3.c"
        fixture.write_text(PREAMBLE + PROVENANCE_SEAM + functions + MAIN)
        cls.binary = directory / "p3"
        command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                              "-I", str(native), "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)), str(fixture)]
        command += [str(source_path('common/src', root=ROOT) / name) for name in
                    ("transaction_state.c", "decision_action.c", "intervention.c", "block_statuses.c",
                     "http_status.c", "late_intervention.c", "event.c", "event_jsonl.c", "json_escape.c", "status.c")]
        command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        if result.returncode:
            raise AssertionError(result.stderr[-7000:])

    def observe(self, native=1, clock_failure=0, budget=10, end=1005000000):
        result = subprocess.run([str(self.binary), str(native), str(clock_failure), str(budget), str(end)],
                                capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        return rows[0], rows[1:]

    def assert_failure(self, state, events, cause, event_name, native_calls, clock_calls, status=500):
        self.assertEqual(state, {"return": -1, "retry": -1, "native_calls": native_calls,
                                "downstream_calls": 0, "intervention_calls": 0,
                                "clock_calls": clock_calls, "writes": len(events), "failed": 1,
                                "headers_seen": 0, "phase_mask": 3, "last_phase": "request_body", "error_class": cause})
        technical = [event for event in events if event["event"] == event_name]
        self.assertEqual(len(technical), 1)
        event = technical[0]
        self.assertEqual(event["message_id"], "MSCONN_EVENT_" + event_name.upper())
        self.assertEqual(event["status"], "error")
        self.assertEqual(event["phase"], "response_headers")
        self.assertEqual(event["rule_id"], "")
        self.assertEqual(event["http_status"], status)
        self.assertEqual(event["transaction_id"], "actual-tx")
        self.assertEqual(event["uri"], "/p3-source-control")
        self.assertEqual(event["requested_action"], "error")
        self.assertFalse(event["headers_sent"])
        self.assertFalse(event["eos_seen"])

    def test_native_zero_and_invalid_returns_fail_with_actual_technical_event(self):
        for native in (0, -1, 2):
            for end in (1005000000, 1025000000):
                with self.subTest(native=native, end=end):
                    state, events = self.observe(native=native, end=end)
                    self.assertEqual(len(events), 1)
                    self.assert_failure(state, events, "invalid_engine_response", "invalid_engine_response", 1, 2)

    def test_begin_clock_failure_does_not_call_native_or_forward(self):
        state, events = self.observe(clock_failure=1)
        self.assertEqual(len(events), 1)
        self.assert_failure(state, events, "connector_error", "connector_error", 0, 1)

    def test_finish_clock_failure_does_not_complete_or_forward(self):
        state, events = self.observe(clock_failure=2)
        self.assertEqual(len(events), 1)
        self.assert_failure(state, events, "connector_error", "connector_error", 1, 2)

    def test_valid_over_budget_has_exactly_timing_and_technical_events(self):
        state, events = self.observe(end=1025000000)
        self.assertEqual([event["event"] for event in events], ["engine_call_budget_exceeded", "engine_timeout"])
        self.assert_failure(state, events, "engine_timeout", "engine_timeout", 1, 2, 504)
        self.assertEqual(events[0]["reason"], "budget_ms=10;elapsed_ns=25000000;native_return=1;common_completed=0")
        self.assertEqual(events[1]["timeout_stage"], "response_headers")

    def test_disabled_success_and_at_budget_complete_actual_p3_then_forward(self):
        for budget, end, calls in ((0, 1050000000, 0), (10, 1010000000, 2)):
            with self.subTest(budget=budget):
                state, events = self.observe(budget=budget, end=end)
                self.assertEqual(events, [])
                self.assertEqual(state, {"return": 0, "retry": 99, "native_calls": 1,
                                        "downstream_calls": 1, "intervention_calls": 1,
                                        "clock_calls": calls, "writes": 0, "failed": 0,
                                        "headers_seen": 1, "phase_mask": 7, "last_phase": "response_headers", "error_class": "none"})

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
