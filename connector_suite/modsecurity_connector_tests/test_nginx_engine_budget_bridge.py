"""Compile the real post-return bridge with real Common state and JSONL.

Only the monotonic clock and NGX host/file APIs are controlled seams. This is
not a live timeout or hard-interruption proof; native probes remain required.
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
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "msconnector/event_jsonl.h"
#include "msconnector/phase.h"
#include "msconnector/transaction_state.h"
#include "msconnector/transaction_contract.h"
#include "connectors/profile_registry.h"
#include "ngx_http_modsecurity_engine_call_budget.h"
typedef long ngx_int_t;
typedef unsigned long ngx_uint_t;
typedef unsigned char u_char;
typedef ngx_http_modsecurity_engine_call_budget ngx_http_modsecurity_engine_call_measurement;
typedef struct { int error; void *log; } connection_t;
typedef struct { connection_t *connection; int header_sent; } ngx_http_request_t;
typedef struct { int fd; } ngx_open_file_t;
typedef struct { ngx_uint_t engine_call_budget_ms; ngx_open_file_t *phase4_log_file; } ngx_http_modsecurity_conf_t;
typedef struct {
    msconnector_transaction_contract contract;
    int contract_initialized, native_response_body_eos;
} ngx_http_modsecurity_ctx_t;
typedef struct { const char *method, *uri, *content_type; }
    ngx_http_modsecurity_event_request_metadata_t;
enum { NGX_OK=0, NGX_ERROR=-1, NGX_LOG_ERR=4, NGX_INVALID_FILE=-1, NGX_HTTP_GATEWAY_TIME_OUT=504 };
#define NGX_CONF_UNSET_UINT ((ngx_uint_t)-1)
static int ngx_http_modsecurity_module, clock_calls, writes, fail_clock;
static uint64_t end_ns;
static ngx_http_modsecurity_ctx_t context;
static ngx_http_modsecurity_conf_t config;
static char jsonl[8192];
static int controlled_clock(int clock, struct timespec *value) {
    uint64_t ns = clock_calls++ == 0 ? UINT64_C(1000000000) : end_ns;
    if (clock != CLOCK_MONOTONIC || fail_clock) return -1;
    value->tv_sec = (time_t)(ns / UINT64_C(1000000000));
    value->tv_nsec = (long)(ns % UINT64_C(1000000000));
    return 0;
}
#define clock_gettime controlled_clock
static void ngx_log_error(int level, void *log, int number, const char *format, ...) {
    (void)level; (void)log; (void)number; (void)format;
}
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_get_module_ctx(ngx_http_request_t *r) {
    (void)r; return &context;
}
static ngx_http_modsecurity_conf_t *ngx_http_get_module_loc_conf(ngx_http_request_t *r, int module) {
    (void)r; (void)module; return &config;
}
static ngx_http_modsecurity_event_request_metadata_t ngx_http_modsecurity_event_request_metadata(ngx_http_request_t *r) {
    (void)r;
    return (ngx_http_modsecurity_event_request_metadata_t){"GET", "/budget-control", "text/plain"};
}
static ngx_int_t ngx_http_modsecurity_write_phase_event_jsonl(ngx_http_request_t *r,
        const ngx_http_modsecurity_conf_t *conf, const msconnector_event *event, const char *phase) {
    int truncated=0;
    char line[4096];
    (void)r; (void)conf; (void)phase;
    ++writes;
    if (!msconnector_event_write_jsonl_line(event, line, sizeof(line), &truncated) || truncated ||
        strlen(jsonl) + strlen(line) >= sizeof(jsonl)) return NGX_ERROR;
    strcat(jsonl,line);
    return NGX_OK;
}
'''
MAIN = r'''
int main(int argc, char **argv) {
    connection_t connection={0};
    ngx_http_request_t request={&connection, 0};
    ngx_open_file_t file={7};
    ngx_http_modsecurity_engine_call_measurement measurement;
    enum msconnector_phase target;
    const char *before_cleanup_cause;
    int before, after=99, cleanup;
    if (argc != 6) return 2;
    config.engine_call_budget_ms=strtoul(argv[1], NULL, 10);
    end_ns=strtoull(argv[2], NULL, 10);
    target=atoi(argv[3]) == 1 ? MSCONNECTOR_PHASE_REQUEST_HEADERS :
        atoi(argv[3]) == 3 ? MSCONNECTOR_PHASE_RESPONSE_HEADERS : MSCONNECTOR_PHASE_RESPONSE_BODY;
    fail_clock=atoi(argv[4]); config.phase4_log_file=&file;
    if (msconnector_transaction_contract_init(&context.contract,
        msconnector_profile_registry_find("nginx"), "budget-control", "nginx", "budget-tx",
        MSCONNECTOR_TRANSACTION_MODE_SAFE, 100U) != MSCONNECTOR_TRANSACTION_TRANSITION_OK) return 3;
    context.contract_initialized=1;
    for (enum msconnector_phase phase=MSCONNECTOR_PHASE_REQUEST_HEADERS; phase<target; ++phase) {
        if (msconnector_transaction_contract_begin_phase(&context.contract, phase, 0U) != 0 ||
            msconnector_transaction_contract_complete_phase(&context.contract, phase, 0U) != 0) return 4;
    }
    if (msconnector_transaction_contract_begin_phase(&context.contract, target, 0U) != 0) return 5;
    request.header_sent=target == MSCONNECTOR_PHASE_RESPONSE_BODY;
    context.native_response_body_eos=request.header_sent;
    before=ngx_http_modsecurity_engine_call_begin(&request, target, &measurement);
    if (before == NGX_OK) after=ngx_http_modsecurity_engine_call_finish(&request, target, &measurement, atoi(argv[5]));
    before_cleanup_cause=msconnector_transaction_error_class_name(context.contract.error_class);
    cleanup=msconnector_transaction_contract_cleanup(&context.contract, 0U);
    printf("%d %d %d %d %d %d %s\n", before, after, clock_calls, writes,
        cleanup, context.contract.cleanup_complete,
        before_cleanup_cause);
    fputs(jsonl, stdout);
    return 0;
}
'''


class EngineBudgetBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or not shutil.which(compiler[0]):
            raise RuntimeError("real C17 compiler is required")
        temporary = tempfile.TemporaryDirectory(prefix="nginx-budget-bridge-",
                                                 dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        source = (NATIVE / "ngx_http_modsecurity_module.c").read_text()
        names = ("ngx_http_modsecurity_engine_call_log_budget",
                 "ngx_http_modsecurity_engine_call_begin", "ngx_http_modsecurity_engine_call_finish")
        functions = "\n".join("static ngx_int_t\n" + function_definition(source, name) for name in names)
        fixture = directory / "budget.c"
        fixture.write_text(PREAMBLE + functions + MAIN)
        cls.binary = directory / "budget"
        command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                              "-I", str(NATIVE), "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)), str(fixture)]
        command += [str(source_path('common/src', root=ROOT) / name) for name in
                    ("transaction_state.c", "decision_action.c", "intervention.c", "block_statuses.c",
                     "http_status.c", "late_intervention.c", "event.c", "event_jsonl.c", "json_escape.c", "status.c")]
        command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        if result.returncode:
            raise AssertionError(result.stderr[-7000:])

    def observe(self, budget=10, end=1025000000, phase=1, fail=0, native=1):
        result = subprocess.run([str(self.binary), str(budget), str(end), str(phase), str(fail), str(native)],
                                capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        state, _, event = result.stdout.partition("\n")
        values = state.split()
        records = [json.loads(line) for line in event.splitlines() if line.strip()]
        return [int(value) for value in values[:-1]], values[-1], records[0] if len(records) == 1 else records or None

    def test_disabled_and_at_or_under_budget_preserve_non_timeout(self):
        for budget, end, calls in ((0, 1050000000, 0), (10, 1010000000, 2), (100, 1025000000, 2)):
            values, cause, event = self.observe(budget, end)
            self.assertEqual(values[:4], [0, 0, calls, 0])
            # The bridge does not complete its caller's active phase. Leaving
            # this controlled positive call unfinished must remain detectable.
            self.assertEqual(values[4:], [-8, 1])
            self.assertEqual(cause, "none")
            self.assertIsNone(event)

    def test_exceeded_actual_phases_seal_common_before_completion_without_rule(self):
        for phase in (1, 4):
            values, cause, event = self.observe(phase=phase)
            self.assertEqual(values, [0, -1, 2, 1, 0, 1])
            self.assertEqual(cause, "engine_timeout")
            self.assertEqual(event["event"], "engine_call_budget_exceeded")
            self.assertEqual(event["reason"], "budget_ms=10;elapsed_ns=25000000;native_return=1;common_completed=0")
            self.assertEqual(event["rule_id"], "")
            self.assertEqual(event["phase"], "request_headers" if phase == 1 else "response_body")
            self.assertEqual(event["http_status"], 504)
            self.assertIs(event["eos_seen"], phase == 4)

    def test_invalid_or_backward_clock_is_not_fabricated_timeout(self):
        for end, fail in ((1025000000, 1), (999999999, 0)):
            values, cause, event = self.observe(end=end, fail=fail)
            self.assertIn(-1, values[:2])
            self.assertEqual(cause, "connector_error")
            self.assertEqual(values[4:], [0, 1])
            self.assertIsNone(event)

    def test_slow_invalid_native_return_reaches_native_gate_not_timeout(self):
        for native in (0, -1, 2, 99):
            values, cause, event = self.observe(native=native)
            self.assertEqual(values[:4], [0, 0, 2, 0])
            self.assertEqual(cause, "none")
            self.assertIsNone(event)

    def test_response_headers_emit_real_budget_and_technical_timeout(self):
        values, cause, events = self.observe(phase=3)
        self.assertEqual(values, [0, -1, 2, 2, 0, 1])
        self.assertEqual(cause, "engine_timeout")
        self.assertEqual([event["event"] for event in events],
                         ["engine_call_budget_exceeded", "engine_timeout"])
        self.assertEqual(events[1]["message_id"], "MSCONN_EVENT_ENGINE_TIMEOUT")
        for event in events:
            self.assertEqual(event["rule_id"], "")
            self.assertEqual(event["phase"], "response_headers")
            self.assertEqual(event["http_status"], 504)
        self.assertEqual(events[1]["timeout_stage"], "response_headers")

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
