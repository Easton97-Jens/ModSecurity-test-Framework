"""Actual full P1 caller/result boundary with real Common state and JSONL.

Host metadata/header plumbing, native APIs and monotonic time are controlled.
This is a C17 source contract, not a native host runtime or request allow proof.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include "msconnector/event_jsonl.h"
#include "msconnector/native_result.h"
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
typedef struct { connection_t *connection; int header_sent, error_page; ngx_pool_t *pool; ngx_str_t method_name, unparsed_uri, uri; } ngx_http_request_t;
typedef struct { int fd; } ngx_open_file_t;
typedef ngx_http_modsecurity_engine_call_budget ngx_http_modsecurity_engine_call_measurement;
typedef struct { ngx_uint_t engine_call_budget_ms; ngx_open_file_t *phase4_log_file; } ngx_http_modsecurity_conf_t;
typedef struct {
    msconnector_transaction_contract contract;
    int contract_initialized, native_response_body_eos, native_event_phase_active;
    enum msconnector_phase native_event_phase;
    int intervention_triggered, native_request_body_limit_rejection, request_error_event_attempted, request_body_processed;
    ngx_int_t last_intervention_status, request_error_status;
    size_t request_body_bytes_seen;
    char last_intervention_rule_id[64];
    ngx_str_t event_transaction_id;
    void *modsec_transaction;
} ngx_http_modsecurity_ctx_t;
typedef struct { const char *method, *uri, *content_type; } ngx_http_modsecurity_event_request_metadata_t;
typedef enum { MSCONNECTOR_NGINX_INTERVENTION_FAILURE, MSCONNECTOR_NGINX_INTERVENTION_BYPASS, MSCONNECTOR_NGINX_INTERVENTION_ACTIVE, MSCONNECTOR_NGINX_INTERVENTION_ALLOW } msconnector_nginx_intervention_disposition;
enum { NGX_OK=0, NGX_ERROR=-1, NGX_AGAIN=-2, NGX_DONE=-4, NGX_DECLINED=-5, NGX_LOG_ERR=4, NGX_LOG_WARN=5, NGX_INVALID_FILE=-1, NGX_HTTP_GATEWAY_TIME_OUT=504, NGX_HTTP_INTERNAL_SERVER_ERROR=500, NGX_HTTP_FORBIDDEN=403, NGX_HTTP_BAD_REQUEST=400, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE=413 };
#define NGX_CONF_UNSET_UINT ((ngx_uint_t)-1)
#define dd(...) ((void)0)
#define ngx_strlen strlen
#define ngx_errno 0
static int ngx_http_modsecurity_module, clock_calls, clock_failure, native_return, native_calls, intervention_return, intervention_calls, writes, sink_failure, callback_failure;
static uint64_t end_ns;
static ngx_http_modsecurity_ctx_t context;
static ngx_http_modsecurity_conf_t config;
static char jsonl[16384];
static int controlled_clock(int clock, struct timespec *value) {
    int ordinal=++clock_calls;
    uint64_t ns=ordinal == 1 ? UINT64_C(1000000000) : end_ns;
    if (clock != CLOCK_MONOTONIC || clock_failure == ordinal) return -1;
    value->tv_sec=(time_t)(ns/UINT64_C(1000000000)); value->tv_nsec=(long)(ns%UINT64_C(1000000000)); return 0;
}
#define clock_gettime controlled_clock
static void ngx_log_error(int level, void *log, int number, const char *format, ...) { (void)level; (void)log; (void)number; (void)format; }
static ssize_t ngx_write_fd(int fd, u_char *data, size_t size) {
    size_t used=strlen(jsonl);
    if (fd != 7 || size >= sizeof(jsonl)-used || sink_failure) return -1;
    memcpy(jsonl+used,data,size); jsonl[used+size]='\0'; ++writes; return (ssize_t)size;
}
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_get_module_ctx(ngx_http_request_t *r) { (void)r; return &context; }
static ngx_http_modsecurity_conf_t *ngx_http_get_module_loc_conf(ngx_http_request_t *r, int module) { (void)r; (void)module; return &config; }
static ngx_http_modsecurity_event_request_metadata_t ngx_http_modsecurity_event_request_metadata(ngx_http_request_t *r) { return (ngx_http_modsecurity_event_request_metadata_t){(char *)r->method_name.data,(char *)r->unparsed_uri.data,""}; }
static char *ngx_str_to_char(ngx_str_t value, ngx_pool_t *pool) { (void)pool; return (char *)value.data; }
static ngx_int_t ngx_http_modsecurity_request_header_metrics(ngx_http_request_t *r, size_t *count, size_t *bytes) { (void)r; *count=0; *bytes=0; return NGX_OK; }
static ngx_int_t ngx_http_modsecurity_add_request_headers(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx) { (void)r; (void)ctx; return NGX_OK; }
static ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool) { return pool; }
static void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *pool) { (void)pool; }
static int msc_process_request_headers(void *tx) {
    if (tx != &context || !context.native_event_phase_active || context.native_event_phase != MSCONNECTOR_PHASE_REQUEST_HEADERS || context.contract.active_phase != MSCONNECTOR_PHASE_REQUEST_HEADERS || context.contract.cleanup_started) abort();
    ++native_calls;
    if (callback_failure) (void)msconnector_transaction_contract_fail(&context.contract,MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL,0U);
    return native_return;
}
static int ngx_http_modsecurity_process_intervention(void *tx, ngx_http_request_t *r, int early) {
    (void)r;
    if (tx != &context || early != 1 || context.native_event_phase_active || context.contract.last_completed_phase != MSCONNECTOR_PHASE_REQUEST_HEADERS) abort();
    ++intervention_calls;
    if (intervention_return > 0) {
        context.last_intervention_status=intervention_return;
        strcpy(context.last_intervention_rule_id,"1100001");
        if (msconnector_transaction_contract_record_decision(&context.contract,MSCONNECTOR_TRANSACTION_DECISION_BLOCK,"1100001",0U) != 0) abort();
    }
    return intervention_return;
}
'''

MAIN = r'''
int main(int argc, char **argv) {
    connection_t connection={0}; ngx_http_request_t request={0}; ngx_open_file_t file={7};
    ngx_int_t first, retry; int prestate;
    if (argc != 8) return 2;
    native_return=atoi(argv[1]); intervention_return=atoi(argv[2]); clock_failure=atoi(argv[3]);
    config.engine_call_budget_ms=strtoul(argv[4],NULL,10); end_ns=strtoull(argv[5],NULL,10); prestate=atoi(argv[6]); sink_failure=atoi(argv[7]);
    callback_failure=prestate == 4;
    config.phase4_log_file=sink_failure == 2 ? NULL : &file;
    request.connection=&connection;
    request.method_name=(ngx_str_t){3,(u_char *)"GET"}; request.unparsed_uri=(ngx_str_t){18,(u_char *)"/p1-source-control"}; request.uri=request.unparsed_uri;
    context.event_transaction_id=(ngx_str_t){9,(u_char *)"actual-tx"}; context.modsec_transaction=&context;
    if (msconnector_transaction_contract_init(&context.contract,msconnector_profile_registry_find("nginx"),"actual-tx","nginx","p1-control",MSCONNECTOR_TRANSACTION_MODE_SAFE,100U) != 0) return 3;
    context.contract_initialized=1;
    if (prestate == 1 && msconnector_transaction_contract_cleanup(&context.contract,0U) != MSCONNECTOR_TRANSACTION_TRANSITION_PREMATURE_CLEANUP) return 4;
    if (prestate == 2) (void)msconnector_transaction_contract_fail(&context.contract,MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL,0U);
    if (prestate == 3) {
        if (msconnector_transaction_contract_begin_phase(&context.contract,MSCONNECTOR_PHASE_REQUEST_HEADERS,0U) != 0 || msconnector_transaction_contract_complete_phase(&context.contract,MSCONNECTOR_PHASE_REQUEST_HEADERS,0U) != 0) return 5;
    }
    first=ngx_http_modsecurity_process_request_headers(&request,&context,&config);
    first=ngx_http_modsecurity_request_result(&request,&config,MSCONNECTOR_PHASE_REQUEST_HEADERS,first);
    retry=ngx_http_modsecurity_process_request_headers(&request,&context,&config);
    retry=ngx_http_modsecurity_request_result(&request,&config,MSCONNECTOR_PHASE_REQUEST_HEADERS,retry);
    printf("{\"return\":%ld,\"retry\":%ld,\"native_calls\":%d,\"intervention_calls\":%d,\"clock_calls\":%d,\"writes\":%d,\"phase_mask\":%u,\"error_class\":\"%s\"}\n",first,retry,native_calls,intervention_calls,clock_calls,writes,(unsigned)context.contract.completed_phase_mask,msconnector_transaction_error_class_name(context.contract.error_class));
    fputs(jsonl,stdout); return 0;
}
'''


PROVENANCE_SEAM = r'''
/* Provenance is independently exercised by the exact-writer fixture. */
static int ngx_http_modsecurity_apply_event_provenance(ngx_http_request_t *r,
    msconnector_event *event, char *connection_id, size_t capacity) {
    (void)r; (void)event; (void)connection_id; (void)capacity; return 1;
}
'''


class P1CompletionSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or not shutil.which(compiler[0]):
            raise RuntimeError("real C17 compiler is required")
        temporary = tempfile.TemporaryDirectory(prefix="nginx-p1-source-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        native = source_path('connectors/nginx/src', root=ROOT)
        module = (native / "ngx_http_modsecurity_module.c").read_text()
        common = (native / "ngx_http_modsecurity_common.h").read_text()
        access = (native / "ngx_http_modsecurity_access.c").read_text()
        selections = [
            (common, "static int", "ngx_http_modsecurity_write_event_jsonl"),
            (common, "static ngx_int_t", "ngx_http_modsecurity_write_phase_event_jsonl"),
            (common, "static msconnector_nginx_intervention_disposition", "ngx_http_modsecurity_intervention_disposition"),
            (module, "", "ngx_http_modsecurity_contract_begin"),
            (module, "", "ngx_http_modsecurity_contract_complete"),
            (module, "static ngx_int_t", "ngx_http_modsecurity_engine_call_log_budget"),
            (module, "ngx_int_t", "ngx_http_modsecurity_engine_call_begin"),
            (module, "ngx_int_t", "ngx_http_modsecurity_engine_call_finish"),
            (access, "static int", "ngx_http_modsecurity_request_has_rule_decision"),
            (access, "static void", "ngx_http_modsecurity_request_intervention_log_event"),
            (access, "static msconnector_transaction_error_class", "ngx_http_modsecurity_request_error_cause"),
            (access, "static const char *", "ngx_http_modsecurity_request_error_message_id"),
            (access, "static void", "ngx_http_modsecurity_request_error_log_event"),
            (access, "static ngx_int_t", "ngx_http_modsecurity_request_terminal_status"),
            (access, "static ngx_int_t", "ngx_http_modsecurity_request_result"),
        ]
        # A baseline without the new producer still compiles the actual caller:
        # RED must be missing completion evidence, not a missing-header error.
        constructor = native / "ngx_http_modsecurity_request_completion.h"
        include = ''
        if constructor.exists():
            include = '#include "ngx_http_modsecurity_request_completion.h"\n'
            selections.append((access, "static void", "ngx_http_modsecurity_request_completion_log_event"))
        selections.append((access, "static ngx_int_t", "ngx_http_modsecurity_process_request_headers"))
        functions = "\n".join(kind + "\n" + function_definition(source, name) for source, kind, name in selections)
        fixture = directory / "p1.c"
        fixture.write_text(PREAMBLE + PROVENANCE_SEAM + include + functions + MAIN)
        cls.binary = directory / "p1"
        command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread", "-I", str(native), "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)), str(fixture)]
        command += [str(source_path('common/src', root=ROOT) / name) for name in ("transaction_state.c", "decision_action.c", "intervention.c", "block_statuses.c", "http_status.c", "late_intervention.c", "event.c", "event_jsonl.c", "json_escape.c", "status.c")]
        command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        if result.returncode:
            raise AssertionError(result.stderr[-7000:])

    def observe(self, native=1, intervention=0, clock_failure=0, budget=10, end=1005000000, prestate=0, sink=0):
        result = subprocess.run([str(self.binary), *map(str, (native, intervention, clock_failure, budget, end, prestate, sink))], capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        return rows[0], rows[1:]

    def test_actual_native_one_common_completed_no_intervention_emits_once(self):
        for budget, end in ((0, 1050000000), (10, 1005000000), (10, 1010000000)):
            with self.subTest(budget=budget, end=end):
                state, events = self.observe(budget=budget, end=end)
                completion = [event for event in events if event["event"] == "request_headers_complete"]
                self.assertEqual(len(completion), 1)
                event = completion[0]
                expected = {"message_id": "MSCONN_PHASE1_COMPLETE", "phase": "request_headers", "status": "ok", "action": "allow", "requested_action": "allow", "actual_action": "", "rule_id": "", "http_status": 0, "visible_http_status": 0, "transport_result": "not_observable", "transaction_id": "actual-tx", "method": "GET", "uri": "/p1-source-control"}
                self.assertEqual({key: event[key] for key in expected}, expected)
                self.assertEqual(event["reason"], "native_return=1;common_completed=1")
                self.assertEqual((state["return"], state["native_calls"], state["intervention_calls"], state["phase_mask"]), (0, 1, 1, 1))
                self.assertFalse(event["headers_sent"])
                self.assertFalse(event["eos_seen"])

    def test_native_invalid_budget_clock_and_existing_terminal_never_complete(self):
        for parameters in ({"native": 0}, {"native": -1}, {"native": 2}, {"clock_failure": 1}, {"clock_failure": 2}, {"end": 1025000000}, {"prestate": 1}, {"prestate": 2}, {"prestate": 3}, {"prestate": 4}):
            with self.subTest(parameters=parameters):
                state, events = self.observe(**parameters)
                self.assertFalse(any(event["event"] == "request_headers_complete" for event in events))
                self.assertNotEqual(state["return"], 0)
                self.assertEqual(state["native_calls"], 0 if parameters.get("clock_failure") == 1 or parameters.get("prestate") in (1, 2, 3) else 1)
                self.assertEqual(state["intervention_calls"], 0)

    def test_denied_or_invalid_intervention_is_not_completion(self):
        for intervention in (403, -1):
            with self.subTest(intervention=intervention):
                state, events = self.observe(intervention=intervention)
                self.assertFalse(any(event["event"] == "request_headers_complete" for event in events))
                self.assertEqual(state["native_calls"], 1)
                self.assertEqual(state["intervention_calls"], 1)
                self.assertEqual(state["return"], 403 if intervention == 403 else 500)
                if intervention == 403:
                    # Common's actual protocol view keeps unobserved native
                    # denial as engine_decision, not a delivered host action.
                    self.assertEqual(events[0]["event"], "engine_decision")
                    self.assertEqual(events[0]["message_id"], "MSCONN_EVENT_ENGINE_DECISION")
                    self.assertEqual(events[0]["rule_id"], "1100001")

    def test_missing_or_failed_request_sink_does_not_change_enforcement(self):
        for sink in (1, 2):
            with self.subTest(sink=sink):
                state, events = self.observe(sink=sink)
                self.assertEqual((state["return"], state["native_calls"], state["phase_mask"]), (0, 1, 1))
                self.assertFalse(any(event["event"] == "request_headers_complete" for event in events))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
