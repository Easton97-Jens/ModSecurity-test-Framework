"""Compile actual owned Phase-4 functions with controlled native/host seams.

The fixtures exercise production orchestration and real Common serialization;
they are not actual NGINX/Engine runtime or final artifact proof.
"""
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
BODY = source_path('connectors/nginx/src/ngx_http_modsecurity_body_filter.c', root=ROOT)
PREAMBLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include "msconnector/event_jsonl.h"
#include "msconnector/native_result.h"
#include "msconnector/options.h"
#include "ngx_http_modsecurity_phase4_observation.h"
typedef long ngx_int_t;
typedef unsigned long ngx_uint_t;
typedef unsigned char u_char;
typedef void ngx_pool_t;
typedef ngx_pool_t *ngx_http_modsecurity_pcre_pool_snapshot_t;
typedef struct { int fd; } ngx_open_file_t;
typedef struct { int error; void *log; } connection_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct {
    int header_sent, err_status; void *pool; connection_t *connection;
    struct { int status; ngx_str_t content_type; } headers_out;
} ngx_http_request_t;
typedef struct { ngx_open_file_t *phase4_log_file; unsigned long phase4_mode; } ngx_http_modsecurity_conf_t;
typedef struct { int unused; } Transaction;
typedef struct {
    msconnector_transaction_contract contract;
    int contract_initialized, phase4_processed, intervention_triggered;
    int phase4_strict_abort, phase4_headers_checked, native_response_body_limit_rejection;
    int native_response_body_eos, response_committed, phase4_intervention;
    enum msconnector_phase native_event_phase;
    int native_event_phase_active;
    int response_body_seen, response_body_truncated;
    size_t response_body_bytes_seen, response_body_bytes_inspected, response_body_append_calls;
    ngx_str_t event_transaction_id;
    int last_intervention_status;
    Transaction *modsec_transaction; ngx_http_request_t *r;
} ngx_http_modsecurity_ctx_t;
typedef struct { int last_buf, last_in_chain; u_char *data; size_t bytes; } ngx_buf_t;
typedef struct ngx_chain_s { ngx_buf_t *buf; struct ngx_chain_s *next; } ngx_chain_t;
typedef struct { int unused; } ngx_http_modsecurity_engine_call_measurement;
typedef struct { const char *method, *uri; } ngx_http_modsecurity_event_request_metadata_t;
#define NGX_OK 0
#define NGX_ERROR (-1)
#define NGX_INVALID_FILE (-1)
#define NGX_HTTP_FORBIDDEN 403
#define NGX_HTTP_REQUEST_ENTITY_TOO_LARGE 413
#define NGX_HTTP_INTERNAL_SERVER_ERROR 500
#define NGX_HTTP_GATEWAY_TIME_OUT 504
#define NGX_LOG_ERR 3
#define ngx_http_modsecurity_module 0
#define ngx_memcpy memcpy
#define ngx_strlen strlen
#define dd(...) ((void)0)
static ngx_http_modsecurity_conf_t conf;
static ngx_http_modsecurity_ctx_t *active_ctx;
static int append_return = 1, process_return = 1, intervention_return;
static int append_calls, process_calls, collect_calls, forward_calls, native_limit;
static int begin_failure, complete_failure, timeout_failure, log_failure;
static size_t native_retained;
static int terminal_status, pool_balance, writes;
static char lines[16384];
static ngx_http_modsecurity_conf_t *ngx_http_get_module_loc_conf(ngx_http_request_t *r, int module) { (void)r; (void)module; return &conf; }
static void ngx_log_error(int level, void *log, int error, const char *format, ...) { (void)level; (void)log; (void)error; (void)format; }
static ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(void *pool) { ++pool_balance; return pool; }
static void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *pool) { (void)pool; --pool_balance; }
static int ngx_http_modsecurity_contract_begin(ngx_http_modsecurity_ctx_t *ctx, enum msconnector_phase phase) { ctx->contract.active_phase = phase; return NGX_OK; }
static int ngx_http_modsecurity_contract_complete(ngx_http_modsecurity_ctx_t *ctx, enum msconnector_phase phase) {
    if (complete_failure) return NGX_ERROR;
    ctx->contract.active_phase = -1; ctx->contract.last_completed_phase = phase;
    ctx->contract.completed_phase_mask |= MSCONNECTOR_TRANSACTION_PHASE_MASK_P4; return NGX_OK;
}
static int msc_append_response_body(Transaction *tx, const u_char *data, size_t bytes) {
    (void)tx; (void)data; (void)bytes;
    if (!active_ctx->native_event_phase_active || active_ctx->native_event_phase != MSCONNECTOR_PHASE_RESPONSE_BODY) abort();
    ++append_calls; return append_return;
}
static size_t msc_get_response_body_length(Transaction *tx) { (void)tx; return native_retained; }
static int msc_process_response_body(Transaction *tx) {
    (void)tx;
    if (!active_ctx->native_event_phase_active || active_ctx->native_event_phase != MSCONNECTOR_PHASE_RESPONSE_BODY) abort();
    ++process_calls; return process_return;
}
static int ngx_http_modsecurity_process_intervention(Transaction *tx, ngx_http_request_t *r, int early) {
    (void)tx; (void)r; (void)early; ++collect_calls;
    if (native_limit) {
        active_ctx->native_response_body_limit_rejection = 1;
        active_ctx->contract.error_class = MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT;
        active_ctx->last_intervention_status = 403; return NGX_ERROR;
    }
    return intervention_return;
}
static int ngx_http_modsecurity_phase4_handle_intervention(ngx_http_request_t *r, const ngx_http_modsecurity_conf_t *mcf) { (void)r; (void)mcf; return NGX_OK; }
static int ngx_http_next_body_filter(ngx_http_request_t *r, ngx_chain_t *in) { (void)r; (void)in; ++forward_calls; return NGX_OK; }
static int ngx_http_modsecurity_engine_call_begin(ngx_http_request_t *r, enum msconnector_phase phase, ngx_http_modsecurity_engine_call_measurement *measurement) { (void)r; (void)phase; (void)measurement; return begin_failure ? NGX_ERROR : NGX_OK; }
static int ngx_http_modsecurity_engine_call_finish(ngx_http_request_t *r, enum msconnector_phase phase, ngx_http_modsecurity_engine_call_measurement *measurement, int native_result) {
    (void)r; (void)phase; (void)measurement; (void)native_result;
    if (timeout_failure) { active_ctx->contract.error_class = MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT; return NGX_ERROR; }
    return NGX_OK;
}
static int ngx_http_modsecurity_phase4_send_terminal_error(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx, int status) { (void)r; (void)ctx; terminal_status = status; return status; }
static int ngx_http_modsecurity_phase4_event_write_result(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx, int result) {
    if (result != NGX_OK) { ctx->contract.error_class = MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR; ctx->phase4_processed = 1; ctx->intervention_triggered = 1; if (r->header_sent) r->connection->error = 1; }
    return result;
}
static ngx_http_modsecurity_event_request_metadata_t ngx_http_modsecurity_event_request_metadata(ngx_http_request_t *r) { (void)r; return (ngx_http_modsecurity_event_request_metadata_t){"GET", "/unit-native"}; }
static int ngx_http_modsecurity_phase4_original_status(ngx_http_request_t *r) { return r->headers_out.status; }
static int ngx_http_modsecurity_write_phase_event_jsonl(ngx_http_request_t *r, const ngx_http_modsecurity_conf_t *mcf, const msconnector_event *event, const char *phase) {
    char line[4096]; int truncated = 0; (void)r; (void)mcf; (void)phase;
    if (log_failure || !msconnector_event_write_jsonl_line(event, line, sizeof(line), &truncated)) return NGX_ERROR;
    if (strlen(lines) + strlen(line) >= sizeof(lines)) abort();
    strcat(lines, line); ++writes; return NGX_OK;
}
static ngx_int_t ngx_http_modsecurity_phase4_log_failure(ngx_http_request_t *, const ngx_http_modsecurity_conf_t *, ngx_http_modsecurity_ctx_t *);
static ngx_int_t ngx_http_modsecurity_phase4_fail_control(ngx_http_request_t *, const ngx_http_modsecurity_conf_t *, ngx_http_modsecurity_ctx_t *, msconnector_transaction_error_class);
static ngx_int_t ngx_http_modsecurity_append_response_body_chunk(ngx_http_modsecurity_ctx_t *, const u_char *, size_t);
static ngx_int_t ngx_http_modsecurity_process_final_response_body(ngx_http_request_t *, ngx_http_modsecurity_ctx_t *, const ngx_http_modsecurity_conf_t *, ngx_chain_t *, ngx_uint_t *);
static int ngx_http_modsecurity_append_response_chain_buffer(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx, const ngx_http_modsecurity_conf_t *mcf, const ngx_chain_t *chain) {
    (void)r; (void)mcf; return ngx_http_modsecurity_append_response_body_chunk(ctx, chain->buf->data, chain->buf->bytes);
}
static int ngx_http_modsecurity_forward_response_body_prefix(ngx_http_request_t *r, ngx_chain_t *start, ngx_chain_t *previous, ngx_chain_t *chain, ngx_chain_t **in) {
    (void)r; (void)start; (void)previous; (void)chain; (void)in; return NGX_OK;
}
static int ngx_http_modsecurity_finalize_terminal_response_body(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx, const ngx_http_modsecurity_conf_t *mcf, ngx_chain_t *in, ngx_uint_t *forwarded, ngx_uint_t *processed) {
    *processed = 1; return ngx_http_modsecurity_process_final_response_body(r, ctx, mcf, in, forwarded);
}
'''
MAIN = r'''
int main(int argc, char **argv) {
    connection_t connection = {0};
    ngx_http_request_t request = {0};
    static ngx_http_modsecurity_ctx_t ctx;
    ngx_open_file_t file = {7}; Transaction tx = {0}; ngx_chain_t chain = {0}; ngx_buf_t buffer = {0};
    ngx_uint_t forwarded = 0;
    u_char data[65] = {0}; int result;
    if (argc != 2) return 2;
    request.connection = &connection; request.headers_out.status = 200;
    request.headers_out.content_type = (ngx_str_t){10, (u_char *)"text/plain"};
    ctx.r = &request; ctx.modsec_transaction = &tx; ctx.contract_initialized = 1;
    ctx.contract.active_phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
    ctx.contract.last_completed_phase = MSCONNECTOR_PHASE_RESPONSE_HEADERS;
    ctx.contract.status = MSCONNECTOR_TRANSACTION_STATUS_PHASE_ACTIVE;
    ctx.contract.direct_phase_mask = MSCONNECTOR_TRANSACTION_PHASE_MASK_ALL;
    ctx.contract.mode = MSCONNECTOR_TRANSACTION_MODE_SAFE;
    ctx.contract.created_at_ms = 1;
    strcpy(ctx.contract.transaction_id, "unit-tx-2-1");
    strcpy(ctx.contract.canonical_transaction_id, "unit-canonical");
    strcpy(ctx.contract.connector_id, "nginx");
    strcpy(ctx.contract.host_id, "unit-host");
    ctx.event_transaction_id = (ngx_str_t){11, (u_char *)"unit-tx-2-1"};
    active_ctx = &ctx; conf.phase4_log_file = &file; conf.phase4_mode = MSCONNECTOR_PHASE4_MODE_SAFE;
    if (strcmp(argv[1], "split") == 0) {
        ctx.response_body_bytes_seen = 16; native_retained = 16;
        result = ngx_http_modsecurity_append_response_body_chunk(&ctx, data, 16);
        if (result != NGX_OK) return 3;
        ctx.response_body_bytes_seen = 27; native_retained = 27;
        result = ngx_http_modsecurity_append_response_body_chunk(&ctx, data, 11);
        if (result != NGX_OK) return 4;
        result = ngx_http_modsecurity_process_final_response_body(&request, &ctx, &conf, &chain, &forwarded);
    } else if (strcmp(argv[1], "partial") == 0) {
        ctx.response_body_bytes_seen = 65; native_retained = 64; append_return = 0;
        result = ngx_http_modsecurity_append_response_body_chunk(&ctx, data, 65);
        if (result != NGX_OK) return 5;
        result = ngx_http_modsecurity_process_final_response_body(&request, &ctx, &conf, &chain, &forwarded);
    } else if (strcmp(argv[1], "reject") == 0 || strcmp(argv[1], "reject-precommit") == 0) {
        ctx.response_body_bytes_seen = 65; native_retained = 0; native_limit = 1;
        request.header_sent = strcmp(argv[1], "reject") == 0;
        buffer.data = data; buffer.bytes = 65; buffer.last_buf = 1; chain.buf = &buffer;
        result = ngx_http_modsecurity_process_response_body_chain(&request, &chain, &ctx);
    } else if (strcmp(argv[1], "invalid") == 0) {
        ctx.response_body_bytes_seen = 65; append_return = 2;
        result = ngx_http_modsecurity_append_response_body_chunk(&ctx, data, 65);
    } else if (strcmp(argv[1], "retained-invalid") == 0) {
        ctx.response_body_bytes_seen = 65; native_retained = 66;
        result = ngx_http_modsecurity_append_response_body_chunk(&ctx, data, 65);
    } else if (strcmp(argv[1], "append-count-overflow") == 0) {
        ctx.response_body_bytes_seen = 65; ctx.response_body_append_calls = SIZE_MAX;
        result = ngx_http_modsecurity_append_response_body_chunk(&ctx, data, 65);
    } else {
        if (strcmp(argv[1], "timeout") == 0) timeout_failure = 1;
        else if (strcmp(argv[1], "timeout-committed") == 0) { timeout_failure = 1; request.header_sent = 1; }
        else if (strcmp(argv[1], "complete-fail") == 0) complete_failure = 1;
        else if (strcmp(argv[1], "process-fail") == 0) process_return = 0;
        else if (strcmp(argv[1], "begin-fail") == 0) begin_failure = 1;
        else if (strcmp(argv[1], "write-fail") == 0) log_failure = 1;
        else if (strcmp(argv[1], "empty") != 0) return 2;
        result = ngx_http_modsecurity_process_final_response_body(&request, &ctx, &conf, &chain, &forwarded);
    }
    if (ctx.native_event_phase_active) return 7;
    printf("%ld %d %d %d %d %d %d %zu %d %d %d\n", (long)result, append_calls, process_calls, collect_calls,
           forward_calls, terminal_status, ctx.native_response_body_eos,
           ctx.response_body_bytes_inspected, pool_balance, connection.error, writes);
    fputs(lines, stdout); return 0;
}
'''


class NativeBodySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or not shutil.which(compiler[0]):
            raise RuntimeError("real C17 compiler required")
        temp = tempfile.TemporaryDirectory(prefix="native-body-source-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temp.cleanup)
        source = BODY.read_text()
        names = ("ngx_http_modsecurity_phase4_copy_content_type", "ngx_http_modsecurity_phase4_observation_event",
                 "ngx_http_modsecurity_phase4_log_native_append", "ngx_http_modsecurity_phase4_log_native_completion",
                 "ngx_http_modsecurity_append_response_body_chunk", "ngx_http_modsecurity_phase4_log_failure",
                 "ngx_http_modsecurity_phase4_fail_control", "ngx_http_modsecurity_process_final_response_body",
                 "ngx_http_modsecurity_process_response_body_chain")
        functions = "\n".join(("static void\n" if name.endswith("copy_content_type") else "static ngx_int_t\n") + function_definition(source, name) for name in names)
        fixture = Path(temp.name) / "source.c"
        fixture.write_text(PREAMBLE + functions + MAIN)
        cls.binaries = []
        for sanity in (0, 1):
            binary = Path(temp.name) / f"source-{sanity}"
            command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", f"-DMODSECURITY_SANITY_CHECKS={sanity}",
                                  "-I", str(source_path('common/include', root=ROOT)), "-I", str(source_path('connectors/nginx/src', root=ROOT)), str(fixture)]
            command += [str(source_path('common/src', root=ROOT) / name) for name in
                        ("event.c", "event_jsonl.c", "json_escape.c", "http_status.c", "status.c", "transaction_state.c")]
            command += ["-o", str(binary)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise AssertionError(result.stderr[-7000:])
            cls.binaries.append(binary)

    def observe(self, binary, scenario):
        result = subprocess.run([str(binary), scenario], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        header, _, lines = result.stdout.partition("\n")
        values = list(map(int, header.split()))
        self.assertEqual(values[8], 0, "PCRE pool balanced on every exit")
        return values, [json.loads(line) for line in lines.splitlines()]

    def test_split_observes_actual_calls_then_native_common_completion(self):
        for binary in self.binaries:
            values, events = self.observe(binary, "split")
            self.assertEqual(values[:5], [0, 2, 1, 3, 0])
            self.assertEqual([event["event"] for event in events], ["phase4_append", "phase4_append", "phase4_completion"])
            self.assertIn("append_size=16;append_index=1;engine_retained_bytes=16", events[0]["reason"])
            self.assertIn("append_size=11;append_index=2;engine_retained_bytes=27", events[1]["reason"])
            self.assertEqual(events[-1]["reason"], "engine_retained_bytes=27;append_calls=2")
            self.assertIs(events[-1]["eos_seen"], True)

    def test_partial_retains64_and_common_supplied65(self):
        for binary in self.binaries:
            values, events = self.observe(binary, "partial")
            self.assertEqual(values[7], 65)
            self.assertEqual(events[-1]["reason"], "engine_retained_bytes=64;append_calls=1")
            self.assertEqual(events[-1]["body_bytes_inspected"], 65)
            self.assertIs(events[-1]["body_truncated"], True)

    def test_immediate_reject_never_processes_or_forwards_body(self):
        for binary in self.binaries:
            for scenario, status in (("reject", -1), ("reject-precommit", 403)):
                values, events = self.observe(binary, scenario)
                self.assertEqual(values[:5], [status, 1, 0, 1, 0])
                self.assertEqual(events[-1]["message_id"], "MSCONN_EVENT_BODY_LIMIT")
                self.assertEqual(events[-1]["http_status"], 403)
                self.assertEqual(events[-1]["rule_id"], "")
                self.assertEqual(events[-1]["body_limit_outcome"], "reject")
                self.assertIs(events[-1]["eos_seen"], False)

    def test_failure_controls_never_claim_completion(self):
        for binary in self.binaries:
            for scenario in ("invalid", "retained-invalid", "append-count-overflow", "complete-fail", "process-fail", "begin-fail", "write-fail"):
                with self.subTest(scenario=scenario, sanity=binary.name):
                    values, events = self.observe(binary, scenario)
                    self.assertNotEqual(values[0], 0)
                    self.assertEqual(values[4], 0)
                    self.assertFalse(any(event["event"] == "phase4_completion" for event in events))

    def test_empty_response_completion_does_not_invent_append_calls(self):
        for binary in self.binaries:
            values, events = self.observe(binary, "empty")
            self.assertEqual(values[:5], [0, 0, 1, 1, 0])
            self.assertEqual(events[-1]["reason"], "engine_retained_bytes=0;append_calls=0")

    def test_timeout_has_native_eos_but_no_common_completion(self):
        for binary in self.binaries:
            for scenario in ("timeout", "timeout-committed"):
                values, events = self.observe(binary, scenario)
                self.assertEqual(values[0], 504 if scenario == "timeout" else -1)
                self.assertEqual(values[6], 1)
                self.assertEqual(events[-1]["message_id"], "MSCONN_EVENT_ENGINE_TIMEOUT")
                self.assertEqual(events[-1]["http_status"], 504)
                self.assertIs(events[-1]["eos_seen"], True)
                self.assertFalse(any(event["event"] == "phase4_completion" for event in events))

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
