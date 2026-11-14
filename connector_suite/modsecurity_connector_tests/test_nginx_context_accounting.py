"""Compile the actual native context declaration without a running host."""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

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
HEADER = source_path('connectors/nginx/src/ngx_http_modsecurity_common.h', root=ROOT)
PREAMBLE = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include "msconnector/transaction_contract.h"
typedef unsigned char u_char;
typedef intptr_t ngx_int_t;
typedef struct request ngx_http_request_t;
typedef struct pool { int unused; } ngx_pool_t;
typedef struct { void *log; } fixture_connection;
struct request { ngx_pool_t *pool; fixture_connection *connection; };
typedef struct { int unused; } ngx_file_t;
typedef struct { off_t file_pos, file_last; ngx_file_t *file; } ngx_buf_t;
#define NGX_HTTP_MODSECURITY_PHASE4_FILE_READ_CHUNK 32768U
#define NGX_LOG_ERR 4
#define ngx_errno 0
static unsigned char scratch[32768];
static uint64_t read_total;
static size_t max_read;
static void *ngx_pnalloc(ngx_pool_t *pool, size_t bytes) {
    (void)pool; if (bytes != sizeof(scratch)) abort(); return scratch;
}
static void ngx_log_error(int level, void *log, int error, const char *format, ...) {
    (void)level; (void)log; (void)error; (void)format;
}
static ssize_t ngx_read_file(ngx_file_t *file, void *buffer, size_t bytes, off_t offset) {
    if (file == NULL || buffer != scratch || offset != (off_t)(3U + read_total) ||
        bytes == 0U || bytes > sizeof(scratch)) abort();
    read_total += bytes;
    if (bytes > max_read) max_read = bytes;
    return (ssize_t)bytes;
}
typedef struct ngx_http_modsecurity_conf_s ngx_http_modsecurity_conf_t;
struct ngx_http_modsecurity_conf_s { int unused; };
#define NGX_OK 0
#define NGX_ERROR -1
#define ngx_inline inline
int msconnector_transaction_contract_fail(msconnector_transaction_contract *contract,
    msconnector_transaction_error_class cause, uint64_t now) {
    (void)now; contract->error_class = cause; return -1;
}
typedef struct transaction Transaction;
typedef struct intervention {
    int status;
    int pause;
    char *url;
    char *log;
    int disruptive;
} ModSecurityIntervention;
typedef struct array ngx_array_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
'''
APPEND_STUB = r'''
static ngx_int_t ngx_http_modsecurity_append_response_body_chunk(
    ngx_http_modsecurity_ctx_t *ctx, const u_char *data, size_t bytes) {
    if (data != scratch) abort();
    ctx->response_body_bytes_inspected = msconnector_transaction_counter_add(
        ctx->response_body_bytes_inspected, bytes);
    ctx->response_body_append_calls = msconnector_transaction_counter_add(
        ctx->response_body_append_calls, 1U);
    return NGX_OK;
}
'''
MAIN = r'''
int main(void) {
    ngx_http_modsecurity_ctx_t ctx = {0};
    if (ctx.request_error_status || ctx.request_error_event_attempted ||
        ctx.request_body_bytes_seen || ctx.response_body_bytes_seen ||
        ctx.response_body_bytes_inspected || ctx.request_header_count ||
        ctx.request_header_bytes || ctx.response_header_count ||
        ctx.response_header_bytes || ctx.phase4_processed) {
        return 1;
    }
    ctx.request_body_bytes_seen = SIZE_MAX;
    ctx.response_body_bytes_seen = 9U;
    ctx.response_body_bytes_inspected = 8U;
    ctx.request_header_count = 7U;
    ctx.request_header_bytes = 6U;
    ctx.response_header_count = 5U;
    ctx.response_header_bytes = 4U;
    ctx.request_error_status = 500;
    ctx.request_error_event_attempted = 1;
    ctx.phase4_processed = 1;
    ctx.last_intervention_status = 403;
    if (ctx.request_body_bytes_seen != SIZE_MAX ||
        ctx.response_body_bytes_seen != 9U || ctx.response_body_bytes_inspected != 8U ||
        ctx.request_header_count != 7U || ctx.request_header_bytes != 6U ||
        ctx.response_header_count != 5U || ctx.response_header_bytes != 4U ||
        ctx.request_error_status != 500 || !ctx.request_error_event_attempted ||
        !ctx.phase4_processed || ctx.last_intervention_status != 403) {
        return 2;
    }
    memset(&ctx, 0, sizeof(ctx));
    ngx_http_modsecurity_conf_t config = {0};
    size_t allowed = 0;
    ctx.response_body_bytes_seen = UINT32_MAX - 1U;
    ctx.response_body_bytes_inspected = UINT32_MAX - 1U;
    if (ngx_http_modsecurity_account_response_body(&ctx, &config, 3U, &allowed)
            != NGX_OK || allowed != 3U ||
        ctx.response_body_bytes_seen != UINT64_C(4294967297) ||
        ctx.contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE) return 3;
    ctx.response_body_bytes_seen = UINT64_MAX - 1U;
    ctx.response_body_bytes_inspected = UINT64_MAX - 1U;
    if (ngx_http_modsecurity_account_response_body(&ctx, &config, 3U, &allowed)
            != NGX_OK || allowed != 3U || ctx.response_body_bytes_seen != UINT64_MAX ||
        ctx.contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE) return 4;
    memset(&ctx, 0, sizeof(ctx));
    ngx_pool_t pool = {0};
    fixture_connection connection = {0};
    ngx_http_request_t request = {&pool, &connection};
    ngx_file_t source = {0};
    const uint64_t file_length = UINT64_C(4294967312);
    ngx_buf_t file = {3, (off_t)(3U + file_length), &source};
    if (ngx_http_modsecurity_append_file_response_body(&request, &ctx, &config, &file)
            != NGX_OK || read_total != file_length || max_read != 32768U ||
        ctx.response_body_bytes_seen != file_length ||
        ctx.response_body_bytes_inspected != file_length ||
        ctx.response_body_append_calls != (file_length + 32767U) / 32768U ||
        ctx.contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE) return 5;
    return 0;
}
'''


class NginxContextAccountingTests(unittest.TestCase):
    def test_context_accounting_and_terminal_state_remain_independent(self) -> None:
        source = HEADER.read_text(encoding="utf-8")
        end = source.index("} ngx_http_modsecurity_ctx_t;") + len("} ngx_http_modsecurity_ctx_t;")
        start = source.rfind("typedef struct {", 0, end)
        self.assertGreaterEqual(start, 0)
        declaration = source[start:end]
        accounting = function_definition(BODY.read_text(encoding="utf-8"),
                                         "ngx_http_modsecurity_account_response_body")
        appended = function_definition(BODY.read_text(encoding="utf-8"),
                                       "ngx_http_modsecurity_append_accounted_response_body")
        file_stream = function_definition(BODY.read_text(encoding="utf-8"),
                                         "ngx_http_modsecurity_append_file_response_body")
        model = "\n#undef SIZE_MAX\n#define SIZE_MAX UINT32_MAX\n#define size_t uint32_t\n"
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            self.fail("a C compiler is required for context accounting tests")
        with tempfile.TemporaryDirectory(prefix="nginx-context-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
            directory = Path(temporary)
            fixture = directory / "context.c"
            fixture.write_text(PREAMBLE + model + declaration + APPEND_STUB +
                               "\nstatic ngx_int_t\n" + accounting +
                               "\nstatic ngx_int_t\n" + appended +
                               "\nstatic ngx_int_t\n" + file_stream + "\n" + MAIN,
                               encoding="utf-8")
            for sanity in (0, 1):
                with self.subTest(sanity_checks=sanity):
                    binary = directory / ("context-" + str(sanity))
                    command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pedantic-errors",
                                          "-DMODSECURITY_SANITY_CHECKS=" + str(sanity),
                                          "-I", str(source_path('common/include', root=ROOT)), str(fixture), "-o", str(binary)]
                    compiled = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr[-6000:])
                    executed = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5, check=False)
                    self.assertEqual(executed.returncode, 0, executed.stderr[-2000:])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
