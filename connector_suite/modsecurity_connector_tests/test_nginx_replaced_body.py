"""Run the actual discarded-body helper against NGINX-shaped buffer controls.

This compiled test proves consumption, ownership and downstream link semantics;
real writer/client behavior is covered separately by the native host fixture.
"""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

from modsecurity_test_framework.connector_context import connector_root, source_path
from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()
SOURCE = source_path("connectors/nginx/src/ngx_http_modsecurity_body_filter.c", root=ROOT)
PREAMBLE = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char u_char;
typedef long ngx_int_t;
typedef struct { int unused; } ngx_pool_t;
typedef struct ngx_buf_s {
    u_char *pos, *last;
    int64_t file_pos, file_last;
    unsigned temporary:1, memory:1, mmap:1, in_file:1;
    unsigned flush:1, sync:1, last_buf:1, last_in_chain:1;
} ngx_buf_t;
typedef struct ngx_chain_s {
    ngx_buf_t *buf;
    struct ngx_chain_s *next;
} ngx_chain_t;
typedef struct { unsigned buffered; } connection_t;
typedef struct ngx_http_request_s {
    ngx_pool_t *pool;
    struct ngx_http_request_s *main;
    unsigned buffered;
    connection_t *connection;
} ngx_http_request_t;
typedef struct { unsigned replacement_body_terminal_sent:1; }
    ngx_http_modsecurity_ctx_t;
#define NGX_OK 0
#define NGX_ERROR -1
#define NGX_AGAIN -2
#define ngx_buf_in_memory(b) ((b)->temporary || (b)->memory || (b)->mmap)
#define ngx_buf_special(b) (((b)->flush || (b)->last_buf || (b)->sync) && \
    !ngx_buf_in_memory(b) && !(b)->in_file)
static int fail_allocation, allocation_calls, filter_calls, null_calls, empty_writer_errors;
static int links, terminals, chains, flushes, syncs, next_result;
static void *allocations[64];
static size_t allocation_count;
static ngx_buf_t *originals[4];
static size_t original_count;
static ngx_chain_t *retained;
static void *allocate(size_t bytes) {
    ++allocation_calls;
    if (fail_allocation == allocation_calls) return NULL;
    void *result = calloc(1, bytes);
    if (result == NULL || allocation_count == 64U) abort();
    allocations[allocation_count++] = result;
    return result;
}
static ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool) {
    (void)pool; return allocate(sizeof(ngx_chain_t));
}
static ngx_buf_t *ngx_calloc_buf(ngx_pool_t *pool) {
    (void)pool; return allocate(sizeof(ngx_buf_t));
}
static ngx_int_t ngx_http_next_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    ++filter_calls;
    if (in == NULL) {
        ++null_calls;
        /* Model the real writer's empty-chain error. Pending downstream
         * filter/connection output must still be drained through this seam. */
        if (!r->buffered && !r->connection->buffered) {
            ++empty_writer_errors;
            return NGX_ERROR;
        }
    } else retained = in;
    for (ngx_chain_t *link = in; link != NULL; link = link->next) {
        ngx_buf_t *buffer = link->buf;
        uint64_t size = ngx_buf_in_memory(buffer)
            ? (uint64_t)((uintptr_t)buffer->last - (uintptr_t)buffer->pos)
            : buffer->in_file ? (uint64_t)(buffer->file_last - buffer->file_pos) : 0;
        /* Match the writer's zero-size non-special buffer rejection before
         * asserting the stricter replacement-only ownership contract. */
        if (size == 0 && !ngx_buf_special(buffer)) return NGX_ERROR;
        if (!ngx_buf_special(buffer) || buffer->pos != NULL ||
            buffer->last != NULL || buffer->file_pos != 0 ||
            buffer->file_last != 0) abort();
        for (size_t i = 0; i < original_count; ++i) {
            if (link->buf == originals[i]) abort();
        }
        ++links;
        terminals += link->buf->last_buf;
        chains += link->buf->last_in_chain;
        flushes += link->buf->flush;
        syncs += link->buf->sync;
    }
    r->buffered = 0;
    r->connection->buffered = next_result == NGX_AGAIN;
    return next_result;
}
"""
MAIN = r"""
int main(int argc, char **argv) {
    ngx_pool_t pool = {0};
    connection_t connection = {0};
    ngx_http_request_t main_request = {&pool, NULL, 0, &connection};
    ngx_http_request_t request = {&pool, &main_request, 0, &connection};
    ngx_http_modsecurity_ctx_t ctx = {0};
    u_char bytes[] = "ORIGINAL";
    ngx_buf_t memory = {0}, file = {0}, late = {0};
    ngx_chain_t b = {&file, NULL}, a = {&memory, &b}, c = {&late, NULL};
    int result = 0;
    main_request.main = &main_request;
    if (argc != 2) return 2;
    memory.pos = bytes; memory.last = bytes + 8;
    memory.memory = 1;
    file.in_file = 1; file.file_pos = 2; file.file_last = 10;
    file.last_buf = 1; file.last_in_chain = 1;
    originals[original_count++] = &memory;
    originals[original_count++] = &file;
    originals[original_count++] = &late;
    if (strcmp(argv[1], "main") == 0) {
        request.main = &request;
        memory.flush = 1;
        next_result = NGX_AGAIN;
        result = ngx_http_modsecurity_discard_replaced_response_body(&request, &ctx, &a);
        if (result != NGX_AGAIN || links != 2 || terminals != 1 || chains != 1 ||
            flushes != 1 || syncs != 1 || !ctx.replacement_body_terminal_sent ||
            memory.pos != memory.last || file.file_pos != file.file_last ||
            a.next != &b || b.next != NULL || strcmp((char *)bytes, "ORIGINAL") ||
            retained == NULL || retained->next == NULL ||
            !retained->next->buf->last_buf) return 3;
        late.temporary = 1; late.pos = bytes; late.last = bytes + 8;
        late.last_buf = 1; late.last_in_chain = 1;
        next_result = NGX_OK;
        result = ngx_http_modsecurity_discard_replaced_response_body(&request, &ctx, &c);
        if (result || terminals != 1 || links != 2 || late.pos != late.last ||
            null_calls != 1) return 4;
    } else if (strcmp(argv[1], "subrequest") == 0) {
        result = ngx_http_modsecurity_discard_replaced_response_body(&request, &ctx, &b);
        if (result || links != 1 || terminals || chains != 1 || syncs != 1 ||
            !ctx.replacement_body_terminal_sent || file.file_pos != file.file_last)
            return 5;
        result = ngx_http_modsecurity_discard_replaced_response_body(&request, &ctx, &b);
        if (result || links != 1 || chains != 1 || null_calls || filter_calls != 1)
            return 6;
    } else if (strcmp(argv[1], "flush") == 0) {
        request.buffered = 1;
        result = ngx_http_modsecurity_discard_replaced_response_body(&request, &ctx, NULL);
        a.next = NULL;
        result |= ngx_http_modsecurity_discard_replaced_response_body(&request, &ctx, &a);
        if (result || links || null_calls != 1 || filter_calls != 1 ||
            memory.pos != memory.last || ctx.replacement_body_terminal_sent) return 7;
    } else if (strcmp(argv[1], "unbuffered") == 0) {
        request.main = &request;
        a.next = NULL;
        result = ngx_http_modsecurity_discard_replaced_response_body(&request, &ctx, &a);
        if (result || filter_calls || memory.pos != memory.last || allocation_count)
            return 10;
        result = ngx_http_modsecurity_discard_replaced_response_body(&request, &ctx, NULL);
        if (result || filter_calls) return 14;
        result = ngx_http_modsecurity_discard_replaced_response_body(&request, &ctx, &b);
        if (result || filter_calls != 1 || links != 1 || terminals != 1 ||
            !ctx.replacement_body_terminal_sent) return 11;
    } else if (strcmp(argv[1], "file-data") == 0) {
        request.main = &request;
        file.last_buf = file.last_in_chain = 0;
        result = ngx_http_modsecurity_discard_replaced_response_body(&request, &ctx, &b);
        if (result || filter_calls || file.file_pos != file.file_last || allocation_count)
            return 15;
        file.last_buf = file.last_in_chain = 1;
        result = ngx_http_modsecurity_discard_replaced_response_body(&request, &ctx, &b);
        if (result || filter_calls != 1 || terminals != 1 ||
            !ctx.replacement_body_terminal_sent) return 16;
    } else if (strcmp(argv[1], "request-pending") == 0 ||
               strcmp(argv[1], "connection-pending") == 0) {
        a.next = NULL;
        request.buffered = strcmp(argv[1], "request-pending") == 0;
        connection.buffered = !request.buffered;
        result = ngx_http_modsecurity_discard_replaced_response_body(&request, &ctx, &a);
        if (result || filter_calls != 1 || null_calls != 1 || empty_writer_errors ||
            request.buffered || connection.buffered || memory.pos != memory.last)
            return 12;
    } else if (strcmp(argv[1], "empty-null") == 0) {
        result = ngx_http_modsecurity_discard_replaced_response_body(&request, &ctx, NULL);
        if (result || filter_calls || empty_writer_errors) return 13;
    } else if (strcmp(argv[1], "allocation") == 0) {
        fail_allocation = 1;
        result = ngx_http_modsecurity_discard_replaced_response_body(&request, &ctx, &b);
        if (result != NGX_ERROR || filter_calls || ctx.replacement_body_terminal_sent)
            return 8;
    } else return 9;
    for (size_t i = 0; i < allocation_count; ++i) free(allocations[i]);
    puts("control-forwarding-ok");
    return 0;
}
"""


class NginxReplacedBodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("C compiler required")
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="nginx-replaced-body-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(cls.temporary.cleanup)
        fixture = Path(cls.temporary.name) / "replaced.c"
        cls.binary = fixture.with_suffix("")
        production = function_definition(SOURCE.read_text(encoding="utf-8"),
                                        "ngx_http_modsecurity_discard_replaced_response_body")
        fixture.write_text(PREAMBLE + "\nstatic ngx_int_t\n" + production + MAIN,
                           encoding="utf-8")
        compiled = subprocess.run(compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror",
                                  "-pedantic-errors", str(fixture), "-o", str(cls.binary)],
                                  capture_output=True, text=True, timeout=30)
        if compiled.returncode:
            raise AssertionError(compiled.stderr[-4000:])

    def invoke(self, scenario: str) -> None:
        observed = subprocess.run([str(self.binary), scenario], capture_output=True,
                                  text=True, timeout=5)
        self.assertEqual(observed.returncode, 0, observed.stderr)
        self.assertEqual(observed.stdout.strip(), "control-forwarding-ok")

    def test_memory_file_and_late_body_are_consumed_without_forwarding_data(self):
        self.invoke("main")

    def test_subrequest_control_is_special_and_finishes_once(self):
        self.invoke("subrequest")

    def test_null_and_data_only_callbacks_drain_downstream(self):
        self.invoke("flush")

    def test_data_only_unbuffered_callback_does_not_manufacture_empty_writer_input(self):
        self.invoke("unbuffered")

    def test_file_only_data_callback_does_not_forward_an_empty_data_link(self):
        self.invoke("file-data")

    def test_request_buffered_output_is_drained_after_discarding_data(self):
        self.invoke("request-pending")

    def test_connection_buffered_output_is_drained_after_discarding_data(self):
        self.invoke("connection-pending")

    def test_replaced_response_null_callback_without_pending_output_is_noop(self):
        self.invoke("empty-null")

    def test_control_allocation_failure_is_still_a_delivery_failure(self):
        self.invoke("allocation")


# This task-specific regression stays outside automatic default selection.
if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
