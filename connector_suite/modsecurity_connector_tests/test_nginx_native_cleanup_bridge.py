"""Exercise actual module cleanup ordering with real Common state/JSONL.

Native void cleanup and NGINX host calls are controlled seams; this is a C17
source-bound regression, not live process or runtime cleanup evidence.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()
PREAMBLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "msconnector/event_jsonl.h"
#include "msconnector/transaction_state.h"
#include "connectors/profile_registry.h"
#include "ngx_http_modsecurity_cleanup_observation.h"
#include "ngx_http_modsecurity_event_uri.h"
typedef long ngx_int_t;
typedef unsigned char u_char;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int live; } ngx_pool_t;
typedef struct { ngx_str_t value; } header_t;
typedef struct { int fd; } ngx_open_file_t;
typedef struct { void *log; } connection_t;
typedef struct {
    connection_t *connection;
    ngx_pool_t *pool;
    ngx_str_t method_name, unparsed_uri;
    struct { header_t *content_type; } headers_in;
} ngx_http_request_t;
typedef struct { ngx_open_file_t *phase4_log_file; } ngx_http_modsecurity_conf_t;
/* SDK intervention storage is a controlled native seam, like transaction cleanup. */
typedef struct {
    int status, pause;
    char *url, *log;
    int disruptive;
} ModSecurityIntervention;
typedef struct {
    msconnector_transaction_contract contract;
    int contract_initialized;
    void *modsec_transaction;
    ngx_http_request_t *r;
    ngx_str_t event_transaction_id;
    const char *cleanup_method, *cleanup_uri;
    unsigned request_intervention_pending:1;
    ModSecurityIntervention pending_request_intervention;
} ngx_http_modsecurity_ctx_t;
typedef struct { const char *method, *uri, *content_type; }
    ngx_http_modsecurity_event_request_metadata_t;
enum { NGX_OK=0, NGX_ERROR=-1, NGX_LOG_WARN=5, NGX_INVALID_FILE=-1 };
static int ngx_http_modsecurity_module, native_calls, writes, errors, null_pool_allocations;
static int intervention_cleanup_calls;
static int allocations, fail_allocation;
static ngx_http_modsecurity_ctx_t context;
static ngx_http_modsecurity_conf_t config;
static char jsonl[4096];
static void msc_intervention_cleanup(ModSecurityIntervention *intervention) {
    if (intervention != &context.pending_request_intervention ||
        context.contract.cleanup_complete != 1 ||
        !context.request_intervention_pending || intervention_cleanup_calls != 0) abort();
    ++intervention_cleanup_calls;
    memset(intervention, 0, sizeof(*intervention));
}
static void msc_transaction_cleanup(void *native) {
    if (!native || context.contract.cleanup_complete != 1 ||
        intervention_cleanup_calls != 1 || context.request_intervention_pending) abort();
    ++native_calls;
}
static void ngx_log_error(int level, void *log, int number, const char *format, ...) {
    (void)level; (void)log; (void)number; (void)format; ++errors;
}
static ngx_http_modsecurity_conf_t *ngx_http_get_module_loc_conf(ngx_http_request_t *r, int module) {
    (void)r; (void)module; return &config;
}
static void *ngx_pnalloc(ngx_pool_t *pool, size_t length) {
    if (pool == NULL) { ++null_pool_allocations; return NULL; }
    if (++allocations == fail_allocation) return NULL;
    return malloc(length);
}
#define ngx_inline
#define ngx_memcpy memcpy
#define dd(...) ((void)0)
#define ngx_strlen strlen
#define ngx_errno 5
static ssize_t ngx_write_fd(int fd, u_char *line, size_t length) {
    if (fd != 7 || context.modsec_transaction != NULL || length >= sizeof(jsonl)) abort();
    ++writes;
    memcpy(jsonl,line,length); jsonl[length]='\0';
    return (ssize_t)length;
}
'''
MAIN = r'''
int main(int argc,char **argv) {
    connection_t connection={0};
    ngx_pool_t pool={1};
    /* Deliberately not C strings: reading beyond these slices is invalid. */
    u_char method[]={'G','E','T'};
    u_char uri[]={'/','c','l','e','a','n','u','p','-','c','o','n','t','r','o','l'};
    u_char long_uri[1024];
    static u_char query_uri[]="/cleanup-control?token=private";
    ngx_http_request_t request={.connection=&connection,.pool=&pool,
        .method_name={sizeof(method),method},.unparsed_uri={sizeof(uri),uri}};
    ngx_open_file_t file={7};
    static u_char transaction[]="actual-cleanup-tx";
    int mode;
    if (argc != 2) return 2;
    mode=atoi(argv[1]);
    if (mode == 6) fail_allocation=2;
    if (mode == 7) request.method_name.len=request.unparsed_uri.len=0U;
    if (mode == 9) request.unparsed_uri.data=NULL;
    if (mode == 10) request.unparsed_uri.len=(size_t)-1;
    if (mode == 11) request.unparsed_uri=(ngx_str_t){sizeof(query_uri)-1,query_uri};
    if (mode == 12) {
        memset(long_uri,'a',sizeof(long_uri)); long_uri[0]='/';
        request.unparsed_uri=(ngx_str_t){sizeof(long_uri),long_uri};
    }
    context.r=&request; config.phase4_log_file=&file;
    PREPARE_METADATA
    context.event_transaction_id=(ngx_str_t){sizeof(transaction)-1,transaction};
    if (msconnector_transaction_contract_init(&context.contract,
        msconnector_profile_registry_find("nginx"),"cleanup-control","nginx","actual-cleanup-tx",
        MSCONNECTOR_TRANSACTION_MODE_SAFE,100U) != 0) return 3;
    context.contract_initialized=1;
    context.modsec_transaction=mode == 3 ? NULL : &request;
    context.request_intervention_pending=context.modsec_transaction != NULL;
    if (mode == 2) {
        if (msconnector_transaction_contract_begin_phase(&context.contract,MSCONNECTOR_PHASE_REQUEST_HEADERS,0U) != 0) return 4;
    } else if (mode == 4) {
        if (msconnector_transaction_contract_fail(&context.contract,MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT,0U) != 0) return 5;
    } else {
        for (enum msconnector_phase phase=MSCONNECTOR_PHASE_REQUEST_HEADERS;phase<=MSCONNECTOR_PHASE_RESPONSE_BODY;++phase) {
            if (msconnector_transaction_contract_begin_phase(&context.contract,phase,0U) != 0 ||
                msconnector_transaction_contract_complete_phase(&context.contract,phase,0U) != 0) return 6;
        }
        if (msconnector_transaction_contract_finish(&context.contract,0U) != 0) return 7;
    }
    if (mode == 5 || mode == 7 || mode == 8 || mode == 11 || mode == 12) request.pool=NULL;
    if (mode == 8) {
        memset(method,'X',sizeof(method)); memset(uri,'X',sizeof(uri));
    }
    ngx_http_modsecurity_cleanup(&context);
    if (null_pool_allocations != 0) return 19;
    if (mode == 1 || mode == 5) ngx_http_modsecurity_cleanup(&context);
    printf("%d %d %d %d %d\n",native_calls,writes,errors,context.contract_initialized,context.modsec_transaction == NULL);
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


class NativeCleanupBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if compiler is None:
            raise RuntimeError("real C17 compiler is required")
        temporary = tempfile.TemporaryDirectory(prefix="nginx-cleanup-bridge-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        source = (source_path('connectors/nginx/src/ngx_http_modsecurity_module.c', root=ROOT)).read_text()
        common = (source_path('connectors/nginx/src/ngx_http_modsecurity_common.h', root=ROOT)).read_text()
        cleanup = function_definition(source, "ngx_http_modsecurity_cleanup_log_event")
        metadata = function_definition(source, "ngx_str_to_char")
        prepare = ""
        if "ngx_http_modsecurity_event_request_metadata(r)" in cleanup:
            metadata += "\nstatic ngx_inline ngx_http_modsecurity_event_request_metadata_t\n" + function_definition(common, "ngx_http_modsecurity_event_request_metadata")
        else:
            metadata += "\nstatic ngx_int_t\n" + function_definition(source, "ngx_http_modsecurity_snapshot_cleanup_metadata")
            prepare = """if (ngx_http_modsecurity_snapshot_cleanup_metadata(&context) != NGX_OK) {
                if (mode == 6 || mode == 9 || mode == 10) {
                    puts("snapshot-rejected"); return 0;
                }
                return 18;
            }"""
        fixture = directory / "cleanup.c"
        writer = "\nstatic ngx_inline ngx_int_t\n" + function_definition(common, "ngx_http_modsecurity_write_phase_event_jsonl")
        fixture.write_text(PREAMBLE + PROVENANCE_SEAM + metadata + writer + "\nstatic void\n" + cleanup
                           + "\nvoid\n" + function_definition(source, "ngx_http_modsecurity_cleanup") + MAIN.replace("PREPARE_METADATA", prepare))
        cls.binary = directory / "cleanup"
        command = [compiler, "-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                   "-I", str(source_path('connectors/nginx/src', root=ROOT)), "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)), str(fixture)]
        command += [str(source_path('common/src', root=ROOT) / name) for name in
                    ("transaction_state.c", "decision_action.c", "intervention.c", "block_statuses.c", "http_status.c",
                     "late_intervention.c", "event.c", "event_jsonl.c", "json_escape.c", "status.c")]
        command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        if result.returncode:
            raise AssertionError(result.stderr[-7000:])

    def observe(self, mode):
        result = subprocess.run([str(self.binary), str(mode)], capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        state, _, raw = result.stdout.partition("\n")
        return list(map(int, state.split())), json.loads(raw)

    def test_normal_cleanup_is_emitted_after_actual_native_cleanup(self):
        state, event = self.observe(0)
        self.assertEqual(state, [1, 1, 0, 0, 1])
        self.assertEqual(event["reason"], "common_return=0;common_complete=1;native_cleanup_completed=1;error_class=none")
        self.assertEqual(event["phase"], "logging")
        self.assertEqual(event["transaction_id"], "actual-cleanup-tx")
        self.assertEqual(event["cleanup_reason"], "normal")
        self.assertEqual(event["actual_action"], "allow")

    def test_reentry_does_not_duplicate_cleanup_or_observation(self):
        state, _ = self.observe(1)
        self.assertEqual(state, [1, 1, 0, 0, 1])

    def test_destroyed_pool_cleanup_retains_exact_request_metadata_without_allocation(self):
        state, event = self.observe(5)
        self.assertEqual(state, [1, 1, 0, 0, 1])
        self.assertEqual(event["method"], "GET")
        self.assertEqual(event["uri"], "/cleanup-control")

    def test_snapshot_owns_length_delimited_metadata_after_original_bytes_change(self):
        state, event = self.observe(8)
        self.assertEqual(state, [1, 1, 0, 0, 1])
        self.assertEqual(event["method"], "GET")
        self.assertEqual(event["uri"], "/cleanup-control")

    def test_actual_empty_metadata_remains_empty_during_pool_cleanup(self):
        state, event = self.observe(7)
        self.assertEqual(state, [1, 1, 0, 0, 1])
        self.assertEqual(event["method"], "")
        self.assertEqual(event["uri"], "")

    def test_cleanup_keeps_real_query_redaction(self):
        state, event = self.observe(11)
        self.assertEqual(state, [1, 1, 0, 0, 1])
        self.assertEqual(event["uri"], "/cleanup-control?<redacted>")
        self.assertTrue(event["redacted"])
        self.assertNotIn("private", json.dumps(event))

    def test_cleanup_keeps_bounded_long_uri_projection(self):
        state, event = self.observe(12)
        self.assertEqual(state, [1, 1, 0, 0, 1])
        self.assertTrue(event["truncated"])
        self.assertEqual(event["uri"], "/" + "a" * 254)

    def test_invalid_or_unretained_metadata_cannot_admit_a_context(self):
        for mode in (6, 9, 10):
            with self.subTest(mode=mode):
                result = subprocess.run([str(self.binary), str(mode)], capture_output=True,
                                        text=True, timeout=5, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "snapshot-rejected\n")

    def test_snapshot_precedes_contract_and_cleanup_registration(self):
        source = (source_path('connectors/nginx/src/ngx_http_modsecurity_module.c', root=ROOT)).read_text()
        create = function_definition(source, "ngx_http_modsecurity_create_ctx")
        snapshot = create.index("ngx_http_modsecurity_snapshot_cleanup_metadata(ctx)")
        self.assertLess(snapshot, create.index("msconnector_transaction_contract_init("))
        self.assertLess(snapshot, create.index("ngx_pool_cleanup_add("))
        self.assertIn("return NULL;", create[snapshot:create.index("mmcf =", snapshot)])

    def test_incomplete_common_cleanup_is_not_relabelled_success(self):
        state, event = self.observe(2)
        self.assertEqual(state[:2], [1, 1])
        self.assertEqual(event["reason"], "common_return=-8;common_complete=1;native_cleanup_completed=1;error_class=cleanup_incomplete")
        self.assertEqual(event["status"], "error")

    def test_absent_native_pointer_is_recorded_not_fabricated(self):
        state, event = self.observe(3)
        self.assertEqual(state[:2], [0, 1])
        self.assertIn("native_cleanup_completed=0", event["reason"])

    def test_terminal_engine_error_survives_real_cleanup(self):
        state, event = self.observe(4)
        self.assertEqual(state[:2], [1, 1])
        self.assertEqual(event["reason"], "common_return=0;common_complete=1;native_cleanup_completed=1;error_class=engine_timeout")
        self.assertEqual(event["cleanup_reason"], "engine_timeout")

# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)
