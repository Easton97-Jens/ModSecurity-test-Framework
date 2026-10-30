"""Compile the actual native audit epilogue with controlled API/host boundaries."""
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
SOURCE = source_path('connectors/nginx/src/ngx_http_modsecurity_log.c', root=ROOT)
PREAMBLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "msconnector/native_result.h"
#include "msconnector/transaction_contract.h"
typedef int ngx_int_t;
typedef struct { int unused; } ngx_pool_t;
typedef ngx_pool_t *ngx_http_modsecurity_pcre_pool_snapshot_t;
typedef struct { void *log; } connection_t;
typedef struct { connection_t *connection; ngx_pool_t *pool; } ngx_http_request_t;
typedef struct {
    msconnector_transaction_contract contract;
    void *modsec_transaction;
    int contract_initialized, logged, native_logging_failed;
} ngx_http_modsecurity_ctx_t;
enum { NGX_OK = 0, NGX_ERROR = -1, NGX_LOG_ERR = 4 };
static ngx_http_modsecurity_ctx_t context;
static ngx_http_request_t *active_request;
static int raw_result = 1, finish_result, calls, finishes, failures, diagnostics;
static int restores, reenter, nested_result = 99, no_context, technical_events;
static ngx_int_t ngx_http_modsecurity_log_technical_failure(ngx_http_request_t *r,
        ngx_http_modsecurity_ctx_t *ctx, enum msconnector_phase phase,
        msconnector_transaction_error_class cause, ngx_int_t http_status) {
    if (r == NULL || ctx == NULL || phase != MSCONNECTOR_PHASE_LOGGING ||
        cause == MSCONNECTOR_TRANSACTION_ERROR_NONE || http_status != 0) abort();
    ++technical_events;
    return NGX_OK;
}
static ngx_int_t ngx_http_modsecurity_log_handler(ngx_http_request_t *request);
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_get_module_ctx(ngx_http_request_t *r) {
    (void)r; return no_context ? NULL : &context;
}
static void ngx_log_error(int level, void *log, int error, const char *format, ...) {
    (void)level; (void)log; (void)error; (void)format; ++diagnostics;
}
int msconnector_transaction_contract_finish(msconnector_transaction_contract *contract, uint64_t now) {
    (void)contract; (void)now; ++finishes; return finish_result;
}
int msconnector_transaction_contract_fail(msconnector_transaction_contract *contract,
        msconnector_transaction_error_class cause, uint64_t now) {
    (void)now; ++failures; contract->error_class = cause;
    return MSCONNECTOR_TRANSACTION_TRANSITION_OK;
}
static ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool) { return pool; }
static void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *pool) { (void)pool; ++restores; }
static int msc_process_logging(void *transaction) {
    (void)transaction; ++calls;
    if (reenter && calls == 1) { nested_result = ngx_http_modsecurity_log_handler(active_request); }
    return raw_result;
}
'''
MAIN = r'''
int main(int argc, char **argv) {
    connection_t connection = {NULL};
    ngx_http_request_t request = {&connection, NULL};
    int first, second;
    if (argc != 3) { return 2; }
    raw_result = (int)strtol(argv[2], NULL, 10);
    active_request = &request;
    context.modsec_transaction = &context;
    context.contract_initialized = 1;
    if (strcmp(argv[1], "missing") == 0) { context.modsec_transaction = NULL; }
    if (strcmp(argv[1], "disabled") == 0) { no_context = 1; }
    if (strcmp(argv[1], "reentry") == 0) { reenter = 1; }
    if (strcmp(argv[1], "sequence") == 0) { finish_result = MSCONNECTOR_TRANSACTION_TRANSITION_INVALID; }
    if (strcmp(argv[1], "prior") == 0) { context.contract.error_class = MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL; }
    if (strcmp(argv[1], "null-request") == 0) { active_request = NULL; }
    first = ngx_http_modsecurity_log_handler(active_request);
    second = ngx_http_modsecurity_log_handler(active_request);
    printf("{\"first\":%d,\"second\":%d,\"calls\":%d,\"finishes\":%d,"
        "\"failures\":%d,\"diagnostics\":%d,\"restores\":%d,\"nested\":%d,"
        "\"logged\":%d,\"failed\":%d,\"cause\":%d,\"technical_events\":%d}\n",
        first, second, calls, finishes, failures, diagnostics, restores, nested_result,
        context.logged, context.native_logging_failed, context.contract.error_class,technical_events);
    return 0;
}
'''


class NativeLoggingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("a C compiler is required for native logging regressions")
        temporary = tempfile.TemporaryDirectory(prefix="nginx-audit-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        cls.binary = directory / "audit"
        source = SOURCE.read_text(encoding="utf-8")
        functions = ("ngx_http_modsecurity_logging_failure", "ngx_http_modsecurity_log_handler")
        fixture = directory / "audit.c"
        fixture.write_text(PREAMBLE + "\n" + "\n".join(
            "static ngx_int_t\n" + function_definition(source, name) for name in functions
        ) + MAIN, encoding="utf-8")
        result = subprocess.run(compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror",
            "-I", str(source_path('common/include', root=ROOT)), str(fixture), "-o", str(cls.binary)],
            capture_output=True, text=True, timeout=30, check=False)
        if result.returncode:
            raise AssertionError("native audit fixture failed to compile:\n" + result.stderr[-4000:])

    def case(self, scenario: str = "normal", result: int = 1) -> dict:
        run = subprocess.run([str(self.binary), scenario, str(result)],
                             capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_success_is_one_native_call_and_one_completion(self) -> None:
        event = self.case()
        self.assertEqual((event["first"], event["second"]), (0, 0))
        self.assertEqual((event["calls"], event["finishes"], event["restores"]), (1, 1, 1))
        self.assertEqual((event["logged"], event["failed"]), (1, 0))
        self.assertEqual(event["technical_events"], 0)

    def test_zero_negative_and_undocumented_positive_are_persistent_failures(self) -> None:
        for native in (0, -1, -2, 2, 99):
            with self.subTest(native=native):
                event = self.case(result=native)
                self.assertEqual((event["first"], event["second"]), (-1, -1))
                self.assertEqual((event["calls"], event["restores"]), (1, 1))
                self.assertEqual((event["failed"], event["failures"], event["diagnostics"]), (1, 1, 1))
                self.assertEqual(event["technical_events"], 1)

    def test_missing_native_transaction_is_not_dereferenced_or_retried(self) -> None:
        event = self.case("missing")
        self.assertEqual((event["first"], event["second"]), (-1, -1))
        self.assertEqual((event["calls"], event["finishes"]), (0, 0))
        self.assertEqual(event["diagnostics"], 1)

    def test_native_success_does_not_repair_failed_contract_completion(self) -> None:
        event = self.case("sequence")
        self.assertEqual((event["first"], event["second"]), (-1, -1))
        self.assertEqual((event["calls"], event["finishes"]), (1, 1))
        self.assertEqual(event["failed"], 1)

    def test_existing_failure_class_survives_native_audit_failure(self) -> None:
        control = self.case("prior")
        failed = self.case("prior", 0)
        self.assertEqual(failed["cause"], control["cause"])
        self.assertEqual(failed["failures"], 0)
        self.assertEqual(failed["failed"], 1)

    def test_native_callback_cannot_reenter_the_audit_phase(self) -> None:
        event = self.case("reentry")
        self.assertEqual(event["nested"], -1)
        self.assertEqual(event["calls"], 1)
        self.assertEqual((event["first"], event["second"]), (0, 0))

    def test_disabled_context_remains_noop(self) -> None:
        event = self.case("disabled")
        self.assertEqual((event["first"], event["second"]), (0, 0))
        self.assertEqual(event["calls"], 0)

    def test_missing_request_is_rejected(self) -> None:
        event = self.case("null-request")
        self.assertEqual((event["first"], event["second"]), (-1, -1))
        self.assertEqual(event["calls"], 0)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
