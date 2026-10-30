"""Compile the actual connection/URI callers and their shared result tail.

The native engine, address conversion, canonical failure operation and host
intervention dispatch are controlled seams. This characterizes the extraction,
including PCRE/phase brackets; it is not a live server or transport test.
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
ACCESS = source_path('connectors/nginx/src/ngx_http_modsecurity_access.c', root=ROOT)
PREAMBLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "msconnector/native_result.h"
typedef unsigned char u_char;
typedef long ngx_int_t;
typedef struct { int unused; } ngx_pool_t;
typedef ngx_pool_t *ngx_http_modsecurity_pcre_pool_snapshot_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { void *log, *sockaddr, *local_sockaddr; ngx_str_t addr_text; } ngx_connection_t;
typedef struct {
    ngx_connection_t *connection; ngx_pool_t *pool;
    ngx_str_t unparsed_uri, method_name, http_protocol; int http_version;
} ngx_http_request_t;
typedef struct { int error_class; } contract_t;
typedef struct {
    contract_t contract; void *modsec_transaction;
    int intervention_triggered, native_event_phase, native_event_phase_active;
} ngx_http_modsecurity_ctx_t;
enum { NGX_OK=0, NGX_ERROR=-1, NGX_LOG_ERR=4, NGX_HTTP_INTERNAL_SERVER_ERROR=500,
       NGX_HTTP_VERSION_9=9, NGX_HTTP_VERSION_10=10, NGX_HTTP_VERSION_11=11,
       NGX_SOCKADDR_STRLEN=128, MSCONNECTOR_PHASE_REQUEST_HEADERS=2,
       MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE=4 };
static int phase_result, host_result, native_calls, dispatch_calls, failures;
static int pool_active, restored, conversion_failed, address_failed;
static ngx_http_modsecurity_ctx_t *observed;
static void dd(const char *format, ...) { (void)format; }
static void ngx_log_error(int level, void *log, int number, const char *format, ...) {
    (void)level; (void)log; (void)number; (void)format;
}
static void msconnector_transaction_contract_fail(contract_t *contract, int cause, unsigned long now) {
    (void)now; ++failures;
    if (contract->error_class == 0) { contract->error_class = cause; }
}
static char *ngx_str_to_char(ngx_str_t value, ngx_pool_t *pool) {
    (void)pool; return conversion_failed ? (char *)-1 : (char *)value.data;
}
static int ngx_inet_get_port(const void *address) { (void)address; return 80; }
static int ngx_connection_local_sockaddr(ngx_connection_t *connection, ngx_str_t *out, int port) {
    (void)connection; (void)port;
    if (address_failed) { return NGX_ERROR; }
    memcpy(out->data, "127.0.0.1", 10U); out->len=9U; return NGX_OK;
}
static ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool) {
    ++pool_active; return pool;
}
static void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *pool) {
    (void)pool; --pool_active; ++restored;
}
static int msc_process_connection(void *transaction, const char *client, int client_port,
        const char *server, int server_port) {
    (void)transaction; (void)client; (void)client_port; (void)server; (void)server_port;
    if (pool_active != 1) { abort(); }
    ++native_calls; return phase_result;
}
static int msc_process_uri(void *transaction, const char *uri, const char *method, const char *version) {
    (void)transaction; (void)uri; (void)method; (void)version;
    if (pool_active != 1 || observed->native_event_phase_active != 1 ||
        observed->native_event_phase != MSCONNECTOR_PHASE_REQUEST_HEADERS) { abort(); }
    ++native_calls; return phase_result;
}
static int ngx_http_modsecurity_process_intervention(void *transaction,
        ngx_http_request_t *request, int early_log) {
    (void)transaction; (void)request;
    if (pool_active != 0 || observed->native_event_phase_active || early_log != 1) { abort(); }
    ++dispatch_calls; return host_result;
}
'''
MAIN = r'''
int main(int argc, char **argv) {
    ngx_pool_t pool={0};
    ngx_connection_t connection={0};
    ngx_http_request_t request={0};
    ngx_http_modsecurity_ctx_t context={0};
    ngx_int_t result;
    if (argc != 6) { return 2; }
    phase_result=(int)strtol(argv[2], NULL, 10);
    host_result=(int)strtol(argv[3], NULL, 10);
    conversion_failed=strcmp(argv[4], "conversion") == 0;
    address_failed=strcmp(argv[4], "address") == 0;
    context.contract.error_class=(int)strtol(argv[5], NULL, 10);
    connection.addr_text=(ngx_str_t){9U, (u_char *)"127.0.0.1"};
    request.connection=&connection; request.pool=&pool; request.http_version=NGX_HTTP_VERSION_11;
    request.unparsed_uri=(ngx_str_t){8U, (u_char *)"/fixture"};
    request.method_name=(ngx_str_t){3U, (u_char *)"GET"};
    observed=&context;
    result=strcmp(argv[1], "connection") == 0 ?
        ngx_http_modsecurity_process_connection(&request, &context) :
        ngx_http_modsecurity_process_request_uri(&request, &context);
    printf("{\"result\":%ld,\"native\":%d,\"dispatch\":%d,\"failures\":%d,"
        "\"cause\":%d,\"triggered\":%d,\"restored\":%d,\"active\":%d}\n",
        result,native_calls,dispatch_calls,failures,context.contract.error_class,
        context.intervention_triggered,restored,context.native_event_phase_active);
    return 0;
}
'''


class NginxRequestPhaseCompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler=shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("a C compiler is required for connection/URI regression tests")
        temporary=tempfile.TemporaryDirectory(prefix="nginx-phase-result-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory=Path(temporary.name)
        source=ACCESS.read_text(encoding="utf-8")
        functions=(("ngx_int_t", "ngx_http_modsecurity_request_native_result"),
                   ("ngx_int_t", "ngx_http_modsecurity_process_connection"),
                   ("const char *", "ngx_http_modsecurity_request_http_version"),
                   ("ngx_int_t", "ngx_http_modsecurity_process_request_uri"))
        selected="\n".join("static " + result + "\n" + function_definition(source, name)
                           for result,name in functions)
        fixture=directory / "phase.c"
        fixture.write_text(PREAMBLE+selected+MAIN, encoding="utf-8")
        cls.binary=directory / "phase"
        command=compiler+["-std=c17", "-Wall", "-Wextra", "-Werror", "-I",
                          str(source_path('common/include', root=ROOT)), str(fixture), "-o", str(cls.binary)]
        result=subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        if result.returncode:
            raise AssertionError("connection/URI fixture compilation failed:\n"+result.stderr[-6000:])

    def case(self, phase, native=1, host=0, failure="none", cause=0):
        run=subprocess.run([str(self.binary), phase, str(native), str(host), failure, str(cause)],
                           capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(run.returncode,0,run.stderr)
        return json.loads(run.stdout)

    def test_native_failure_stops_before_dispatch_in_both_callers(self):
        for phase in ("connection", "uri"):
            for native in (0,-1,2,99):
                with self.subTest(phase=phase,native=native):
                    result=self.case(phase,native,403)
                    self.assertEqual((result["result"],result["native"],result["dispatch"]),(500,1,0))
                    self.assertEqual((result["failures"],result["cause"],result["triggered"]),(1,4,1))
                    self.assertEqual((result["restored"],result["active"]),(1,0))

    def test_native_success_without_intervention_remains_ok(self):
        for phase in ("connection", "uri"):
            with self.subTest(phase=phase):
                result=self.case(phase)
                self.assertEqual((result["result"],result["dispatch"],result["failures"]),(0,1,0))
                self.assertEqual((result["triggered"],result["restored"],result["active"]),(0,1,0))

    def test_positive_host_statuses_are_not_native_result_codes(self):
        for phase in ("connection", "uri"):
            for host in (302,403,429,500):
                with self.subTest(phase=phase,host=host):
                    result=self.case(phase,host=host)
                    self.assertEqual((result["result"],result["triggered"],result["cause"]),(host,1,0))

    def test_negative_dispatch_is_terminal_not_success(self):
        for phase in ("connection", "uri"):
            for host in (-1,-2):
                with self.subTest(phase=phase,host=host):
                    result=self.case(phase,host=host)
                    self.assertEqual((result["result"],result["dispatch"],result["triggered"]),(500,1,1))

    def test_existing_cause_survives_failed_native_result(self):
        result=self.case("uri",native=0,cause=7)
        self.assertEqual(result["cause"],7)
        self.assertEqual(result["dispatch"],0)

    def test_conversion_and_local_address_failures_never_enter_native_code(self):
        cases=(("connection","conversion"),("uri","conversion"),("connection","address"))
        for phase,failure in cases:
            with self.subTest(phase=phase,failure=failure):
                result=self.case(phase,failure=failure)
                self.assertEqual((result["result"],result["native"],result["dispatch"]),(500,0,0))
                self.assertEqual(result["restored"],0)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
