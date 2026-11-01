"""Compile the real native collector, intervention dispatcher and P4 caller.

The engine and final host I/O are controlled seams, not the intervention
function connecting native collection to the filter. Common lifecycle, rule
correlation and late policy use real code. This is not a live transport test.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import itertools
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
FUNCTIONS = {
    "ngx_http_modsecurity_module.c": (
        ("ngx_int_t", "ngx_http_modsecurity_contract_record_intervention"),
        ("int", "ngx_http_modsecurity_process_status_intervention"),
        ("int", "ngx_http_modsecurity_reject_native_intervention"),
        ("ngx_int_t", "ngx_http_modsecurity_collect_native_intervention"),
        ("int", "ngx_http_modsecurity_defer_late_phase4_intervention"),
        ("void", "ngx_http_modsecurity_extract_intervention_rule_id"),
        ("void", "ngx_http_modsecurity_log_native_intervention"),
        ("int", "ngx_http_modsecurity_process_intervention"),
    ),
    "ngx_http_modsecurity_body_filter.c": (
        ("int", "ngx_http_modsecurity_phase4_response_started"),
        ("const char *", "ngx_http_modsecurity_phase4_actual_action"),
        ("ngx_int_t", "ngx_http_modsecurity_phase4_fail_control"),
        ("ngx_int_t", "ngx_http_modsecurity_phase4_handle_intervention"),
        ("ngx_int_t", "ngx_http_modsecurity_process_final_response_body"),
    ),
}
PREAMBLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "msconnector/config.h"
#include "msconnector/intervention.h"
#include "msconnector/late_intervention.h"
#include "msconnector/native_result.h"
#include "msconnector/rule_id.h"
#include "msconnector/transaction_state.h"
#include "ngx_http_modsecurity_response_body_limit.h"
#include "connectors/profile_registry.h"
#define ngx_memzero(pointer, length) memset(pointer, 0, length)
#define ngx_strcmp strcmp
#define ngx_inline inline
typedef long ngx_int_t;
typedef unsigned long ngx_uint_t;
typedef unsigned char u_char;
typedef struct { int unused; } ngx_pool_t;
typedef ngx_pool_t *ngx_http_modsecurity_pcre_pool_snapshot_t;
typedef struct { int unused; } ngx_chain_t;
typedef struct { int unused; } Transaction;
typedef struct { int status, disruptive; char *url, *log; } ModSecurityIntervention;
typedef struct { int error; void *log; } ngx_log_t;
typedef struct { ngx_log_t *log; int error; } connection_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct {
    connection_t *connection;
    ngx_pool_t *pool;
    int header_sent, filter_finalize;
    ngx_str_t uri;
} ngx_http_request_t;
typedef struct {
    msconnector_transaction_contract contract;
    Transaction *modsec_transaction;
    int contract_initialized, intervention_triggered, logged;
    int native_request_body_limit_rejection;
    int native_response_body_limit_rejection;
    int native_response_body_eos, native_event_phase_active;
    enum msconnector_phase native_event_phase;
    ngx_int_t last_intervention_status;
    char last_intervention_rule_id[MSCONNECTOR_MAX_RULE_ID_LENGTH + 1U];
    int phase4_processed, phase4_headers_checked, phase4_intervention, phase4_strict_abort;
    int phase4_terminal_error_started, phase4_terminal_error_emitting;
    int response_committed, response_body_seen;
    int request_intervention_pending;
    ModSecurityIntervention pending_request_intervention;
} ngx_http_modsecurity_ctx_t;
typedef struct { ngx_uint_t phase4_mode; msconnector_config common_config; }
    ngx_http_modsecurity_conf_t;
enum { NGX_OK = 0, NGX_ERROR = -1, NGX_DECLINED = -5, NGX_LOG_ERR = 4,
       NGX_HTTP_FORBIDDEN = 403, NGX_HTTP_TOO_MANY_REQUESTS = 429,
       NGX_HTTP_REQUEST_ENTITY_TOO_LARGE = 413, NGX_HTTP_INTERNAL_SERVER_ERROR = 500,
       NGX_HTTP_GATEWAY_TIME_OUT = 504 };
static int ngx_http_modsecurity_module;
static ngx_http_modsecurity_ctx_t context;
static ngx_http_modsecurity_conf_t config;
static int raw_result, phase_result = 1, disruptive = 1, use_redirect;
static int missing_context, missing_config, missing_rule, response_limit;
static int collections, cleanups, native_phases, status_updates, redirects, forwards;
static int events, errors, core_calls, sink_result;
static char observed_action[32];
static const char *rule_text = "rule [id \"12345\"]";
static void dd(const char *format, ...) { (void)format; }
static void ngx_log_error(int level, void *log, int error, const char *format, ...) {
    (void)level; (void)log; (void)error; (void)format;
}
static char *owned_text(const char *source) {
    size_t length = strlen(source) + 1U;
    char *copy = malloc(length);
    if (copy == NULL) { exit(3); }
    memcpy(copy, source, length);
    return copy;
}
static int msc_intervention(Transaction *transaction, ModSecurityIntervention *out) {
    (void)transaction; ++collections;
    out->disruptive = disruptive;
    out->status = use_redirect ? 302 : 403;
    out->log = owned_text(response_limit ? "Response body limit is marked to reject the request"
                         : missing_rule ? "no rule identifier" : rule_text);
    out->url = use_redirect ? owned_text("/redirect") : NULL;
    return raw_result;
}
static void msc_intervention_cleanup(ModSecurityIntervention *out) {
    ++cleanups; free(out->url); free(out->log);
    out->url = NULL; out->log = NULL;
}
static void msc_update_status_code(Transaction *transaction, int status) {
    (void)transaction; (void)status; ++status_updates;
}
static int msc_process_response_body(Transaction *transaction) {
    (void)transaction; ++native_phases; return phase_result;
}
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_get_module_ctx(ngx_http_request_t *r) {
    (void)r; return missing_context ? NULL : &context;
}
static ngx_http_modsecurity_conf_t *ngx_http_get_module_loc_conf(ngx_http_request_t *r, int module) {
    (void)r; (void)module; return missing_config ? NULL : &config;
}
static int ngx_http_modsecurity_contract_begin(ngx_http_modsecurity_ctx_t *ctx,
        enum msconnector_phase phase) {
    return msconnector_transaction_contract_begin_phase(&ctx->contract, phase, 0U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK ? NGX_OK : NGX_ERROR;
}
static int ngx_http_modsecurity_contract_complete(ngx_http_modsecurity_ctx_t *ctx,
        enum msconnector_phase phase) {
    return msconnector_transaction_contract_complete_phase(&ctx->contract, phase, 0U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK ? NGX_OK : NGX_ERROR;
}
static ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool) { return pool; }
static void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *pool) { (void)pool; }
typedef struct { int enabled; } ngx_http_modsecurity_engine_call_measurement;
static ngx_int_t ngx_http_modsecurity_engine_call_begin(ngx_http_request_t *r,
    enum msconnector_phase phase, ngx_http_modsecurity_engine_call_measurement *value) {
    (void)r; (void)phase; value->enabled=0; return NGX_OK;
}
static ngx_int_t ngx_http_modsecurity_engine_call_finish(ngx_http_request_t *r,
    enum msconnector_phase phase, ngx_http_modsecurity_engine_call_measurement *value, int result) {
    (void)r; (void)phase; (void)value; (void)result; return NGX_OK;
}
static ngx_int_t ngx_http_modsecurity_phase4_log_native_completion(ngx_http_request_t *r,
    const ngx_http_modsecurity_conf_t *conf, ngx_http_modsecurity_ctx_t *ctx, int result) {
    (void)r; (void)conf; (void)ctx;
    return result == 1 ? NGX_OK : NGX_ERROR;
}
static ngx_int_t ngx_http_modsecurity_log_handler(ngx_http_request_t *r) { (void)r; return NGX_OK; }
static int ngx_http_modsecurity_process_redirect_intervention(ngx_http_request_t *r,
        ngx_http_modsecurity_ctx_t *ctx, const ModSecurityIntervention *intervention) {
    (void)ctx; ++redirects; return r->header_sent ? NGX_ERROR : intervention->status;
}
static ngx_int_t ngx_http_next_body_filter(ngx_http_request_t *r, ngx_chain_t *chain) {
    (void)r; (void)chain; ++forwards; return NGX_OK;
}
static ngx_int_t ngx_http_modsecurity_phase4_log_event(ngx_http_request_t *r,
        const ngx_http_modsecurity_conf_t *mcf, const char *wanted,
        const char *actual, const char *reason) {
    (void)r; (void)mcf; (void)wanted; (void)reason; ++events;
    snprintf(observed_action, sizeof(observed_action), "%s", actual);
    return sink_result;
}
static ngx_int_t ngx_http_modsecurity_phase4_log_failure(ngx_http_request_t *r,
        const ngx_http_modsecurity_conf_t *mcf, ngx_http_modsecurity_ctx_t *ctx) {
    (void)r; (void)mcf; (void)ctx; ++errors; return NGX_OK;
}
static ngx_int_t ngx_http_filter_finalize_request(ngx_http_request_t *r, int *module,
        ngx_int_t status) {
    (void)r; (void)module; (void)status; ++core_calls; return NGX_ERROR;
}
#include "ngx_http_modsecurity_phase4_error.h"
'''
MAIN = r'''
static int prepare_context(int committed) {
    const msconnector_transaction_profile *profile = msconnector_profile_registry_find("nginx");
    if (profile == NULL || msconnector_transaction_contract_init(&context.contract,
            profile, "native-chain", "nginx", "fixture",
            MSCONNECTOR_TRANSACTION_MODE_SAFE, 100U) != MSCONNECTOR_TRANSACTION_TRANSITION_OK) {
        return 0;
    }
    context.contract_initialized = 1;
    for (enum msconnector_phase phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
            phase <= MSCONNECTOR_PHASE_RESPONSE_HEADERS; ++phase) {
        if (ngx_http_modsecurity_contract_begin(&context, phase) != NGX_OK ||
            ngx_http_modsecurity_contract_complete(&context, phase) != NGX_OK) {
            return 0;
        }
    }
    if (msconnector_transaction_contract_set_response_committed(&context.contract, committed) !=
            MSCONNECTOR_TRANSACTION_TRANSITION_OK) { return 0; }
    context.last_intervention_status = 451;
    strcpy(context.last_intervention_rule_id, "stale-rule");
    context.native_event_phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
    return 1;
}
int main(int argc, char **argv) {
    ngx_log_t log = {0};
    connection_t connection = {&log, 0};
    ngx_http_request_t request = {0};
    ngx_chain_t chain = {0};
    Transaction transaction = {0};
    ngx_uint_t forwarded = 0;
    ngx_int_t result;
    if (argc != 6) { return 2; }
    config.common_config.default_block_status = 403;
    config.common_config.use_error_log = MSCONNECTOR_BOOL_OFF;
    if (strcmp(argv[1], "off") == 0) { config.phase4_mode = MSCONNECTOR_PHASE4_MODE_OFF; }
    else if (strcmp(argv[1], "safe") == 0) { config.phase4_mode = MSCONNECTOR_PHASE4_MODE_SAFE; }
    else if (strcmp(argv[1], "strict") == 0) { config.phase4_mode = MSCONNECTOR_PHASE4_MODE_STRICT; }
    else { return 2; }
    request.header_sent = strcmp(argv[2], "after") == 0;
    request.connection = &connection;
    raw_result = (int)strtol(argv[3], NULL, 10);
    disruptive = (int)strtol(argv[4], NULL, 10);
    use_redirect = strcmp(argv[5], "redirect") == 0;
    missing_context = strcmp(argv[5], "missing-context") == 0;
    missing_config = strcmp(argv[5], "missing-config") == 0;
    missing_rule = strcmp(argv[5], "missing-rule") == 0;
    response_limit = strcmp(argv[5], "response-limit") == 0;
    if (strcmp(argv[5], "sink-error") == 0) { sink_result = NGX_ERROR; }
    if (strcmp(argv[5], "native-error") == 0) { phase_result = 0; }
    if (!prepare_context(request.header_sent)) { return 3; }
    context.modsec_transaction = strcmp(argv[5], "missing-transaction") == 0 ? NULL : &transaction;
    context.phase4_processed = 1;
    result = strcmp(argv[5], "unexpected-append-rule") == 0
        ? ngx_http_modsecurity_process_intervention(&transaction, &request, 0)
        : ngx_http_modsecurity_process_final_response_body(&request, &context,
            &config, &chain, &forwarded);
    printf("{\"result\":%ld,\"raw_calls\":%d,\"cleanup\":%d,\"native\":%d,"
        "\"events\":%d,\"errors\":%d,\"forwards\":%d,\"status_updates\":%d,"
        "\"redirects\":%d,\"cause\":\"%s\",\"rule\":\"%s\","
        "\"actual\":\"%s\",\"abort\":%d,\"connection_error\":%d,\"core\":%d}\n",
        result, collections, cleanups, native_phases, events, errors, forwards,
        status_updates, redirects, msconnector_transaction_error_class_name(context.contract.error_class),
        context.last_intervention_rule_id, observed_action, context.phase4_strict_abort,
        connection.error, core_calls);
    return 0;
}
'''


class NativeInterventionChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("a C compiler is required for native intervention chain tests")
        temporary = tempfile.TemporaryDirectory(prefix="nginx-native-chain-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        definitions = []
        for path, functions in FUNCTIONS.items():
            source = (NATIVE / path).read_text(encoding="utf-8")
            definitions.extend("static " + result_type + "\n" + function_definition(source, name)
                               for result_type, name in functions)
        declarations = "\n".join(value[:value.index("{")] + ";" for value in definitions)
        fixture = directory / "chain.c"
        fixture.write_text(PREAMBLE + declarations + "\n" + "\n".join(definitions) + MAIN, encoding="utf-8")
        cls.binary = directory / "chain"
        sources = ("transaction_state.c", "decision_action.c", "intervention.c", "block_statuses.c",
                   "http_status.c", "late_intervention.c", "rule_id.c")
        command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                              "-I", str(source_path('common/include', root=ROOT)), "-I", str(ROOT), "-I", str(NATIVE), str(fixture)]
        command += [str(source_path('common/src', root=ROOT) / name) for name in sources]
        command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(cls.binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        if compiled.returncode:
            raise AssertionError("native intervention fixture compilation failed:\n" + compiled.stderr[-6000:])

    def case(self, mode="safe", commitment="after", native=1, disruptive=1, scenario="normal") -> dict:
        result = subprocess.run([str(self.binary), mode, commitment, str(native), str(disruptive), scenario],
                                capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        return json.loads(result.stdout)

    def test_late_valid_rule_reaches_safe_policy_through_real_collector(self):
        for scenario in ("normal", "redirect"):
            with self.subTest(scenario=scenario):
                result = self.case(scenario=scenario)
                self.assertEqual(result["result"], 0)
                self.assertEqual(result["actual"], "log_only")
                self.assertEqual(result["forwards"], 1)
                self.assertEqual(result["cause"], "none")
                self.assertEqual(result["cleanup"], 1)
                self.assertEqual(result["status_updates"], 0)
                self.assertEqual(result["redirects"], 0)

    def test_late_valid_rule_reaches_strict_abort_not_technical_error(self):
        for scenario in ("normal", "redirect"):
            with self.subTest(scenario=scenario):
                result = self.case(mode="strict", scenario=scenario)
                self.assertEqual(result["result"], -1)
                self.assertEqual(result["actual"], "abort_connection")
                self.assertEqual(result["abort"], 1)
                self.assertEqual(result["forwards"], 0)
                self.assertEqual(result["cause"], "none")
                self.assertEqual(result["cleanup"], 1)

    def test_invalid_native_results_never_reach_rule_or_host_dispatch(self):
        for mode, commitment, native in itertools.product(("off", "safe", "strict"), ("before", "after"), (-2, -1, 2, 99)):
            with self.subTest(mode=mode, commitment=commitment, native=native):
                result = self.case(mode, commitment, native)
                self.assertEqual(result["result"], -1)
                self.assertEqual(result["cause"], "invalid_engine_response")
                self.assertEqual(result["rule"], "")
                self.assertEqual(result["cleanup"], 1)
                self.assertEqual(result["events"], 0)
                self.assertEqual(result["forwards"], 0)
                self.assertEqual(result["status_updates"], 0)

    def test_no_intervention_and_nondisruptive_collection_remain_noop(self):
        for native, disruptive in ((0, 1), (1, 0)):
            with self.subTest(native=native, disruptive=disruptive):
                result = self.case(native=native, disruptive=disruptive)
                self.assertEqual(result["result"], 0)
                self.assertEqual(result["cause"], "none")
                self.assertEqual(result["events"], 0)
                self.assertEqual(result["rule"], "")
                self.assertEqual(result["cleanup"], 1)

    def test_off_keeps_native_late_status_path(self):
        result = self.case(mode="off")
        self.assertEqual(result["result"], -1)
        self.assertEqual(result["status_updates"], 1)
        self.assertEqual(result["events"], 0)
        self.assertEqual(result["forwards"], 0)

    def test_before_commit_preserves_real_status_and_redirect(self):
        for mode, scenario in itertools.product(("off", "safe", "strict"), ("normal", "redirect")):
            with self.subTest(mode=mode, scenario=scenario):
                result = self.case(mode=mode, commitment="before", scenario=scenario)
                self.assertEqual(result["result"], 302 if scenario == "redirect" else 403)
                self.assertEqual(result["cause"], "none")
                self.assertEqual(result["cleanup"], 1)
                self.assertEqual(result["forwards"], 0)

    def test_missing_context_transaction_or_config_is_technical(self):
        for scenario in ("missing-context", "missing-transaction", "missing-config"):
            with self.subTest(scenario=scenario):
                result = self.case(scenario=scenario)
                self.assertEqual(result["result"], -1)
                self.assertNotEqual(result["cause"], "none")
                self.assertEqual(result["events"], 0)
                self.assertEqual(result["cleanup"], 1)
                self.assertEqual(result["forwards"], 0)

    def test_unexpected_append_time_rule_does_not_forge_engine_eos(self):
        for mode in ("off", "safe", "strict"):
            value = self.case(mode=mode, scenario="unexpected-append-rule")
            self.assertEqual(value["result"], -1)
            self.assertEqual(value["cause"], "invalid_engine_response")
            self.assertEqual(value["rule"], "")
            self.assertEqual(value["forwards"], 0)
            self.assertEqual(value["events"], 0)
            self.assertEqual(value["cleanup"], 1)

    def test_missing_rule_correlation_does_not_become_safe_allow(self):
        result = self.case(scenario="missing-rule")
        self.assertEqual(result["result"], -1)
        self.assertEqual(result["cause"], "invalid_engine_response")
        self.assertEqual(result["events"], 0)
        self.assertEqual(result["cleanup"], 1)

    def test_exact_native_response_body_limit_is_not_a_rule_or_safe_allow(self):
        for mode in ("off", "safe", "strict"):
            with self.subTest(mode=mode):
                result = self.case(mode=mode, scenario="response-limit")
                self.assertEqual(result["result"], -1)
                self.assertEqual(result["cause"], "body_limit")
                self.assertEqual(result["rule"], "")
                self.assertEqual(result["forwards"], 0)
                self.assertEqual(result["events"], 0)
                self.assertEqual(result["cleanup"], 1)

    def test_failed_evaluation_does_not_call_native_intervention(self):
        result = self.case(scenario="native-error")
        self.assertEqual(result["result"], -1)
        self.assertEqual(result["cause"], "invalid_engine_response")
        self.assertEqual(result["raw_calls"], 0)
        self.assertEqual(result["cleanup"], 0)
        self.assertEqual(result["forwards"], 0)

    def test_safe_sink_failure_never_forwards_body(self):
        result = self.case(scenario="sink-error")
        self.assertEqual(result["result"], -1)
        self.assertEqual(result["forwards"], 0)
        self.assertEqual(result["connection_error"], 1)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
