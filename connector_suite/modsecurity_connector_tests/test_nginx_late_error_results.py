"""Exercise actual NGINX P4 functions and the real Common late-action policy.

Native evaluation, core response generation, and the JSONL sink are controlled
collaborators. Budget measurement is a controlled boundary; native-completion validation
and its optional event path execute the production implementations.
These are compiled control-flow/producer tests, not a live host
or client-transport claim. Core re-entry models filter_finalize_request.
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
SOURCE = source_path('connectors/nginx/src/ngx_http_modsecurity_body_filter.c', root=ROOT)
FUNCTIONS = (
    ("int", "ngx_http_modsecurity_phase4_original_status"),
    ("int", "ngx_http_modsecurity_phase4_response_started"),
    ("const char *", "ngx_http_modsecurity_phase4_actual_action"),
    ("const char *", "ngx_http_modsecurity_phase4_mode_name"),
    ("const char *", "ngx_http_modsecurity_phase4_message_id"),
    ("int", "ngx_http_modsecurity_phase4_visible_status"),
    ("const char *", "ngx_http_modsecurity_phase4_transport_result"),
    ("void", "ngx_http_modsecurity_phase4_copy_content_type"),
    ("void", "ngx_http_modsecurity_phase4_copy_intervention_identifier"),
    ("ngx_int_t", "ngx_http_modsecurity_phase4_observation_event"),
    ("ngx_int_t", "ngx_http_modsecurity_phase4_log_native_completion"),
    ("ngx_int_t", "ngx_http_modsecurity_phase4_log_event"),
    ("ngx_int_t", "ngx_http_modsecurity_phase4_log_failure"),
    ("ngx_int_t", "ngx_http_modsecurity_phase4_fail_control"),
    ("ngx_int_t", "ngx_http_modsecurity_phase4_handle_intervention"),
    ("ngx_int_t", "ngx_http_modsecurity_process_final_response_body"),
    ("ngx_int_t", "ngx_http_modsecurity_finalize_terminal_response_body"),
    ("ngx_int_t", "ngx_http_modsecurity_prepare_response_body_filter"),
)
PREAMBLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "msconnector/config.h"
#include "msconnector/event.h"
#include "msconnector/limits.h"
#include "msconnector/native_result.h"
#include "msconnector/late_intervention.h"
#include "msconnector/transaction_contract.h"
#define ngx_inline inline
#define ngx_strcmp strcmp
#define ngx_strlen strlen
#define ngx_memcpy memcpy
typedef unsigned char u_char;
typedef long ngx_int_t;
typedef unsigned long ngx_uint_t;
typedef struct { int unused; } ngx_pool_t;
typedef ngx_pool_t *ngx_http_modsecurity_pcre_pool_snapshot_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int fd; } ngx_open_file_t;
typedef struct { int error; void *log; } connection_t;
typedef struct { int unused; } ngx_chain_t;
typedef struct {
    connection_t *connection;
    ngx_pool_t *pool;
    int header_sent, filter_finalize, err_status;
    struct { int status; ngx_str_t content_type; } headers_out;
    ngx_str_t uri;
} ngx_http_request_t;
typedef struct {
    ngx_uint_t phase4_mode;
    ngx_open_file_t *phase4_log_file;
} ngx_http_modsecurity_conf_t;
typedef struct {
    msconnector_transaction_contract contract;
    void *modsec_transaction;
    int contract_initialized, intervention_triggered, phase4_processed;
    int phase4_headers_checked, phase4_strict_abort, phase4_intervention;
    int phase4_terminal_error_started, phase4_terminal_error_emitting;
    int response_committed, response_body_seen, response_body_truncated;
    int response_replaced;
    int native_response_body_limit_rejection, native_response_body_eos;
    enum msconnector_phase native_event_phase;
    int native_event_phase_active;
    uint64_t response_body_bytes_seen, response_body_bytes_inspected, response_body_append_calls;
    ngx_str_t event_transaction_id;
    char last_intervention_rule_id[MSCONNECTOR_MAX_RULE_ID_LENGTH + 1U];
    ngx_int_t last_intervention_status;
} ngx_http_modsecurity_ctx_t;
typedef struct { const char *method, *uri, *content_type; }
    ngx_http_modsecurity_event_request_metadata_t;
enum { NGX_OK = 0, NGX_ERROR = -1, NGX_DECLINED = -5,
    NGX_DONE = -4, NGX_LOG_ERR = 4, NGX_LOG_WARN = 5, NGX_INVALID_FILE = -1, NGX_HTTP_OK = 200,
    NGX_HTTP_FORBIDDEN = 403, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE = 413,
    NGX_HTTP_INTERNAL_SERVER_ERROR = 500, NGX_HTTP_GATEWAY_TIME_OUT = 504 };
typedef struct { int unused; } ngx_http_modsecurity_engine_call_measurement;
static int ngx_http_modsecurity_module;
static ngx_http_modsecurity_ctx_t context;
static int native_result = 1, intervention_result, sink_result;
static int fail_begin, fail_complete, fail_commit;
static int fail_completion_observation, invalid_retained;
static int completion_observations;
static int native_calls, intervention_calls, completions, writes, forwards;
static int core_calls, core_status, core_body_gate = 99, last_eos = -1;
static char last_id[100], last_actual[40];
static ngx_int_t ngx_http_filter_finalize_request(ngx_http_request_t *r,
    int *module, ngx_int_t status);
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_get_module_ctx(
    ngx_http_request_t *r) { (void)r; return &context; }
static void dd(const char *format, ...) { (void)format; }
static void ngx_log_error(int level, void *log, int error, const char *format, ...) {
    (void)level; (void)log; (void)error; (void)format;
}
static ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool) { return pool; }
static void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *pool) { (void)pool; }
int msconnector_transaction_contract_fail(msconnector_transaction_contract *contract,
    msconnector_transaction_error_class cause, uint64_t now) {
    (void)now; contract->error_class = cause;
    return MSCONNECTOR_TRANSACTION_TRANSITION_OK;
}
static int ngx_http_modsecurity_contract_begin(ngx_http_modsecurity_ctx_t *ctx,
    enum msconnector_phase phase) {
    if (fail_begin) { return NGX_ERROR; }
    ctx->contract.active_phase = phase; return NGX_OK;
}
static int ngx_http_modsecurity_contract_complete(ngx_http_modsecurity_ctx_t *ctx,
    enum msconnector_phase phase) {
    if (fail_complete) { return NGX_ERROR; }
    ++completions; ctx->contract.active_phase = -1;
    ctx->contract.last_completed_phase = phase;
    if (phase == MSCONNECTOR_PHASE_RESPONSE_BODY)
        ctx->contract.completed_phase_mask |= MSCONNECTOR_TRANSACTION_PHASE_MASK_P4;
    return NGX_OK;
}
static ngx_int_t ngx_http_modsecurity_contract_record_response_commit(
    ngx_http_modsecurity_ctx_t *ctx, ngx_http_request_t *r) {
    (void)ctx; (void)r; return fail_commit ? NGX_ERROR : NGX_OK;
}
static int msc_process_response_body(void *transaction) {
    if (transaction != &context || !context.native_event_phase_active ||
        context.native_event_phase != MSCONNECTOR_PHASE_RESPONSE_BODY) abort();
    ++native_calls; return native_result;
}
/* This fixture selects the disabled-budget boundary, not a timing proof. */
static ngx_int_t ngx_http_modsecurity_engine_call_begin(ngx_http_request_t *r,
    enum msconnector_phase phase, ngx_http_modsecurity_engine_call_measurement *m) {
    (void)r; (void)m;
    if (phase != MSCONNECTOR_PHASE_RESPONSE_BODY) abort();
    return NGX_OK;
}
static ngx_int_t ngx_http_modsecurity_engine_call_finish(ngx_http_request_t *r,
    enum msconnector_phase phase, ngx_http_modsecurity_engine_call_measurement *m,
    int result) {
    (void)r; (void)m;
    if (phase != MSCONNECTOR_PHASE_RESPONSE_BODY || result != native_result ||
        context.native_event_phase_active) abort();
    return NGX_OK;
}
/* The actual completion logger reads the native getter exactly here. */
static size_t msc_get_response_body_length(void *transaction) {
    if (transaction != &context || !context.native_response_body_eos ||
        completions != 1) abort();
    ++completion_observations;
    return invalid_retained ? 1U : 0U;
}
static int ngx_http_modsecurity_process_intervention(void *transaction,
    ngx_http_request_t *r, int early) {
    (void)transaction; (void)r; (void)early; ++intervention_calls;
    return intervention_result;
}
static ngx_int_t ngx_http_next_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    (void)r; (void)in; ++forwards; return NGX_OK;
}
static ngx_int_t ngx_http_modsecurity_validate_response_mapper_once(
    ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx) {
    (void)r; (void)ctx; return NGX_OK;
}
void msconnector_event_init(msconnector_event *event) { memset(event, 0, sizeof(*event)); }
const char *msconnector_event_default_level(const char *id) { (void)id; return "error"; }
const char *msconnector_event_default_message(const char *id) { return id; }
static ngx_http_modsecurity_event_request_metadata_t
ngx_http_modsecurity_event_request_metadata(ngx_http_request_t *r) {
    (void)r;
    return (ngx_http_modsecurity_event_request_metadata_t){"GET", "/case", "text/plain"};
}
static ngx_int_t ngx_http_modsecurity_write_phase_event_jsonl(ngx_http_request_t *r,
    const ngx_http_modsecurity_conf_t *mcf, const msconnector_event *event, const char *phase) {
    (void)r; (void)phase;
    if (mcf == NULL || mcf->phase4_log_file == NULL || mcf->phase4_log_file->fd < 0) {
        abort();
    }
    ++writes; last_eos = event->flags.eos_seen;
    snprintf(last_id, sizeof(last_id), "%s", event->meta.message_id);
    snprintf(last_actual, sizeof(last_actual), "%s",
        event->decision.actual_action != NULL ? event->decision.actual_action : "");
    if (fail_completion_observation &&
        strcmp(event->meta.event, "phase4_completion") == 0) return NGX_ERROR;
    return sink_result;
}
#include "ngx_http_modsecurity_phase4_error.h"
#include "ngx_http_modsecurity_phase4_observation.h"
'''
MAIN = r'''
static ngx_int_t ngx_http_filter_finalize_request(ngx_http_request_t *r,
    int *module, ngx_int_t status) {
    ngx_chain_t core_body = {0};
    ngx_http_modsecurity_ctx_t *selected = NULL;
    (void)module;
    ++core_calls; core_status = (int)status;
    r->filter_finalize = 1;
    r->header_sent = 1;
    core_body_gate = (int)ngx_http_modsecurity_prepare_response_body_filter(
        r, &core_body, &selected);
    /* Real NGINX returns NGX_ERROR after successfully emitting an error page
     * to ensure no pending upstream data is released. */
    return NGX_ERROR;
}
int main(int argc, char **argv) {
    connection_t connection = {0};
    ngx_open_file_t logfile = {3};
    ngx_http_modsecurity_conf_t config = {0};
    ngx_http_request_t request = {0};
    ngx_http_modsecurity_ctx_t *selected = NULL;
    ngx_chain_t chain = {0};
    ngx_uint_t forwarded = 0, processed = 0;
    ngx_int_t result, retry, flush;
    if (argc != 7) { return 2; }
    config.phase4_mode = (ngx_uint_t)strtoul(argv[1], NULL, 10);
    config.phase4_log_file = &logfile;
    request.connection = &connection;
    request.header_sent = (int)strtol(argv[2], NULL, 10);
    request.headers_out.status = 201;
    native_result = (int)strtol(argv[3], NULL, 10);
    intervention_result = (int)strtol(argv[4], NULL, 10);
    sink_result = (int)strtol(argv[5], NULL, 10);
    context.modsec_transaction = &context;
    context.contract.active_phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
    context.contract.last_completed_phase = MSCONNECTOR_PHASE_RESPONSE_HEADERS;
    context.last_intervention_status = 403;
    if (strcmp(argv[6], "disabled") == 0) { config.phase4_log_file = NULL; }
    if (strcmp(argv[6], "invalid-fd") == 0) { logfile.fd = NGX_INVALID_FILE; }
    if (strcmp(argv[6], "begin") == 0) {
        fail_begin = 1; context.contract.active_phase = -1;
    }
    if (strcmp(argv[6], "complete") == 0) { fail_complete = 1; }
    if (strcmp(argv[6], "commit") == 0) { fail_commit = 1; }
    if (strcmp(argv[6], "completion-observation") == 0) {
        fail_completion_observation = 1;
    }
    if (strcmp(argv[6], "invalid-retained") == 0) invalid_retained = 1;
    if (strcmp(argv[6], "invalid-retained-no-log") == 0) {
        invalid_retained = 1; config.phase4_log_file = NULL;
    }
    if (strcmp(argv[6], "body-limit") == 0) {
        context.contract.error_class = MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT;
        result = ngx_http_modsecurity_phase4_fail_control(&request, &config,
            &context, MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);
    } else {
        result = ngx_http_modsecurity_finalize_terminal_response_body(&request,
            &context, &config, &chain, &forwarded, &processed);
    }
    retry = ngx_http_modsecurity_prepare_response_body_filter(&request, &chain, &selected);
    flush = ngx_http_modsecurity_prepare_response_body_filter(&request, NULL, &selected);
    if (context.contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE) {
        (void)ngx_http_modsecurity_phase4_fail_control(&request, &config,
            &context, MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);
    }
    printf("{\"result\":%ld,\"retry\":%ld,\"flush\":%ld,"
        "\"native\":%d,\"intervention\":%d,\"completions\":%d,"
        "\"completion_observations\":%d,"
        "\"writes\":%d,\"forwards\":%d,\"core\":%d,\"core_status\":%d,"
        "\"core_gate\":%d,\"emitting\":%d,\"error\":%d,\"abort\":%d,"
        "\"eos\":%d,\"id\":\"%s\",\"actual\":\"%s\","
        "\"off\":%d,\"safe\":%d,\"strict\":%d,\"connection_error\":%d}\n",
        result, retry, flush, native_calls, intervention_calls, completions,
        completion_observations, writes, forwards, core_calls, core_status, core_body_gate,
        context.phase4_terminal_error_emitting, context.contract.error_class,
        context.phase4_strict_abort, last_eos, last_id, last_actual,
        MSCONNECTOR_PHASE4_MODE_OFF, MSCONNECTOR_PHASE4_MODE_SAFE,
        MSCONNECTOR_PHASE4_MODE_STRICT, connection.error);
    return 0;
}
'''


class NginxLateErrorResultsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("a C compiler is required for late-error regressions")
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="nginx-late-error-", dir=os.environ.get("RUNNER_TEMP")
        )
        cls.addClassCleanup(cls.temporary.cleanup)
        root = Path(cls.temporary.name)
        cls.binary = root / "late-error"
        source = SOURCE.read_text(encoding="utf-8")
        definitions = [
            "static " + result_type + "\n" + function_definition(source, name)
            for result_type, name in FUNCTIONS
        ]
        declarations = "\n".join(value[:value.index("{")] + ";" for value in definitions)
        fixture = root / "late-error.c"
        fixture.write_text(PREAMBLE + declarations + "\n" + "\n".join(definitions) + MAIN,
                           encoding="utf-8")
        compiled = subprocess.run(
            compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror",
                        "-I", str(source_path('common/include', root=ROOT)),
                        "-I", str(SOURCE.parent), str(fixture),
                        str(source_path('common/src/late_intervention.c', root=ROOT)), "-o", str(cls.binary)],
            check=False, capture_output=True, text=True, timeout=30,
        )
        if compiled.returncode != 0:
            raise AssertionError("late-error fixture compilation failed:\n" + compiled.stderr[-4000:])
        control = cls.invoke(0)
        cls.modes = tuple(control[name] for name in ("off", "safe", "strict"))

    @classmethod
    def invoke(cls, mode: int, committed: int = 0, native: int = 1,
               intervention: int = 0, sink: int = 0, scenario: str = "normal") -> dict:
        result = subprocess.run(
            [str(cls.binary), str(mode), str(committed), str(native),
             str(intervention), str(sink), scenario],
            check=True, capture_output=True, text=True, timeout=5,
        )
        return json.loads(result.stdout)

    def assert_terminal(self, result: dict, committed: int) -> None:
        self.assertEqual(result["result"], -1)
        self.assertEqual(result["retry"], -1)
        self.assertEqual(result["flush"], -1)
        self.assertEqual(result["forwards"], 0)
        self.assertEqual(result["core"], 1 - committed)
        self.assertEqual(result["emitting"], 0)
        self.assertNotEqual(result["error"], 0)
        if not committed:
            self.assertEqual(result["core_gate"], -5)
            self.assertEqual(result["core_status"], 500)

    def test_native_failures_never_complete_or_forward_in_any_mode(self) -> None:
        for mode in self.modes:
            for committed in (0, 1):
                for native in (-1, 0, 2):
                    with self.subTest(mode=mode, committed=committed, native=native):
                        result = self.invoke(mode, committed, native=native)
                        self.assert_terminal(result, committed)
                        self.assertEqual(result["completions"], 0)
                        self.assertEqual(result["completion_observations"], 0)
                        self.assertEqual(result["intervention"], 0)
                        self.assertEqual(result["eos"], 0)
                        self.assertEqual(result["writes"], 1)
                        self.assertEqual(result["id"], "MSCONN_EVENT_INVALID_ENGINE_RESPONSE")

    def test_negative_interventions_cannot_become_safe_log_only(self) -> None:
        for mode in self.modes:
            for committed in (0, 1):
                with self.subTest(mode=mode, committed=committed):
                    result = self.invoke(mode, committed, intervention=-1)
                    self.assert_terminal(result, committed)
                    self.assertEqual(result["completions"], 1)
                    self.assertEqual(result["eos"], 1)
                    self.assertEqual(result["writes"], 2)
                    self.assertEqual(result["id"], "MSCONN_EVENT_INVALID_ENGINE_RESPONSE")
                    self.assertNotEqual(result["actual"], "log_only")

    def test_disabled_or_invalid_log_descriptor_never_reaches_sink(self) -> None:
        for scenario in ("disabled", "invalid-fd"):
            for committed in (0, 1):
                with self.subTest(scenario=scenario, committed=committed):
                    result = self.invoke(self.modes[1], committed, native=0, scenario=scenario)
                    self.assert_terminal(result, committed)
                    self.assertEqual(result["writes"], 0)

    def test_successful_empty_finalization_still_allows_normal_forwarding(self) -> None:
        for mode in self.modes:
            result = self.invoke(mode)
            self.assertEqual(result["result"], 0)
            self.assertEqual(result["completions"], 1)
            self.assertEqual(result["completion_observations"], 1)
            self.assertEqual(result["retry"], -5)
            self.assertEqual(result["writes"], 1)
            self.assertEqual(result["error"], 0)

    def test_real_safe_policy_applies_only_to_a_rule_intervention(self) -> None:
        result = self.invoke(self.modes[1], committed=1, intervention=403)
        self.assertEqual(result["result"], 0)
        self.assertEqual(result["actual"], "log_only")
        self.assertEqual(result["forwards"], 1)
        self.assertEqual(result["error"], 0)

    def test_real_strict_rule_abort_remains_terminal_without_technical_reclassification(self) -> None:
        result = self.invoke(self.modes[2], committed=1, intervention=403)
        self.assertEqual(result["result"], -1)
        self.assertEqual(result["retry"], -1)
        self.assertEqual(result["flush"], -1)
        self.assertEqual(result["abort"], 1)
        self.assertEqual(result["error"], 0)
        self.assertEqual(result["actual"], "abort_connection")
        self.assertEqual(result["forwards"], 0)

    def test_event_only_metadata_allocation_failure_is_diagnosed_without_host_error(self) -> None:
        common = source_path("connectors/nginx/src/ngx_http_modsecurity_common.h", root=ROOT)
        helper = function_definition(common.read_text(encoding="utf-8"),
                                     "ngx_http_modsecurity_event_request_metadata")
        preamble = r"""
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef unsigned char u_char;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { ngx_str_t value; } ngx_table_elt_t;
typedef struct { int error; void *log; } connection_t;
typedef struct {
    void *pool;
    connection_t *connection;
    ngx_str_t method_name, unparsed_uri;
    struct { ngx_table_elt_t *content_type; } headers_in;
} ngx_http_request_t;
typedef struct { const char *method, *uri, *content_type; }
    ngx_http_modsecurity_event_request_metadata_t;
#define NGX_LOG_WARN 5
static int fail_at, calls, warnings;
static char *ngx_str_to_char(ngx_str_t value, void *pool) {
    (void)value; (void)pool;
    return ++calls == fail_at ? (char *)-1 : "kept";
}
static void ngx_log_error(int level, void *log, int error, const char *format, ...) {
    (void)log; (void)error; (void)format;
    if (level == NGX_LOG_WARN) ++warnings;
}
"""
        main = r"""
int main(void) {
    connection_t connection = {0};
    ngx_table_elt_t content = {{1, (u_char *)"c"}};
    ngx_http_request_t request = {NULL, &connection,
        {1, (u_char *)"m"}, {1, (u_char *)"u"}, {&content}};
    for (fail_at = 0; fail_at <= 3; ++fail_at) {
        calls = warnings = 0;
        ngx_http_modsecurity_event_request_metadata_t value =
            ngx_http_modsecurity_event_request_metadata(&request);
        if (strcmp(value.method, fail_at == 1 ? "" : "kept") ||
            strcmp(value.uri, fail_at == 2 ? "" : "kept") ||
            strcmp(value.content_type, fail_at == 3 ? "" : "kept") ||
            warnings != (fail_at != 0) || connection.error) return 1;
    }
    return 0;
}
"""
        with tempfile.TemporaryDirectory(prefix="nginx-event-allocation-",
                                         dir=os.environ.get("RUNNER_TEMP")) as temporary:
            fixture = Path(temporary) / "metadata.c"
            binary = fixture.with_suffix("")
            fixture.write_text(preamble +
                               "\nstatic inline ngx_http_modsecurity_event_request_metadata_t\n" +
                               helper + main, encoding="utf-8")
            compiler = shlex.split(os.environ.get("CC", "cc"))
            built = subprocess.run(compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror",
                                              "-pedantic-errors", str(fixture), "-o", str(binary)],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr[-4000:])
            observed = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)
            self.assertEqual(observed.returncode, 0, observed.stderr)

    def test_optional_log_failure_keeps_safe_late_response_and_reentry_open(self) -> None:
        result = self.invoke(self.modes[1], committed=1, intervention=403, sink=-1)
        self.assertEqual(result["result"], 0)
        self.assertEqual(result["actual"], "log_only")
        self.assertEqual(result["forwards"], 1)
        self.assertEqual(result["error"], 0)
        self.assertEqual(result["connection_error"], 0)
        self.assertEqual(result["retry"], -5)
        self.assertEqual(result["flush"], -5)
        self.assertEqual(result["core"], 0)
        self.assertEqual(result["writes"], 2)

    def test_log_failure_does_not_change_strict_abort_or_precommit_error(self) -> None:
        strict = self.invoke(self.modes[2], committed=1, intervention=403, sink=-1)
        self.assertEqual(strict["result"], -1)
        self.assertEqual(strict["abort"], 1)
        self.assertEqual(strict["connection_error"], 1)
        self.assertEqual(strict["forwards"], 0)
        self.assertEqual(strict["core"], 0)
        early = self.invoke(self.modes[1], committed=0, intervention=403, sink=-1)
        self.assert_terminal(early, 0)
        self.assertEqual(early["writes"], 2)

    def test_invalid_canonical_transitions_fail_closed(self) -> None:
        for scenario in ("begin", "complete", "commit"):
            for committed in (0, 1):
                with self.subTest(scenario=scenario, committed=committed):
                    result = self.invoke(self.modes[1], committed, scenario=scenario)
                    self.assert_terminal(result, committed)
                    self.assertEqual(result["completions"], 0)
                    self.assertEqual(result["writes"], 1)

    def test_specific_body_limit_cause_survives_generic_error_dispatch(self) -> None:
        result = self.invoke(self.modes[1], scenario="body-limit")
        self.assertEqual(result["result"], -1)
        self.assertEqual(result["core_status"], 413)
        self.assertEqual(result["id"], "MSCONN_EVENT_BODY_LIMIT")
        self.assertEqual(result["core"], 1)
        self.assertEqual(result["writes"], 1)
        self.assertEqual(result["native"], 0)

    def test_impossible_native_eos_retained_length_fails_even_without_event_log(self) -> None:
        for committed in (0, 1):
            for scenario in ("invalid-retained", "invalid-retained-no-log"):
                with self.subTest(committed=committed, scenario=scenario):
                    result = self.invoke(self.modes[1], committed, scenario=scenario)
                    self.assert_terminal(result, committed)
                    self.assertEqual(result["completion_observations"], 1)
                    self.assertEqual(result["intervention"], 0)
                    self.assertEqual(result["writes"], scenario == "invalid-retained")
                    if scenario == "invalid-retained":
                        self.assertEqual(result["id"], "MSCONN_EVENT_INVALID_ENGINE_RESPONSE")

    def test_optional_completion_failure_still_collects_safe_and_strict_decisions(self) -> None:
        for mode, expected_result, expected_action in (
            (self.modes[1], 0, "log_only"),
            (self.modes[2], -1, "abort_connection"),
        ):
            with self.subTest(mode=mode):
                result = self.invoke(mode, committed=1, intervention=403,
                                     scenario="completion-observation")
                self.assertEqual(result["result"], expected_result)
                self.assertEqual(result["actual"], expected_action)
                self.assertEqual(result["intervention"], 1)
                self.assertEqual(result["completions"], 1)
                self.assertEqual(result["completion_observations"], 1)
                self.assertEqual(result["eos"], 1)
                self.assertEqual(result["error"], 0)
                self.assertEqual(result["connection_error"], mode == self.modes[2])
                self.assertEqual(result["core"], 0)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
