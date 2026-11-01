"""Execute Apache filter phase boundaries and the real Common JSON producer.

APR and Common are real; native results, diagnostic/file sinks and host calls
are controlled. This proves code/API behavior, not live httpd transport.
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
FILTERS = source_path('connectors/apache/src/msc_filters.c', root=ROOT)
MODULE = source_path('connectors/apache/src/mod_security3.c', root=ROOT)
FUNCTIONS = (
    "apache_intervention_message_id", "apache_intervention_content_type",
    "apache_intervention_body_bytes_seen", "apache_intervention_body_bytes_inspected",
    "apache_intervention_set_http", "apache_event_sink_result", "apache_intervention_write_event",
    "apache_log_intervention_event", "apache_contract_failure_event_name",
    "apache_contract_failure_reason", "apache_emit_contract_failure_event_with_action",
    "apache_emit_contract_failure_event", "msc_finalize_request_body",
    "apache_add_response_headers", "apache_output_filter_process_headers",
    "apache_phase4_response_committed", "apache_phase4_abort_response_connection",
    "apache_phase4_fail_closed", "apache_phase4_finish_response_body",
    "apache_phase4_release_response_brigade",
)
PREAMBLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "connectors/apache/src/msc_filters.h"
#include "msconnector/event.h"
#include "msconnector/event_jsonl.h"
#include "msconnector/native_result.h"
#include "msconnector/rule_id.h"
#include "connectors/profile_registry.h"

static int native_result = 1, native_calls, host_calls, writes, closes, discard_calls;
static char captured[4096];
static uint64_t apache_contract_now_ms(void) { return 100U; }
static void diagnostic(const char *file, ...) { (void)file; }
#undef ap_log_rerror
#define ap_log_rerror(...) diagnostic(__VA_ARGS__)
#undef ap_get_module_config
#define ap_get_module_config(vector, module) (vector)
static const char *apache_request_content_type(request_rec *r) { (void)r; return "text/plain"; }
static const char *apache_response_content_type(request_rec *r) { (void)r; return "text/plain"; }
static const char *apache_phase4_mode_name(enum msconnector_phase4_mode mode) { (void)mode; return "abort"; }
static apr_status_t apache_open_event_file(apr_file_t **file, const char *path, apr_pool_t *pool) {
    (void)path; (void)pool; *file = (apr_file_t *)captured; return APR_SUCCESS;
}
static apr_status_t fixture_write_full(apr_file_t *file, const void *data,
    apr_size_t size, apr_size_t *written) {
    (void)file; ++writes;
    if (size >= sizeof(captured)) return APR_EGENERAL;
    memcpy(captured, data, size); captured[size] = '\0'; *written = size;
    return APR_SUCCESS;
}
static apr_status_t fixture_close(apr_file_t *file) { (void)file; ++closes; return APR_SUCCESS; }
#define apr_file_write_full fixture_write_full
#define apr_file_close fixture_close
msconnector_error_code apache_emit_contract_failure_event(msc_t *, request_rec *, enum msconnector_phase,
    msconnector_transaction_error_class, int);
static msconnector_error_code apache_log_intervention_event(msc_t *, request_rec *, const apache_intervention_event_input *);
int process_intervention(Transaction *t, request_rec *r) { (void)t; (void)r; return N_INTERVENTION_STATUS; }
int msc_apache_contract_record_intervention_decision(msc_t *msr) { (void)msr; return 1; }
const char *msc_apache_contract_intervention_action(const msc_t *msr) { (void)msr; return "deny"; }
int msc_process_request_body(Transaction *t) { (void)t; ++native_calls; return native_result; }
int msc_process_response_body(Transaction *t) { (void)t; ++native_calls; return native_result; }
int msc_process_response_headers(Transaction *t, int status, const char *protocol) {
    (void)t; (void)status; (void)protocol; ++native_calls; return native_result;
}
int msc_add_response_header(Transaction *t, const unsigned char *key, const unsigned char *value) {
    (void)t; (void)key; (void)value; return 1;
}
static int apache_contract_record_response_metadata(msc_t *msr, request_rec *r,
    const char *type) { (void)msr; (void)r; (void)type; return 1; }
static int apache_phase3_snapshot_response_state(msc_t *msr, request_rec *r) {
    msr->response_status_snapshot = r->status; msr->response_headers_snapshot_taken = 1; return 1;
}
static msconnector_error_code apache_phase3_log_event(msc_t *msr, request_rec *r,
    const char *wanted, const char *actual, int status) {
    (void)msr; (void)r; (void)wanted; (void)actual; (void)status;
    return MSCONNECTOR_ERROR_NONE;
}
static void fixture_remove(ap_filter_t *f) { (void)f; }
#define ap_remove_output_filter fixture_remove
void msc_discard_response_brigade(msc_t *msr) { (void)msr; ++discard_calls; }
static apr_status_t apache_send_precommit_terminal_error(msc_t *msr, ap_filter_t *f,
    apr_bucket_brigade *brigade, int status) {
    (void)msr; (void)f; (void)brigade; (void)status; ++host_calls; return APR_EGENERAL;
}
static int apache_phase4_brigade_starts_response(const apr_bucket_brigade *brigade) {
    (void)brigade; return 1;
}
static int apache_phase3_restore_response_state(msc_t *msr, request_rec *r) {
    (void)msr; (void)r; return 1;
}
int msc_apache_contract_mark_response_committed(msc_t *msr) { (void)msr; return 1; }
static apr_status_t fixture_pass(ap_filter_t *f, apr_bucket_brigade *brigade) {
    (void)f; (void)brigade; ++host_calls; return APR_EGENERAL;
}
#define ap_pass_brigade fixture_pass
'''
MAIN = r'''
int main(int argc, char **argv) {
    apr_pool_t *pool = NULL;
    request_rec r;
    conn_rec connection;
    ap_filter_t filter;
    msc_t msr;
    msc_conf_t conf;
    int phase, result = 0, repeated = 0, intervention = 0;
    if (argc != 5 || apr_initialize() != APR_SUCCESS || apr_pool_create(&pool, NULL) != APR_SUCCESS) return 90;
    memset(&r, 0, sizeof(r)); memset(&msr, 0, sizeof(msr)); memset(&connection, 0, sizeof(connection));
    memset(&filter, 0, sizeof(filter)); memset(&conf, 0, sizeof(conf));
    phase = atoi(argv[2]); native_result = atoi(argv[3]);
    r.pool = pool; r.status = 201; r.method = "GET"; r.unparsed_uri = "/fixture";
    r.connection = atoi(argv[4]) == 2 ? NULL : &connection;
    r.per_dir_config = (struct ap_conf_vector_t *)&conf;
    r.headers_out = apr_table_make(pool, 2); r.err_headers_out = apr_table_make(pool, 2);
    conf.common_config.phase4_log_path = "/controlled";
    filter.r = &r; filter.ctx = &msr; msr.r = &r; msr.t = (Transaction *)&msr;
    msr.event_transaction_id = "apache-filter-fixture";
    if (msconnector_transaction_contract_init(&msr.contract,
        msconnector_profile_registry_find("apache"), msr.event_transaction_id, NULL, NULL,
        MSCONNECTOR_TRANSACTION_MODE_SAFE, 100U) != MSCONNECTOR_TRANSACTION_TRANSITION_OK) return 91;
    msr.contract_initialized = 1;
    for (enum msconnector_phase p = MSCONNECTOR_PHASE_REQUEST_HEADERS; (int)p < phase; ++p) {
        if (!msc_apache_contract_begin(&msr, p) || !msc_apache_contract_complete(&msr, p)) return 92;
    }
    if (strcmp(argv[1], "rule") == 0) {
        apache_intervention_event_input input = {0};
        msr.last_intervention_log = "[id \"42\"] real rule";
        msr.last_intervention_status = 500;
        input.event_name = "phase2_intervention"; input.phase = phase;
        input.wanted = "deny"; input.actual = "deny"; input.reason = "fixture rule";
        input.original_status = 201;
        apache_log_intervention_event(&msr, &r, &input);
    } else if (strcmp(argv[1], "release") == 0) {
        ap_filter_t next = {0};
        apr_bucket_alloc_t *allocator = apr_bucket_alloc_create(pool);
        apr_bucket_brigade *brigade = apr_brigade_create(pool, allocator);
        filter.next = &next;
        result = apache_phase4_release_response_brigade(&msr, &filter, brigade, 0);
    } else if (strcmp(argv[1], "event") == 0 || strcmp(argv[1], "event_rephase") == 0) {
        msr.last_intervention_log = "[id \"42\"] stale rule";
        if (strcmp(argv[1], "event_rephase") == 0 && !msc_apache_contract_begin(&msr, phase)) return 93;
        (void)msc_apache_contract_fail(&msr, (msconnector_transaction_error_class)native_result);
        if (strcmp(argv[1], "event_rephase") == 0) phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
        apache_emit_contract_failure_event(&msr, &r, phase,
            MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR, 500);
        apache_emit_contract_failure_event(&msr, &r,
            strcmp(argv[1], "event_rephase") == 0 ? MSCONNECTOR_PHASE_REQUEST_HEADERS : phase,
            MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR, 500);
    } else if (strcmp(argv[1], "abort") == 0 || strcmp(argv[1], "abort_limit") == 0) {
        if (strcmp(argv[1], "abort_limit") == 0) {
            (void)msc_apache_contract_fail(&msr, (msconnector_transaction_error_class)native_result);
            msr.response_body_truncated = 1;
        }
        msr.response.committed = 1;
        result = apache_phase4_fail_closed(&msr, &filter, NULL, "fixture");
    } else {
        if (strcmp(argv[1], "prior") == 0) {
            (void)msc_apache_contract_fail(&msr, MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT);
            msr.request_body_processed = 1; msr.response_headers_processed = 1;
            msr.response_body_processed = 1;
        }
        for (int attempt = 0; attempt < (native_result == 1 ? 1 : 2); ++attempt) {
            if (phase == MSCONNECTOR_PHASE_REQUEST_BODY) result = msc_finalize_request_body(&msr, &r);
            else if (phase == MSCONNECTOR_PHASE_RESPONSE_HEADERS)
                result = apache_output_filter_process_headers(&msr, &r, &filter, NULL);
            else result = apache_phase4_finish_response_body(&msr, &filter, NULL, &intervention);
            if (attempt == 0) repeated = result;
        }
    }
    printf("{\"result\":%d,\"first\":%d,\"native_calls\":%d,\"host_calls\":%d,"
        "\"writes\":%d,\"closes\":%d,\"aborted\":%d,\"processed\":%d,\"cause\":\"%s\"}\n",
        result, repeated, native_calls, host_calls, writes, closes, connection.aborted,
        phase == MSCONNECTOR_PHASE_REQUEST_BODY ? msr.request_body_processed :
        phase == MSCONNECTOR_PHASE_RESPONSE_HEADERS ? msr.response_headers_processed : msr.response_body_processed,
        msconnector_transaction_error_class_name(msr.contract.error_class));
    if (writes) fputs(captured, stdout);
    apr_pool_destroy(pool); apr_terminate(); return 0;
}
'''


class ApacheI09FilterEventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        apxs = shutil.which("apxs") or shutil.which("apxs2")
        apr = shutil.which("apr-1-config")
        if not apxs or not apr or not shutil.which("cc"):
            raise RuntimeError("Apache/APR headers and compiler are required")
        def flags(command):
            return shlex.split(subprocess.run(command, check=True, capture_output=True,
                                              text=True, timeout=10).stdout)
        include = subprocess.run([apxs, "-q", "INCLUDEDIR"], check=True,
                                 capture_output=True, text=True, timeout=10).stdout.strip()
        temporary = tempfile.TemporaryDirectory(prefix="apache-i09-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        filters = FILTERS.read_text(encoding="utf-8")
        module = MODULE.read_text(encoding="utf-8")
        bodies = "\n\n".join(function_definition(module, name) for name in
            ("msc_apache_contract_fail", "msc_apache_contract_begin", "msc_apache_contract_complete"))
        bodies += "\n\n" + "\n\n".join(function_definition(filters, name) for name in FUNCTIONS)
        fixture = directory / "filters.c"
        fixture.write_text(PREAMBLE + bodies + MAIN, encoding="utf-8")
        cls.binary = directory / "filters"
        sources = ("transaction_state.c", "decision_action.c", "event.c", "event_jsonl.c",
                   "http_status.c", "rule_id.c", "json_escape.c", "status.c")
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread", "-ffunction-sections",
            "-fdata-sections", "-I", include, "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT))]
        command += flags([apr, "--includes"]) + [str(fixture)]
        command += [str(source_path('common/src', root=ROOT) / name) for name in sources]
        command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-Wl,--gc-sections"]
        command += flags([apr, "--link-ld", "--libs"]) + ["-laprutil-1", "-o", str(cls.binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=90)
        if compiled.returncode:
            raise AssertionError("Apache filter fixture failed to compile:\n" + compiled.stderr[-8000:])

    def run_case(self, mode, phase=3, native=1, connection=0):
        result = subprocess.run([str(self.binary), mode, str(phase), str(native), str(connection)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        return json.loads(lines[0]), json.loads(lines[1]) if len(lines) > 1 else None

    def test_phase_native_success_completes(self):
        for phase in (3, 4, 5):
            with self.subTest(phase=phase):
                result, event = self.run_case("phase", phase)
                self.assertEqual(result["processed"], 1)
                self.assertEqual(result["cause"], "none")
                self.assertIsNone(event)

    def test_phase_native_failure_is_terminal_without_completion_or_second_event(self):
        for phase in (3, 4, 5):
            for native in (-1, 0, 2, 17):
                with self.subTest(phase=phase, native=native):
                    result, event = self.run_case("phase", phase, native)
                    self.assertEqual(result["native_calls"], 1)
                    self.assertEqual(result["processed"], 0)
                    self.assertEqual(result["cause"], "invalid_engine_response")
                    self.assertEqual(result["writes"], 1)
                    self.assertEqual(result["closes"], 1)
                    self.assertLessEqual(result["host_calls"], 1)
                    self.assertEqual(event["message_id"], "MSCONN_EVENT_INVALID_ENGINE_RESPONSE")
                    self.assertEqual(event["status"], "error")
                    self.assertEqual(event["actual_action"], "")
                    self.assertEqual(event["rule_id"], "")
                    self.assertEqual(event["visible_http_status"], 0)

    def test_producer_preserves_prior_cause_and_empty_unobserved_host_action(self):
        # Error enum values bind to the checked-in public contract.
        for cause, name in ((4, "engine_timeout"), (5, "engine_unavailable"),
                            (6, "invalid_engine_response"), (8, "protocol_error"),
                            (7, "connector_error"), (9, "client_cancel"), (10, "upstream_disconnect")):
            with self.subTest(cause=name):
                result, event = self.run_case("event", 3, cause)
                self.assertEqual(result["writes"], 1)
                self.assertEqual(event["event"], name)
                self.assertEqual(event["status"], "error")
                self.assertEqual(event["requested_action"], "error")
                self.assertEqual(event["actual_action"], "")
                self.assertEqual(event["rule_id"], "")
                self.assertEqual(event["visible_http_status"], 0)

    def test_completed_phase_shortcut_cannot_turn_prior_failure_into_success(self):
        for phase in (3, 4, 5):
            with self.subTest(phase=phase):
                result, event = self.run_case("prior", phase)
                self.assertNotIn(result["result"], (0, 200))
                self.assertEqual(result["cause"], "engine_timeout")
                self.assertEqual(result["native_calls"], 0)
                self.assertEqual(result["host_calls"], 0)
                self.assertIsNone(event)

    def test_first_error_phase_survives_a_later_callback_phase(self):
        for phase, expected in ((3, "request_body"), (4, "response_headers"), (5, "response_body")):
            with self.subTest(phase=expected):
                result, event = self.run_case("event_rephase", phase, 4)
                self.assertEqual(result["writes"], 1)
                self.assertEqual(event["phase"], expected)
                self.assertEqual(event["event"], "engine_timeout")

    def test_abort_is_claimed_only_after_observed_connection_control(self):
        for connection in (0, 2):
            with self.subTest(connection=connection):
                result, event = self.run_case("abort", 5, 1, connection)
                self.assertEqual(result["aborted"], int(connection == 0))
                self.assertEqual(event["actual_action"],
                                 "abort_connection" if connection == 0 else "")

    def test_downstream_release_failure_does_not_claim_failed_connection_control(self):
        for connection in (0, 2):
            with self.subTest(connection=connection):
                result, event = self.run_case("release", 5, 1, connection)
                self.assertEqual(result["host_calls"], 1)
                self.assertEqual(result["cause"], "connector_error")
                self.assertEqual(event["actual_action"],
                                 "abort_connection" if connection == 0 else "")
                self.assertEqual(event["connection_aborted"], connection == 0)

    def test_body_limit_remains_a_policy_cause(self):
        result, event = self.run_case("event", 3, 2)
        self.assertEqual(result["cause"], "body_limit")
        self.assertEqual(event["message_id"], "MSCONN_EVENT_BODY_LIMIT")
        self.assertEqual(event["status"], "blocked")
        self.assertEqual(event["requested_action"], "deny")
        self.assertEqual(event["actual_action"], "")
        self.assertEqual(event["rule_id"], "")

    def test_truncation_cannot_overwrite_an_earlier_technical_cause(self):
        for cause, expected in ((4, "engine_timeout"), (7, "connector_error")):
            with self.subTest(cause=expected):
                result, event = self.run_case("abort_limit", 5, cause)
                self.assertEqual(result["cause"], expected)
                self.assertEqual(event["event"], expected)
                self.assertEqual(event["status"], "error")

    def test_rule_status_500_retains_real_rule_semantics(self):
        result, event = self.run_case("rule")
        self.assertEqual(result["cause"], "none")
        self.assertEqual(event["message_id"], "MSCONN_EVENT_REQUEST_BLOCKED")
        self.assertEqual(event["status"], "blocked")
        self.assertEqual(event["rule_id"], "42")
        self.assertEqual(event["actual_action"], "deny")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
