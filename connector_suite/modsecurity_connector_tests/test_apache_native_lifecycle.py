"""Compile actual Apache native/lifecycle functions with real APR and Common.

Only native results, allocations, diagnostics and the final event emitter are
controlled. This is not physical-log persistence or a live httpd/transport run.
Apache development headers are installed by the existing test-apache job.
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
MODULE = source_path('connectors/apache/src/mod_security3.c', root=ROOT)
FUNCTIONS = (
    "msc_apache_contract_fail", "msc_apache_contract_record_decision",
    "msc_apache_contract_finish", "apache_intervention_decision_kind",
    "msc_apache_contract_record_intervention_decision", "msc_release_intervention_buffers",
    "apache_failure_phase", "apache_record_failure", "apache_store_native_intervention",
    "apache_request_context", "process_intervention", "retrieve_tx_context", "apache_fail_closed_with_cause",
    "apache_fail_closed", "apache_native_failed", "msc_module_cleanup",
    "msc_apache_init", "msc_apache_cleanup", "msc_hook_pre_config", "hook_log_transaction",
)
PREAMBLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "connectors/apache/src/mod_security3.h"
#include "msconnector/intervention.h"
#include "msconnector/rule_id.h"
#include "connectors/profile_registry.h"

static int native_result, native_status, native_disruptive, native_redirect;
static int native_calls, releases, copies, copy_failure, writes, diagnostics;
static int update_result = 1, logging_result = 1, updates, loggings;
static int recurse_intervention, recurse_logging, nested_result;
static int engine_failure, pool_failure, engine_count, cleanup_count;
static int userdata_get_failure, userdata_set_failure;
static int info_calls, callback_calls;
static char engines[4];
static void *native_url, *native_log;
static msconnector_transaction_error_class event_cause;
static enum msconnector_phase event_phase;
static request_rec *current_request;
msc_global *msc_apache;
static apr_status_t msc_module_cleanup(void *data);
static int hook_log_transaction(request_rec *r);

static uint64_t apache_contract_now_ms(void) { return 100U; }
static void fixture_log(const char *file, ...) { (void)file; ++diagnostics; }
#undef ap_log_rerror
#undef ap_log_error
#define ap_log_rerror(...) fixture_log(__VA_ARGS__)
#define ap_log_error(...) fixture_log(__VA_ARGS__)
#undef ap_get_module_config
#define ap_get_module_config(vector, module) ((void *)(vector))

msconnector_error_code apache_emit_contract_failure_event(msc_t *msr, request_rec *r,
        enum msconnector_phase phase, msconnector_transaction_error_class cause,
        int status) {
    (void)r; (void)status;
    if (!msr->contract_failure_event_emitted) {
        msr->contract_failure_event_emitted = 1;
        event_cause = cause;
        event_phase = phase;
        ++writes;
    }
    return MSCONNECTOR_ERROR_NONE;
}
void modsecurity_log_cb(void *log, const void *data) { (void)log; (void)data; }

static char *fixture_copy(const char *text) {
    size_t size = strlen(text) + 1U;
    char *value = malloc(size);
    if (value == NULL) { exit(90); }
    memcpy(value, text, size);
    return value;
}
void __real_free(void *value);
void __wrap_free(void *value) {
    if (value != NULL && (value == native_url || value == native_log)) {
        ++releases;
    }
    __real_free(value);
}
static char *fixture_pstrdup(apr_pool_t *pool, const char *text) {
    ++copies;
    return copies == copy_failure ? NULL : apr_pstrdup(pool, text);
}
static void *fixture_pcalloc(apr_pool_t *pool, apr_size_t size) {
    if (pool_failure) { return NULL; }
    void *storage = apr_palloc(pool, size);
    return storage == NULL ? NULL : memset(storage, 0, size);
}
static apr_status_t fixture_userdata_get(void **data, const char *key,
        apr_pool_t *pool) {
    return userdata_get_failure ? APR_EGENERAL : apr_pool_userdata_get(data, key, pool);
}
static apr_status_t fixture_userdata_set(const void *data, const char *key,
        apr_status_t (*cleanup)(void *), apr_pool_t *pool) {
    return userdata_set_failure ? APR_EGENERAL :
        apr_pool_userdata_set(data, key, cleanup, pool);
}
#define apr_pstrdup fixture_pstrdup
#undef apr_pcalloc
#define apr_pcalloc fixture_pcalloc
#define apr_pool_userdata_get fixture_userdata_get
#define apr_pool_userdata_set fixture_userdata_set

ModSecurity *msc_init(void) {
    if (engine_failure) { return NULL; }
    if (engine_count >= 4) { exit(91); }
    return (ModSecurity *)&engines[engine_count++];
}
void msc_cleanup(ModSecurity *engine) {
    if (engine == NULL || (msc_apache != NULL && msc_apache->modsec == engine)) {
        exit(92);
    }
    ++cleanup_count;
}
void msc_set_connector_info(ModSecurity *engine, const char *name) {
    if (engine == NULL || name == NULL) { exit(93); }
    ++info_calls;
}
void msc_set_log_cb(ModSecurity *engine, void (*callback)(void *, const void *)) {
    if (engine == NULL || callback == NULL) { exit(94); }
    ++callback_calls;
}
int msc_intervention(Transaction *transaction, ModSecurityIntervention *out) {
    ++native_calls;
    out->status = native_status;
    out->disruptive = native_disruptive;
    out->url = native_redirect ? fixture_copy("/target") : NULL;
    out->log = fixture_copy("[id \"42\"] fixture rule");
    native_url = out->url;
    native_log = out->log;
    if (recurse_intervention) {
        recurse_intervention = 0;
        nested_result = process_intervention(transaction, current_request);
    }
    return native_result;
}
int msc_update_status_code(Transaction *transaction, int status) {
    if (transaction == NULL || status != 201) { exit(95); }
    ++updates;
    return update_result;
}
int msc_process_logging(Transaction *transaction) {
    if (transaction == NULL) { exit(96); }
    ++loggings;
    if (recurse_logging) {
        recurse_logging = 0;
        nested_result = hook_log_transaction(current_request);
    }
    return logging_result;
}
'''
MAIN = r'''
#undef apr_pstrdup
#undef apr_pcalloc
#undef apr_pool_userdata_get
#undef apr_pool_userdata_set
#define REQUIRE(value) do { if (!(value)) { return 97; } } while (0)

static int prepare(request_rec *r, msc_t *msr, apr_pool_t *pool, int complete) {
    const msconnector_transaction_profile *profile = msconnector_profile_registry_find("apache");
    memset(r, 0, sizeof(*r));
    memset(msr, 0, sizeof(*msr));
    r->pool = pool;
    r->notes = apr_table_make(pool, 4);
    r->headers_out = apr_table_make(pool, 4);
    r->status = 201;
    r->connection = apr_palloc(pool, sizeof(conn_rec));
    REQUIRE(r->connection != NULL);
    memset(r->connection, 0, sizeof(conn_rec));
    msr->r = r;
    msr->t = (Transaction *)&engines[3];
    msr->native_event_phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
    REQUIRE(msconnector_transaction_contract_init(&msr->contract, profile,
        "apache-native-fixture", NULL, NULL, MSCONNECTOR_TRANSACTION_MODE_SAFE,
        100U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    msr->contract_initialized = 1;
    if (complete) {
        for (enum msconnector_phase phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
                phase <= MSCONNECTOR_PHASE_RESPONSE_BODY; ++phase) {
            REQUIRE(msconnector_transaction_contract_begin_phase(&msr->contract,
                phase, 100U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
            REQUIRE(msconnector_transaction_contract_complete_phase(&msr->contract,
                phase, 100U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        }
    } else {
        REQUIRE(msconnector_transaction_contract_begin_phase(&msr->contract,
            MSCONNECTOR_PHASE_REQUEST_HEADERS, 100U) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    }
    r->request_config = (ap_conf_vector_t *)msr;
    current_request = r;
    return 0;
}

static int check_intervention(int argc, char **argv, apr_pool_t *pool) {
    request_rec request;
    msc_t transaction;
    int result, repeated, rule;
    REQUIRE(argc == 9);
    REQUIRE(prepare(&request, &transaction, pool, 0) == 0);
    native_result = (int)strtol(argv[2], NULL, 10);
    native_status = (int)strtol(argv[3], NULL, 10);
    native_redirect = (int)strtol(argv[4], NULL, 10);
    native_disruptive = native_result != 0;
    transaction.response.committed = (int)strtol(argv[5], NULL, 10);
    copy_failure = (int)strtol(argv[6], NULL, 10);
    if (strcmp(argv[7], "prior") == 0) {
        (void)msc_apache_contract_fail(&transaction,
            MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT);
        transaction.last_intervention_log = "[id \"42\"] stale rule";
    }
    if (strcmp(argv[7], "sink") == 0) {
        transaction.intervention.event_sink_error = MSCONNECTOR_ERROR_IO;
        transaction.intervention.mandatory_event_failed = 1;
        transaction.last_intervention_log = "[id \"42\"] stale rule";
    }
    recurse_intervention = strcmp(argv[7], "recursive") == 0;
    transaction.native_event_phase = (enum msconnector_phase)strtol(argv[8], NULL, 10);
    result = process_intervention(transaction.t, &request);
    rule = result != N_INTERVENTION_STATUS &&
        msc_apache_contract_record_intervention_decision(&transaction);
    repeated = result;
    if (transaction.contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE ||
        transaction.intervention.mandatory_event_failed) {
        repeated = process_intervention(transaction.t, &request);
    }
    printf("{\"result\":%d,\"repeated\":%d,\"native_calls\":%d,\"releases\":%d,"
        "\"copies\":%d,\"writes\":%d,\"rule\":%d,\"location\":%d,\"status\":%d,"
        "\"cause\":\"%s\",\"event_cause\":\"%s\",\"event_phase\":%d,"
        "\"nested\":%d,\"collecting\":%d}\n", result, repeated, native_calls,
        releases, copies, writes, rule, apr_table_get(request.headers_out, "Location") != NULL,
        request.status, msconnector_transaction_error_class_name(transaction.contract.error_class),
        msconnector_transaction_error_class_name(event_cause), (int)event_phase,
        nested_result, transaction.intervention.collecting);
    return 0;
}

static int check_audit(int argc, char **argv, apr_pool_t *pool) {
    request_rec request;
    msc_t transaction;
    int result, repeated;
    REQUIRE(argc == 6);
    REQUIRE(prepare(&request, &transaction, pool, strcmp(argv[4], "incomplete") != 0) == 0);
    update_result = (int)strtol(argv[2], NULL, 10);
    logging_result = (int)strtol(argv[3], NULL, 10);
    if (strcmp(argv[4], "missing") == 0) { transaction.t = NULL; }
    if (strcmp(argv[4], "prior") == 0) {
        (void)msc_apache_contract_fail(&transaction,
            MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT);
    }
    recurse_logging = (int)strtol(argv[5], NULL, 10);
    result = hook_log_transaction(&request);
    repeated = hook_log_transaction(&request);
    printf("{\"result\":%d,\"repeated\":%d,\"updates\":%d,\"loggings\":%d,"
        "\"native_calls\":%d,\"status\":%d,\"writes\":%d,\"nested\":%d,"
        "\"cause\":\"%s\",\"event_cause\":\"%s\"}\n", result, repeated, updates,
        loggings, native_calls, request.status, writes, nested_result,
        msconnector_transaction_error_class_name(transaction.contract.error_class),
        msconnector_transaction_error_class_name(event_cause));
    return 0;
}

static int check_init(int argc, char **argv, apr_pool_t *pool) {
    msc_global *first, *second;
    int result, repeated;
    REQUIRE(argc == 3);
    if (strcmp(argv[2], "generations") == 0) {
        REQUIRE(msc_apache_init(pool) == 0);
        first = msc_apache;
        REQUIRE(msc_apache_init(pool) == 0);
        second = msc_apache;
        REQUIRE(msc_module_cleanup(first) == APR_SUCCESS);
        REQUIRE(msc_apache == second && second->modsec != NULL);
        REQUIRE(msc_module_cleanup(first) == APR_SUCCESS && cleanup_count == 1);
        REQUIRE(msc_apache_cleanup() == 0 && cleanup_count == 2);
        REQUIRE(msc_apache_cleanup() == 0 && cleanup_count == 2);
        puts("{\"cleanup_count\":2}");
        return 0;
    }
    engine_failure = strcmp(argv[2], "engine") == 0;
    pool_failure = strcmp(argv[2], "pool") == 0;
    userdata_get_failure = strcmp(argv[2], "get") == 0;
    userdata_set_failure = strcmp(argv[2], "set") == 0;
    result = msc_hook_pre_config(pool, pool, pool);
    repeated = msc_hook_pre_config(pool, pool, pool);
    printf("{\"result\":%d,\"repeated\":%d,\"info\":%d,\"callbacks\":%d,"
        "\"engine_count\":%d,\"cleanup_count\":%d,\"available\":%d}\n",
        result, repeated, info_calls, callback_calls, engine_count, cleanup_count,
        msc_apache != NULL && msc_apache->modsec != NULL);
    return 0;
}

int main(int argc, char **argv) {
    apr_pool_t *pool = NULL;
    int result;
    REQUIRE(argc >= 2);
    REQUIRE(apr_initialize() == APR_SUCCESS);
    REQUIRE(apr_pool_create(&pool, NULL) == APR_SUCCESS);
    if (strcmp(argv[1], "intervention") == 0) {
        result = check_intervention(argc, argv, pool);
    } else if (strcmp(argv[1], "audit") == 0) {
        result = check_audit(argc, argv, pool);
    } else if (strcmp(argv[1], "init") == 0) {
        result = check_init(argc, argv, pool);
    } else {
        request_rec request;
        msc_t transaction;
        REQUIRE(prepare(&request, &transaction, pool, 0) == 0);
        result = apache_fail_closed(&request, "fixture host failure") ==
            HTTP_INTERNAL_SERVER_ERROR ? 0 : 98;
        printf("{\"cause\":\"%s\"}\n",
            msconnector_transaction_error_class_name(transaction.contract.error_class));
    }
    apr_pool_destroy(pool);
    apr_terminate();
    return result;
}
'''


class ApacheNativeLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        apxs = shutil.which("apxs") or shutil.which("apxs2")
        apr = shutil.which("apr-1-config")
        if not compiler or shutil.which(compiler[0]) is None or not apxs or not apr:
            raise RuntimeError("Apache/APR development headers and a C compiler are required")
        def flags(command: list[str]) -> list[str]:
            output = subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)
            return shlex.split(output.stdout)
        include = subprocess.run([apxs, "-q", "INCLUDEDIR"], check=True,
                                 capture_output=True, text=True, timeout=10).stdout.strip()
        temporary = tempfile.TemporaryDirectory(prefix="apache-native-lifecycle-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        source = MODULE.read_text(encoding="utf-8")
        definitions = "\n\n".join(function_definition(source, name) for name in FUNCTIONS)
        cls.binary = directory / "native-lifecycle"
        common_sources = ("transaction_state.c", "decision_action.c", "intervention.c",
                          "block_statuses.c", "http_status.c", "rule_id.c")
        base = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                           "-ffunction-sections", "-fdata-sections", "-I", include,
                           "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT))]
        base += flags([apr, "--includes"])
        links = [str(source_path('common/src', root=ROOT) / name) for name in common_sources]
        links += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-Wl,--gc-sections", "-Wl,--wrap=free"]
        links += flags([apr, "--link-ld", "--libs"])
        for control in (False, True):
            body = definitions
            if control:
                marker = "msc_release_intervention_buffers(&intervention);"
                if body.count(marker) != 1:
                    raise AssertionError("unique native cleanup marker is required")
                body = body.replace(marker, "if (native_result == 0) { return result; }\n    " + marker)
            fixture = directory / ("control.c" if control else "actual.c")
            binary = directory / ("control" if control else "native-lifecycle")
            fixture.write_text(PREAMBLE + body + MAIN, encoding="utf-8")
            compiled = subprocess.run(base + [str(fixture)] + links + ["-o", str(binary)],
                                      capture_output=True, text=True, timeout=90, check=False)
            if compiled.returncode:
                raise AssertionError("Apache native fixture failed to compile:\n" + compiled.stderr[-8000:])
        cls.control = directory / "control"

    def run_case(self, *arguments, control=False) -> dict:
        binary = self.control if control else self.binary
        result = subprocess.run([str(binary), *map(str, arguments)], capture_output=True,
                                text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        return json.loads(result.stdout)

    def intervention(self, native=1, status=403, redirect=0, committed=0,
                     allocation=0, state="normal", phase=2, control=False) -> dict:
        return self.run_case("intervention", native, status, redirect, committed,
                             allocation, state, phase, control=control)

    def test_zero_result_releases_native_buffers_without_a_rule(self):
        result = self.intervention(native=0, redirect=1)
        self.assertEqual(result["result"], 200)
        self.assertEqual(result["releases"], 2)
        self.assertEqual(result["copies"], 0)
        self.assertEqual(result["rule"], 0)
        self.assertEqual(result["location"], 0)

    def test_compiled_original_zero_cleanup_control_exposes_leak(self):
        result = self.intervention(native=0, redirect=1, control=True)
        self.assertEqual(result["result"], 200)
        self.assertEqual(result["releases"], 0)

    def test_invalid_native_values_never_become_rules_or_redirects(self):
        for native in (-2, -1, 2, 17):
            for committed in (0, 1):
                with self.subTest(native=native, committed=committed):
                    result = self.intervention(native=native, status=302,
                                               redirect=1, committed=committed)
                    self.assertEqual(result["result"], 500)
                    self.assertEqual(result["repeated"], 500)
                    self.assertEqual(result["cause"], "invalid_engine_response")
                    self.assertEqual(result["event_cause"], result["cause"])
                    self.assertEqual(result["native_calls"], 1)
                    self.assertEqual(result["releases"], 2)
                    self.assertEqual(result["rule"], 0)
                    self.assertEqual(result["location"], 0)
                    self.assertEqual(result["status"], 201)
                    self.assertEqual(result["writes"], 1)

    def test_real_rule_status_500_is_not_a_technical_failure(self):
        result = self.intervention(status=500)
        self.assertEqual(result["result"], 500)
        self.assertEqual(result["rule"], 1)
        self.assertEqual(result["writes"], 0)
        self.assertEqual(result["releases"], 1)

    def test_redirect_copy_is_checked_and_never_mutates_committed_headers(self):
        for committed in (0, 1):
            with self.subTest(committed=committed):
                result = self.intervention(status=307, redirect=1, committed=committed)
                self.assertEqual(result["result"], 307)
                self.assertEqual(result["rule"], 1)
                self.assertEqual(result["location"], 1 - committed)
                self.assertEqual(result["releases"], 2)
                self.assertEqual(result["status"], 201)

    def test_failed_pool_copies_are_terminal_and_release_native_values(self):
        for allocation in (1, 2):
            with self.subTest(allocation=allocation):
                result = self.intervention(status=302, redirect=1, allocation=allocation)
                self.assertEqual(result["result"], 500)
                self.assertEqual(result["cause"], "connector_error")
                self.assertEqual(result["location"], 0)
                self.assertEqual(result["releases"], 2)
                self.assertEqual(result["rule"], 0)
                self.assertEqual(result["native_calls"], 1)

    def test_prior_technical_cause_cannot_borrow_stale_rule_or_enter_native(self):
        result = self.intervention(state="prior")
        self.assertEqual(result["cause"], "engine_timeout")
        self.assertEqual(result["event_cause"], "engine_timeout")
        self.assertEqual(result["native_calls"], 0)
        self.assertEqual(result["rule"], 0)
        self.assertEqual(result["writes"], 1)

    def test_failed_mandatory_sink_never_reenters_native_or_stale_rule(self):
        result = self.intervention(state="sink", status=302, redirect=1)
        self.assertEqual(result["result"], 500)
        self.assertEqual(result["repeated"], 500)
        self.assertEqual(result["native_calls"], 0)
        self.assertEqual(result["rule"], 0)
        self.assertEqual(result["writes"], 0)
        self.assertEqual(result["location"], 0)

    def test_intervention_callback_reentry_is_bounded_and_terminal(self):
        result = self.intervention(state="recursive", redirect=1)
        self.assertEqual(result["nested"], 500)
        self.assertEqual(result["result"], 500)
        self.assertEqual(result["native_calls"], 1)
        self.assertEqual(result["releases"], 2)
        self.assertEqual(result["collecting"], 0)
        self.assertEqual(result["rule"], 0)

    def test_invalid_intervention_retains_all_business_phase_correlations(self):
        for phase in (2, 3, 4, 5):
            with self.subTest(phase=phase):
                result = self.intervention(native=-1, phase=phase)
                self.assertEqual(result["event_phase"], phase)

    def test_audit_success_is_one_attempt_without_intervention_collection(self):
        result = self.run_case("audit", 1, 1, "complete", 0)
        self.assertEqual(result["result"], -1)
        self.assertEqual(result["repeated"], -1)
        self.assertEqual(result["updates"], 1)
        self.assertEqual(result["loggings"], 1)
        self.assertEqual(result["native_calls"], 0)
        self.assertEqual(result["status"], 201)

    def test_audit_failures_are_sticky_and_do_not_change_http(self):
        for update, logging in ((0, 1), (-1, 1), (2, 1), (1, 0), (1, -1), (1, 2)):
            with self.subTest(update=update, logging=logging):
                result = self.run_case("audit", update, logging, "complete", 0)
                self.assertEqual(result["result"], 500)
                self.assertEqual(result["repeated"], 500)
                self.assertEqual(result["updates"], 1)
                self.assertEqual(result["loggings"], int(update == 1))
                self.assertEqual(result["cause"], "invalid_engine_response")
                self.assertEqual(result["status"], 201)
                self.assertEqual(result["native_calls"], 0)

    def test_missing_audit_transaction_never_reaches_native(self):
        result = self.run_case("audit", 1, 1, "missing", 0)
        self.assertEqual(result["result"], 500)
        self.assertEqual(result["repeated"], 500)
        self.assertEqual(result["updates"], 0)
        self.assertEqual(result["loggings"], 0)
        self.assertEqual(result["cause"], "engine_unavailable")

    def test_successful_native_audit_cannot_repair_failed_contract_finish(self):
        result = self.run_case("audit", 1, 1, "incomplete", 0)
        self.assertEqual(result["result"], 500)
        self.assertEqual(result["repeated"], 500)
        self.assertEqual(result["updates"], 1)
        self.assertEqual(result["loggings"], 1)
        self.assertEqual(result["writes"], 1)

    def test_audit_native_failure_preserves_prior_cause(self):
        result = self.run_case("audit", 1, 0, "prior", 0)
        self.assertEqual(result["result"], 500)
        self.assertEqual(result["cause"], "engine_timeout")
        self.assertEqual(result["event_cause"], "engine_timeout")

    def test_audit_callback_cannot_invoke_native_logging_twice(self):
        result = self.run_case("audit", 1, 1, "complete", 1)
        self.assertEqual(result["loggings"], 1)
        self.assertEqual(result["updates"], 1)
        self.assertEqual(result["native_calls"], 0)

    def test_unavailable_engine_or_pool_never_reaches_native_configuration(self):
        for failure in ("engine", "pool", "get"):
            with self.subTest(failure=failure):
                result = self.run_case("init", failure)
                self.assertEqual(result["result"], 500)
                self.assertEqual(result["repeated"], 500)
                self.assertEqual(result["info"], 0)
                self.assertEqual(result["callbacks"], 0)
                self.assertEqual(result["available"], 0)

    def test_failed_initialization_bookkeeping_never_marks_success(self):
        result = self.run_case("init", "set")
        self.assertEqual(result["result"], 500)
        self.assertEqual(result["repeated"], 500)
        self.assertEqual(result["cleanup_count"], 2)
        self.assertEqual(result["available"], 0)

    def test_successful_initialization_is_not_repeated(self):
        result = self.run_case("init", "success")
        self.assertEqual(result["result"], 0)
        self.assertEqual(result["repeated"], 0)
        self.assertEqual(result["engine_count"], 1)
        self.assertEqual(result["callbacks"], 1)

    def test_cleanup_is_once_and_bound_to_its_configuration_generation(self):
        self.assertEqual(self.run_case("init", "generations")["cleanup_count"], 2)

    def test_host_failure_keeps_its_distinct_cause(self):
        self.assertEqual(self.run_case("host")["cause"], "connector_error")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
