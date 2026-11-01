"""Compile productive Apache sink/callers with real APR and OS write faults.

Host core error rendering and native engine calls are controlled boundaries;
this is physical APR persistence evidence, not a live httpd/client run.
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
FILTER_FUNCTIONS = (
    "apache_open_event_file", "apache_response_content_type",
    "apache_request_content_type", "apache_phase4_mode_name",
    "apache_phase4_actual_action", "apache_intervention_message_id",
    "apache_intervention_content_type", "apache_intervention_body_bytes_seen",
    "apache_intervention_body_bytes_inspected", "apache_intervention_set_http",
    "apache_event_sink_result", "apache_intervention_write_event",
    "apache_log_intervention_event", "apache_emit_intervention_event",
    "apache_contract_failure_event_name", "apache_contract_failure_reason",
    "apache_emit_contract_failure_event_with_action", "apache_emit_contract_failure_event",
    "apache_log_rule_match_event", "apache_phase4_log_event", "apache_phase3_log_event",
    "apache_phase4_response_committed", "apache_phase4_abort_response_connection",
    "apache_phase4_fail_closed", "apache_phase4_handle_intervention",
    "msc_finalize_request_body", "apache_output_filter_process_headers",
    "apache_input_filter_process_bucket", "apache_phase4_append_bucket",
    "apache_phase4_finish_response_body",
)
MODULE_FUNCTIONS = (
    "msc_apache_contract_fail", "msc_apache_contract_finish",
    "apache_intervention_decision_kind", "msc_apache_contract_intervention_action",
    "apache_emit_phase1_intervention_event",
)
PREAMBLE = r'''
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <apr_portable.h>
#include "connectors/apache/src/mod_security3.h"
#include "msconnector/event_jsonl.h"
#include "msconnector/late_intervention.h"
#include "msconnector/rule_id.h"
#include "msconnector/native_result.h"
#include "connectors/profile_registry.h"
static int fault, opens, writes, closes, diagnostics, responses, response_status;
static int native_calls;
static uint64_t apache_contract_now_ms(void) { return 100U; }
static void fixture_log(const char *file, ...) { (void)file; ++diagnostics; }
#undef ap_log_rerror
#define ap_log_rerror(...) fixture_log(__VA_ARGS__)
#undef ap_get_module_config
#define ap_get_module_config(vector, module) (vector)

int __real_msconnector_open_private_event_file(const char *, int *);
int __wrap_msconnector_open_private_event_file(const char *path, int *fd) {
    ++opens;
    return __real_msconnector_open_private_event_file(path, fd);
}
apr_status_t __real_apr_file_write_full(apr_file_t *, const void *, apr_size_t, apr_size_t *);
apr_status_t __wrap_apr_file_write_full(apr_file_t *file, const void *data,
        apr_size_t size, apr_size_t *written) {
    apr_os_file_t descriptor;
    ++writes;
    if (fault == 1 || fault == 2) {
        int bad = open(fault == 1 ? "/dev/full" : "/dev/null",
            fault == 1 ? O_WRONLY : O_RDONLY);
        if (bad < 0 || apr_os_file_get(&descriptor, file) != APR_SUCCESS ||
            dup2(bad, descriptor) < 0) { exit(91); }
        close(bad);
    }
    if (fault == 4) {
        struct rlimit limit = {100U, 100U};
        signal(SIGXFSZ, SIG_IGN);
        if (setrlimit(RLIMIT_FSIZE, &limit) != 0) { exit(92); }
    }
    return __real_apr_file_write_full(file, data, size, written);
}
apr_status_t __real_apr_file_close(apr_file_t *);
apr_status_t __wrap_apr_file_close(apr_file_t *file) {
    apr_status_t status;
    ++closes;
    status = __real_apr_file_close(file);
    /* POSIX close errors cannot be induced safely/portably after successful
     * write on a private regular file. Preserve actual cleanup, return fault. */
    return fault == 3 ? APR_EGENERAL : status;
}
void ap_remove_input_filter(ap_filter_t *filter) { (void)filter; }
static apr_status_t apache_input_filter_terminal_error(msc_t *msr, request_rec *r, int status) {
    (void)msr; (void)r; (void)status; return APR_EGENERAL;
}
int msc_apache_contract_record_body(msc_t *msr, int response, size_t size) {
    (void)msr; (void)response; (void)size; return 1;
}
int msc_append_request_body(Transaction *transaction, const unsigned char *body, size_t size) {
    (void)transaction; (void)body; (void)size; return 1;
}
int msc_append_response_body(Transaction *transaction, const unsigned char *body, size_t size) {
    (void)transaction; (void)body; (void)size; return 1;
}
static void msc_discard_response_brigade(msc_t *msr) { (void)msr; }
void ap_remove_output_filter(ap_filter_t *filter) { (void)filter; }
static apr_status_t apache_send_precommit_terminal_error(msc_t *msr,
        ap_filter_t *filter, apr_bucket_brigade *brigade, int status) {
    (void)msr; (void)brigade; ++responses;
    response_status = status; filter->r->status = status;
    return AP_FILTER_ERROR;
}
static int apache_contract_record_response_metadata(msc_t *msr,
        request_rec *r, const char *type) {
    (void)msr; (void)r; (void)type; return 1;
}
static int apache_add_response_headers(msc_t *msr, apr_table_t *headers) {
    (void)msr; (void)headers; return 1;
}
static int apache_phase3_snapshot_response_state(msc_t *msr, request_rec *r) {
    (void)msr; (void)r; return 1;
}
int msc_add_response_header(Transaction *transaction,
        const unsigned char *name, const unsigned char *value) {
    (void)transaction; (void)name; (void)value; return 1;
}
int msc_process_response_headers(Transaction *transaction, int status, const char *protocol) {
    (void)transaction; (void)status; (void)protocol; ++native_calls; return 1;
}
int msc_apache_contract_begin(msc_t *msr, enum msconnector_phase phase) {
    (void)msr; (void)phase; return 1;
}
int msc_apache_contract_complete(msc_t *msr, enum msconnector_phase phase) {
    (void)msr; (void)phase; return 1;
}
static int eos_diagnostic;
int msc_process_request_body(Transaction *transaction) {
    msc_t *owner = (msc_t *)transaction;
    ++native_calls;
    if (eos_diagnostic) {
        (void)apache_log_rule_match_event(owner, owner->r,
            MSCONNECTOR_PHASE_REQUEST_BODY, "1234");
    }
    return 1;
}
int msc_process_response_body(Transaction *transaction) {
    msc_t *owner = (msc_t *)transaction;
    ++native_calls;
    if (eos_diagnostic) {
        (void)apache_log_rule_match_event(owner, owner->r,
            MSCONNECTOR_PHASE_RESPONSE_BODY, "1234");
    }
    return 1;
}
int process_intervention(Transaction *transaction, request_rec *r) {
    (void)transaction; (void)r; return HTTP_FORBIDDEN;
}
int msc_apache_contract_record_intervention_decision(msc_t *msr) {
    (void)msr; return 1;
}
'''
MAIN = r'''
int main(int argc, char **argv) {
    apr_pool_t *pool;
    msc_t msr = {0};
    request_rec request = {0};
    conn_rec connection = {0};
    msc_conf_t conf = {0};
    ap_filter_t filter = {0};
    msconnector_event event;
    apache_intervention_event_input input = {
        "phase1_intervention", MSCONNECTOR_PHASE_REQUEST_HEADERS,
        "deny", "deny", "request_headers_before_handler", 200, 0};
    msconnector_error_code first = MSCONNECTOR_ERROR_NONE, repeated;
    int result = 0, finish, original, mode;
    char *oversize;
    if (argc != 7 || apr_initialize() != APR_SUCCESS ||
        apr_pool_create(&pool, NULL) != APR_SUCCESS) { return 90; }
    mode = atoi(argv[1]); fault = atoi(argv[3]); original = atoi(argv[4]);
    conf.common_config.phase4_log_path = argv[2];
    conf.common_config.phase4_mode = (enum msconnector_phase4_mode)atoi(argv[6]);
    request.pool = pool; request.status = HTTP_OK;
    request.method = "GET"; request.unparsed_uri = "/sink-control";
    request.per_dir_config = (struct ap_conf_vector_t *)&conf;
    request.connection = &connection;
    request.headers_in = apr_table_make(pool, 1);
    request.headers_out = apr_table_make(pool, 1);
    request.err_headers_out = apr_table_make(pool, 1);
    apr_table_setn(request.headers_out, "Location", "/rule-redirect");
    msr.r = &request; msr.t = (Transaction *)&msr;
    msr.event_transaction_id = "apache-sink-transaction";
    msr.last_intervention_status = mode == 10 ? HTTP_MOVED_TEMPORARILY : HTTP_FORBIDDEN;
    msr.last_intervention_log = "[id \"1234\"]";
    msr.contract_initialized = 1;
    if (msconnector_transaction_contract_init(&msr.contract,
        msconnector_profile_registry_find("apache"), msr.event_transaction_id,
        NULL, NULL, MSCONNECTOR_TRANSACTION_MODE_SAFE, 1U) !=
        MSCONNECTOR_TRANSACTION_TRANSITION_OK) { return 93; }
    if (original) {
        (void)msc_apache_contract_fail(&msr, MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT);
    }
    if (mode == 0 || mode == 9) {
        if (msconnector_transaction_contract_record_decision(&msr.contract,
            MSCONNECTOR_TRANSACTION_DECISION_BLOCK, "1234", 100U) !=
            MSCONNECTOR_TRANSACTION_TRANSITION_OK) { return 94; }
    }
    msr.response.committed = atoi(argv[5]);
    filter.r = &request;
    if (mode == 1) {
        msconnector_event_init(&event);
        first = apache_intervention_write_event(&msr, &request, argv[2], NULL, 1);
    } else if (mode == 2) {
        oversize = apr_palloc(pool, 8192U);
        memset(oversize, 'x', 8191U); oversize[8191U] = '\0';
        request.unparsed_uri = oversize;
        first = apache_emit_intervention_event(&msr, &request, &input);
    } else if (mode == 3) {
        first = apache_log_rule_match_event(&msr, &request,
            MSCONNECTOR_PHASE_REQUEST_HEADERS, "1234");
        result = msr.intervention.mandatory_event_failed;
    } else if (mode == 4 || mode == 10) {
        result = apache_emit_phase1_intervention_event(&msr, &request, msr.last_intervention_status, "control");
        first = msr.intervention.event_sink_error;
    } else if (mode == 5 || mode == 11) {
        if (mode == 11) {
            apr_bucket_alloc_t *allocator = apr_bucket_alloc_create(pool);
            apr_bucket_brigade *output = apr_brigade_create(pool, allocator);
            apr_bucket *bucket = apr_bucket_immortal_create("body", 4U, allocator);
            APR_BRIGADE_INSERT_TAIL(output, bucket);
            if (apache_input_filter_process_bucket(&msr, &request, &filter, &conf,
                    output, bucket, APR_BLOCK_READ) != APR_SUCCESS ||
                    !msr.request_intervention_pending) { return 95; }
            eos_diagnostic = 1;
        }
        result = msc_finalize_request_body(&msr, &request);
        first = msr.intervention.event_sink_error;
        (void)msc_finalize_request_body(&msr, &request);
    } else if (mode == 12) {
        apr_bucket_alloc_t *allocator = apr_bucket_alloc_create(pool);
        apr_bucket_brigade *brigade = apr_brigade_create(pool, allocator);
        apr_bucket *bucket = apr_bucket_immortal_create("body", 4U, allocator);
        int native_intervention;
        APR_BRIGADE_INSERT_TAIL(brigade, bucket);
        if (apache_phase4_append_bucket(&msr, &conf, bucket) != APR_SUCCESS ||
                !msr.response_intervention_pending) { return 96; }
        eos_diagnostic = 1;
        if (apache_phase4_finish_response_body(&msr, &filter, brigade,
                &native_intervention) != APR_SUCCESS) { return 97; }
        result = apache_phase4_handle_intervention(&msr, &conf, &filter,
            brigade, native_intervention);
        first = msr.intervention.event_sink_error;
    } else if (mode == 6) {
        result = apache_output_filter_process_headers(&msr, &request, &filter, NULL);
        first = msr.intervention.event_sink_error;
        (void)apache_output_filter_process_headers(&msr, &request, &filter, NULL);
    } else if (mode == 7) {
        apr_bucket_alloc_t *allocator = apr_bucket_alloc_create(pool);
        apr_bucket_brigade *brigade = apr_brigade_create(pool, allocator);
        result = apache_phase4_handle_intervention(&msr, &conf, &filter,
            brigade, HTTP_FORBIDDEN);
        first = msr.intervention.event_sink_error;
        (void)apache_phase4_handle_intervention(&msr, &conf, &filter, brigade, HTTP_FORBIDDEN);
    } else if (mode == 9) {
        first = apache_emit_intervention_event(&msr, &request, &input);
        fault = 1;
        (void)apache_log_rule_match_event(&msr, &request,
            MSCONNECTOR_PHASE_REQUEST_HEADERS, "1234");
    } else if (mode == 8) {
        first = apache_emit_contract_failure_event(&msr, &request,
            MSCONNECTOR_PHASE_REQUEST_HEADERS,
            MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT, HTTP_INTERNAL_SERVER_ERROR);
    } else {
        first = apache_emit_intervention_event(&msr, &request, &input);
    }
    repeated = mode == 9 ? msr.intervention.event_sink_error
        : apache_emit_intervention_event(&msr, &request, &input);
    finish = msc_apache_contract_finish(&msr);
    printf("{\"first\":%d,\"repeat\":%d,\"io\":%d,\"size\":%d,"
        "\"internal\":%d,\"opens\":%d,\"writes\":%d,\"closes\":%d,"
        "\"cause\":\"%s\",\"failed\":%d,\"initial_diagnostic_failed\":%d,"
        "\"finish\":%d,\"result\":%d,\"responses\":%d,\"status\":%d,"
        "\"aborted\":%d,\"native_calls\":%d,\"location\":%d}\n",
        first, repeated, MSCONNECTOR_ERROR_IO, MSCONNECTOR_ERROR_EVENT_TOO_LARGE,
        MSCONNECTOR_ERROR_INTERNAL, opens, writes, closes,
        msconnector_transaction_error_class_name(msr.contract.error_class),
        msr.intervention.mandatory_event_failed, mode == 3 ? result : -1,
        finish, result, responses, response_status, connection.aborted, native_calls,
        apr_table_get(request.headers_out, "Location") != NULL);
    apr_pool_destroy(pool); apr_terminate(); return 0;
}
'''


class ApacheEventSinkFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        apxs = shutil.which("apxs") or shutil.which("apxs2")
        apr = shutil.which("apr-1-config")
        apu = shutil.which("apu-1-config")
        if not apxs or not apr or not apu or not shutil.which(compiler[0]):
            raise RuntimeError("Apache/APR development headers and C compiler required")
        def flags(command: list[str]) -> list[str]:
            return shlex.split(subprocess.run(command, check=True, capture_output=True,
                text=True, timeout=10).stdout)
        include = subprocess.run([apxs, "-q", "INCLUDEDIR"], check=True,
            capture_output=True, text=True, timeout=10).stdout.strip()
        cls.temporary = tempfile.TemporaryDirectory(prefix="apache-event-sink-",
            dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        definitions = "\n\n".join(function_definition(FILTERS.read_text(), name)
            for name in FILTER_FUNCTIONS)
        definitions += "\n\n" + "\n\n".join(function_definition(MODULE.read_text(), name)
            for name in MODULE_FUNCTIONS)
        # Signatures are extracted independently because bodies contain blank lines.
        declaration_list = [function_definition(FILTERS.read_text(), name).split("{", 1)[0].strip() + ";"
            for name in FILTER_FUNCTIONS]
        declaration_list += [function_definition(MODULE.read_text(), name).split("{", 1)[0].strip() + ";"
            for name in MODULE_FUNCTIONS]
        source = cls.directory / "fixture.c"
        fixture = PREAMBLE + "\n".join(declaration_list) + "\n" + definitions + MAIN
        source.write_text(fixture)
        cls.binary = cls.directory / "fixture"
        sources = ("transaction_state.c", "decision_action.c", "intervention.c", "block_statuses.c",
            "http_status.c", "rule_id.c", "event.c", "event_jsonl.c", "integrity_event.c",
            "json_escape.c", "status.c", "late_intervention.c")
        command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
            "-I", include, "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT))]
        command += flags([apr, "--includes"]) + flags([apu, "--includes"])
        command += [str(source)] + [str(source_path('common/src', root=ROOT) / name) for name in sources]
        command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-Wl,--wrap=msconnector_open_private_event_file",
            "-Wl,--wrap=apr_file_write_full", "-Wl,--wrap=apr_file_close"]
        command += flags([apr, "--link-ld", "--libs"]) + flags([apu, "--link-ld", "--libs"])
        command += shlex.split(os.environ.get("APACHE_SINK_CFLAGS", ""))
        command += ["-o", str(cls.binary)]
        built = subprocess.run(command, text=True, capture_output=True, timeout=60)
        if built.returncode:
            raise AssertionError(built.stdout + built.stderr)
        # Compile the former caller behavior as a negative control: a Safe
        # committed response discards the physical writer result and succeeds.
        guard = ('if (apache_phase4_log_event(msr, r, wanted, actual,\n'
                 '                "response_committed_safe") != MSCONNECTOR_ERROR_NONE)')
        if fixture.count(guard) != 1:
            raise AssertionError("Safe caller failure guard not found exactly once")
        source.write_text(fixture.replace(guard, guard.replace(
            "MSCONNECTOR_ERROR_NONE", "MSCONNECTOR_ERROR_IO"), 1))
        cls.negative_binary = cls.directory / "ignored-sink-negative-control"
        negative = subprocess.run(command[:-1] + [str(cls.negative_binary)],
            text=True, capture_output=True, timeout=60)
        if negative.returncode:
            raise AssertionError(negative.stdout + negative.stderr)


    def run_case(self, mode=0, fault=0, original=0, committed=0, phase4_mode=1, path=None, negative=False):
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            target = Path(temporary) / "events.jsonl" if path is None else path
            process = subprocess.run([str(self.negative_binary if negative else self.binary), str(mode), str(target), str(fault),
                str(original), str(committed), str(phase4_mode)], capture_output=True,
                text=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(process.stdout)
            result["bytes"] = target.read_bytes() if target.is_file() else b""
            return result

    def assert_io_failure(self, result):
        self.assertEqual(result["first"], result["io"])
        self.assertEqual(result["repeat"], result["io"])
        self.assertEqual(result["opens"], 1)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["finish"], 0)

    def test_success_has_one_complete_terminal_line_and_no_duplicate(self):
        result = self.run_case()
        self.assertEqual(result["first"], 0)
        self.assertEqual(result["repeat"], 0)
        self.assertEqual(result["finish"], 1)
        self.assertEqual((result["opens"], result["writes"], result["closes"]), (1, 1, 1))
        self.assertEqual(len(result["bytes"].splitlines()), 1)
        json.loads(result["bytes"])

    def test_eos_diagnostic_sink_failure_survives_pending_native_restore(self):
        result = self.run_case(mode=11, fault=1)
        self.assert_io_failure(result)
        self.assertEqual(result["result"], 500)
        self.assertEqual((result["opens"], result["writes"], result["closes"]), (1, 1, 1))

    def test_response_eos_sink_failure_survives_captured_append_intervention(self):
        result = self.run_case(mode=12, fault=1)
        self.assert_io_failure(result)
        self.assertNotEqual(result["result"], 0)
        self.assertEqual(result["status"], 500)
        self.assertEqual((result["opens"], result["writes"], result["closes"]), (1, 1, 1))

    def test_invalid_serialization_never_opens_sink(self):
        result = self.run_case(mode=1)
        self.assertEqual(result["first"], result["internal"])
        self.assertEqual(result["opens"], 0)
        self.assertEqual(result["bytes"], b"")
        self.assertEqual(result["finish"], 0)

    def test_oversized_serialization_never_opens_sink(self):
        result = self.run_case(mode=2)
        self.assertEqual(result["first"], result["size"])
        self.assertEqual(result["opens"], 0)
        self.assertEqual(result["cause"], "event_limit")

    def test_missing_parent_and_directory_and_invalid_target_fail_open(self):
        for target in (self.directory / "missing-parent" / "event.jsonl", self.directory,
                       self.directory / "bad" / ".." / "event.jsonl"):
            with self.subTest(target=target):
                result = self.run_case(path=target)
                self.assert_io_failure(result)
                self.assertEqual(result["writes"], 0)

    def test_insecure_parent_is_rejected_without_write(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            parent = Path(temporary)
            parent.chmod(0o777)
            result = self.run_case(path=parent / "event.jsonl")
            self.assert_io_failure(result)
            self.assertEqual(result["writes"], 0)

    def test_real_full_and_readonly_descriptors_propagate_write_error(self):
        for fault in (1, 2):
            with self.subTest(fault=fault):
                result = self.run_case(fault=fault)
                self.assert_io_failure(result)
                self.assertEqual((result["writes"], result["closes"]), (1, 1))

    def test_real_partial_write_is_not_complete_or_retried(self):
        result = self.run_case(fault=4)
        self.assert_io_failure(result)
        self.assertEqual(len(result["bytes"]), 100)
        self.assertEqual(result["writes"], 1)

    def test_compiled_ignored_result_control_reproduces_safe_host_success(self):
        result = self.run_case(mode=7, fault=1, committed=1, negative=True)
        self.assertEqual(result["first"], result["io"])
        self.assertEqual(result["result"], 0)
        self.assertEqual(result["aborted"], 0)
        corrected = self.run_case(mode=7, fault=1, committed=1)
        self.assertNotEqual(corrected["result"], 0)
        self.assertEqual(corrected["aborted"], 1)

    def test_close_failure_is_terminal_even_after_complete_line(self):
        result = self.run_case(fault=3)
        self.assert_io_failure(result)
        self.assertEqual(len(result["bytes"].splitlines()), 1)
        self.assertEqual(result["closes"], 1)

    def test_original_engine_cause_survives_sink_failure(self):
        result = self.run_case(mode=8, fault=1, original=1)
        self.assert_io_failure(result)
        self.assertEqual(result["cause"], "engine_timeout")

    def test_rule_match_failure_is_diagnostic_but_later_mandatory_fails(self):
        result = self.run_case(mode=3, fault=1)
        self.assert_io_failure(result)
        self.assertEqual(result["initial_diagnostic_failed"], 0)
        self.assertEqual(result["writes"], 1)

    def test_diagnostic_failure_after_successful_terminal_cannot_mask_finish(self):
        result = self.run_case(mode=9)
        self.assertEqual(result["first"], 0)
        self.assertEqual(result["repeat"], result["io"])
        self.assertEqual(result["writes"], 2)
        self.assertEqual(result["finish"], 0)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(len(result["bytes"].splitlines()), 1)

    def test_phase1_host_status_fails_closed_with_positive_control(self):
        positive = self.run_case(mode=4)
        self.assertEqual(positive["result"], 403)
        self.assertEqual(positive["location"], 1)
        result = self.run_case(mode=4, fault=1)
        self.assert_io_failure(result)
        self.assertEqual(result["result"], 500)
        self.assertEqual(result["location"], 0)

    def test_failed_pending_redirect_clears_only_uncommitted_location(self):
        healthy = self.run_case(mode=10)
        self.assertEqual(healthy["result"], 302)
        self.assertEqual(healthy["location"], 1)
        event = json.loads(healthy["bytes"])
        self.assertEqual(event["requested_action"], "redirect")
        self.assertEqual(event["actual_action"], "redirect")
        failed = self.run_case(mode=10, fault=1)
        self.assert_io_failure(failed)
        self.assertEqual(failed["result"], 500)
        self.assertEqual(failed["location"], 0)
        self.assertEqual(failed["bytes"], b"")

    def test_phase2_no_native_reentry_after_sink_failure(self):
        self.assertEqual(self.run_case(mode=5)["result"], 403)
        result = self.run_case(mode=5, fault=1)
        self.assert_io_failure(result)
        self.assertEqual(result["result"], 500)
        self.assertEqual(result["native_calls"], 1)

    def test_phase3_returns_error_to_precommit_filter(self):
        self.assertEqual(self.run_case(mode=6)["status"], 403)
        result = self.run_case(mode=6, fault=1)
        self.assert_io_failure(result)
        self.assertEqual(result["responses"], 1)
        self.assertEqual(result["status"], 500)
        self.assertEqual(result["native_calls"], 1)

    def test_phase4_precommit_fails_closed_for_off_safe_strict(self):
        for mode in (0, 1, 2):
            with self.subTest(mode=mode):
                result = self.run_case(mode=7, fault=1, phase4_mode=mode)
                self.assert_io_failure(result)
                self.assertEqual(result["responses"], 1)
                self.assertEqual(result["status"], 500)
                self.assertEqual(result["aborted"], 0)

    def test_phase4_postcommit_safe_strict_abort_without_second_response(self):
        for mode in (1, 2):
            with self.subTest(mode=mode):
                result = self.run_case(mode=7, fault=1, committed=1, phase4_mode=mode)
                self.assert_io_failure(result)
                self.assertEqual(result["responses"], 0)
                self.assertEqual(result["location"], 1)
                self.assertEqual(result["aborted"], 1)
                self.assertNotEqual(result["result"], 0)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
