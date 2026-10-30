"""Real native response limits through Apache's productive APR filter callers.

Apache transport/error rendering are controlled boundaries, not a hosted httpd
claim. Native rules, interventions, and APR buckets/files are real.
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
from modsecurity_connector_tests.test_apache_event_sink_failures import FILTERS, MODULE, PREAMBLE, ROOT

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
    "apache_phase4_log_event", "apache_phase4_response_committed",
    "apache_phase4_abort_response_connection", "apache_phase4_fail_closed",
    "apache_phase4_handle_intervention", "apache_phase4_append_bucket",
    "apache_phase4_finish_response_body", "apache_phase4_brigade_starts_response",
    "apache_phase4_release_response_brigade", "apache_output_filter_finish_response",
    "apache_output_filter_terminal_result",
    "apache_phase4_normalize_response_brigade", "apache_phase4_error_bucket_status",
    "apache_output_filter_prepare_response_brigade",
)
MODULE_FUNCTIONS = (
    "msc_apache_contract_begin", "msc_apache_contract_complete", "msc_apache_contract_record_body",
    "msc_apache_contract_fail", "msc_apache_contract_finish",
    "msc_apache_contract_record_decision", "apache_intervention_decision_kind",
    "msc_apache_contract_record_intervention_decision", "msc_apache_contract_intervention_action",
    "msc_release_intervention_buffers", "apache_failure_phase", "apache_record_failure",
    "apache_store_native_intervention", "apache_request_context", "process_intervention",
)
EXTRA = r'''
#include "msconnector/intervention.h"
const apr_bucket_type_t ap_bucket_type_error = {.name = "ERROR"};
static int passed, passed_eos, passed_bytes, cleanups, native_appends;
int __real_msc_append_response_body(Transaction *, const unsigned char *, size_t);
int __wrap_msc_append_response_body(Transaction *t, const unsigned char *body, size_t size) {
    ++native_appends; return __real_msc_append_response_body(t, body, size);
}
int __real_msc_process_response_body(Transaction *);
int __wrap_msc_process_response_body(Transaction *t) {
    ++native_calls; return __real_msc_process_response_body(t);
}
void __real_msc_transaction_cleanup(Transaction *);
void __wrap_msc_transaction_cleanup(Transaction *t) {
    ++cleanups; __real_msc_transaction_cleanup(t);
}
static int apache_phase3_restore_response_state(msc_t *msr, request_rec *r) {
    (void)msr; (void)r; return 1;
}
int msc_apache_contract_mark_response_committed(msc_t *msr) {
    return msconnector_transaction_contract_set_response_committed(&msr->contract, 1)
        == MSCONNECTOR_TRANSACTION_TRANSITION_OK;
}
apr_status_t ap_pass_brigade(ap_filter_t *f, apr_bucket_brigade *brigade) {
    apr_bucket *bucket;
    (void)f; ++passed;
    for (bucket = APR_BRIGADE_FIRST(brigade);
            bucket != APR_BRIGADE_SENTINEL(brigade); bucket = APR_BUCKET_NEXT(bucket)) {
        if (APR_BUCKET_IS_EOS(bucket)) { ++passed_eos; }
        else if (!APR_BUCKET_IS_METADATA(bucket)) {
            const char *data; apr_size_t size;
            if (apr_bucket_read(bucket, &data, &size, APR_BLOCK_READ) != APR_SUCCESS) {
                return APR_EGENERAL;
            }
            passed_bytes += (int)size;
        }
    }
    apr_brigade_cleanup(brigade);
    return APR_SUCCESS;
}
'''
MAIN = r'''
#define REQUIRE(expr) do { if (!(expr)) { fprintf(stderr, "failed line %d\n", __LINE__); return 90; } } while (0)
int main(int argc, char **argv) {
    apr_pool_t *pool;
    apr_bucket_alloc_t *allocator;
    apr_bucket_brigade *brigade;
    msc_t msr = {0}; request_rec request = {0}; conn_rec connection = {0};
    msc_conf_t conf = {0}; ap_filter_t filter = {0}, next = {0};
    ModSecurity *engine; RulesSet *rules;
    const char *error = NULL;
    int size, commit, action, detection, ordinary, handled, before, repeat, append_before, append_after, producer;
    apr_status_t result;
    char directives[1024];
    REQUIRE(argc == 11);
    size = atoi(argv[2]); commit = atoi(argv[3]); action = atoi(argv[4]);
    detection = atoi(argv[5]); ordinary = atoi(argv[7]); fault = atoi(argv[8]);
    producer = atoi(argv[9]);
    REQUIRE(apr_initialize() == APR_SUCCESS && apr_pool_create(&pool, NULL) == APR_SUCCESS);
    allocator = apr_bucket_alloc_create(pool);
    brigade = apr_brigade_create(pool, allocator);
    engine = msc_init(); rules = msc_create_rules_set();
    snprintf(directives, sizeof(directives),
        "SecRuleEngine %s\nSecRequestBodyAccess Off\nSecResponseBodyAccess On\n"
        "SecResponseBodyMimeType text/plain\nSecResponseBodyLimit %s\n"
        "SecResponseBodyLimitAction %s\n%s",
        detection ? "DetectionOnly" : "On", argv[10], action ? "ProcessPartial" : "Reject",
        ordinary ? "SecRule RESPONSE_BODY \"@contains x\" \"id:1234,phase:4,deny,status:403\"\n" : "");
    REQUIRE(msc_rules_add(rules, directives, &error) >= 0);
    msr.t = msc_new_transaction(engine, rules, NULL); REQUIRE(msr.t != NULL);
    request.pool = pool; request.status = HTTP_OK; request.method = "GET";
    request.unparsed_uri = "/native-response-limit"; request.connection = &connection;
    request.headers_in = apr_table_make(pool, 1); request.headers_out = apr_table_make(pool, 1);
    request.err_headers_out = apr_table_make(pool, 1); request.notes = apr_table_make(pool, 1);
    request.per_dir_config = (struct ap_conf_vector_t *)&conf;
    conf.common_config.phase4_log_path = argv[1];
    conf.common_config.phase4_mode = (enum msconnector_phase4_mode)atoi(argv[6]);
    conf.common_config.default_block_status = HTTP_FORBIDDEN;
    msr.r = &request; msr.contract_initialized = 1; msr.event_transaction_id = "native-apache-limit";
    request.request_config = (ap_conf_vector_t *)&msr;
    REQUIRE(msconnector_transaction_contract_init(&msr.contract,
        msconnector_profile_registry_find("apache"), msr.event_transaction_id,
        NULL, NULL, MSCONNECTOR_TRANSACTION_MODE_SAFE, 1U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    for (enum msconnector_phase phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
            phase <= MSCONNECTOR_PHASE_RESPONSE_HEADERS; ++phase) {
        REQUIRE(msc_apache_contract_begin(&msr, phase));
        REQUIRE(msc_apache_contract_complete(&msr, phase));
    }
    REQUIRE(msc_process_connection(msr.t, "127.0.0.1", 1234, "127.0.0.1", 80) == 1);
    REQUIRE(msc_process_uri(msr.t, "/", "GET", "1.1") == 1);
    REQUIRE(msc_process_request_headers(msr.t) == 1 && msc_process_request_body(msr.t) == 1);
    REQUIRE(msc_add_response_header(msr.t, (const unsigned char *)"Content-Type",
        (const unsigned char *)"text/plain") == 1);
    REQUIRE(msc_process_response_headers(msr.t, 200, "HTTP/1.1") == 1);
    filter.r = &request; filter.next = &next;
    if (commit) {
        if (commit == 1) { APR_BRIGADE_INSERT_TAIL(brigade, apr_bucket_flush_create(allocator)); }
        else {
            int prefix_size = producer ? 4 : 2;
            apr_bucket *prefix = apr_bucket_immortal_create("xxxx", (apr_size_t)prefix_size, allocator);
            APR_BRIGADE_INSERT_TAIL(brigade, prefix);
            REQUIRE(apache_phase4_append_bucket(&msr, &conf, prefix) == APR_SUCCESS);
            size -= prefix_size;
        }
        REQUIRE(apache_phase4_release_response_brigade(&msr, &filter, brigade, 0) == APR_SUCCESS);
    }
    before = passed;
    if (producer) {
        apr_bucket *eos = NULL;
        APR_BRIGADE_INSERT_TAIL(brigade,
            apr_bucket_immortal_create("xxxxxxxxx", (apr_size_t)size, allocator));
        APR_BRIGADE_INSERT_TAIL(brigade, apr_bucket_flush_create(allocator));
        result = apache_output_filter_prepare_response_brigade(&msr, &conf, &filter, &brigade, &eos);
        REQUIRE(eos == NULL); /* No host EOS was supplied or fabricated. */
        if (result == APR_SUCCESS) {
            result = apache_phase4_release_response_brigade(&msr, &filter, brigade, 0);
            /* The rejected sample deliberately has no later HTTP EOS. Allowed
             * controls receive their normal host EOS after the prefix. */
            if (result == APR_SUCCESS && !msr.last_intervention_body_limit) {
                APR_BRIGADE_INSERT_TAIL(brigade, apr_bucket_eos_create(allocator));
                result = apache_output_filter_finish_response(&msr, &conf, &filter, brigade, brigade);
            }
        }
    } else {
        while (size-- > 0) {
            apr_bucket *bucket = apr_bucket_immortal_create("x", 1U, allocator);
            APR_BRIGADE_INSERT_TAIL(brigade, bucket);
            REQUIRE(apache_phase4_append_bucket(&msr, &conf, bucket) == APR_SUCCESS);
        }
        APR_BRIGADE_INSERT_TAIL(brigade, apr_bucket_eos_create(allocator));
        result = apache_output_filter_finish_response(&msr, &conf, &filter, brigade, brigade);
    }
    APR_BRIGADE_INSERT_TAIL(brigade, apr_bucket_immortal_create("later", 5U, allocator));
    repeat = apache_output_filter_terminal_result(&msr, &filter, brigade, &handled);
    append_before = native_appends;
    if (msr.response_phase4_gate_failed) {
        apr_bucket *later = apr_bucket_immortal_create("later", 5U, allocator);
        REQUIRE(apache_phase4_append_bucket(&msr, &conf, later) != APR_SUCCESS);
        apr_bucket_destroy(later);
    }
    append_after = native_appends;
    msc_transaction_cleanup(msr.t); msc_rules_cleanup(rules); msc_cleanup(engine);
    printf("{\"result\":%d,\"cause\":\"%s\",\"aborted\":%d,\"responses\":%d,"
        "\"status\":%d,\"native_status\":%d,\"eos\":%d,\"released\":%d,"
        "\"native_calls\":%d,\"cleanups\":%d,\"handled\":%d,\"repeat\":%d,\"reentered\":%d,\"forwarded\":%d}"
        "\n", result, msconnector_transaction_error_class_name(msr.contract.error_class),
        connection.aborted, responses, response_status, msr.last_intervention_status,
        passed_eos, passed - before, native_calls, cleanups, handled, repeat, append_after - append_before, passed_bytes);
    apr_pool_destroy(pool); apr_terminate(); return 0;
}
'''


class ApacheNativeResponseLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="apache-native-limit-",
            dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        preamble = PREAMBLE.replace(
            "#define ap_get_module_config(vector, module) (vector)",
            "#define ap_get_module_config(vector, module) ((void *)(vector))",
        )
        for name in ("msc_append_request_body", "msc_append_response_body",
                     "msc_apache_contract_begin", "msc_apache_contract_complete", "msc_apache_contract_record_body",
                     "msc_add_response_header", "msc_process_response_headers",
                     "msc_process_request_body", "msc_process_response_body",
                     "process_intervention", "msc_apache_contract_record_intervention_decision",
                     "apache_phase3_snapshot_response_state", "apache_add_response_headers",
                     "apache_contract_record_response_metadata", "apache_input_filter_terminal_error"):
            preamble = preamble.replace(function_definition(preamble, name), "")
        preamble = preamble.replace("static int eos_diagnostic;", "")
        definitions = [function_definition(FILTERS.read_text(), name) for name in FILTER_FUNCTIONS]
        definitions += [function_definition(MODULE.read_text(), name) for name in MODULE_FUNCTIONS]
        declarations = [definition.split("{", 1)[0].strip() + ";" for definition in definitions]
        source = cls.directory / "fixture.c"
        fixture = preamble + EXTRA + "\n".join(declarations) + "\n".join(definitions) + MAIN
        source.write_text(fixture)
        def flags(*command):
            return shlex.split(subprocess.run(command, check=True, capture_output=True,
                text=True, timeout=10).stdout)
        apxs = shutil.which("apxs") or shutil.which("apxs2")
        include = subprocess.run([apxs, "-q", "INCLUDEDIR"], check=True,
            capture_output=True, text=True, timeout=10).stdout.strip()
        cls.binary = cls.directory / "fixture"
        sources = ("transaction_state.c", "decision_action.c", "intervention.c", "block_statuses.c",
            "http_status.c", "rule_id.c", "event.c", "event_jsonl.c", "integrity_event.c",
            "json_escape.c", "status.c", "late_intervention.c")
        command = shlex.split(os.environ.get("CC", "cc")) + ["-std=c17", "-Wall", "-Wextra", "-Werror",
            "-pthread", "-I", include, "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT))]
        command += flags("apr-1-config", "--includes") + flags("apu-1-config", "--includes")
        command += [str(source)] + [str(source_path('common/src', root=ROOT) / name) for name in sources]
        command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-Wl,--wrap=msconnector_open_private_event_file",
            "-Wl,--wrap=apr_file_write_full", "-Wl,--wrap=apr_file_close",
            "-Wl,--wrap=msc_process_response_body", "-Wl,--wrap=msc_transaction_cleanup",
            "-Wl,--wrap=msc_append_response_body"]
        command += flags("apr-1-config", "--link-ld", "--libs") + flags("apu-1-config", "--link-ld", "--libs")
        command += ["-lmodsecurity", "-o", str(cls.binary)]
        built = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if built.returncode:
            raise AssertionError(built.stdout + built.stderr)
        # Preserve the demonstrated former behavior as an executable negative
        # control, without changing the native engine or the surrounding callers.
        start = fixture.index("    /* Native Reject is a terminal inspection failure")
        end = fixture.index("    if (conf->common_config.phase4_mode == MSCONNECTOR_PHASE4_MODE_OFF)", start)
        negative_fixture = fixture[:start] + fixture[end:]
        start = negative_fixture.index("        if (msr->response_intervention_pending &&\n            msr->last_intervention_body_limit)")
        end = negative_fixture.index("    }\n    return APR_SUCCESS;\n}", start)
        source.write_text(negative_fixture[:start] + negative_fixture[end:])
        cls.negative_binary = cls.directory / "native-reject-log-only-negative"
        negative = subprocess.run(command[:-1] + [str(cls.negative_binary)],
            capture_output=True, text=True, timeout=60)
        if negative.returncode:
            raise AssertionError(negative.stdout + negative.stderr)

    def run_case(self, *, response_limit, limit_action, size=9, commit=1, detection=0, mode=1, ordinary=0, fault=0, negative=False, producer=0):
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            target = Path(temporary) / "events.jsonl"
            process = subprocess.run([str(self.negative_binary if negative else self.binary), str(target), str(size), str(commit), str(int(limit_action == "ProcessPartial")),
                str(detection), str(mode), str(ordinary), str(fault), str(producer), str(response_limit)], capture_output=True, text=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(process.stdout)
            result["events"] = [json.loads(line) for line in target.read_text().splitlines()] if target.exists() else []
            return result

    def test_native_reject_after_flush_or_body_commit_never_releases_eos(self):
        for commit in (1, 2):
            for mode in (0, 1, 2):
                with self.subTest(commit=commit, mode=mode):
                    result = self.run_case(response_limit=8, limit_action="Reject", commit=commit, mode=mode)
                    self.assertNotEqual(result["result"], 0)
                    self.assertEqual(result["cause"], "body_limit")
                    self.assertEqual((result["aborted"], result["responses"], result["eos"], result["released"]), (1, 0, 0, 0))
                    self.assertEqual((result["native_calls"], result["cleanups"], result["handled"]), (1, 1, 1))
                    self.assertEqual(result["reentered"], 0)
                    self.assertNotEqual(result["repeat"], 0)
                    self.assertEqual(len(result["events"]), 1)
                    event = result["events"][0]
                    self.assertEqual(event["event"], "body_limit")
                    self.assertEqual(event["actual_action"], "abort_connection")
                    self.assertTrue(event["eos_seen"])
                    self.assertIn(result["native_status"], (403, 413))

    def test_native_precommit_reject_preserves_native_status(self):
        result = self.run_case(response_limit=8, limit_action="Reject", commit=0)
        self.assertNotEqual(result["result"], 0)
        self.assertEqual(result["cause"], "body_limit")
        self.assertIn(result["native_status"], (403, 413))
        self.assertEqual(result["status"], result["native_status"])
        self.assertEqual((result["responses"], result["aborted"], result["eos"]), (1, 0, 0))

    def test_within_limit_partial_and_detection_only_continue(self):
        for options in ({"size": 7}, {"size": 8}, {"limit_action": "ProcessPartial"}, {"detection": 1}):
            with self.subTest(options=options):
                result = self.run_case(response_limit=8, **{"limit_action": "Reject", **options})
                self.assertEqual(result["result"], 0)
                self.assertEqual(result["cause"], "none")
                self.assertEqual((result["eos"], result["aborted"], result["cleanups"]), (1, 0, 1))

    def test_ordinary_late_rule_safe_remains_log_only(self):
        result = self.run_case(response_limit=8, limit_action="Reject", size=8, ordinary=1)
        self.assertEqual(result["result"], 0)
        self.assertEqual(result["cause"], "none")
        self.assertEqual((result["eos"], result["aborted"]), (1, 0))
        self.assertEqual(result["events"][0]["actual_action"], "log_only")

    def test_native_reject_sink_failure_does_not_replace_first_cause(self):
        result = self.run_case(response_limit=8, limit_action="Reject", fault=1)
        self.assertNotEqual(result["result"], 0)
        self.assertEqual(result["cause"], "body_limit")
        self.assertEqual((result["eos"], result["aborted"], result["cleanups"]), (0, 1, 1))

    def test_negative_control_detects_native_reject_downgraded_to_safe_log_only(self):
        result = self.run_case(response_limit=8, limit_action="Reject", negative=True)
        self.assertEqual(result["cause"], "body_limit")
        self.assertEqual((result["result"], result["aborted"], result["eos"]), (0, 0, 1))
        self.assertEqual(result["events"][0]["actual_action"], "log_only")

    def test_append_reject_stops_brigade_before_downstream_without_host_eos(self):
        for commit in (0, 1, 2):
            with self.subTest(commit=commit):
                result = self.run_case(response_limit=8, limit_action="Reject", commit=commit, producer=1)
                self.assertNotEqual(result["result"], 0)
                self.assertEqual(result["cause"], "body_limit")
                self.assertEqual((result["eos"], result["released"], result["reentered"]), (0, 0, 0))
                self.assertEqual((result["native_calls"], result["cleanups"], result["handled"]), (1, 1, 1))
                self.assertEqual(result["aborted"], int(commit != 0))
                self.assertEqual(result["responses"], int(commit == 0))
                self.assertEqual(result["forwarded"], 4 if commit == 2 else 0)
                self.assertEqual(len(result["events"]), 1)
                self.assertFalse(result["events"][0]["eos_seen"])
                if commit == 0:
                    self.assertEqual(result["status"], result["native_status"])

    def test_negative_control_detects_rejected_append_forwarded_before_host_eos(self):
        for commit in (0, 2):
            with self.subTest(commit=commit):
                result = self.run_case(response_limit=8, limit_action="Reject", commit=commit, producer=1, negative=True)
                self.assertEqual((result["result"], result["native_calls"], result["eos"]), (0, 0, 0))
                self.assertEqual(result["forwarded"], 9)
                self.assertEqual(result["released"], 1)

    def test_append_allow_partial_detection_and_ordinary_rule_keep_streaming(self):
        for options in ({"size": 8}, {"limit_action": "ProcessPartial"}, {"detection": 1}, {"size": 8, "ordinary": 1}):
            with self.subTest(options=options):
                result = self.run_case(response_limit=8, producer=1, **{"limit_action": "Reject", **options})
                self.assertEqual(result["result"], 0)
                self.assertEqual(result["cause"], "none")
                self.assertEqual((result["aborted"], result["eos"], result["native_calls"]), (0, 1, 1))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
