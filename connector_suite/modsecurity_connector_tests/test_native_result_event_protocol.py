"""Compiled Common/native-boundary regressions, not live host HTTP tests.

The event fixture links the real serializer, JSONL writer and integrity code.
The callback fixture extracts the real Runtime functions and substitutes only
libModSecurity and the surrounding host state. Source checks cover the other
native owners and the three Runtime consumer families.
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

EVENT_FIXTURE = r'''
#include "msconnector/native_result.h"
#include "msconnector/event_protocol.h"
#include "msconnector/event_jsonl.h"
#include "msconnector/integrity_event.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "check failed: %s at %d\n", #x, __LINE__); return 1; } } while (0)
int main(int argc, char **argv) {
    msconnector_event event, canonical, second;
    char line[8192], other[8192], oversized[512];
    int truncated = 0;
    CHECK(argc == 3);
    if (strcmp(argv[1], "native") == 0) {
        const int values[] = {INT_MIN, -2, -1, 0, 1, 2, INT_MAX};
        size_t i;
        for (i = 0; i < sizeof(values)/sizeof(values[0]); ++i) {
            int value = values[i];
            CHECK(!!msconnector_native_body_append_can_continue(value) == (value == 0 || value == 1));
            CHECK(!!msconnector_native_phase_succeeded(value) == (value == 1));
            CHECK(msconnector_native_body_result_classify(value) ==
                (value == 0 ? MSCONNECTOR_NATIVE_BODY_PARTIAL :
                 value == 1 ? MSCONNECTOR_NATIVE_BODY_SUCCESS : MSCONNECTOR_NATIVE_BODY_FAILURE));
        }
        return 0;
    }
    msconnector_event_init(&event);
    event.meta.connector = argv[2];
    event.meta.integration_mode = "contract-fixture";
    event.meta.transaction_id = "tx-protocol";
    event.meta.timestamp = "2026-09-21T00:00:00Z";
    event.meta.message_id = MSCONN_EVENT_RESPONSE_BLOCKED;
    event.meta.event = "legacy_name";
    event.decision.phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
    event.decision.status = MSCONNECTOR_STATUS_BLOCKED;
    event.decision.action = "deny";
    event.decision.requested_action = "deny";
    event.decision.actual_action = "deny";
    event.decision.rule_id = "1001";
    event.http.http_status = 403;
    event.http.original_http_status = 200;
    event.http.visible_http_status = 403;
    event.http.transport_result = "http_status";
    event.request.method = "GET";
    event.request.uri = "/public?token=do-not-log";
    event.body.bytes_seen = 4096;
    event.body.bytes_inspected = 4096;
    if (strcmp(argv[1], "safe") == 0) {
        event.decision.actual_action = "log_only";
        event.flags.late_intervention = 1;
        event.flags.response_committed = 1;
        event.flags.headers_sent = 1;
        event.flags.late_intervention_mode = "safe";
        event.http.visible_http_status = 200;
        event.http.transport_result = "log_only";
    } else if (strcmp(argv[1], "abort") == 0) {
        event.meta.message_id = MSCONN_EVENT_PHASE4_HARD_ABORT_AFTER_200;
        event.decision.actual_action = "abort_connection";
        event.flags.response_committed = 1;
        event.flags.connection_aborted = 1;
        event.flags.late_intervention_mode = "strict";
        event.http.original_http_status = 201;
        event.http.visible_http_status = 201;
        event.http.transport_result = "connection_aborted";
    } else if (strcmp(argv[1], "error") == 0 || strcmp(argv[1], "invalid") == 0) {
        event.meta.message_id = MSCONN_EVENT_INVALID_ENGINE_RESPONSE;
        event.http.http_status = 500;
        event.http.visible_http_status = 500;
        event.flags.eos_seen = 0;
        if (strcmp(argv[1], "invalid") == 0) {
            memset(oversized, 'x', sizeof(oversized)-1);
            oversized[sizeof(oversized)-1] = '\0';
            event.meta.message = oversized;
            CHECK(!msconnector_event_write_jsonl_line(&event, line, sizeof(line), &truncated));
            CHECK(truncated && line[0] == '\0');
            event.meta.message = "";
            event.protocol.reset_by = "not/a/valid/token";
            CHECK(!msconnector_event_write_jsonl_line(&event, line, sizeof(line), &truncated));
            CHECK(truncated && line[0] == '\0');
            return 0;
        }
    } else if (strcmp(argv[1], "pending") == 0) {
        event.http.transport_result = NULL;
        event.http.visible_http_status = 0;
    } else if (strcmp(argv[1], "custom") == 0) {
        event.meta.message_id = "APPLICATION_CUSTOM";
        event.meta.event = "application_event";
        event.meta.message = "application text";
    } else if (strcmp(argv[1], "small") == 0) {
        CHECK(!msconnector_event_write_jsonl_line(&event, line, 8, &truncated));
        CHECK(truncated && line[0] == '\0');
        return 0;
    } else if (strcmp(argv[1], "byte-escape") == 0) {
        event.request.client_ip = "127.0.0.\200";
    } else if (strcmp(argv[1], "escape-overflow") == 0) {
        memset(oversized, 0x80, 11);
        oversized[11] = '\0';
        event.request.client_ip = oversized;
        CHECK(!msconnector_event_write_jsonl_line(&event, line, sizeof(line), &truncated));
        CHECK(truncated && line[0] == '\0');
        return 0;
    } else if (strcmp(argv[1], "null") == 0) {
        CHECK(!msconnector_event_protocol_view(NULL, &canonical));
        CHECK(!msconnector_event_protocol_view(&event, NULL));
        CHECK(!msconnector_event_write_jsonl_line(NULL, line, sizeof(line), &truncated));
        CHECK(line[0] == '\0');
        return 0;
    }
    event.integrity.previous_hash = 17;
    event.integrity.event_hash = msconnector_integrity_event_hash(&event, 17);
    CHECK(msconnector_event_protocol_view(&event, &canonical));
    CHECK(msconnector_event_protocol_view(&canonical, &second));
    CHECK(msconnector_integrity_event_hash(&canonical, 17) == event.integrity.event_hash);
    CHECK(msconnector_integrity_event_hash(&second, 17) == event.integrity.event_hash);
    CHECK(msconnector_event_write_jsonl_line(&event, line, sizeof(line), &truncated));
    CHECK(msconnector_event_write_jsonl_line(&canonical, other, sizeof(other), &truncated));
    CHECK(strcmp(line, other) == 0);
    CHECK(strstr(line, "do-not-log") == NULL);
    CHECK(event.body.bytes_seen == canonical.body.bytes_seen);
    CHECK(event.body.bytes_inspected == canonical.body.bytes_inspected);
    CHECK(event.flags.eos_seen == canonical.flags.eos_seen);
    CHECK(event.http.visible_http_status == canonical.http.visible_http_status);
    CHECK(event.flags.connection_aborted == canonical.flags.connection_aborted);
    canonical.decision.phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
    CHECK(msconnector_integrity_event_hash(&canonical, 17) != event.integrity.event_hash);
    canonical.decision.phase = event.decision.phase;
    canonical.http.visible_http_status++;
    CHECK(msconnector_integrity_event_hash(&canonical, 17) != event.integrity.event_hash);
    fputs(line, stdout);
    return 0;
}
'''

CALLBACK_PREAMBLE = r'''
#include "msconnector/native_result.h"
#include <stddef.h>
#include <stdio.h>
typedef struct { int value; } Transaction;
typedef struct { int value; } msconnector_runtime;
typedef struct { int code; } msconnector_error;
typedef struct { int phase, disruptive; } msconnector_decision;
typedef struct {
    Transaction *transaction;
    msconnector_decision pending_request_decision;
    int request_decision_pending;
    int request_partial_observed;
    msconnector_decision pending_response_decision;
    int response_decision_pending;
} msconnector_native_transaction;
#define MSCONNECTOR_ERROR_MODSECURITY_FAILURE 1
#define MSCONNECTOR_PHASE_REQUEST_BODY 3
#define MSCONNECTOR_PHASE_RESPONSE_BODY 5
static int native_result, decisions, calls;
static int runtime_error(msconnector_error *error, int code, const char *message, const char *source) {
    (void)message; (void)source; error->code = code; return 0;
}
static int msc_append_request_body(Transaction *t, const unsigned char *data, size_t size) {
    (void)t; (void)data; (void)size; calls++; return native_result;
}
static int msc_append_response_body(Transaction *t, const unsigned char *data, size_t size) {
    (void)t; (void)data; (void)size; calls++; return native_result;
}
static int msc_process_request_body(Transaction *t) { (void)t; calls++; return native_result; }
static int msc_process_response_body(Transaction *t) { (void)t; calls++; return native_result; }
static int native_decision(msconnector_runtime *runtime, msconnector_native_transaction *tx,
        int phase, msconnector_decision *decision, msconnector_error *error) {
    (void)runtime; (void)tx; (void)error; decision->phase=phase; decisions++; return 1;
}
'''
CALLBACK_MAIN = r'''
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "check failed at %d\n", __LINE__); return 1; } } while (0)
int main(void) {
    Transaction tx={0}; msconnector_native_transaction native={.transaction=&tx}; msconnector_runtime runtime={0};
    msconnector_error error={0}; msconnector_decision decision={0};
    const int results[]={-1,0,1,2}; unsigned i;
    for (i=0;i<sizeof(results)/sizeof(results[0]);i++) {
        int append_ok=results[i]==0 || results[i]==1;
        native_result=results[i]; calls=decisions=0; error.code=0;
        native.request_partial_observed=0;
        CHECK(native_append_request_body(&runtime,&native,(const unsigned char *)"abc",3,&error)==append_ok);
        CHECK(calls==1 && decisions==append_ok && error.code==(append_ok ? 0:1));
        CHECK(native.request_partial_observed==(results[i]==0));
        calls=decisions=0; error.code=0;
        CHECK(native_append_response_body(&runtime,&native,(const unsigned char *)"abc",3,&error)==append_ok);
        CHECK(calls==1 && decisions==append_ok && error.code==(append_ok ? 0:1));
        calls=decisions=0; error.code=0;
        CHECK(native_finish_request_body(&runtime,&native,&decision,&error)==(results[i]==1));
        CHECK(calls==1 && decisions==(results[i]==1));
        calls=decisions=0; error.code=0;
        CHECK(native_finish_response_body(&runtime,&native,&decision,&error)==(results[i]==1));
        CHECK(calls==1 && decisions==(results[i]==1));
    }
    /* A later successful or empty append must preserve an earlier partial. */
    native.request_partial_observed=0;
    native_result=0;
    CHECK(native_append_request_body(&runtime,&native,(const unsigned char *)"abc",3,&error)==1);
    native_result=1;
    CHECK(native_append_request_body(&runtime,&native,(const unsigned char *)"def",3,&error)==1);
    CHECK(native.request_partial_observed==1);
    calls=0;
    CHECK(native_append_request_body(&runtime,&native,NULL,0,&error)==1 && calls==0);
    CHECK(native.request_partial_observed==1);
    native.request_partial_observed=0;
    CHECK(native_append_request_body(&runtime,&native,NULL,0,&error)==1);
    CHECK(native.request_partial_observed==0);
    calls=0;
    CHECK(native_append_response_body(&runtime,&native,NULL,0,&error)==1 && calls==0);
    return 0;
}
'''


class NativeResultEventProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("a C compiler is required for native/event protocol tests")
        temporary_root = os.environ.get("TMP_ROOT")
        if temporary_root:
            Path(temporary_root).mkdir(parents=True, exist_ok=True)
        tmp = tempfile.TemporaryDirectory(prefix="native-event-contract-", dir=temporary_root)
        cls.addClassCleanup(tmp.cleanup)
        directory = Path(tmp.name)
        cls.event_binary = directory / "events"
        cls.callback_binary = directory / "callbacks"
        phase_source = (source_path('common/src/transaction_state.c', root=ROOT)).read_text(encoding="utf-8")
        # These definitions already include their return type on the name line.
        # Adding another return type creates invalid C before any test can run.
        phase = '#include "msconnector/transaction_state.h"\n' + function_definition(phase_source, "msconnector_phase_name")
        (directory / "phase.c").write_text(phase, encoding="utf-8")
        (directory / "events.c").write_text(EVENT_FIXTURE, encoding="utf-8")
        sources = ["event.c", "event_jsonl.c", "integrity_event.c", "http_status.c", "json_escape.c", "status.c"]
        common_args = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-I", str(source_path('common/include', root=ROOT))]
        result = subprocess.run(common_args + [str(directory / "events.c"), str(directory / "phase.c")] +
            [str(source_path('common/src', root=ROOT) / name) for name in sources] + ["-o", str(cls.event_binary)],
            capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError("event fixture compilation failed:\n" + result.stderr)
        runtime = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text(encoding="utf-8")
        definitions = "\n".join(function_definition(runtime, name) for name in
            ("native_append_request_body", "native_append_response_body", "native_finish_request_body", "native_finish_response_body"))
        (directory / "callbacks.c").write_text(CALLBACK_PREAMBLE + definitions + CALLBACK_MAIN, encoding="utf-8")
        result = subprocess.run(common_args + [str(directory / "callbacks.c"), "-o", str(cls.callback_binary)],
            capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError("callback fixture compilation failed:\n" + result.stderr)

    def run_event(self, scenario: str, connector: str = "common") -> dict:
        result = subprocess.run([str(self.event_binary), scenario, connector], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout) if result.stdout else {}

    def test_native_result_table(self) -> None:
        self.run_event("native")

    def test_real_runtime_callbacks_keep_partial_and_fail_final_errors(self) -> None:
        result = subprocess.run([str(self.callback_binary)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_family_identities_use_the_same_wire_contract(self) -> None:
        for scenario in ("error", "safe", "abort", "pending"):
            expected = None
            for family in ("apache", "nginx", "haproxy", "envoy", "traefik", "lighttpd"):
                with self.subTest(scenario=scenario, family=family):
                    event = self.run_event(scenario, family)
                    self.assertEqual(event.pop("connector"), family)
                    event.pop("event_hash")  # Connector identity intentionally changes the hash.
                    if expected is None:
                        expected = event
                    self.assertEqual(event, expected)

    def test_error_does_not_claim_rule_block_or_eos(self) -> None:
        event = self.run_event("error")
        self.assertEqual(event["status"], "error")
        self.assertEqual(event["event"], "invalid_engine_response")
        self.assertEqual(event["reason"], "invalid_engine_response")
        self.assertEqual(event["requested_action"], "error")
        self.assertEqual(event["actual_action"], "deny")
        self.assertEqual(event["rule_id"], "")
        self.assertFalse(event["eos_seen"])

    def test_safe_and_non_200_abort_are_truthful(self) -> None:
        safe = self.run_event("safe")
        self.assertEqual(safe["action"], "log_only")
        self.assertEqual(safe["requested_action"], "deny")
        self.assertEqual(safe["visible_http_status"], 200)
        self.assertEqual(safe["event"], "phase4_intervention")
        abort = self.run_event("abort")
        self.assertEqual(abort["visible_http_status"], 201)
        self.assertEqual(abort["message_id"], "MSCONN_EVENT_PHASE4_HARD_ABORT")
        self.assertNotIn("HTTP 200", abort["message"])

    def test_pending_decision_and_custom_event(self) -> None:
        pending = self.run_event("pending")
        self.assertEqual(pending["event"], "engine_decision")
        self.assertEqual(pending["actual_action"], "")
        self.assertEqual(pending["visible_http_status"], 0)
        custom = self.run_event("custom")
        self.assertEqual(custom["event"], "application_event")
        self.assertEqual(custom["message"], "application text")

    def test_normalization_cannot_hide_invalid_or_lossy_input(self) -> None:
        for scenario in ("invalid", "small", "null", "escape-overflow"):
            self.run_event(scenario)

    def test_malformed_byte_escape_preserves_value_phase_and_integrity(self) -> None:
        event = self.run_event("byte-escape")
        self.assertEqual(event["client_ip"], "127.0.0.\u0080")
        self.assertEqual(event["phase"], "response_body")
        self.assertFalse(event["truncated"])
        self.assertEqual(event["previous_event_hash"], 17)
        self.assertNotEqual(event["event_hash"], 0)


class NativeResultWiringTests(unittest.TestCase):
    def test_native_byte_append_owners_use_shared_semantics(self) -> None:
        owners = {
            "common/runtime/msconnector_runtime.c": ("native_append_request_body", "native_append_response_body"),
            "connectors/apache/src/msc_filters.c": ("apache_input_filter_process_bucket", "apache_phase4_append_bucket"),
            "connectors/nginx/src/ngx_http_modsecurity_body_filter.c": ("ngx_http_modsecurity_append_response_body_chunk",),
            "connectors/haproxy/src/haproxy_modsecurity_binding.c": ("append_body_chunk", "process_request_body"),
        }
        for relative, names in owners.items():
            source = (ROOT / relative).read_text(encoding="utf-8")
            for name in names:
                with self.subTest(path=relative, function=name):
                    self.assertIn("msconnector_native_body_append_can_continue", function_definition(source, name))
        header = (source_path('common/include/msconnector/native_result.h', root=ROOT)).read_text(encoding="utf-8")
        self.assertNotRegex(header, r"#define\s+msc_(?:append|process|intervention)")

    def test_runtime_consumer_families_share_the_native_owner(self) -> None:
        for relative in (
            "connectors/envoy/ext_proc/internal/processor/common_runtime_bridge.c",
            "connectors/traefik/src/traefik_engine_service.c",
            "connectors/lighttpd/stock_sidecar/stock_sidecar.c",
        ):
            with self.subTest(path=relative):
                self.assertIn("msconnector_runtime_transaction_append_response_body_chunk", (ROOT / relative).read_text(encoding="utf-8"))
        runtime = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text(encoding="utf-8")
        profile = function_definition(runtime, "msconnector_runtime_set_transaction_profile")
        self.assertIn("MSCONNECTOR_PHASE4_MODE_STRICT", profile)
        self.assertIn("strict_post_commit_action", profile)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
