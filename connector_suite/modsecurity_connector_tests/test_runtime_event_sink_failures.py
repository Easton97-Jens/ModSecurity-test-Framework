"""Exercise the actual runtime emitters, stdio writer and completion boundaries.

Common serialization, error mapping, allocation and lifecycle code are real.
GNU stdio cookies inject failures at the physical write boundary; only native
audit/free callbacks are replaced. This is not a live adapter/transport matrix.
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
RUNTIME = source_path('common/runtime/msconnector_runtime.c', root=ROOT)
FUNCTIONS = (
    "runtime_error", "replay_event_write_failure", "transaction_now_ms",
    "contract_error", "runtime_operation_lock", "runtime_operation_unlock",
    "valid_host_action", "valid_host_transport_result", "bounded_c_string",
    "phase4_mode_name", "utc_calendar_time", "timestamp_now",
    "populate_event_body", "populate_event_response_state", "populate_event_host_action",
    "write_event_jsonl", "write_transaction_event_jsonl",
    "emit_integrity_chained_event_locked", "emit_decision_event",
    "contract_terminal_message_id", "contract_terminal_phase", "contract_terminal_http_status",
    "emit_contract_terminal_event", "msconnector_runtime_transaction_record_host_action",
    "reserve_cleanup_event_sequence", "emit_cleanup_event",
    "msconnector_runtime_transaction_snapshot_get", "runtime_transaction_cleanup_checked",
    "runtime_transaction_cleanup_best_effort", "msconnector_runtime_transaction_finalize_and_snapshot",
    "finish_transaction_with_logging", "prepare_transaction_finish",
    "msconnector_runtime_transaction_finish_host_rejected_request_body",
    "msconnector_runtime_transaction_finish", "msconnector_runtime_transaction_destroy",
)
INCLUDES = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "common/runtime/msconnector_runtime.h"
#include "msconnector/config.h"
#include "msconnector/dos_guard.h"
#include "msconnector/event_jsonl.h"
#include "msconnector/flow_guard.h"
#include "msconnector/http_status.h"
#include "msconnector/integrity_event.h"
#include "msconnector/memory.h"
#include "msconnector/modsecurity_engine.h"
#include "connectors/profile_registry.h"
typedef void Transaction;
typedef void ModSecurity;
static int audit_calls, cleanup_calls;
int msconnector_modsecurity_process_logging(msconnector_modsecurity_transaction *tx,
        msconnector_error *error) {
    (void)tx; (void)error; ++audit_calls; return 1;
}
void msconnector_modsecurity_transaction_cleanup(msconnector_modsecurity_transaction *tx) {
    (void)tx; ++cleanup_calls;
}
'''
MAIN = r'''
typedef struct {
    int calls;
    int failure;
    size_t accepted;
} sink_state;

static ssize_t sink_write(void *opaque, const char *data, size_t size) {
    sink_state *sink = opaque;
    (void)data;
    ++sink->calls;
    if (sink->failure == 1) { errno = ENOSPC; return -1; }
    if (sink->failure == 2) {
        sink->accepted += size / 2U;
        return (ssize_t)(size / 2U);
    }
    sink->accepted += size;
    return (ssize_t)size;
}

static int prepare(msconnector_runtime *runtime,
        msconnector_runtime_transaction *tx, int committed) {
    const msconnector_transaction_profile *profile =
        msconnector_profile_registry_find("lighttpd-stock");
    msconnector_resource_limits_init(&runtime->limits);
    runtime->config.default_error_status = 500;
    runtime->config.phase4_mode = MSCONNECTOR_PHASE4_MODE_SAFE;
    strcpy(runtime->connector_name, "common");
    strcpy(runtime->integration_mode, "compiled-runtime-sink");
    atomic_flag_clear(&runtime->operation_lock);
    tx->runtime = runtime;
    strcpy(tx->metadata.transaction_id, "sink-regression");
    strcpy(tx->metadata.request_method, "GET");
    strcpy(tx->metadata.request_uri, "/resource?password=fixture-value");
    msconnector_flow_guard_init(&tx->flow, tx->metadata.transaction_id);
    if (msconnector_transaction_contract_init(&tx->contract, profile,
            tx->metadata.transaction_id, "common", "fixture",
            MSCONNECTOR_TRANSACTION_MODE_SAFE, 100U) !=
            MSCONNECTOR_TRANSACTION_TRANSITION_OK) { return 0; }
    for (enum msconnector_phase phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
            phase <= MSCONNECTOR_PHASE_RESPONSE_BODY; ++phase) {
        if (msconnector_transaction_contract_begin_phase(&tx->contract, phase, 101U) != 0 ||
            msconnector_transaction_contract_complete_phase(&tx->contract, phase, 102U) != 0) {
            return 0;
        }
        if (phase == MSCONNECTOR_PHASE_RESPONSE_HEADERS && committed &&
                msconnector_transaction_contract_set_response_committed(&tx->contract, 1) != 0) {
            return 0;
        }
    }
    tx->request_body.finished = 1;
    tx->response_body.finished = 1;
    tx->response_headers_processed = 1;
    tx->response_headers_sent = committed;
    tx->response_original_status = committed ? 200 : 0;
    tx->native_started = 1;
    return msconnector_transaction_contract_fail(&tx->contract,
        MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE, 103U) == 0;
}

int main(int argc, char **argv) {
    msconnector_runtime runtime = {0};
    msconnector_runtime_transaction *tx = calloc(1U, sizeof(*tx));
    msconnector_runtime_transaction_snapshot snapshot;
    msconnector_decision decision;
    msconnector_error error;
    sink_state sink = {0};
    cookie_io_functions_t functions = { .write = sink_write };
    int first, again, terminal, finish, rejected, finalized;
    int first_code, again_code, finish_code, snapshot_code;
    int first_calls, final_calls, before_cleanup, attempted, retained;
    unsigned long sequence;
    uint64_t hash_before;
    int cause;
    if (argc != 3 || tx == NULL) { free(tx); return 2; }
    if (!prepare(&runtime, tx, strcmp(argv[2], "after") == 0)) { free(tx); return 3; }
    runtime.event_file = fopencookie(&sink, "w", functions);
    if (runtime.event_file == NULL) { free(tx); return 4; }
    if (setvbuf(runtime.event_file, NULL,
            strcmp(argv[1], "flush") == 0 ? _IOFBF : _IONBF, 0U) != 0) {
        fclose(runtime.event_file); free(tx); return 5;
    }
    msconnector_error_init(&error);
    msconnector_decision_set_error(&decision, 500, "fixture failure");
    decision.phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
    if (strcmp(argv[1], "followup") == 0) {
        if (!emit_contract_terminal_event(tx, &error)) {
            fclose(runtime.event_file); free(tx); return 6;
        }
    }
    hash_before = runtime.previous_event_hash;
    if (strcmp(argv[1], "serialize") == 0) {
        runtime.limits.max_event_json_bytes = 1U;
    } else if (strcmp(argv[1], "lossy-field") == 0) {
        memset(tx->metadata.request_client_ip, 0x80, 11U);
        tx->metadata.request_client_ip[11] = '\0';
    } else if (strcmp(argv[1], "short") == 0) {
        sink.failure = 2;
    } else if (strcmp(argv[1], "success") != 0) {
        sink.failure = 1;
    }
    first = emit_decision_event(tx, &decision, NULL,
        strcmp(argv[1], "null-error") == 0 ? NULL : &error);
    first_code = tx->event_write_failed;
    first_calls = sink.calls;
    sequence = tx->flow.sequence;
    msconnector_error_init(&error);
    again = emit_decision_event(tx, &decision, NULL, &error);
    again_code = error.code;
    terminal = emit_contract_terminal_event(tx, &error);
    msconnector_error_init(&error);
    finish = msconnector_runtime_transaction_finish(tx, &error);
    finish_code = error.code;
    rejected = msconnector_runtime_transaction_finish_host_rejected_request_body(tx, &error);
    before_cleanup = audit_calls;
    attempted = tx->completion.finish_attempted;
    final_calls = sink.calls;
    cause = tx->contract.error_class;
    retained = runtime.previous_event_hash == hash_before && tx->flow.sequence == sequence;
    msconnector_error_init(&error);
    finalized = msconnector_runtime_transaction_finalize_and_snapshot(&tx, &snapshot, &error);
    snapshot_code = error.code;
    printf("{\"first\":%d,\"again\":%d,\"terminal\":%d,\"finish\":%d,"
        "\"rejected\":%d,\"finalized\":%d,\"first_code\":%d,\"again_code\":%d,"
        "\"finish_code\":%d,\"snapshot_code\":%d,\"io\":%d,\"too_large\":%d,"
        "\"first_calls\":%d,\"final_calls\":%d,\"audit\":%d,\"attempted\":%d,"
        "\"retained\":%d,\"cause\":%d,\"engine_cause\":%d,\"pointer_kept\":%d,",
        first, again, terminal, finish, rejected, finalized, first_code, again_code,
        finish_code, snapshot_code, MSCONNECTOR_ERROR_IO, MSCONNECTOR_ERROR_EVENT_TOO_LARGE,
        first_calls, final_calls, before_cleanup, attempted, retained, cause,
        MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE, tx != NULL);
    msconnector_runtime_transaction_destroy(&tx);
    printf("\"cleanup\":%d,\"destroyed\":%d}\n", cleanup_calls, tx == NULL);
    /* The stream belongs to the runtime, not the destroyed transaction. */
    sink.failure = 0;
    clearerr(runtime.event_file);
    (void)fclose(runtime.event_file);
    return 0;
}
'''


class RuntimeEventSinkFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("a C compiler is required for runtime sink tests")
        temporary = tempfile.TemporaryDirectory(prefix="runtime-event-sink-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        source = RUNTIME.read_text(encoding="utf-8")
        types = source[source.index("#define RUNTIME_NAME_SIZE"):source.index("static void set_text_error")]
        definitions = [function_definition(source, name) for name in FUNCTIONS]
        declarations = "\n".join(value[:value.index("{")] + ";" for value in definitions)
        fixture_text = INCLUDES + types + declarations + "\n" + "\n".join(definitions) + MAIN
        sources = (
            "transaction_state.c", "decision.c", "decision_action.c", "intervention.c",
            "block_statuses.c", "http_status.c", "error.c", "status.c", "event.c",
            "event_jsonl.c", "integrity_event.c", "json_escape.c", "memory.c",
            "body_policy.c", "flow_guard.c", "dos_guard.c", "resource_limits.c", "rule_id.c",
        )
        cls.binaries = {}
        for variant in ("current", "old-classification"):
            text = fixture_text
            if variant == "old-classification":
                before = "return runtime_error(error, transaction->event_write_failed,"
                if text.count(before) != 1:
                    raise AssertionError("failure replay negative-control anchor drifted")
                text = text.replace(before, "return runtime_error(error, MSCONNECTOR_ERROR_EVENT_TOO_LARGE,", 1)
            fixture = directory / (variant + ".c")
            fixture.write_text(text, encoding="utf-8")
            binary = directory / variant
            command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                                  "-I", str(source_path('common/include', root=ROOT)), "-I", str(ROOT), str(fixture)]
            command += [str(source_path('common/src', root=ROOT) / name) for name in sources]
            command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(binary)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
            if result.returncode:
                raise AssertionError("runtime sink fixture compilation failed:\n" + result.stderr[-6000:])
            cls.binaries[variant] = binary

    def case(self, scenario: str, commitment: str = "after", variant: str = "current") -> dict:
        result = subprocess.run([str(self.binaries[variant]), scenario, commitment],
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        return json.loads(result.stdout)

    def assert_terminal_sink_failure(self, result: dict, expected: str = "io") -> None:
        for operation in ("first", "again", "terminal", "finish", "rejected", "finalized"):
            self.assertEqual(result[operation], 0, operation)
        for code in ("first_code", "again_code", "finish_code", "snapshot_code"):
            self.assertEqual(result[code], result[expected], code)
        self.assertEqual(result["first_calls"], result["final_calls"])
        self.assertEqual(result["retained"], 1)
        self.assertEqual(result["audit"], 0)
        self.assertEqual(result["attempted"], 0)
        self.assertEqual(result["cause"], result["engine_cause"])
        self.assertEqual(result["pointer_kept"], 1)
        self.assertEqual(result["cleanup"], 1)
        self.assertEqual(result["destroyed"], 1)

    def test_physical_write_error_retains_its_class_before_and_after_commit(self) -> None:
        for commitment in ("before", "after"):
            with self.subTest(commitment=commitment):
                self.assert_terminal_sink_failure(self.case("write", commitment))

    def test_flush_error_remains_io_not_serialization(self) -> None:
        self.assert_terminal_sink_failure(self.case("flush"))

    def test_short_write_does_not_complete_or_retry_the_event(self) -> None:
        self.assert_terminal_sink_failure(self.case("short"))

    def test_null_first_error_output_does_not_lose_the_cause(self) -> None:
        self.assert_terminal_sink_failure(self.case("null-error"))

    def test_serialization_limit_does_not_touch_the_physical_sink(self) -> None:
        result = self.case("serialize")
        self.assert_terminal_sink_failure(result, "too_large")
        self.assertEqual(result["first_calls"], 0)

    def test_lossy_field_does_not_write_chain_or_mask_the_first_cause(self) -> None:
        for commitment in ("before", "after"):
            with self.subTest(commitment=commitment):
                result = self.case("lossy-field", commitment)
                self.assert_terminal_sink_failure(result, "too_large")
                self.assertEqual(result["first_calls"], 0)

    def test_successful_terminal_event_does_not_mask_failed_followup(self) -> None:
        result = self.case("followup")
        self.assert_terminal_sink_failure(result)
        self.assertGreater(result["first_calls"], 1)

    def test_successful_sink_keeps_existing_completion_and_cleanup(self) -> None:
        result = self.case("success")
        for operation in ("first", "again", "terminal", "finish", "rejected", "finalized"):
            self.assertEqual(result[operation], 1, operation)
        self.assertEqual(result["first_code"], 0)
        self.assertEqual(result["audit"], 1)
        self.assertEqual(result["cleanup"], 1)
        self.assertEqual(result["pointer_kept"], 0)

    def test_compiled_old_classification_control_reproduces_original_defect(self) -> None:
        result = self.case("write", variant="old-classification")
        self.assertEqual(result["first_code"], result["io"])
        self.assertEqual(result["again_code"], result["too_large"])
        self.assertNotEqual(result["again_code"], result["io"])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
