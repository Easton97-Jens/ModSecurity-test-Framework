"""Compile real begin, copying, event, and cleanup paths with a P1 engine seam.

The native callback is a deny stub. These tests verify metadata/lifetime and
cleanup boundaries, not physical HTTP reuse or native engine EOS behavior.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition
from modsecurity_connector_tests.test_i09_common_routes import SOURCES
from modsecurity_connector_tests.test_runtime_event_sink_failures import FUNCTIONS, INCLUDES

ROOT = connector_root()
EXTRA = (
    "handle_decision", "msconnector_runtime_transaction_cancel",
    "valid_trusted_provenance_text", "transaction_begin_internal",
    "msconnector_runtime_transaction_begin",
    "msconnector_runtime_transaction_begin_request_stream",
    "msconnector_runtime_transaction_begin_with_trusted_provenance",
    "msconnector_runtime_transaction_begin_request_stream_with_trusted_provenance",
)
SEAMS = r'''
static int native_calls;
static const char *fixture_mode;
static int validate_transaction_begin_request(msconnector_runtime *runtime,
    const msconnector_request *request, msconnector_decision *decision,
    msconnector_error *error) {
    (void)runtime; (void)request; (void)decision; (void)error; return 1;
}
static msconnector_runtime_transaction *create_runtime_transaction(
    msconnector_runtime *runtime, const msconnector_request *request,
    const char *host_request_id, msconnector_error *error) {
    (void)request; (void)host_request_id; (void)error;
    msconnector_runtime_transaction *tx = calloc(1U, sizeof(*tx));
    if (tx == NULL) return NULL;
    tx->runtime = runtime;
    strcpy(tx->metadata.transaction_id, "trusted-p1");
    msconnector_flow_guard_init(&tx->flow, tx->metadata.transaction_id);
    if (msconnector_transaction_contract_init(&tx->contract,
            msconnector_profile_registry_find("traefik-forwardauth"),
            tx->metadata.transaction_id, "traefik", "test",
            MSCONNECTOR_TRANSACTION_MODE_SAFE, 1U) != 0) abort();
    return tx;
}
static int begin_native_transaction(msconnector_runtime_transaction *tx,
    const msconnector_request *request, msconnector_decision *decision,
    msconnector_error *error) {
    (void)request; ++native_calls; tx->native_started = 1;
    if (msconnector_transaction_contract_begin_phase(&tx->contract,
            MSCONNECTOR_PHASE_REQUEST_HEADERS, 2U) != 0 ||
        msconnector_transaction_contract_complete_phase(&tx->contract,
            MSCONNECTOR_PHASE_REQUEST_HEADERS, 3U) != 0) abort();
    if (strcmp(fixture_mode, "allow") == 0 || strcmp(fixture_mode, "cancel") == 0) {
        int terminal;
        msconnector_decision_set_allow(decision);
        decision->phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
        if (!handle_decision(tx, decision, error, &terminal)) return 0;
        if (strcmp(fixture_mode, "allow") == 0) {
            if (msconnector_transaction_contract_begin_phase(&tx->contract,
                    MSCONNECTOR_PHASE_REQUEST_BODY, 4U) != 0 ||
                msconnector_transaction_contract_complete_phase(&tx->contract,
                    MSCONNECTOR_PHASE_REQUEST_BODY, 5U) != 0) abort();
            tx->request_body.finished = 1;
            decision->phase = MSCONNECTOR_PHASE_REQUEST_BODY;
            return handle_decision(tx, decision, error, &terminal);
        }
        return 1;
    }
    if (msconnector_transaction_contract_record_decision(&tx->contract,
            MSCONNECTOR_TRANSACTION_DECISION_BLOCK, "12345", 4U) != 0) abort();
    tx->request_blocked = 1;
    msconnector_decision_set_deny(decision, 403, "12345", "P1 fixture");
    decision->phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
    return emit_decision_event(tx, decision, NULL, error);
}
static int abort_transaction_begin(msconnector_runtime_transaction **out) {
    msconnector_runtime_transaction_destroy(out); return 0;
}
'''
MAIN = r'''
int main(int argc, char **argv) {
    msconnector_runtime runtime = {0};
    msconnector_runtime_transaction *tx = NULL;
    msconnector_runtime_transaction_snapshot snapshot;
    msconnector_request request = {0};
    msconnector_decision decision;
    msconnector_error error;
    char run[] = "run-1", transport_case[] = "case-1", connection[] = "opaque-1";
    msconnector_runtime_trusted_provenance provenance = {run, transport_case, connection, 0};
    char *events = NULL;
    size_t events_size = 0;
    if (argc != 2) return 2;
    fixture_mode = argv[1];
    msconnector_resource_limits_init(&runtime.limits);
    runtime.config.phase4_mode = MSCONNECTOR_PHASE4_MODE_SAFE;
    strcpy(runtime.connector_name, "traefik");
    strcpy(runtime.integration_mode, "forwardAuth");
    atomic_flag_clear(&runtime.operation_lock);
    runtime.event_file = open_memstream(&events, &events_size);
    if (runtime.event_file == NULL) return 3;
    if (strcmp(argv[1], "bad-token") == 0) provenance.run_id = "bad value";
    if (strcmp(argv[1], "bad-reuse") == 0) provenance.connection_reused = 2;
    if (strcmp(argv[1], "missing") == 0) provenance.connection_id = NULL;
    int result = strcmp(argv[1], "old") == 0 ?
        msconnector_runtime_transaction_begin_request_stream(&runtime, &request,
            NULL, &tx, &decision, &error) :
        msconnector_runtime_transaction_begin_request_stream_with_trusted_provenance(
            &runtime, &request, NULL, &provenance, &tx, &decision, &error);
    if (result) {
        memset(run, 'x', sizeof(run)-1U);
        memset(transport_case, 'x', sizeof(transport_case)-1U);
        memset(connection, 'x', sizeof(connection)-1U);
        /* The event flag must reflect this runtime state, not the caller's
         * identity strings, socket EOF, or cancellation label. */
        if (strcmp(argv[1], "eos") == 0) tx->request_body.finished = 1;
        if (strcmp(argv[1], "cancel") == 0 &&
            !msconnector_runtime_transaction_cancel(tx, 0, &error)) return 8;
        if (strcmp(argv[1], "allow") == 0 &&
            !msconnector_runtime_transaction_cancel(tx, 1, &error)) return 9;
        if (!emit_decision_event(tx, &decision, NULL, &error)) return 4;
        if (strcmp(argv[1], "cleanup-io") == 0) {
            if (!msconnector_runtime_transaction_finish(tx, &error)) return 5;
            FILE *saved = runtime.event_file;
            runtime.event_file = fopen("/dev/full", "w");
            if (runtime.event_file == NULL) return 6;
            int finalized = msconnector_runtime_transaction_finalize_and_snapshot(&tx, &snapshot, &error);
            printf("{\"result\":%d,\"code\":%d,\"io\":%d,\"cleanup\":%d,\"kept\":%d}\n",
                finalized, error.code, MSCONNECTOR_ERROR_IO, cleanup_calls, tx != NULL);
            fclose(runtime.event_file); runtime.event_file = saved;
            msconnector_runtime_transaction_destroy(&tx);
        } else {
            if (!msconnector_runtime_transaction_finalize_and_snapshot(&tx, &snapshot, &error)) return 7;
            printf("{\"result\":1,\"native\":%d,\"cleanup\":%d,\"audit\":%d}\n",
                native_calls, cleanup_calls, audit_calls);
        }
    } else printf("{\"result\":0,\"native\":%d}\n", native_calls);
    fflush(runtime.event_file);
    fputs(events, stdout);
    fclose(runtime.event_file); free(events);
    return 0;
}
'''


class RuntimeTrustedProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="trusted-provenance-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        source = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text()
        types = source[source.index("#define RUNTIME_NAME_SIZE"):source.index("static void set_text_error")]
        definitions = [function_definition(source, name) for name in FUNCTIONS + EXTRA]
        declarations = "\n".join(value[:value.index("{")] + ";" for value in definitions)
        text = INCLUDES + types + declarations + SEAMS + "\n".join(definitions) + MAIN
        cls.binaries = {}
        for variant in ("current", "missing-copy"):
            candidate = text
            if variant == "missing-copy":
                anchor = "if (provenance != NULL) {\n        memcpy(transaction->provenance.run_id"
                if candidate.count(anchor) != 1:
                    raise AssertionError("copy negative-control anchor drift")
                candidate = candidate.replace(anchor, "if (0) {\n        memcpy(transaction->provenance.run_id", 1)
            fixture = directory / (variant + ".c")
            fixture.write_text(candidate)
            binary = directory / variant
            command = shlex.split(os.environ.get("CC", "cc")) + [
                "-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                "-I", str(source_path('common/include', root=ROOT)), "-I", str(ROOT), str(fixture),
            ] + [str(source_path('common/src', root=ROOT) / name) for name in SOURCES]
            command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(binary)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=90)
            if result.returncode:
                raise AssertionError(result.stderr[-6000:])
            cls.binaries[variant] = binary

    def run_case(self, case="valid", variant="current"):
        result = subprocess.run([str(self.binaries[variant]), case], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = [json.loads(line) for line in result.stdout.splitlines()]
        return lines[0], lines[1:]

    def test_provenance_precedes_p1_and_is_deep_copied(self):
        result, events = self.run_case()
        self.assertEqual(result, {"result": 1, "native": 1, "cleanup": 1, "audit": 1})
        self.assertGreaterEqual(len(events), 3)
        for event in events:
            self.assertEqual(event["run_id"], "run-1")
            self.assertEqual(event["transport_case_id"], "case-1")
            self.assertEqual(event["connection_id"], "opaque-1")
            self.assertFalse(event["connection_reused"])
        self.assertEqual(events[0]["phase"], "request_headers")
        self.assertEqual(events[-1]["event"], "transaction_cleanup")
        self.assertEqual(events[-1]["cleanup_reason"], "normal")
        self.assertFalse(events[-1]["eos_seen"])
        self.assertEqual([e["sequence"] for e in events], list(range(1, len(events)+1)))

    def test_eos_flag_uses_runtime_state(self):
        _, events = self.run_case("eos")
        self.assertFalse(events[0]["eos_seen"])
        self.assertTrue(events[-1]["eos_seen"])

    def test_allow_p1_and_p2_are_observable_without_inventing_rule_decisions(self):
        result, events = self.run_case("allow")
        self.assertEqual(result["cleanup"], 1)
        self.assertEqual(events[0]["phase"], "request_headers")
        self.assertEqual(events[0]["action"], "allow")
        self.assertEqual(events[0]["message_id"], "MSCONN_EVENT_TRANSACTION_PHASE")
        self.assertFalse(events[0]["eos_seen"])
        self.assertTrue(events[1]["eos_seen"])
        self.assertEqual(events[-1]["cleanup_reason"], "upstream_disconnect")

    def test_cancel_records_lifecycle_reason_without_inventing_eos(self):
        result, events = self.run_case("cancel")
        self.assertEqual(result["cleanup"], 1)
        self.assertEqual(result["audit"], 1)
        self.assertEqual(events[-1]["cleanup_reason"], "client_cancel")
        self.assertFalse(events[-1]["eos_seen"])

    def test_invalid_binding_fails_before_native_p1(self):
        for case in ("bad-token", "bad-reuse", "missing"):
            with self.subTest(case=case):
                result, events = self.run_case(case)
                self.assertEqual(result, {"result": 0, "native": 0})
                self.assertEqual(events, [])

    def test_old_api_retains_null_behavior(self):
        _, events = self.run_case("old")
        self.assertTrue(all("run_id" not in event for event in events))
        self.assertFalse(any(event["event"] == "transaction_cleanup" for event in events))

    def test_cleanup_sink_failure_keeps_io_and_does_not_repeat_native_free(self):
        result, _ = self.run_case("cleanup-io")
        self.assertEqual(result["result"], 0)
        self.assertEqual(result["code"], result["io"])
        self.assertEqual(result["cleanup"], 1)
        self.assertEqual(result["kept"], 1)

    def test_compiled_missing_copy_control_exposes_gap(self):
        _, events = self.run_case(variant="missing-copy")
        self.assertNotIn("run_id", events[0])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
