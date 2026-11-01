"""Execute first-chunk checked accounting failures at actual P2/P4 boundaries.

Production append, contract and event serialization are compiled. Only native
append/logging/free callbacks are controlled; no live host or transport claim.
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
from modsecurity_connector_tests import test_i09_common_routes as common_fixture
from modsecurity_connector_tests.test_runtime_event_sink_failures import FUNCTIONS, INCLUDES

ROOT = connector_root()
PROFILES = (
    "envoy-ext-authz", "traefik-forwardauth", "haproxy-spoe-spop",
    "traefik-native-uds", "lighttpd-stock", "lighttpd-patched",
)
EXTRA_FUNCTIONS = (
    "transaction_mutable_runtime",
    "begin_contract_phase", "begin_companion_contract_phase",
    "begin_or_resume_streaming_body_phase", "append_request_body_to_engine",
    "msconnector_runtime_transaction_append_request_body_chunk",
    "append_response_body_to_engine", "validate_response_body_append",
    "append_response_body_chunk_internal", "msconnector_runtime_transaction_fail",
)
NATIVE_SEAMS = r'''
static int append_calls;
size_t msc_get_request_body_length(Transaction *transaction) {
    (void)transaction;
    /* These overflow/prior-error cases must fail before any native access. */
    abort();
}
int msconnector_modsecurity_append_request_body(msconnector_modsecurity_transaction *tx,
        const unsigned char *data, size_t size, msconnector_error *error) {
    (void)tx; (void)data; (void)size; (void)error; ++append_calls; return 1;
}
int msconnector_modsecurity_append_response_body(msconnector_modsecurity_transaction *tx,
        const unsigned char *data, size_t size, msconnector_error *error) {
    (void)tx; (void)data; (void)size; (void)error; ++append_calls; return 1;
}
int msconnector_modsecurity_append_response_body_companion(msconnector_modsecurity_transaction *tx,
        const unsigned char *data, size_t size, msconnector_error *error) {
    return msconnector_modsecurity_append_response_body(tx, data, size, error);
}
'''
BODY_MAIN = r'''
int main(int argc, char **argv) {
    msconnector_runtime runtime = {0};
    msconnector_runtime_transaction *tx = calloc(1U, sizeof(*tx));
    msconnector_error error;
    int phase, previous, companion, first, second, first_code, second_code;
    if (argc != 4 || tx == NULL) return 2;
    phase = atoi(argv[2]); previous = phase - 1;
    if (!prepare(&runtime, tx, argv[1], previous) ||
        msconnector_transaction_contract_complete_phase(&tx->contract,
            (enum msconnector_phase)previous, 105U) != 0) return 3;
    companion = msconnector_transaction_profile_phase_route(msconnector_profile_registry_find(argv[1]),
        (enum msconnector_phase)phase) == MSCONNECTOR_TRANSACTION_PHASE_ROUTE_COMPANION_REQUIRED;
    tx->completion.response_companion_handed_off = phase == MSCONNECTOR_PHASE_RESPONSE_BODY && companion;
    msconnector_body_policy_init(&runtime.body_policy);
    runtime.body_policy.request_body_mode = MSCONNECTOR_BODY_MODE_STREAMING;
    runtime.body_policy.response_body_mode = MSCONNECTOR_BODY_MODE_STREAMING;
    runtime.config.enable = MSCONNECTOR_BOOL_ON;
    tx->response_headers_processed = phase == MSCONNECTOR_PHASE_RESPONSE_BODY;
    if (strcmp(argv[3], "prior") == 0) {
        if (msconnector_runtime_transaction_fail(tx,
                MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT, &error) != 1) return 4;
    }
    /* Neither direction has a connector-owned inspection ceiling. SIZE_MAX
     * tests the real checked-accounting overflow path with a one-byte input;
     * no corresponding allocation or large buffer is created. */
    if (phase == MSCONNECTOR_PHASE_RESPONSE_BODY) tx->response_body.bytes_seen = SIZE_MAX;
    else tx->request_body.bytes_seen = SIZE_MAX;
    for (int attempt = 0; attempt < 2; ++attempt) {
        int result = phase == MSCONNECTOR_PHASE_REQUEST_BODY ?
            msconnector_runtime_transaction_append_request_body_chunk(tx,
                (const unsigned char *)"x", 1U, &error) :
            append_response_body_chunk_internal(tx,
                (const unsigned char *)"x", 1U, &error, companion);
        if (attempt == 0) { first = result; first_code = error.code; }
        else { second = result; second_code = error.code; }
    }
    if (!emit_contract_terminal_event(tx, &error) ||
        !emit_contract_terminal_event(tx, &error)) return 5;
    fflush(runtime.event_file);
    fputs(event_text, stdout);
    printf("{\"first\":%d,\"second\":%d,\"first_code\":%d,\"second_code\":%d,"
        "\"cause\":\"%s\",\"error_phase\":%d,\"completed\":%u,\"append_calls\":%d,"
        "\"request_finished\":%d,\"response_finished\":%d,\"body_bytes_seen\":%zu}\n", first, second,
        first_code, second_code, msconnector_transaction_error_class_name(tx->contract.error_class),
        tx->contract.error_phase, tx->contract.completed_phase_mask, append_calls,
        tx->request_body.finished, tx->response_body.finished,
        phase == MSCONNECTOR_PHASE_REQUEST_BODY ? tx->request_body.bytes_seen : tx->response_body.bytes_seen);
    msconnector_runtime_transaction_destroy(&tx);
    fclose(runtime.event_file); free(event_text); return 0;
}
'''


class RuntimeBodyPhaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = shlex.split(os.environ.get("CC", "cc"))
        if not cls.compiler or not shutil.which(cls.compiler[0]):
            raise RuntimeError("C compiler required")
        temporary = tempfile.TemporaryDirectory(prefix="i09-body-phase-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        source = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text(encoding="utf-8")
        types = source[source.index("#define RUNTIME_NAME_SIZE"):source.index("static void set_text_error")]
        names = tuple(dict.fromkeys((*FUNCTIONS, *EXTRA_FUNCTIONS)))
        definitions = [function_definition(source, name) for name in names]
        declarations = "\n".join(value[:value.index("{")] + ";" for value in definitions)
        includes = INCLUDES
        fixture = includes + types + NATIVE_SEAMS + declarations + "\n"
        fixture += "\n".join(definitions) + common_fixture.MAIN[:common_fixture.MAIN.index("int main(")] + BODY_MAIN
        cls.binary = common_fixture.CommonRouteErrorTests.compile.__func__(
            cls, "body-phase", fixture, common_fixture.SOURCES)

    def run_case(self, profile, phase, mode="overflow"):
        result = subprocess.run([str(self.binary), profile, str(phase), mode],
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        records = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(records), 2, "exactly one terminal event and state record")
        return records

    def test_first_overflow_keeps_body_phase_and_distinct_connector_error_event(self):
        for profile in PROFILES:
            for phase, expected in ((3, "request_body"), (5, "response_body")):
                with self.subTest(profile=profile, phase=expected):
                    event, state = self.run_case(profile, phase)
                    self.assertEqual(state["first"], 0)
                    self.assertEqual(state["second"], 0)
                    self.assertEqual(state["cause"], "connector_error")
                    self.assertEqual(state["error_phase"], phase)
                    self.assertEqual(state["append_calls"], 0)
                    self.assertEqual(state["request_finished"], int(phase == 5))
                    self.assertEqual(state["response_finished"], 0)
                    self.assertNotEqual(state["first_code"], 0)
                    self.assertNotEqual(state["second_code"], 0)
                    self.assertFalse(state["completed"] & (1 << (phase - 2)))
                    self.assertEqual(event["message_id"], "MSCONN_EVENT_CONNECTOR_ERROR")
                    self.assertEqual(event["event"], "connector_error")
                    self.assertEqual(event["phase"], expected)
                    self.assertEqual(event["status"], "error")
                    self.assertEqual(event["rule_id"], "")
                    self.assertEqual(event["actual_action"], "")
                    self.assertEqual(event["body_bytes_seen"], state["body_bytes_seen"])

    def test_prior_technical_failure_prevents_overflow_reclassification_or_native_reentry(self):
        for profile in PROFILES:
            for phase in (3, 5):
                with self.subTest(profile=profile, phase=phase):
                    event, state = self.run_case(profile, phase, "prior")
                    self.assertEqual(state["cause"], "engine_timeout")
                    self.assertEqual(state["append_calls"], 0)
                    self.assertEqual(state["first"], 0)
                    self.assertEqual(state["second"], 0)
                    self.assertEqual(event["message_id"], "MSCONN_EVENT_ENGINE_TIMEOUT")
                    self.assertEqual(event["phase"], "request_headers" if phase == 3 else "response_headers")
                    self.assertEqual(event["status"], "error")
                    self.assertEqual(event["actual_action"], "")



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
