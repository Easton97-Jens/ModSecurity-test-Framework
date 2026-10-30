"""Compile real Common error/event/lifecycle seams; no live host claims."""
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
from modsecurity_connector_tests.test_runtime_event_sink_failures import FUNCTIONS, INCLUDES

ROOT = connector_root()
SOURCES = (
    "transaction_state.c", "decision.c", "decision_action.c", "intervention.c",
    "block_statuses.c", "http_status.c", "error.c", "status.c", "event.c",
    "event_jsonl.c", "integrity_event.c", "json_escape.c", "memory.c",
    "body_policy.c", "flow_guard.c", "dos_guard.c", "resource_limits.c", "rule_id.c",
)
MAIN = r'''
static char *event_text;
static size_t event_text_size;
static int prepare(msconnector_runtime *runtime, msconnector_runtime_transaction *tx,
        const char *profile_name, int phase) {
    const msconnector_transaction_profile *profile = msconnector_profile_registry_find(profile_name);
    msconnector_resource_limits_init(&runtime->limits);
    runtime->config.default_error_status = 500;
    runtime->config.phase4_mode = MSCONNECTOR_PHASE4_MODE_SAFE;
    strcpy(runtime->connector_name, "common");
    strcpy(runtime->integration_mode, "compiled-i09-route");
    atomic_flag_clear(&runtime->operation_lock);
    runtime->event_file = open_memstream(&event_text, &event_text_size);
    if (runtime->event_file == NULL || profile == NULL) return 0;
    tx->runtime = runtime;
    strcpy(tx->metadata.transaction_id, "i09-regression");
    msconnector_flow_guard_init(&tx->flow, tx->metadata.transaction_id);
    if (msconnector_transaction_contract_init(&tx->contract, profile, tx->metadata.transaction_id,
            "common", "fixture", MSCONNECTOR_TRANSACTION_MODE_SAFE, 100U) != 0) return 0;
    for (int p = MSCONNECTOR_PHASE_REQUEST_HEADERS; p <= phase; ++p) {
        int companion = msconnector_transaction_profile_phase_route(profile, (enum msconnector_phase)p) ==
            MSCONNECTOR_TRANSACTION_PHASE_ROUTE_COMPANION_REQUIRED;
        if (p == MSCONNECTOR_PHASE_RESPONSE_HEADERS && companion) {
            if (msconnector_transaction_contract_handoff_response_companion(&tx->contract, 101U) != 0 ||
                msconnector_transaction_contract_claim_response_companion(&tx->contract, 102U) != 0) return 0;
        }
        if ((companion ? msconnector_transaction_contract_begin_companion_phase(&tx->contract,
                (enum msconnector_phase)p, 103U) : msconnector_transaction_contract_begin_phase(
                &tx->contract, (enum msconnector_phase)p, 103U)) != 0) return 0;
        if (p < phase || phase == MSCONNECTOR_PHASE_RESPONSE_BODY + 1) {
            if (msconnector_transaction_contract_complete_phase(&tx->contract,
                    (enum msconnector_phase)p, 104U) != 0) return 0;
        }
    }
    tx->request_body.finished = phase > MSCONNECTOR_PHASE_REQUEST_BODY;
    tx->response_headers_processed = phase > MSCONNECTOR_PHASE_RESPONSE_HEADERS;
    tx->response_body.finished = phase > MSCONNECTOR_PHASE_RESPONSE_BODY;
    return 1;
}

int main(int argc, char **argv) {
    msconnector_runtime runtime = {0};
    msconnector_runtime_transaction *tx = calloc(1U, sizeof(*tx));
    msconnector_error error;
    int first, second, first_code, second_code, phase, cause;
    if (argc != 5 || tx == NULL) return 2;
    phase = atoi(argv[3]);
    cause = atoi(argv[4]);
    if (strcmp(argv[2], "logging") == 0) {
        /* Complete each business phase before the once-only native audit. */
        if (!prepare(&runtime, tx, argv[1], MSCONNECTOR_PHASE_RESPONSE_BODY)) return 3;
        if (msconnector_transaction_contract_complete_phase(&tx->contract,
                MSCONNECTOR_PHASE_RESPONSE_BODY, 105U) != 0) return 4;
        tx->request_body.finished = tx->response_headers_processed = tx->response_body.finished = 1;
        tx->native_started = 1;
        audit_failure = 1;
        first = msconnector_runtime_transaction_finish(tx, &error);
        first_code = error.code;
        second = msconnector_runtime_transaction_finish(tx, &error);
        second_code = error.code;
    } else {
        if (!prepare(&runtime, tx, argv[1], phase)) return 5;
        tx->native_started = 1;
        if (strcmp(argv[2], "native-first") == 0) {
            if (msconnector_transaction_contract_fail(&tx->contract,
                    MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE, 105U) != 0) return 6;
        }
        first = msconnector_runtime_transaction_fail(tx,
            (msconnector_transaction_error_class)cause, &error);
        first_code = error.code;
        second = msconnector_runtime_transaction_fail(tx,
            MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR, &error);
        second_code = error.code;
        if (!emit_contract_terminal_event(tx, &error)) return 7;
    }
    fflush(runtime.event_file);
    fputs(event_text, stdout);
    printf("{\"first\":%d,\"second\":%d,\"first_code\":%d,\"second_code\":%d,"
        "\"cause\":%d,\"audit\":%d,\"completed\":%u,\"finished\":%d,",
        first, second, first_code, second_code, tx->contract.error_class, audit_calls,
        tx->contract.completed_phase_mask, tx->completion.finished);
    msconnector_runtime_transaction_destroy(&tx);
    printf("\"cleanup\":%d,\"destroyed\":%d}\n", cleanup_calls, tx == NULL);
    fclose(runtime.event_file);
    free(event_text);
    return 0;
}
'''


class CommonRouteErrorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiler = shlex.split(os.environ.get("CC", "cc"))
        if not cls.compiler or shutil.which(cls.compiler[0]) is None:
            raise RuntimeError("C compiler required")
        cls.tmp = tempfile.TemporaryDirectory(prefix="i09-common-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.directory = Path(cls.tmp.name)
        source = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text()
        types = source[source.index("#define RUNTIME_NAME_SIZE"):source.index("static void set_text_error")]
        names = list(FUNCTIONS) + ["msconnector_runtime_transaction_fail"]
        definitions = [function_definition(source, name) for name in names]
        declarations = "\n".join(value[:value.index("{")] + ";" for value in definitions)
        includes = INCLUDES.replace("static int audit_calls, cleanup_calls;",
                                    "static int audit_calls, cleanup_calls, audit_failure;")
        includes = includes.replace("(void)tx; (void)error; ++audit_calls; return 1;",
            '(void)tx; ++audit_calls; if (audit_failure) { msconnector_error_set(error, '
            'MSCONNECTOR_ERROR_MODSECURITY_FAILURE, "native logging failed", "fixture"); return 0; } return 1;')
        cls.binary = cls.compile("runtime", includes + types + declarations + "\n" +
                                 "\n".join(definitions) + MAIN, SOURCES)

    @classmethod
    def compile(cls, name: str, text: str, sources: tuple[str, ...] = ()) -> Path:
        fixture, binary = cls.directory / (name + ".c"), cls.directory / name
        fixture.write_text(text)
        command = cls.compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                                  "-I", str(source_path('common/include', root=ROOT)), "-I", str(ROOT), str(fixture)]
        command += [str(source_path('common/src', root=ROOT) / value) for value in sources]
        if sources:
            command += [str(source_path('connectors/profile_registry.c', root=ROOT))]
        command += ["-o", str(binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)
        return binary

    def run_case(self, profile: str, mode: str, phase: int, cause: int) -> list[dict]:
        result = subprocess.run([str(self.binary), profile, mode, str(phase), str(cause)],
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines()]

    def test_native_first_error_still_emits_once_at_original_phase(self) -> None:
        for profile in ("envoy-ext-authz", "traefik-forwardauth", "haproxy-spoe-spop",
                        "traefik-native-uds", "lighttpd-stock", "lighttpd-patched"):
            for phase in (2, 3, 4, 5):
                with self.subTest(profile=profile, phase=phase):
                    records = self.run_case(profile, "native-first", phase, 1)
                    self.assertEqual(len(records), 2)
                    event, state = records
                    self.assertEqual(event["message_id"], "MSCONN_EVENT_INVALID_ENGINE_RESPONSE")
                    self.assertEqual(event["phase"], {2: "request_headers", 3: "request_body",
                                                     4: "response_headers", 5: "response_body"}[phase])
                    self.assertEqual(event["status"], "error")
                    self.assertEqual(event["rule_id"], "")
                    self.assertEqual(event["actual_action"], "")
                    self.assertEqual(state["first"], 1)
                    self.assertEqual(state["second"], 1)
                    self.assertEqual(state["finished"], 0)

    def test_logging_failure_is_typed_sticky_and_cleanup_runs_once(self) -> None:
        for profile in ("envoy-ext-authz", "traefik-forwardauth", "traefik-native-uds",
                        "lighttpd-stock", "lighttpd-patched"):
            with self.subTest(profile=profile):
                records = self.run_case(profile, "logging", 6, 1)
                self.assertEqual(len(records), 2)
                event, state = records
                self.assertEqual(event["message_id"], "MSCONN_EVENT_INVALID_ENGINE_RESPONSE")
                self.assertEqual(event["phase"], "logging")
                self.assertEqual(event["actual_action"], "")
                self.assertEqual(state["first"], 0)
                self.assertEqual(state["second"], 0)
                self.assertEqual(state["first_code"], 12)
                self.assertEqual(state["second_code"], 12)
                self.assertEqual(state["audit"], 1)
                self.assertEqual(state["cleanup"], 1)
                self.assertEqual(state["finished"], 0)

    def test_supported_error_causes_produce_distinct_once_only_events(self) -> None:
        causes = {
            2: "BODY_LIMIT", 4: "ENGINE_TIMEOUT", 5: "ENGINE_UNAVAILABLE",
            6: "INVALID_ENGINE_RESPONSE", 7: "CONNECTOR_ERROR", 8: "PROTOCOL_ERROR",
            9: "CLIENT_CANCEL", 10: "UPSTREAM_DISCONNECT",
        }
        for profile in ("envoy-ext-authz", "traefik-forwardauth", "haproxy-spoe-spop",
                        "traefik-native-uds", "lighttpd-stock", "lighttpd-patched"):
            for cause, event_id in causes.items():
                with self.subTest(profile=profile, cause=event_id):
                    records = self.run_case(profile, "explicit", 3, cause)
                    self.assertEqual(len(records), 2)
                    event, state = records
                    self.assertEqual(event["message_id"], "MSCONN_EVENT_" + event_id)
                    self.assertEqual(event["status"], "blocked" if cause == 2 else "error")
                    self.assertEqual(event["requested_action"], "deny" if cause == 2 else "error")
                    self.assertEqual(event["phase"], "request_body")
                    self.assertEqual(event["actual_action"], "")
                    self.assertEqual(event["rule_id"], "")
                    self.assertEqual(state["cause"], cause)
                    self.assertEqual(state["cleanup"], 1)

    def test_companion_native_failure_classifier(self) -> None:
        source = (source_path('common/runtime/response_companion_transport.c', root=ROOT)).read_text()
        function = function_definition(source, "response_companion_error_class_from_error")
        fixture = ('#include "common/runtime/msconnector_runtime.h"\n'
                   'static msconnector_transaction_error_class\n') + function + r'''
int main(void) {
    msconnector_error error = {MSCONNECTOR_ERROR_MODSECURITY_FAILURE, "native", "fixture"};
    if (response_companion_error_class_from_error(&error) !=
        MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE) return 1;
    error.code = MSCONNECTOR_ERROR_BODY_TOO_LARGE;
    if (response_companion_error_class_from_error(&error) !=
        MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT) return 2;
    error.code = MSCONNECTOR_ERROR_HOST_API_FAILURE;
    return response_companion_error_class_from_error(&error) ==
        MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR ? 0 : 3;
}
'''
        binary = self.compile("classifier", fixture)
        result = subprocess.run([str(binary)], timeout=10, check=False)
        self.assertEqual(result.returncode, 0)

    def test_engine_callback_results_and_logging_reentry(self) -> None:
        fixture = r'''
#include "msconnector/modsecurity_engine.h"
#include "connectors/profile_registry.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int native_result, calls, cleanup;
static int init(void *u, msconnector_error *e) { (void)u; (void)e; return 1; }
static void *new_tx(void *u, void *r, const char *id, msconnector_error *e) {
    (void)u; (void)r; (void)id; (void)e; return &calls;
}
static void free_tx(void *u, void *t) { (void)u; (void)t; ++cleanup; }
static int outcome(msconnector_error *e) {
    ++calls;
    if (native_result != 1) msconnector_error_set(e, MSCONNECTOR_ERROR_MODSECURITY_FAILURE,
        "injected engine result", "fixture");
    return native_result;
}
static int request(void *u, void *t, const msconnector_request *r,
        msconnector_decision *d, msconnector_error *e) {
    (void)u; (void)t; (void)r; msconnector_decision_set_allow(d); return outcome(e);
}
static int response(void *u, void *t, const msconnector_response *r,
        msconnector_decision *d, msconnector_error *e) {
    (void)u; (void)t; (void)r; msconnector_decision_set_allow(d); return outcome(e);
}
static int append(void *u, void *t, const unsigned char *b, size_t n, msconnector_error *e) {
    (void)u; (void)t; (void)b; (void)n; return outcome(e);
}
static int finish(void *u, void *t, msconnector_decision *d, msconnector_error *e) {
    (void)u; (void)t; msconnector_decision_set_allow(d); return outcome(e);
}
static int logging(void *u, void *t, msconnector_error *e) {
    (void)u; (void)t; return outcome(e);
}
int main(int argc, char **argv) {
    msconnector_modsecurity_engine engine;
    msconnector_modsecurity_transaction tx;
    msconnector_transaction_contract owner;
    msconnector_modsecurity_engine_ops ops = {.init=init, .new_transaction=new_tx,
        .free_transaction=free_tx, .process_connection=request, .process_request_headers=request, .append_request_body=append,
        .finish_request_body=finish, .process_response_headers=response, .append_response_body=append,
        .finish_response_body=finish, .process_logging=logging};
    msconnector_decision decision;
    msconnector_error error;
    msconnector_error *error_out;
    msconnector_request req = {0};
    msconnector_response res = {0};
    int phase, first, again, before, companion;
    const msconnector_transaction_profile *profile;
    if (argc != 6) return 2;
    error_out = strcmp(argv[5], "null") == 0 ? NULL : &error;
    profile = msconnector_profile_registry_find(argv[1]);
    phase = atoi(argv[2]); native_result = atoi(argv[3]);
    msconnector_error_init(&error);
    msconnector_modsecurity_engine_init(&engine, &ops);
    if (!msconnector_modsecurity_engine_start(&engine, &error)) return 3;
    engine.rules_set = &calls;
    if (!msconnector_modsecurity_transaction_init(&tx, &engine, "i09-engine", &error)) return 4;
    if (msconnector_transaction_contract_init(&owner, profile, "i09-owner", NULL, NULL,
            MSCONNECTOR_TRANSACTION_MODE_SAFE, 100U) != 0) return 5;
    msconnector_modsecurity_transaction_bind_contract(&tx, &owner);
    for (int p = MSCONNECTOR_PHASE_REQUEST_HEADERS; p < phase && p <= MSCONNECTOR_PHASE_RESPONSE_BODY; ++p) {
        int c = msconnector_transaction_profile_phase_route(profile, (enum msconnector_phase)p) ==
            MSCONNECTOR_TRANSACTION_PHASE_ROUTE_COMPANION_REQUIRED;
        if (p == MSCONNECTOR_PHASE_RESPONSE_HEADERS && c) {
            if (msconnector_transaction_contract_handoff_response_companion(&owner, 101U) != 0 ||
                msconnector_transaction_contract_claim_response_companion(&owner, 102U) != 0) return 6;
        }
        if ((c ? msconnector_transaction_contract_begin_companion_phase(&owner, (enum msconnector_phase)p, 103U) :
                msconnector_transaction_contract_begin_phase(&owner, (enum msconnector_phase)p, 103U)) != 0 ||
                msconnector_transaction_contract_complete_phase(&owner, (enum msconnector_phase)p, 104U) != 0) return 7;
    }
    companion = msconnector_transaction_profile_phase_route(profile, (enum msconnector_phase)phase) ==
        MSCONNECTOR_TRANSACTION_PHASE_ROUTE_COMPANION_REQUIRED;
    if (phase == MSCONNECTOR_PHASE_RESPONSE_HEADERS && companion) {
        if (msconnector_transaction_contract_handoff_response_companion(&owner, 105U) != 0 ||
            msconnector_transaction_contract_claim_response_companion(&owner, 106U) != 0) return 8;
    }
    msconnector_decision_set_allow(&decision);
    if (strcmp(argv[4], "terminal-error") == 0) {
        if ((companion ? msconnector_transaction_contract_begin_companion_phase(&owner,
                (enum msconnector_phase)phase, 107U) : msconnector_transaction_contract_begin_phase(
                &owner, (enum msconnector_phase)phase, 107U)) != 0) return 13;
        if (msconnector_transaction_contract_record_decision(&owner,
                MSCONNECTOR_TRANSACTION_DECISION_BLOCK, NULL, 108U) !=
            MSCONNECTOR_TRANSACTION_TRANSITION_INVALID) return 14;
    }
#define CALL() (phase == 0 ? msconnector_modsecurity_process_connection(&tx,&req,&decision,error_out) : \
    phase == 2 ? msconnector_modsecurity_process_request_headers(&tx,&req,&decision,error_out) : \
    phase == 3 ? (strcmp(argv[4],"append")==0 ? msconnector_modsecurity_append_request_body(&tx,(const unsigned char*)"x",1,error_out) : \
        msconnector_modsecurity_finish_request_body(&tx,&decision,error_out)) : \
    phase == 4 ? (companion ? msconnector_modsecurity_process_response_headers_companion(&tx,&res,&decision,error_out) : \
        msconnector_modsecurity_process_response_headers(&tx,&res,&decision,error_out)) : \
    phase == 5 ? (strcmp(argv[4],"append")==0 ? (companion ? msconnector_modsecurity_append_response_body_companion(&tx,(const unsigned char*)"x",1,error_out) : \
        msconnector_modsecurity_append_response_body(&tx,(const unsigned char*)"x",1,error_out)) : \
        (companion ? msconnector_modsecurity_finish_response_body_companion(&tx,&decision,error_out) : \
        msconnector_modsecurity_finish_response_body(&tx,&decision,error_out))) : msconnector_modsecurity_process_logging(&tx,error_out))
    first = CALL(); before = calls;
    if (strcmp(argv[4], "terminal-error") == 0) {
        if (first != 0 || calls != 0 || owner.active_phase != -1 || owner.rule_id[0] ||
            owner.error_class != MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE) return 15;
    } else if (native_result == 1) {
        if (first != 1 || calls != 1 || owner.error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE) return 9;
    } else {
        if (first != 0 || owner.error_class != MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE) return 10;
        msconnector_error_init(&error);
        again = CALL();
        if (again != 0 || calls != before || (phase >= 2 && phase < 6 && (owner.completed_phase_mask & (1U << (phase-2))))) return 11;
    }
    msconnector_modsecurity_transaction_cleanup(&tx);
    msconnector_modsecurity_transaction_cleanup(&tx);
    return cleanup == 1 ? 0 : 12;
}
'''
        sources = ("modsecurity_engine.c", "transaction_state.c", "decision.c", "decision_action.c",
                   "intervention.c", "block_statuses.c", "http_status.c", "error.c", "status.c",
                   "event.c", "rule_id.c", "json_escape.c")
        binary = self.compile("engine-results", fixture, sources)
        for profile in ("envoy-ext-authz", "traefik-forwardauth", "haproxy-spoe-spop",
                        "traefik-native-uds", "lighttpd-stock", "lighttpd-patched"):
            for phase, operation in ((0,"connection"),(2,"phase"),(3,"append"),(3,"phase"),(4,"phase"),
                                     (5,"append"),(5,"phase"),(6,"logging")):
                for value in (-1, 0, 1, 2, 17):
                    for error_out in ("provided", "null"):
                        with self.subTest(profile=profile, phase=phase, operation=operation,
                                          result=value, error_out=error_out):
                            result = subprocess.run([str(binary), profile, str(phase), str(value),
                                                     operation, error_out], capture_output=True,
                                                    text=True, timeout=5, check=False)
                            self.assertEqual(result.returncode, 0, result.stderr)
            for phase in (3, 5):
                with self.subTest(profile=profile, phase=phase, terminal_missing_rule=True):
                    result = subprocess.run([str(binary), profile, str(phase), "1",
                                             "terminal-error", "provided"], capture_output=True,
                                            text=True, timeout=5, check=False)
                    self.assertEqual(result.returncode, 0, result.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
