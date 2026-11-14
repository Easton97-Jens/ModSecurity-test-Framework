"""Behavioral Runtime P4 regressions with real emitters, FSM and stdio writes.

Native callbacks are controlled at the C API boundary. These compiled seams
prove shared Runtime behavior, not an adapter/transport runtime matrix.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

from modsecurity_test_framework.connector_context import connector_root, source_path
from modsecurity_connector_tests.c_source_contract import function_definition
from modsecurity_connector_tests import test_runtime_event_sink_failures as BASE

ROOT = connector_root()
RUNTIME = source_path("common/runtime/msconnector_runtime.c", root=ROOT)
SOURCES = ("transaction_state.c", "decision.c", "decision_action.c", "intervention.c",
           "block_statuses.c", "http_status.c", "error.c", "status.c", "event.c",
           "event_jsonl.c", "integrity_event.c", "json_escape.c", "memory.c",
           "body_policy.c", "flow_guard.c", "dos_guard.c", "resource_limits.c", "rule_id.c")
PROFILES = ("haproxy-htx", "haproxy-spoe-spop", "envoy-ext-proc", "envoy-ext-authz",
            "traefik-native-uds", "traefik-forwardauth", "lighttpd-stock", "lighttpd-patched")


def build(cls, functions, includes, main, variants=None, extra_flags=(), model32=False):
    compiler = shlex.split(os.environ.get("CC", "cc"))
    if not compiler or shutil.which(compiler[0]) is None:
        raise RuntimeError("a C17 compiler is required")
    temporary = tempfile.TemporaryDirectory(prefix="runtime-p4-policy-",
                                             dir=os.environ.get("RUNNER_TEMP"))
    cls.addClassCleanup(temporary.cleanup)
    directory = Path(temporary.name)
    source = RUNTIME.read_text(encoding="utf-8")
    types = source[source.index("#define RUNTIME_NAME_SIZE"):source.index("static void set_text_error")]
    definitions = [function_definition(source, name) for name in functions]
    declarations = "\n".join(value[:value.index("{")] + ";" for value in definitions)
    # Only the actual host-size guard arithmetic is modeled. Real pointers,
    # standard headers, chunk sizes and allocations retain their native ABI.
    model = "\n#undef SIZE_MAX\n#define SIZE_MAX UINT32_MAX\n" if model32 else "\n"
    body = includes + types + declarations + model + "\n".join(definitions) + main
    cls.binaries = {}
    for label, transform in (variants or {"current": lambda value: value}).items():
        fixture = directory / (label + ".c")
        fixture.write_text(transform(body), encoding="utf-8")
        binary = fixture.with_suffix("")
        command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                              "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
                              "-I", str(source_path("common/include", root=ROOT)), "-I", str(ROOT), str(fixture)]
        command += [str(source_path("common/src", root=ROOT) / name) for name in SOURCES]
        command += [str(source_path("connectors/profile_registry.c", root=ROOT)), *extra_flags,
                    "-o", str(binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=90)
        if compiled.returncode:
            raise AssertionError(label + " fixture failed to compile:\n" + compiled.stderr[-6000:])
        cls.binaries[label] = binary


POLICY_INCLUDES = BASE.INCLUDES.replace("static int audit_calls, cleanup_calls;",
                                      "static int audit_calls, cleanup_calls;\nstatic int fail_audit;")
POLICY_INCLUDES = POLICY_INCLUDES.replace("(void)tx; (void)error; ++audit_calls; return 1;", r"""
    (void)tx; ++audit_calls;
    if (fail_audit) {
        msconnector_error_set(error, MSCONNECTOR_ERROR_MODSECURITY_FAILURE,
                              "native audit failed", "fixture");
        return 0;
    }
    return 1;
""")
POLICY_INCLUDES += r"""
static int fail_event_allocation;
int __real_msconnector_alloc_checked(msconnector_allocator *, size_t, void **);
int __wrap_msconnector_alloc_checked(msconnector_allocator *allocator, size_t size, void **out) {
    if (fail_event_allocation) { *out = NULL; return 0; }
    return __real_msconnector_alloc_checked(allocator, size, out);
}
"""
POLICY_MAIN = r"""
typedef struct { int failure, calls; } sink_state;
static ssize_t sink_write(void *opaque, const char *data, size_t size) {
    sink_state *sink = opaque;
    (void)data; ++sink->calls;
    if (sink->failure == 1) { errno = ENOSPC; return -1; }
    if (sink->failure == 2) return (ssize_t)(size / 2U);
    return (ssize_t)size;
}
static int prepare(msconnector_runtime *runtime, msconnector_runtime_transaction *tx,
                   msconnector_decision *decision, const char *scenario, const char *profile_name) {
    const msconnector_transaction_profile *profile = msconnector_profile_registry_find(profile_name);
    int committed = strcmp(scenario, "precommit") != 0;
    if (profile == NULL) return 0;
    runtime->profile = profile;
    runtime->config.phase4_mode = strcmp(scenario, "strict") == 0
        ? MSCONNECTOR_PHASE4_MODE_STRICT : strcmp(scenario, "off") == 0
            ? MSCONNECTOR_PHASE4_MODE_OFF : MSCONNECTOR_PHASE4_MODE_SAFE;
    runtime->config.default_error_status = 500;
    strcpy(runtime->connector_name, "common");
    strcpy(runtime->integration_mode, "compiled-runtime-policy");
    msconnector_resource_limits_init(&runtime->limits);
    atomic_flag_clear(&runtime->operation_lock);
    tx->runtime = runtime;
    strcpy(tx->metadata.transaction_id, "safe-policy");
    strcpy(tx->metadata.request_method, "GET");
    strcpy(tx->metadata.request_uri, "/resource");
    strcpy(tx->provenance.run_id, "runtime-policy");
    strcpy(tx->provenance.transport_case_id, "compiled-case");
    strcpy(tx->provenance.connection_id, "fixture");
    msconnector_flow_guard_init(&tx->flow, tx->metadata.transaction_id);
    for (enum msconnector_phase phase = MSCONNECTOR_PHASE_CONNECTION;
         phase <= MSCONNECTOR_PHASE_RESPONSE_BODY; ++phase)
        if (msconnector_flow_guard_mark_validated(&tx->flow, phase) != 0) return 0;
    if (msconnector_transaction_contract_init(&tx->contract, profile, "safe-policy",
            "common", "fixture", runtime->config.phase4_mode == MSCONNECTOR_PHASE4_MODE_STRICT
                ? MSCONNECTOR_TRANSACTION_MODE_STRICT : MSCONNECTOR_TRANSACTION_MODE_SAFE, 1U) != 0)
        return 0;
    for (enum msconnector_phase phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
         phase <= MSCONNECTOR_PHASE_RESPONSE_BODY; ++phase) {
        unsigned int bit = 1U << (unsigned int)(phase - MSCONNECTOR_PHASE_REQUEST_HEADERS);
        int companion = (profile->companion_phase_mask & bit) != 0;
        if (phase == MSCONNECTOR_PHASE_RESPONSE_HEADERS && companion) {
            if (msconnector_transaction_contract_handoff_response_companion(&tx->contract, 2U) != 0 ||
                msconnector_transaction_contract_claim_response_companion(&tx->contract, 3U) != 0)
                return 0;
            tx->completion.response_companion_handed_off = 1;
        }
        if ((companion ? msconnector_transaction_contract_begin_companion_phase(&tx->contract, phase, 4U)
                       : msconnector_transaction_contract_begin_phase(&tx->contract, phase, 4U)) != 0 ||
            msconnector_transaction_contract_complete_phase(&tx->contract, phase, 5U) != 0) return 0;
        if (phase == MSCONNECTOR_PHASE_RESPONSE_HEADERS && committed &&
            msconnector_transaction_contract_set_response_committed(&tx->contract, 1) != 0) return 0;
    }
    tx->native_started = 1;
    tx->request_body.finished = tx->response_body.finished = 1;
    tx->response_headers_processed = 1;
    tx->response_headers_sent = committed;
    tx->response_original_status = 200;
    if (strcmp(scenario, "contract-strict") == 0)
        tx->contract.mode = MSCONNECTOR_TRANSACTION_MODE_STRICT;
    if (strcmp(scenario, "uncommitted-contract") == 0) tx->contract.response_committed = 0;
    if (strcmp(scenario, "body-commit") == 0) {
        tx->response_headers_sent = 0; tx->response_body_started = 1;
    }
    msconnector_decision_set_deny(decision, 403, "900007", "rule intervention");
    decision->phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
    if (strcmp(scenario, "native-limit") == 0) {
        msconnector_decision_set_response_body_limit(decision, "native response Reject");
        return msconnector_transaction_contract_fail(&tx->contract,
                MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT, 6U) == 0;
    }
    if (strcmp(scenario, "technical") == 0) {
        msconnector_decision_set_error(decision, 500, "engine error");
        decision->phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
        return msconnector_transaction_contract_fail(&tx->contract,
                MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE, 6U) == 0;
    }
    if (strcmp(scenario, "allow") == 0) {
        msconnector_decision_set_allow(decision); decision->phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
        return 1;
    }
    if (msconnector_transaction_contract_record_decision(&tx->contract,
            MSCONNECTOR_TRANSACTION_DECISION_BLOCK, "900007", 6U) != 0) return 0;
    if (strcmp(scenario, "no-eos") == 0) tx->response_body.finished = 0;
    if (strcmp(scenario, "wrong-phase") == 0) decision->phase = MSCONNECTOR_PHASE_RESPONSE_HEADERS;
    if (strcmp(scenario, "wrong-rule") == 0) decision->rule_id = "999999";
    if (strcmp(scenario, "flow-error") == 0) tx->flow.immutable = 1;
    if (strcmp(scenario, "sticky") == 0) tx->event_write_failed = MSCONNECTOR_ERROR_IO;
    return 1;
}
int main(int argc, char **argv) {
    msconnector_runtime runtime = {0};
    msconnector_runtime_transaction *tx = calloc(1U, sizeof(*tx));
    msconnector_runtime_transaction_snapshot snapshot;
    msconnector_decision decision;
    msconnector_error error;
    sink_state sink = {0};
    cookie_io_functions_t functions = { .write = sink_write };
    int handled, host = 1, finish, finalized, terminal = 0;
    int sticky, optional, after_first_calls, after_host_calls, hash_kept, code, cause;
    uint64_t hash_before, hash_after_first, hash_before_finalize;
    if (argc != 4 || tx == NULL || !prepare(&runtime, tx, &decision, argv[1], argv[3])) return 2;
    runtime.event_file = fopencookie(&sink, "w", functions);
    if (runtime.event_file == NULL || setvbuf(runtime.event_file, NULL,
        strcmp(argv[2], "flush") == 0 ? _IOFBF : _IONBF, 0U) != 0) return 3;
    if (strcmp(argv[2], "serialize") == 0) runtime.limits.max_event_json_bytes = 1U;
    if (strcmp(argv[2], "allocation") == 0) fail_event_allocation = 1;
    if (strcmp(argv[2], "short") == 0) sink.failure = 2;
    else if (strcmp(argv[2], "success") != 0 && strcmp(argv[2], "serialize") != 0 &&
        strcmp(argv[2], "allocation") != 0 && strcmp(argv[2], "cleanup") != 0 &&
        strcmp(argv[2], "host") != 0 && strcmp(argv[1], "audit-error") != 0) sink.failure = 1;
    hash_before = runtime.previous_event_hash;
    msconnector_error_init(&error);
    handled = handle_decision(tx, &decision, &error, &terminal);
    after_first_calls = sink.calls;
    hash_after_first = runtime.previous_event_hash;
    if (handled && msconnector_decision_is_disruptive(&decision)) {
        if (strcmp(argv[2], "host") == 0) sink.failure = 1;
        host = msconnector_runtime_transaction_record_host_action(tx, &decision,
            strcmp(argv[1], "host-abort") == 0 ? MSCONNECTOR_DECISION_ACTION_ABORT_CONNECTION
                                               : MSCONNECTOR_DECISION_ACTION_LOG_ONLY,
            strcmp(argv[1], "host-abort") == 0 ? 0 : 200,
            strcmp(argv[1], "host-abort") == 0 ? "connection_aborted" :
                strcmp(argv[1], "host-technical") == 0 ? "engine_error" : "log_only",
            strcmp(argv[1], "host-abort") == 0, &error);
    }
    after_host_calls = sink.calls;
    if (strcmp(argv[1], "audit-error") == 0) fail_audit = 1;
    msconnector_error_init(&error);
    finish = msconnector_runtime_transaction_finish(tx, &error);
    if (strcmp(argv[2], "cleanup") == 0) sink.failure = 1;
    sticky = tx->event_write_failed;
    optional = tx->completion.optional_event_error;
    cause = tx->contract.error_class;
    msconnector_error_init(&error);
    hash_before_finalize = runtime.previous_event_hash;
    finalized = msconnector_runtime_transaction_finalize_and_snapshot(&tx, &snapshot, &error);
    code = error.code;
    hash_kept = strcmp(argv[2], "cleanup") == 0
        ? runtime.previous_event_hash == hash_before_finalize
        : strcmp(argv[2], "host") == 0
            ? runtime.previous_event_hash == hash_after_first
            : runtime.previous_event_hash == hash_before;
    printf("{\"handled\":%d,\"host\":%d,\"finish\":%d,\"finalized\":%d,"
        "\"sticky\":%d,\"optional\":%d,\"code\":%d,\"cause\":%d,"
        "\"first_calls\":%d,\"host_calls\":%d,\"calls\":%d,\"hash_kept\":%d,"
        "\"audit\":%d,\"cleanup\":%d,\"released\":%d,\"io\":%d,\"event_size\":%d}\n",
        handled, host, finish, finalized, sticky, optional, code, cause,
        after_first_calls, after_host_calls, sink.calls, hash_kept, audit_calls, cleanup_calls,
        tx == NULL, MSCONNECTOR_ERROR_IO, MSCONNECTOR_ERROR_EVENT_TOO_LARGE);
    msconnector_runtime_transaction_destroy(&tx);
    sink.failure = 0; clearerr(runtime.event_file); (void)fclose(runtime.event_file);
    return 0;
}
"""


def old_sticky_policy(text):
    anchor = "if (optional && (write_error.code == MSCONNECTOR_ERROR_IO ||"
    if text.count(anchor) != 1:
        raise AssertionError("optional writer negative-control anchor drifted")
    return text.replace(anchor, "if (0 && (write_error.code == MSCONNECTOR_ERROR_IO ||", 1)


class RuntimeLateSafeEventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build(cls, BASE.FUNCTIONS + ("handle_decision",), POLICY_INCLUDES, POLICY_MAIN,
              {"current": lambda value: value, "old-sticky": old_sticky_policy},
              ("-Wl,--wrap=msconnector_alloc_checked",))

    def case(self, scenario="safe", failure="write", profile="lighttpd-stock", variant="current"):
        result = subprocess.run([str(self.binaries[variant]), scenario, failure, profile],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr[-3000:])
        observed = json.loads(result.stdout)
        observed["warnings"] = result.stderr.count("optional late Safe event log failed")
        return observed

    def assert_safe_finished(self, value):
        for name in ("handled", "host", "finish", "finalized", "released"):
            self.assertEqual(value[name], 1, name)
        self.assertEqual((value["sticky"], value["cause"], value["code"]), (0, 0, 0))
        self.assertEqual((value["audit"], value["cleanup"]), (1, 1))

    def test_real_write_short_flush_serialization_and_allocation_failures_do_not_abort_safe(self):
        for failure in ("write", "short", "flush", "serialize", "allocation"):
            with self.subTest(failure=failure):
                value = self.case(failure=failure)
                self.assert_safe_finished(value)
                self.assertEqual(value["optional"], value["event_size"] if failure in
                                 ("serialize", "allocation") else value["io"])
                self.assertEqual(value["first_calls"], value["calls"])
                self.assertEqual((value["hash_kept"], value["warnings"]), (1, 1))

    def test_same_shared_policy_uses_actual_direct_and_companion_profile_contracts(self):
        for profile in PROFILES:
            with self.subTest(profile=profile):
                self.assert_safe_finished(self.case(profile=profile))

    def test_header_only_and_body_commit_are_already_late(self):
        self.assert_safe_finished(self.case())
        self.assert_safe_finished(self.case(scenario="body-commit"))

    def test_host_and_cleanup_sink_failure_do_not_cancel_prior_native_audit(self):
        for failure in ("host", "cleanup"):
            with self.subTest(failure=failure):
                value = self.case(failure=failure)
                self.assert_safe_finished(value)
                self.assertEqual(value["warnings"], 1)
                # Host failure leaves the previous successfully written hash;
                # cleanup failure leaves both successful decision/host hashes.
                self.assertEqual(value["hash_kept"], 1)

    def test_strict_limits_errors_nonlate_or_uncorrelated_rules_remain_mandatory(self):
        for scenario in ("strict", "off", "contract-strict", "uncommitted-contract",
                         "native-limit", "technical", "allow", "precommit", "no-eos",
                         "wrong-phase", "wrong-rule", "sticky"):
            with self.subTest(scenario=scenario):
                value = self.case(scenario=scenario)
                self.assertEqual(value["handled"], 0)
                self.assertEqual(value["finish"], 0)
                self.assertEqual(value["warnings"], 0)
                self.assertEqual(value["audit"], 0)

    def test_host_abort_cannot_inherit_safe_optional_writer_permission(self):
        for scenario in ("host-abort", "host-technical"):
            with self.subTest(scenario=scenario):
                value = self.case(scenario=scenario, failure="host")
                self.assertEqual(value["handled"], 1)
                self.assertEqual((value["host"], value["finish"]), (0, 0))
                self.assertEqual(value["sticky"], value["io"])
                self.assertEqual(value["warnings"], 0)

    def test_native_audit_and_flowguard_failures_are_never_log_only_success(self):
        flow = self.case(scenario="flow-error", failure="success")
        self.assertEqual((flow["handled"], flow["finish"], flow["audit"]), (0, 0, 0))
        self.assertEqual(flow["warnings"], 0)
        audit = self.case(scenario="audit-error", failure="success")
        self.assertEqual((audit["finish"], audit["finalized"], audit["audit"]), (0, 0, 1))
        self.assertNotEqual(audit["cause"], 0)
        self.assertEqual(audit["warnings"], 0)

    def test_successful_sink_keeps_the_native_once_only_epilogue(self):
        value = self.case(failure="success")
        self.assert_safe_finished(value)
        self.assertEqual((value["optional"], value["warnings"]), (0, 0))
        self.assertGreater(value["calls"], 0)

    def test_original_sticky_failure_control_blocks_the_same_safe_response(self):
        value = self.case(variant="old-sticky")
        self.assertEqual((value["handled"], value["finish"], value["finalized"]), (0, 0, 0))
        self.assertEqual(value["sticky"], value["io"])
        self.assertEqual(value["audit"], 0)


COUNTER_INCLUDES = BASE.INCLUDES + r"""
#include <inttypes.h>
#include "msconnector/native_result.h"
static int append_calls, fail_append;
int msconnector_modsecurity_append_response_body(msconnector_modsecurity_transaction *tx,
    const unsigned char *data, size_t bytes, msconnector_error *error) {
    (void)tx;
    if (data == NULL || bytes != 3U) abort();
    ++append_calls;
    if (fail_append) {
        msconnector_error_set(error, MSCONNECTOR_ERROR_MODSECURITY_FAILURE,
                              "native append failed", "fixture");
        return 0;
    }
    return 1;
}
int msconnector_modsecurity_append_response_body_companion(msconnector_modsecurity_transaction *tx,
    const unsigned char *data, size_t bytes, msconnector_error *error) {
    return msconnector_modsecurity_append_response_body(tx, data, bytes, error);
}
static int append_request_body_to_engine(msconnector_runtime_transaction *tx,
    const unsigned char *data, size_t bytes, msconnector_error *error) {
    (void)tx; (void)data; (void)bytes; (void)error; return 1;
}
"""
COUNTER_FUNCTIONS = ("runtime_error", "contract_error", "transaction_now_ms",
    "transaction_mutable_runtime", "runtime_operation_lock", "runtime_operation_unlock",
    "begin_contract_phase", "begin_companion_contract_phase", "begin_or_resume_streaming_body_phase",
    "validate_response_body_append", "append_response_body_to_engine", "append_response_body_chunk_internal",
    "msconnector_runtime_transaction_append_response_body_chunk",
    "msconnector_runtime_transaction_append_request_body_chunk",
    "msconnector_runtime_transaction_request_body_progress", "msconnector_runtime_transaction_response_body_progress")
COUNTER_MAIN = r"""
_Static_assert(sizeof(((msconnector_runtime_body_progress *)0)->bytes_seen) >= 8, "seen width");
_Static_assert(sizeof(((msconnector_runtime_body_progress *)0)->bytes_inspected) >= 8, "supplied width");
_Static_assert(sizeof(((msconnector_runtime_body_progress *)0)->bytes_retained) >= 8, "retained width");
static int prepare_counter(msconnector_runtime *runtime, msconnector_runtime_transaction *tx, int response) {
    const msconnector_transaction_profile *profile = msconnector_profile_registry_find("lighttpd-stock");
    tx->runtime = runtime;
    runtime->config.enable = response ? MSCONNECTOR_BOOL_ON : MSCONNECTOR_BOOL_OFF;
    runtime->body_policy.request_body_mode = MSCONNECTOR_BODY_MODE_STREAMING;
    runtime->body_policy.response_body_mode = MSCONNECTOR_BODY_MODE_STREAMING;
    atomic_flag_clear(&runtime->operation_lock);
    if (msconnector_transaction_contract_init(&tx->contract, profile,
            "counter", "common", "fixture", MSCONNECTOR_TRANSACTION_MODE_SAFE, 1U) != 0) return 0;
    for (enum msconnector_phase phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
         phase <= (response ? MSCONNECTOR_PHASE_RESPONSE_HEADERS : MSCONNECTOR_PHASE_REQUEST_HEADERS); ++phase)
        if (msconnector_transaction_contract_begin_phase(&tx->contract, phase, 2U) != 0 ||
            msconnector_transaction_contract_complete_phase(&tx->contract, phase, 3U) != 0) return 0;
    tx->response_headers_processed = response;
    return 1;
}
int main(void) {
    msconnector_runtime runtime = {0}, request_runtime = {0}, legitimate_runtime = {0};
    msconnector_runtime_transaction tx = {0}, request = {0}, legitimate = {0};
    msconnector_runtime_body_progress progress;
    msconnector_error error;
    const unsigned char bytes[3] = {1, 2, 3};
    int crossed, saturated, bad_pointer, engine_error, request_overflow, request_ok;
    if (!prepare_counter(&runtime, &tx, 1)) return 2;
    tx.response_body.bytes_seen = tx.response_body.bytes_inspected = UINT32_MAX - 1U;
    tx.contract.response_body_bytes = UINT32_MAX - 1U;
    crossed = msconnector_runtime_transaction_append_response_body_chunk(&tx, bytes, 3U, &error);
    msconnector_runtime_transaction_response_body_progress(&tx, &progress);
    crossed = crossed && progress.bytes_seen == UINT64_C(4294967297) &&
        progress.bytes_inspected == UINT64_C(4294967297) &&
        tx.contract.response_body_bytes == UINT64_C(4294967297);
    tx.response_body.bytes_seen = tx.response_body.bytes_inspected = UINT64_MAX - 1U;
    tx.contract.response_body_bytes = UINT64_MAX - 1U;
    saturated = msconnector_runtime_transaction_append_response_body_chunk(&tx, bytes, 3U, &error);
    msconnector_runtime_transaction_response_body_progress(&tx, &progress);
    saturated = saturated && progress.bytes_seen == UINT64_MAX && progress.bytes_inspected == UINT64_MAX &&
        tx.contract.response_body_bytes == UINT64_MAX && tx.contract.error_class == 0;
    bad_pointer = !msconnector_runtime_transaction_append_response_body_chunk(&tx, NULL, 1U, &error);
    fail_append = 1;
    engine_error = !msconnector_runtime_transaction_append_response_body_chunk(&tx, bytes, 3U, &error) &&
        error.code == MSCONNECTOR_ERROR_MODSECURITY_FAILURE;
    if (!prepare_counter(&request_runtime, &request, 0) ||
        !prepare_counter(&legitimate_runtime, &legitimate, 0)) return 3;
    request.request_body.bytes_seen = UINT32_MAX - 1U;
    request_overflow = !msconnector_runtime_transaction_append_request_body_chunk(&request, bytes, 3U, &error) &&
        error.code == MSCONNECTOR_ERROR_HOST_API_FAILURE && request.request_blocked;
    request_ok = msconnector_runtime_transaction_append_request_body_chunk(&legitimate, bytes, 3U, &error);
    printf("{\"crossed\":%d,\"saturated\":%d,\"bad_pointer\":%d,\"engine_error\":%d,"
        "\"request_overflow\":%d,\"request_ok\":%d,\"append_calls\":%d}\n",
        crossed, saturated, bad_pointer, engine_error, request_overflow, request_ok, append_calls);
    return 0;
}
"""


def old_cumulative_limit(text):
    anchor = "transaction->response_body.bytes_seen = msconnector_transaction_counter_add("
    if text.count(anchor) != 1: raise AssertionError("counter negative-control anchor drifted")
    legacy = r"""if (size > SIZE_MAX - transaction->response_body.bytes_seen ||
            size > SIZE_MAX - transaction->response_body.bytes_inspected) {
        (void)msconnector_transaction_contract_fail(&transaction->contract,
            MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR, transaction_now_ms());
        transaction->request_blocked = 1;
        return runtime_error(error, MSCONNECTOR_ERROR_HOST_API_FAILURE,
            "response body accounting overflow", "runtime");
    }
    """
    return text.replace(anchor, legacy + anchor, 1)


class RuntimeResponseObservationCounterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build(cls, COUNTER_FUNCTIONS, COUNTER_INCLUDES, COUNTER_MAIN,
              {"current": lambda value: value, "old-cumulative-limit": old_cumulative_limit}, model32=True)

    def observe(self, variant="current"):
        value = subprocess.run([str(self.binaries[variant])], capture_output=True, text=True, timeout=10)
        self.assertEqual(value.returncode, 0, value.stderr[-3000:])
        return json.loads(value.stdout)

    def test_actual_runtime_public_progress_crosses_32bit_boundary_and_saturates(self):
        value = self.observe()
        for field in ("crossed", "saturated", "bad_pointer", "engine_error", "request_overflow", "request_ok"):
            self.assertEqual(value[field], 1, field)
        self.assertEqual(value["append_calls"], 3)

    def test_old_guard_control_reproduces_additional_32bit_delivery_limit(self):
        value = self.observe("old-cumulative-limit")
        self.assertEqual(value["crossed"], 0)
        self.assertEqual(value["request_overflow"], 1)


NATIVE_INCLUDES = BASE.INCLUDES + r"""
#include "msconnector/native_result.h"
#include "msconnector/rule_id.h"
typedef struct { int status, pause, disruptive; char *url, *log; } ModSecurityIntervention;
static int native_append_result = 1, native_eos_result = 1;
static int native_flag = 1, native_calls, native_empty_url;
static const char *native_text;
static int msc_intervention(Transaction *transaction, ModSecurityIntervention *out) {
    (void)transaction; ++native_calls;
    out->status = 403; out->disruptive = native_flag;
    out->log = native_text == NULL ? NULL : strdup(native_text);
    out->url = native_empty_url ? strdup("") : NULL;
    return 1;
}
static void msc_intervention_cleanup(ModSecurityIntervention *out) {
    free(out->url); free(out->log); out->url = out->log = NULL;
}
static int msc_append_response_body(Transaction *transaction, const unsigned char *data, size_t bytes) {
    (void)transaction; (void)data; (void)bytes; return native_append_result;
}
static int msc_process_response_body(Transaction *transaction) {
    (void)transaction; return native_eos_result;
}
"""
NATIVE_FUNCTIONS = ("runtime_error", "native_is_request_body_limit_rejection", "native_copy_redirect_target",
                    "native_capture_rule_id", "native_intervention_validation_error", "native_decision", "native_append_response_body", "native_finish_response_body")
NATIVE_MAIN = r"""
static const char rule_text[] = "rule [file \"rules.conf\"] [line \"1\"] [id \"900007\"] "
    "[rev \"\"] [msg \"fixture\"] [data \"\"] [severity \"2\"] [ver \"\"] "
    "[maturity \"0\"] [accuracy \"0\"] [hostname \"fixture\"] [uri \"/\"] "
    "[unique_id \"unit\"] [ref \"\"]";
int main(int argc, char **argv) {
    msconnector_runtime runtime = {0};
    msconnector_native_transaction native = {0};
    msconnector_decision decision;
    msconnector_error error;
    unsigned char data = 0;
    int appended = -1, finished = -1;
    if (argc != 2) return 2;
    native.transaction = (Transaction *)&native;
    runtime.config.default_block_status = 403;
    native_text = "Response body limit is marked to reject the request";
    if (strcmp(argv[1], "changed") == 0) native_text = "changed native text";
    if (strcmp(argv[1], "missing") == 0) native_text = NULL;
    if (strcmp(argv[1], "partial") == 0) { native_append_result = 0; native_flag = 0; }
    if (strcmp(argv[1], "unexpected-rule") == 0 || strcmp(argv[1], "eos-rule") == 0)
        native_text = rule_text;
    if (strcmp(argv[1], "invalid-flag") == 0) native_flag = 2;
    if (strcmp(argv[1], "empty-url") == 0) native_empty_url = 1;
    if (strcmp(argv[1], "engine-error") == 0) native_append_result = -1;
    if (strcmp(argv[1], "eos-error") == 0) native_eos_result = 0;
    msconnector_decision_set_allow(&decision); msconnector_error_init(&error);
    if (strcmp(argv[1], "eos-rule") == 0 || strcmp(argv[1], "eos-limit-text") == 0) {
        finished = native_finish_response_body(&runtime, &native, &decision, &error);
    } else {
        appended = native_append_response_body(&runtime, &native, &data, 1U, &error);
        if (appended) finished = native_finish_response_body(&runtime, &native, &decision, &error);
    }
    printf("{\"appended\":%d,\"finished\":%d,\"body_limit\":%d,\"calls\":%d,"
        "\"pending\":%d,\"error\":%d,\"rule\":\"%s\"}\n", appended, finished,
        msconnector_decision_is_body_limit(&decision), native_calls,
        native.response_decision_pending, error.code, decision.rule_id == NULL ? "" : decision.rule_id);
    return 0;
}
"""


class RuntimeNativeResponseLimitContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build(cls, NATIVE_FUNCTIONS, NATIVE_INCLUDES, NATIVE_MAIN)

    def case(self, scenario):
        value = subprocess.run([str(self.binaries["current"]), scenario],
                               capture_output=True, text=True, timeout=10)
        self.assertEqual(value.returncode, 0, value.stderr[-3000:])
        return json.loads(value.stdout)

    def test_native_append_reject_survives_changed_and_absent_prose(self):
        for scenario in ("original", "changed", "missing"):
            with self.subTest(scenario=scenario):
                value = self.case(scenario)
                self.assertEqual((value["appended"], value["finished"], value["body_limit"]), (1, 1, 1))
                self.assertEqual(value["rule"], "")

    def test_process_partial_remains_nondisruptive(self):
        value = self.case("partial")
        self.assertEqual((value["appended"], value["finished"], value["body_limit"]), (1, 1, 0))

    def test_unexpected_rule_flag_url_and_engine_errors_are_not_native_limits(self):
        for scenario in ("unexpected-rule", "invalid-flag", "empty-url", "engine-error"):
            with self.subTest(scenario=scenario):
                value = self.case(scenario)
                self.assertEqual(value["appended"], 0)
                self.assertEqual(value["body_limit"], 0)
                self.assertNotEqual(value["error"], 0)

    def test_eos_rule_and_rulefree_log_prose_are_never_append_limit_signals(self):
        rule = self.case("eos-rule")
        self.assertEqual((rule["finished"], rule["body_limit"], rule["rule"]), (1, 0, "900007"))
        prose = self.case("eos-limit-text")
        self.assertEqual(prose["body_limit"], 0)
        self.assertEqual(prose["rule"], "")

    def test_genuine_eos_failure_cannot_replay_pending_reject_as_success(self):
        value = self.case("eos-error")
        self.assertEqual((value["appended"], value["finished"]), (1, 0))
        self.assertNotEqual(value["error"], 0)


if os.environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
