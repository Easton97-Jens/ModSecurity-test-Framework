"""Compile the complete ext_proc C bridge against controlled Common calls.

These are adapter-boundary regressions, not live Envoy or gRPC transport tests.
The production translation unit and public C entry points are used unchanged.
Only the Common runtime boundary is controlled to inject otherwise rare errors.
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

ROOT = connector_root()
BRIDGE = source_path('connectors/envoy/ext_proc/internal/processor/common_runtime_bridge.c', root=ROOT)
FIXTURE = r'''
#include "connectors/envoy/ext_proc/internal/processor/common_runtime_bridge.c"
struct msconnector_runtime { int unused; };
struct msconnector_runtime_transaction { int unused; };
static int calls_append, calls_eos, calls_commit, calls_failure, calls_host;
static int calls_destroy, calls_finish, last_started, raw_result = 1;
static int send_rule, recursive_failure;
static const char *scenario;
static msc_envoy_ext_proc_transaction *active;
static int boundary_result(const char *stage, msconnector_error *error) {
    if (strcmp(scenario, stage) != 0) { return 1; }
    if (raw_result != 1) {
        msconnector_error_set(error,
            strcmp(stage, "commit") == 0 ? MSCONNECTOR_ERROR_PHASE_SEQUENCE :
            (strcmp(stage, "host") == 0 || strcmp(stage, "finish") == 0) ? MSCONNECTOR_ERROR_IO :
            MSCONNECTOR_ERROR_MODSECURITY_FAILURE,
            "controlled boundary failure", "fixture");
    }
    return raw_result;
}
int msconnector_runtime_transaction_append_request_body_chunk(
    msconnector_runtime_transaction *t, const unsigned char *data, size_t size,
    msconnector_error *error) {
    (void)t; (void)data; (void)size; ++calls_append;
    return boundary_result("append", error);
}
int msconnector_runtime_transaction_append_response_body_chunk(
    msconnector_runtime_transaction *t, const unsigned char *data, size_t size,
    msconnector_error *error) {
    return msconnector_runtime_transaction_append_request_body_chunk(t, data, size, error);
}
static int finish_body(msconnector_decision *decision, msconnector_error *error) {
    ++calls_eos;
    if (send_rule) {
        msconnector_decision_set_error(decision, 403, "fixture rule");
        decision->rule_id = "12345";
    } else {
        msconnector_decision_set_allow(decision);
    }
    return boundary_result("eos", error);
}
int msconnector_runtime_transaction_finish_request_body(
    msconnector_runtime_transaction *t, msconnector_decision *decision,
    msconnector_error *error) {
    (void)t; return finish_body(decision, error);
}
int msconnector_runtime_transaction_finish_response_body(
    msconnector_runtime_transaction *t, msconnector_decision *decision,
    msconnector_error *error) {
    (void)t; return finish_body(decision, error);
}
int msconnector_runtime_transaction_set_response_commit_state_checked(
    msconnector_runtime_transaction *t, int headers, int started, msconnector_error *error) {
    (void)t; (void)headers; ++calls_commit;
    if (boundary_result("commit", error) != 1) { return raw_result; }
    last_started = started;
    return 1;
}
int msconnector_runtime_transaction_fail(msconnector_runtime_transaction *t,
    msconnector_transaction_error_class cause, msconnector_error *error) {
    (void)t; (void)cause; (void)error; ++calls_failure;
    if (recursive_failure) {
        recursive_failure = 0;
        (void)msc_envoy_ext_proc_fail(active, MSCONNECTOR_ERROR_IO, NULL, 0U);
    }
    return 1;
}
int msconnector_runtime_transaction_record_host_action(
    msconnector_runtime_transaction *t, const msconnector_decision *decision,
    msconnector_decision_action action, int visible, const char *transport,
    int aborted, msconnector_error *error) {
    (void)t; (void)decision; (void)action; (void)visible; (void)transport; (void)aborted;
    ++calls_host;
    return boundary_result("host", error);
}
const char *msconnector_runtime_transaction_id(const msconnector_runtime_transaction *t) {
    (void)t; return "bridge-fixture";
}
int msconnector_runtime_transaction_finish(msconnector_runtime_transaction *t,
    msconnector_error *error) {
    (void)t; ++calls_finish; return boundary_result("finish", error);
}
void msconnector_runtime_transaction_destroy(msconnector_runtime_transaction **t) {
    ++calls_destroy; *t = NULL;
}
int main(int argc, char **argv) {
    msconnector_runtime runtime = {0};
    msconnector_runtime_transaction native = {0};
    msc_envoy_ext_proc_transaction *transaction;
    msc_envoy_ext_proc_body body = {0};
    msc_envoy_ext_proc_decision decision = {0};
    char error[128] = {0};
    int first, second, finished, cause, terminal, pending, mode, close_result, close_code = 0;
    if (argc != 5) { return 2; }
    scenario = argv[1];
    raw_result = (int)strtol(argv[2], NULL, 10);
    body.response_direction = (int)strtol(argv[3], NULL, 10);
    mode = (int)strtol(argv[4], NULL, 10);
    transaction = calloc(1U, sizeof(*transaction));
    if (transaction == NULL) { return 3; }
    active = transaction;
    transaction->transaction = &native;
    transaction->runtime = &runtime;
    transaction->request_finished = body.response_direction;
    transaction->response_headers_processed = body.response_direction;
    body.body = (const unsigned char *)"x";
    body.body_size = mode == 0 ? 0U : 1U;
    body.end_of_stream = 1;
    send_rule = strcmp(scenario, "rule") == 0 || strcmp(scenario, "host") == 0;
    recursive_failure = strcmp(scenario, "recursive") == 0;
    if (strcmp(scenario, "recursive") == 0 || strcmp(scenario, "null-output") == 0 || strcmp(scenario, "first-before-finish") == 0) {
        scenario = "append";
    }
    if (strcmp(scenario, "void-commit") == 0) {
        scenario = "commit";
        msc_envoy_ext_proc_transaction_mark_response_committed(transaction, 0);
    }
    if (strcmp(scenario, "chunks") == 0) {
        body.end_of_stream = 0;
        first = msc_envoy_ext_proc_transaction_process_body(transaction, &body,
            &decision, error, sizeof(error));
        if (first != 1) { free(transaction); return 4; }
        body.body_size = 0U;
        body.end_of_stream = 1;
    }
    first = msc_envoy_ext_proc_transaction_process_body(transaction, &body, &decision,
        strcmp(argv[1], "null-output") == 0 ? NULL : error, sizeof(error));
    if (send_rule && first == 1) {
        first = msc_envoy_ext_proc_transaction_record_host_action(transaction,
            MSC_ENVOY_EXT_PROC_DENY, 403, "http_status", error, sizeof(error));
        second = msc_envoy_ext_proc_transaction_record_host_action(transaction,
            MSC_ENVOY_EXT_PROC_DENY, 403, "http_status", error, sizeof(error));
    } else if (first != 1) {
        scenario = "normal";
        second = msc_envoy_ext_proc_transaction_process_body(transaction, &body,
            &decision, error, sizeof(error));
    } else {
        second = 1;
    }
    finished = body.response_direction ? transaction->response_finished : transaction->request_finished;
    cause = transaction->failure_code;
    terminal = transaction->terminal;
    pending = transaction->has_disruptive_decision;
    if (strcmp(argv[1], "incomplete-request") == 0) {
        transaction->request_finished = 0;
        scenario = "finish";
    } else if (strcmp(argv[1], "incomplete-response") == 0) {
        transaction->response_headers_processed = 1;
        transaction->response_finished = 0;
        scenario = "finish";
    }
    if (strcmp(argv[1], "first-before-finish") == 0) {
        scenario = "finish";
        raw_result = 0;
    }
    if (strcmp(argv[1], "void-close") == 0) {
        msc_envoy_ext_proc_transaction_close(transaction);
        close_result = 1;
    } else {
        close_result = msc_envoy_ext_proc_transaction_close_checked(transaction, error, sizeof(error), &close_code);
    }
    printf("{\"first\":%d,\"second\":%d,\"append\":%d,\"eos\":%d,\"commit\":%d,"
        "\"failure\":%d,\"host\":%d,\"started\":%d,\"finished\":%d,\"cause\":%d,"
        "\"terminal\":%d,\"pending\":%d,\"destroy\":%d,\"engine_error\":%d,"
        "\"phase_error\":%d,\"io_error\":%d,\"close_result\":%d,\"finish\":%d,\"close_code\":%d,\"close_cause_retained\":%d}\n",
        first, second, calls_append, calls_eos, calls_commit, calls_failure, calls_host,
        last_started, finished, cause, terminal, pending, calls_destroy,
        MSCONNECTOR_ERROR_MODSECURITY_FAILURE, MSCONNECTOR_ERROR_PHASE_SEQUENCE, MSCONNECTOR_ERROR_IO,
        close_result, calls_finish, close_code, strcmp(error, msconnector_error_default_message(MSCONNECTOR_ERROR_MODSECURITY_FAILURE)) == 0);
    return 0;
}
'''


class EnvoyBridgeFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("a C compiler is required for bridge regressions")
        temporary = tempfile.TemporaryDirectory(prefix="ext-proc-boundary-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        source = directory / "bridge.c"
        source.write_text(FIXTURE, encoding="utf-8")
        cls.binary = directory / "bridge"
        names = ("transaction_state.c", "decision.c", "decision_action.c", "intervention.c",
                 "block_statuses.c", "http_status.c", "error.c", "status.c", "event.c",
                 "event_jsonl.c", "integrity_event.c", "json_escape.c", "memory.c",
                 "body_policy.c", "flow_guard.c", "dos_guard.c", "resource_limits.c", "rule_id.c")
        command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
            "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
            "-I", str(source_path('common/include', root=ROOT)), "-I", str(ROOT), str(source)]
        command += [str(source_path('common/src', root=ROOT) / name) for name in names]
        command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        if result.returncode:
            raise AssertionError("complete bridge compilation failed:\n" + result.stderr[-6000:])

    def case(self, scenario="normal", raw=1, response=1, nonempty=1):
        result = subprocess.run([str(self.binary), scenario, str(raw), str(response), str(nonempty)],
            capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        return json.loads(result.stdout)

    def assert_terminal(self, result, cause):
        self.assertEqual((result["first"], result["second"]), (0, 0))
        self.assertEqual(result["cause"], result[cause])
        self.assertEqual(result["terminal"], 1)
        self.assertEqual(result["pending"], 0)
        self.assertEqual(result["failure"], 1)
        self.assertEqual(result["destroy"], 1)

    def test_checked_close_propagates_finish_failure_and_destroys_once(self):
        for raw in (0, -1, 2):
            with self.subTest(raw=raw):
                result = self.case("finish", raw)
                self.assertEqual((result["first"], result["close_result"], result["finish"], result["destroy"]), (1, 0, 1, 1))

    def test_checked_close_checks_incomplete_request_and_response(self):
        for scenario in ("incomplete-request", "incomplete-response"):
            for raw in (0, -1, 2):
                with self.subTest(scenario=scenario, raw=raw):
                    result = self.case(scenario, raw)
                    self.assertEqual((result["first"], result["close_result"], result["finish"], result["destroy"]), (1, 0, 1, 1))

    def test_void_close_compatibility_finishes_and_destroys_once(self):
        result = self.case("void-close")
        self.assertEqual((result["first"], result["finish"], result["destroy"]), (1, 1, 1))

    def test_checked_close_retains_earlier_cause(self):
        result = self.case("first-before-finish", 0)
        self.assert_terminal(result, "engine_error")
        self.assertEqual((result["close_result"], result["finish"], result["close_cause_retained"]), (0, 1, 1))
        self.assertEqual(result["close_code"], result["io_error"])

    def test_failed_commit_never_reaches_append_or_eos(self):
        for raw in (0, -1, 2):
            with self.subTest(raw=raw):
                result = self.case("commit", raw)
                self.assert_terminal(result, "phase_error")
                self.assertEqual((result["append"], result["eos"], result["commit"]), (0, 0, 1))

    def test_append_failure_is_terminal_in_both_directions(self):
        for direction in (0, 1):
            for raw in (0, -1, 2):
                with self.subTest(direction=direction, raw=raw):
                    result = self.case("append", raw, direction)
                    self.assert_terminal(result, "engine_error")
                    self.assertEqual((result["append"], result["eos"], result["finished"]), (1, 0, 0))

    def test_eos_failure_never_marks_success_and_is_not_retried(self):
        for direction in (0, 1):
            for raw in (0, -1, 2):
                with self.subTest(direction=direction, raw=raw):
                    result = self.case("eos", raw, direction)
                    self.assert_terminal(result, "engine_error")
                    self.assertEqual((result["append"], result["eos"], result["finished"]), (1, 1, 0))

    def test_empty_response_does_not_claim_body_started(self):
        result = self.case(nonempty=0)
        self.assertEqual((result["first"], result["eos"], result["finished"]), (1, 1, 1))
        self.assertEqual(result["started"], 0)
        self.assertEqual(result["cause"], 0)

    def test_empty_eos_keeps_previous_nonempty_commit_monotonic(self):
        result = self.case("chunks")
        self.assertEqual((result["first"], result["append"], result["eos"], result["started"]), (1, 2, 1, 1))
        self.assertEqual(result["cause"], 0)

    def test_void_commit_compatibility_preserves_failure_for_next_call(self):
        result = self.case("void-commit", 0)
        self.assert_terminal(result, "phase_error")
        self.assertEqual((result["append"], result["commit"]), (0, 1))

    def test_null_error_output_still_preserves_the_first_cause(self):
        result = self.case("null-output", 0)
        self.assert_terminal(result, "engine_error")
        self.assertEqual(result["append"], 1)

    def test_recursive_failure_reporting_is_bounded(self):
        result = self.case("recursive", 0)
        self.assert_terminal(result, "engine_error")
        self.assertEqual(result["append"], 1)

    def test_host_log_error_cannot_reuse_a_pending_rule(self):
        result = self.case("host", 0)
        self.assert_terminal(result, "io_error")
        self.assertEqual(result["host"], 1)

    def test_valid_disruptive_decision_and_single_host_record_remain_valid(self):
        result = self.case("rule")
        self.assertEqual((result["first"], result["second"], result["host"]), (1, 0, 1))
        self.assertEqual((result["cause"], result["failure"], result["pending"]), (0, 0, 1))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
