"""Check the actual host-action validator without claiming physical host I/O.

The event-emitter boundary is counted; the validator, error mapping and decision
helpers use production code. Physical sink behavior is tested separately by
runtime_event_sink_failures with the real serializer and stdio writer.
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
from modsecurity_connector_tests.test_runtime_event_sink_failures import INCLUDES, ROOT, RUNTIME

FUNCTIONS = (
    "runtime_error", "replay_event_write_failure", "contract_error",
    "valid_host_action", "valid_host_transport_result", "bounded_c_string",
    "validate_body_limit_host_action", "msconnector_runtime_transaction_record_host_action",
)
EMITTER = r'''
static int emitted;
static int emit_decision_event(msconnector_runtime_transaction *transaction,
        const msconnector_decision *decision,
        const msconnector_runtime_host_action *action, msconnector_error *error) {
    (void)transaction; (void)decision; (void)action; (void)error;
    ++emitted;
    return 1;
}
'''
MAIN = r'''
int main(int argc, char **argv) {
    msconnector_runtime runtime = {0};
    msconnector_runtime_transaction transaction = {0};
    msconnector_decision decision;
    msconnector_error error;
    msconnector_decision_action action;
    int result, status, aborted;
    if (argc != 6) { return 2; }
    if (strcmp(argv[1], "reset") == 0) {
        action = MSCONNECTOR_DECISION_ACTION_STREAM_RESET;
    } else if (strcmp(argv[1], "abort") == 0) {
        action = MSCONNECTOR_DECISION_ACTION_ABORT_CONNECTION;
    } else if (strcmp(argv[1], "drop") == 0) {
        action = MSCONNECTOR_DECISION_ACTION_DROP;
    } else if (strcmp(argv[1], "log") == 0) {
        action = MSCONNECTOR_DECISION_ACTION_LOG_ONLY;
    } else if (strcmp(argv[1], "allow") == 0) {
        action = MSCONNECTOR_DECISION_ACTION_ALLOW;
    } else if (strcmp(argv[1], "redirect") == 0) {
        action = MSCONNECTOR_DECISION_ACTION_REDIRECT;
    } else {
        action = MSCONNECTOR_DECISION_ACTION_DENY;
    }
    aborted = (int)strtol(argv[2], NULL, 10);
    status = (int)strtol(argv[3], NULL, 10);
    transaction.runtime = &runtime;
    msconnector_decision_set_error(&decision, 500, "fixture error");
    msconnector_error_init(&error);
    if (strcmp(argv[5], "saved-io") == 0) {
        transaction.event_write_failed = MSCONNECTOR_ERROR_IO;
        transaction.terminal_event_emitted = 1;
        transaction.host_action_event_emitted = 1;
        transaction.completion.finished = 1;
    } else if (strcmp(argv[5], "duplicate") == 0) {
        transaction.host_action_event_emitted = 1;
    } else if (strcmp(argv[5], "limit") == 0) {
        msconnector_decision_set_body_limit(&decision, 413, "fixture limit");
    } else if (strncmp(argv[5], "response-limit", 14) == 0) {
        msconnector_decision_set_response_body_limit(&decision, "native Reject");
        transaction.contract.response_committed = strcmp(argv[5], "response-limit-committed") == 0;
    } else if (strcmp(argv[5], "p4-rule") == 0) {
        msconnector_decision_set_deny(&decision, 403, "900007", "genuine P4 rule");
        decision.phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
        runtime.config.phase4_mode = MSCONNECTOR_PHASE4_MODE_SAFE;
        transaction.contract.response_committed = 1;
    }
    result = msconnector_runtime_transaction_record_host_action(&transaction,
        &decision, action, status, argv[4], aborted, &error);
    printf("{\"result\":%d,\"error\":%d,\"emitted\":%d,\"recorded\":%d,"
        "\"io\":%d,\"host_error\":%d,\"message\":\"%s\"}\n",
        result, error.code, emitted, transaction.host_action_event_emitted,
        MSCONNECTOR_ERROR_IO, MSCONNECTOR_ERROR_HOST_API_FAILURE,
        error.message == NULL ? "" : error.message);
    return 0;
}
'''


class RuntimeHostActionValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("a C compiler is required for host-action validation")
        temporary = tempfile.TemporaryDirectory(prefix="runtime-host-action-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        source = RUNTIME.read_text(encoding="utf-8")
        types = source[source.index("#define RUNTIME_NAME_SIZE"):source.index("static void set_text_error")]
        definitions = [function_definition(source, name) for name in FUNCTIONS]
        fixture = directory / "host-action.c"
        text = INCLUDES + types + EMITTER + "\n".join(definitions) + MAIN
        anchor = "decision->phase == MSCONNECTOR_PHASE_RESPONSE_BODY) {"
        if text.count(anchor) != 1:
            raise AssertionError("P4 native-limit guard mutation anchor drifted")
        variants = {"current": text, "without-response-guard": text.replace(anchor,
                    "decision->phase == MSCONNECTOR_PHASE_REQUEST_BODY) {", 1)}
        sources = (
            "transaction_state.c", "decision.c", "decision_action.c", "intervention.c",
            "block_statuses.c", "http_status.c", "error.c", "status.c", "event.c",
            "event_jsonl.c", "integrity_event.c", "json_escape.c", "memory.c",
            "body_policy.c", "flow_guard.c", "dos_guard.c", "resource_limits.c", "rule_id.c",
        )
        cls.binaries = {}
        for name, text in variants.items():
            fixture = directory / (name + ".c")
            fixture.write_text(text, encoding="utf-8")
            binary = directory / name
            command = compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                                  "-I", str(source_path('common/include', root=ROOT)), "-I", str(ROOT), str(fixture)]
            command += [str(source_path('common/src', root=ROOT) / name) for name in sources]
            command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(binary)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
            if result.returncode:
                raise AssertionError("host-action fixture compilation failed:\n" + result.stderr[-6000:])
            cls.binaries[name] = binary

    def case(self, action: str, aborted: int, status: int, transport: str,
             state: str = "normal", variant: str = "current") -> dict:
        result = subprocess.run([str(self.binaries[variant]), action, str(aborted), str(status), transport, state],
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        return json.loads(result.stdout)

    def test_response_limit_cannot_become_log_only_or_a_false_replacement(self) -> None:
        for state in ("response-limit", "response-limit-committed"):
            for action, status, transport in (("log", 200, "log_only"),
                                               ("allow", 200, "completed"),
                                               ("redirect", 302, "http_status"),
                                               ("deny", 500, "http_status")):
                with self.subTest(state=state, action=action):
                    value = self.case(action, 0, status, transport, state)
                    self.assertEqual((value["result"], value["emitted"], value["recorded"]), (0, 0, 0))
                    self.assertEqual(value["error"], value["host_error"])
        false_status = self.case("deny", 0, 403, "http_status", "response-limit-committed")
        self.assertEqual((false_status["result"], false_status["emitted"]), (0, 0))

    def test_native_denial_and_real_transport_stop_remain_available(self) -> None:
        denial = self.case("deny", 0, 403, "http_status", "response-limit")
        self.assertEqual((denial["result"], denial["emitted"]), (1, 1))
        for action, aborted, transport in (("reset", 0, "stream_reset"),
                                           ("abort", 1, "connection_aborted"),
                                           ("drop", 1, "connection_aborted")):
            value = self.case(action, aborted, 0, transport, "response-limit-committed")
            self.assertEqual((value["result"], value["emitted"]), (1, 1))
        rule = self.case("log", 0, 200, "log_only", "p4-rule")
        self.assertEqual((rule["result"], rule["emitted"]), (1, 1))

    def test_removing_the_p4_guard_reproduces_the_original_safe_downgrade(self) -> None:
        value = self.case("log", 0, 200, "log_only", "response-limit-committed",
                          "without-response-guard")
        self.assertEqual((value["result"], value["emitted"], value["recorded"]), (1, 1, 1))

    def test_stream_reset_cannot_claim_connection_abort(self) -> None:
        for status in (0, 200, 500):
            for transport in ("stream_reset", "connection_aborted"):
                with self.subTest(status=status, transport=transport):
                    result = self.case("reset", 1, status, transport)
                    self.assertEqual(result["result"], 0)
                    self.assertEqual(result["error"], result["host_error"])
                    self.assertEqual(result["message"], "a connection abort requires an abort or drop host action")
                    self.assertEqual(result["emitted"], 0)
                    self.assertEqual(result["recorded"], 0)

    def test_valid_reset_and_connection_abort_remain_distinct(self) -> None:
        for action, aborted, transport in (("reset", 0, "stream_reset"),
                                           ("abort", 1, "connection_aborted"),
                                           ("drop", 1, "connection_aborted")):
            with self.subTest(action=action):
                result = self.case(action, aborted, 0, transport)
                self.assertEqual(result["result"], 1)
                self.assertEqual(result["error"], 0)
                self.assertEqual(result["emitted"], 1)
                self.assertEqual(result["recorded"], 1)

    def test_reset_transport_must_match_action_in_both_directions(self) -> None:
        for action, aborted, transport in (("reset", 0, "http_status"),
                                           ("deny", 0, "stream_reset"),
                                           ("abort", 1, "stream_reset")):
            with self.subTest(action=action, transport=transport):
                result = self.case(action, aborted, 500, transport)
                self.assertEqual(result["result"], 0)
                self.assertEqual(result["error"], result["host_error"])
                self.assertEqual(result["emitted"], 0)

    def test_saved_io_error_precedes_old_success_and_lifecycle_flags(self) -> None:
        result = self.case("reset", 0, 0, "stream_reset", "saved-io")
        self.assertEqual(result["result"], 0)
        self.assertEqual(result["error"], result["io"])
        self.assertEqual(result["emitted"], 0)

    def test_duplicate_host_action_never_emits_again(self) -> None:
        result = self.case("deny", 0, 403, "http_status", "duplicate")
        self.assertEqual(result["result"], 0)
        self.assertNotEqual(result["error"], 0)
        self.assertEqual(result["emitted"], 0)

    def test_body_limit_keeps_http_413_contract(self) -> None:
        valid = self.case("deny", 0, 413, "http_status", "limit")
        self.assertEqual(valid["result"], 1)
        for action, aborted, status, transport in (("reset", 0, 0, "stream_reset"),
                                                  ("deny", 0, 500, "http_status")):
            with self.subTest(action=action, status=status):
                result = self.case(action, aborted, status, transport, "limit")
                self.assertEqual(result["result"], 0)
                self.assertEqual(result["emitted"], 0)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
