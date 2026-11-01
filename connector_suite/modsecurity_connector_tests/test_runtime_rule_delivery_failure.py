"""Compile real Common pending rule delivery, terminal event and lifecycle code."""
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
from modsecurity_connector_tests.test_i09_common_routes import SOURCES
from modsecurity_connector_tests.test_runtime_event_sink_failures import FUNCTIONS, INCLUDES

ROOT = connector_root()
RUNTIME = source_path('common/runtime/msconnector_runtime.c', root=ROOT)
MAIN = r'''
int main(int argc, char **argv) {
    msconnector_runtime runtime = {0};
    msconnector_runtime_transaction tx = {0};
    msconnector_decision decision;
    msconnector_error error;
    char *events = NULL;
    size_t events_size = 0;
    const msconnector_transaction_profile *profile = msconnector_profile_registry_find("lighttpd-stock");
    const msconnector_transaction_decision_kind kinds[] = {
        MSCONNECTOR_TRANSACTION_DECISION_BLOCK, MSCONNECTOR_TRANSACTION_DECISION_REDIRECT,
        MSCONNECTOR_TRANSACTION_DECISION_RATE_LIMIT, MSCONNECTOR_TRANSACTION_DECISION_ENFORCE};
    if (argc != 4) return 2;
    const int kind = atoi(argv[1]);
    const int strict = strcmp(argv[2], "strict") == 0;
    const int off = strcmp(argv[2], "off") == 0;
    msconnector_resource_limits_init(&runtime.limits);
    runtime.config.default_error_status = 500;
    runtime.config.phase4_mode = strict ? MSCONNECTOR_PHASE4_MODE_STRICT :
        off ? MSCONNECTOR_PHASE4_MODE_OFF : MSCONNECTOR_PHASE4_MODE_SAFE;
    strcpy(runtime.connector_name, "common");
    strcpy(runtime.integration_mode, "compiled-rule-delivery");
    atomic_flag_clear(&runtime.operation_lock);
    runtime.event_file = open_memstream(&events, &events_size);
    if (runtime.event_file == NULL) return 3;
    tx.runtime = &runtime;
    strcpy(tx.metadata.transaction_id, "rule-delivery");
    msconnector_flow_guard_init(&tx.flow, tx.metadata.transaction_id);
    if (msconnector_transaction_contract_init(&tx.contract, profile, tx.metadata.transaction_id,
            "common", "fixture", strict ? MSCONNECTOR_TRANSACTION_MODE_STRICT :
            MSCONNECTOR_TRANSACTION_MODE_SAFE, 100U) != 0) return 4;
    if (msconnector_transaction_contract_begin_phase(&tx.contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 101U) != 0 ||
        msconnector_transaction_contract_complete_phase(&tx.contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 102U) != 0 ||
        msconnector_transaction_contract_begin_phase(&tx.contract, MSCONNECTOR_PHASE_REQUEST_BODY, 103U) != 0) return 5;
    /* Native processing completes P2 before recording its correlated rule. */
    if (msconnector_transaction_contract_complete_phase(&tx.contract, MSCONNECTOR_PHASE_REQUEST_BODY, 104U) != 0) return 6;
    tx.request_body.finished = 1;
    if (msconnector_transaction_contract_record_decision(&tx.contract, kinds[kind], "12345", 105U) != 0) return 6;
    msconnector_decision_init(&decision);
    if (kind == 1) msconnector_decision_set_redirect(&decision, 302, "/blocked", "12345", "rule");
    else msconnector_decision_set_deny(&decision, 403, "12345", "rule");
    decision.phase = MSCONNECTOR_PHASE_REQUEST_BODY;
    int terminal = 0;
    if (handle_decision(&tx, &decision, &error, &terminal) != 1 || !terminal) return 7;
    int prior = 0;
    if (strcmp(argv[3], "applied") == 0) {
        prior = msconnector_runtime_transaction_record_host_action(&tx, &decision,
            kind == 1 ? MSCONNECTOR_DECISION_ACTION_REDIRECT : MSCONNECTOR_DECISION_ACTION_DENY,
            kind == 1 ? 302 : 403, "http_status", 0, &error);
        if (prior != 1) return 8;
    } else if (strcmp(argv[3], "finish") == 0) {
        prior = msconnector_runtime_transaction_finish(&tx, &error);
        if (prior != 1) return 9;
    } else if (strcmp(argv[3], "cleanup") == 0) {
        prior = runtime_transaction_cleanup_checked(&tx, &error);
        if (prior != 1) return 10;
    } else if (strcmp(argv[3], "typed") == 0) {
        prior = msconnector_runtime_transaction_fail(&tx,
            MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE, &error);
    } else if (strcmp(argv[3], "io") == 0) {
        FILE *memory_sink = runtime.event_file;
        fflush(memory_sink);
        FILE *full_sink = fopen("/dev/full", "w");
        if (full_sink == NULL || setvbuf(full_sink, NULL, _IONBF, 0U) != 0) return 11;
        runtime.event_file = full_sink;
        if (emit_decision_event(&tx, &decision, NULL, &error) != 0 || error.code != MSCONNECTOR_ERROR_IO) return 12;
        fclose(full_sink);
        runtime.event_file = memory_sink;
    }
    fflush(runtime.event_file);
    size_t before = events_size;
    int first = msconnector_runtime_transaction_fail(&tx, MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR, &error);
    int first_code = error.code;
    int second = msconnector_runtime_transaction_fail(&tx, MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL, &error);
    int second_code = error.code;
    int phase_retry = msconnector_transaction_contract_begin_phase(&tx.contract,
        MSCONNECTOR_PHASE_RESPONSE_HEADERS, 200U);
    fflush(runtime.event_file);
    fputs(events, stdout);
    printf("{\"first\":%d,\"second\":%d,\"first_code\":%d,\"second_code\":%d,\"cause\":%d,"
        "\"connector\":%d,\"invalid_native\":%d,\"io\":%d,\"rule_empty\":%d,\"phase_retry\":%d,"
        "\"error_phase\":%d,\"before\":%zu,\"after\":%zu,\"prior\":%d,\"cleanup_calls\":%d}\n",
        first, second, first_code, second_code, tx.contract.error_class,
        MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR, MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE,
        MSCONNECTOR_ERROR_IO, tx.contract.rule_id[0] == '\0', phase_retry,
        tx.contract.error_phase, before, events_size, prior, cleanup_calls);
    fclose(runtime.event_file);
    free(events);
    return 0;
}
'''


class RuntimeRuleDeliveryFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = shlex.split(os.environ.get("CC", "cc"))
        if not cls.compiler or shutil.which(cls.compiler[0]) is None:
            raise RuntimeError("C compiler required")
        temporary = tempfile.TemporaryDirectory(prefix="rule-delivery-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        source = RUNTIME.read_text()
        types = source[source.index("#define RUNTIME_NAME_SIZE"):source.index("static void set_text_error")]
        names = list(FUNCTIONS) + ["handle_decision", "msconnector_runtime_transaction_fail"]
        definitions = [function_definition(source, name) for name in names]
        declarations = "\n".join(value[:value.index("{")] + ";" for value in definitions)
        cls.text = INCLUDES + types + declarations + "\n".join(definitions) + MAIN
        cls.binary = cls.compile("current", cls.text)

    @classmethod
    def compile(cls, name, text):
        fixture = cls.directory / (name + ".c")
        binary = cls.directory / name
        fixture.write_text(text)
        command = cls.compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
            "-I", str(source_path('common/include', root=ROOT)), "-I", str(ROOT), str(fixture)]
        command += [str(source_path('common/src', root=ROOT) / name) for name in SOURCES]
        command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        if result.returncode:
            raise AssertionError(result.stderr)
        return binary

    def case(self, kind=0, mode="safe", scenario="pending", binary=None):
        result = subprocess.run([str(binary or self.binary), str(kind), mode, scenario],
            capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        records = [json.loads(line) for line in result.stdout.splitlines()]
        return records[:-1], records[-1]

    def assert_pending_failure(self, events, state):
        self.assertEqual((state["first"], state["second"]), (1, 1))
        self.assertEqual(state["cause"], state["connector"])
        self.assertEqual(state["rule_empty"], 1)
        self.assertNotEqual(state["phase_retry"], 0)
        self.assertEqual(state["error_phase"], 3)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["event"], "engine_decision")
        self.assertEqual(events[0]["rule_id"], "12345")
        self.assertEqual(events[1]["message_id"], "MSCONN_EVENT_CONNECTOR_ERROR")
        self.assertEqual(events[1]["actual_action"], "")
        self.assertEqual(events[1]["phase"], "request_body")
        self.assertIn(events[1].get("rule_id"), ("", None))

    def test_pending_correlated_rule_delivery_failure_emits_exactly_once(self):
        for mode in ("off", "safe", "strict"):
            for kind in range(4):
                with self.subTest(mode=mode, kind=kind):
                    self.assert_pending_failure(*self.case(kind, mode))

    def test_applied_finished_and_cleaned_transactions_cannot_be_reopened(self):
        for scenario in ("applied", "finish", "cleanup"):
            for mode in ("off", "safe"):
                with self.subTest(scenario=scenario, mode=mode):
                    events, state = self.case(mode=mode, scenario=scenario)
                    self.assertEqual((state["first"], state["second"]), (0, 0))
                    self.assertEqual(state["before"], state["after"])
                    self.assertEqual(state["cause"], 0)
                    self.assertEqual(state["rule_empty"], 0)
                    self.assertNotEqual(state["phase_retry"], 0)
                    self.assertFalse(any(e.get("message_id") == "MSCONN_EVENT_CONNECTOR_ERROR" for e in events))

    def test_typed_first_error_and_physical_io_remain_authoritative(self):
        for mode in ("off", "safe"):
            events, state = self.case(mode=mode, scenario="typed")
            self.assertEqual(state["prior"], 1)
            self.assertEqual(state["cause"], state["invalid_native"])
            self.assertEqual(len(events), 2)
            self.assertEqual(events[1]["message_id"], "MSCONN_EVENT_INVALID_ENGINE_RESPONSE")
            self.assertEqual(state["before"], state["after"])
            events, state = self.case(mode=mode, scenario="io")
            self.assertEqual((state["first"], state["second"]), (0, 0))
            self.assertEqual((state["first_code"], state["second_code"]), (state["io"], state["io"]))
            self.assertEqual(state["before"], state["after"])
            self.assertEqual(len(events), 1)

    def test_event_reset_mutation_is_rejected(self):
        definition = function_definition(self.text, "msconnector_runtime_transaction_fail")
        anchor = "transaction->terminal_event_emitted = 0;"
        self.assertEqual(definition.count(anchor), 1)
        mutant = self.compile("no-terminal-reset", self.text.replace(anchor, "/* mutation removes reset */", 1))
        events, state = self.case(binary=mutant)
        with self.assertRaises(AssertionError):
            self.assert_pending_failure(events, state)


    def test_accepted_host_action_guard_mutation_is_rejected(self):
        anchor = "if (terminal_rule_failure &&"
        self.assertEqual(function_definition(self.text, "msconnector_runtime_transaction_fail").count(anchor), 1)
        mutant = self.compile("no-host-seal", self.text.replace(anchor, "if (0 && terminal_rule_failure &&", 1))
        _, state = self.case(scenario="applied", binary=mutant)
        with self.assertRaises(AssertionError):
            self.assertEqual((state["first"], state["second"]), (0, 0))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
