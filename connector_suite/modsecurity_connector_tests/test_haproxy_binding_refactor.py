"""Compile actual HAProxy evaluation/cleanup helpers with controlled API seams.

The rule-ID decoder links the real Common implementation. Native engine calls
are test doubles; this is not a live HAProxy/libModSecurity integration test.
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
SOURCE = source_path('connectors/haproxy/src/haproxy_modsecurity_binding.c', root=ROOT)
PREAMBLE = r'''
#include "msconnector/rule_id.h"
#include "msconnector/native_result.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE 6
#define MSCONNECTOR_TRANSACTION_ERROR_ENGINE_UNAVAILABLE 5
typedef struct { int unused; } ModSecurity;
typedef struct { int unused; } RulesSet;
typedef struct { int unused; } Transaction;
typedef struct { int unused; } haproxy_modsecurity_engine;
typedef struct { int unused; } msconnector_decision;
typedef struct { const char *method; const char *uri; const char *http_version; } haproxy_modsecurity_request;
typedef struct {
    int status, phase, disruptive, rule_id;
    int body_limit, error_class;
    char action[32];
    char redirect_url[1024];
    char log_message[256];
} haproxy_modsecurity_decision;
static ModSecurity engine;
static RulesSet ruleset;
static Transaction transaction_object;
static char trace[64];
static size_t trace_size;
static char fail_at;
static int block_phase;
static void note(char operation) {
    if (trace_size + 1U >= sizeof(trace)) { abort(); }
    trace[trace_size++] = operation;
    trace[trace_size] = '\0';
}
static void msconnector_decision_init(msconnector_decision *decision) { decision->unused = 0; }
static ModSecurity *msc_init(void) { note('M'); return fail_at == 'M' ? NULL : &engine; }
static void msc_set_connector_info(ModSecurity *value, const char *info) { (void)value; (void)info; }
static RulesSet *msc_create_rules_set(void) { note('R'); return fail_at == 'R' ? NULL : &ruleset; }
static int validate_common_mapped_request(const haproxy_modsecurity_engine *value,
        const haproxy_modsecurity_request *request, haproxy_modsecurity_decision *decision) {
    (void)value; (void)request; (void)decision; note('V'); return fail_at != 'V';
}
static int load_request_rules(RulesSet *value, const haproxy_modsecurity_request *request,
        const char *text, haproxy_modsecurity_decision *decision) {
    (void)value; (void)request; (void)text; (void)decision; note('L'); return fail_at == 'L';
}
static Transaction *create_request_transaction(ModSecurity *value, RulesSet *rules,
        const haproxy_modsecurity_request *request) {
    (void)value; (void)rules; (void)request; note('T');
    return fail_at == 'T' ? NULL : &transaction_object;
}
static int process_request_connection(Transaction *value,
        const haproxy_modsecurity_request *request, haproxy_modsecurity_decision *decision) {
    (void)value; (void)request; (void)decision; note('C'); return fail_at == 'C';
}
static int msc_process_uri(Transaction *value, const char *uri, const char *method, const char *version) {
    (void)value; (void)uri; (void)method;
    if (version == NULL || strcmp(version, "1.1") != 0) { abort(); }
    note('U'); return fail_at != 'U';
}
static int process_request_headers(Transaction *value,
        const haproxy_modsecurity_request *request, haproxy_modsecurity_decision *decision) {
    (void)value; (void)request; (void)decision; note('H'); return fail_at == 'H';
}
static int capture_intervention(Transaction *value, int phase, haproxy_modsecurity_decision *decision);
static int process_request_body(Transaction *value,
        const haproxy_modsecurity_request *request, haproxy_modsecurity_decision *decision) {
    (void)request; note('B');
    if (fail_at == 'B') { return 1; }
    return capture_intervention(value, 2, decision);
}
static int capture_intervention(Transaction *value, int phase, haproxy_modsecurity_decision *decision) {
    char operation = phase == 1 ? '1' : '2';
    (void)value; note(operation);
    decision->phase = phase;
    decision->disruptive = block_phase == phase || fail_at == operation;
    return fail_at == operation;
}
static int msc_process_logging(Transaction *value) { (void)value; note('G'); return fail_at != 'G'; }
static void msc_transaction_cleanup(Transaction *value) { (void)value; note('t'); }
static void msc_rules_cleanup(RulesSet *value) { (void)value; note('r'); }
static void msc_cleanup(ModSecurity *value) { (void)value; note('m'); }
'''
MAIN = r'''
int main(int argc, char **argv) {
    haproxy_modsecurity_request request = {"GET", "/public", "1.1"};
    haproxy_modsecurity_decision decision = {0};
    int result = 0;
    int mask;
    if (argc != 4) { return 2; }
    fail_at = argv[2][0];
    block_phase = atoi(argv[3]);
    if (strcmp(argv[1], "rule") == 0) {
        decision.rule_id = 73;
        capture_log_rule_id(&decision, strcmp(argv[2], "NULL") == 0 ? NULL : argv[2]);
    } else if (strcmp(argv[1], "cleanup") == 0) {
        mask = atoi(argv[2]);
        cleanup_evaluation_resources(mask & 1 ? &transaction_object : NULL,
            mask & 2 ? &ruleset : NULL, mask & 4 ? &engine : NULL);
    } else if (strcmp(argv[1], "null_request") == 0) {
        result = eval_request_internal(NULL, NULL, &decision);
    } else if (strcmp(argv[1], "null_decision") == 0) {
        result = eval_request_internal(&request, NULL, NULL);
    } else {
        result = eval_request_internal(&request, NULL, &decision);
    }
    printf("{\"result\":%d,\"trace\":\"%s\",\"rule_id\":%d}\n", result, trace, decision.rule_id);
    return 0;
}
'''


def extract(source: str, name: str, result_type: str) -> str:
    definition = function_definition(source, name)
    return "static " + result_type + "\n" + definition[definition.index(name):] + "\n"


class HaproxyBindingRefactorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("a C compiler is required for HAProxy helper tests")
        temporary = tempfile.TemporaryDirectory(prefix="haproxy-evaluation-")
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        cls.binary = directory / "evaluation"
        source = SOURCE.read_text(encoding="utf-8")
        functions = (("copy_message", "void"), ("init_decision", "void"), ("native_error_decision", "void"),
                     ("capture_log_rule_id", "void"), ("request_text_or_default", "const char *"),
                     ("cleanup_evaluation_resources", "void"), ("evaluate_request_phases", "int"),
                     ("finish_evaluation_logging", "int"), ("eval_request_internal", "int"))
        fixture = PREAMBLE + "\n".join(extract(source, name, result) for name, result in functions) + MAIN
        (directory / "fixture.c").write_text(fixture, encoding="utf-8")
        result = subprocess.run(
            compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-I", str(source_path('common/include', root=ROOT)),
                        str(directory / "fixture.c"), str(source_path('common/src/rule_id.c', root=ROOT)),
                        "-o", str(cls.binary)], capture_output=True, text=True, timeout=90,
        )
        if result.returncode:
            raise AssertionError("HAProxy fixture compilation failed:\n" + result.stderr)

    def run_case(self, scenario: str, value: str = "-", block: int = 0) -> dict:
        result = subprocess.run([str(self.binary), scenario, value, str(block)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_success_completes_both_phases_and_logs_once_before_cleanup(self):
        result = self.run_case("flow")
        self.assertEqual(result["result"], 0)
        self.assertEqual(result["trace"], "VMRLTCUH1B2Gtrm")

    def test_phase1_intervention_does_not_enter_phase2(self):
        result = self.run_case("flow", block=1)
        self.assertEqual(result["result"], 0)
        self.assertEqual(result["trace"], "VMRLTCUH1Gtrm")

    def test_phase2_intervention_preserves_logging_and_cleanup(self):
        result = self.run_case("flow", block=2)
        self.assertEqual(result["result"], 0)
        self.assertEqual(result["trace"], "VMRLTCUH1B2Gtrm")

    def test_each_api_failure_stops_and_cleans_only_owned_resources(self):
        expected = {"V": "V", "M": "VM", "R": "VMRm", "L": "VMRLrm", "T": "VMRLTrm",
                    "C": "VMRLTCtrm", "U": "VMRLTCUtrm", "H": "VMRLTCUHtrm",
                    "1": "VMRLTCUH1trm", "B": "VMRLTCUH1Btrm", "2": "VMRLTCUH1B2trm", "G": "VMRLTCUH1B2Gtrm"}
        for failure, trace in expected.items():
            with self.subTest(failure=failure):
                result = self.run_case("flow", failure)
                self.assertEqual(result["result"], 1)
                self.assertEqual(result["trace"], trace)

    def test_invalid_arguments_never_call_the_engine(self):
        for scenario in ("null_request", "null_decision"):
            with self.subTest(scenario=scenario):
                result = self.run_case(scenario)
                self.assertEqual(result["result"], 1)
                self.assertEqual(result["trace"], "")

    def test_cleanup_preserves_dependency_order_for_every_partial_state(self):
        expected = ("", "t", "r", "tr", "m", "tm", "rm", "trm")
        for mask, trace in enumerate(expected):
            with self.subTest(mask=mask):
                self.assertEqual(self.run_case("cleanup", str(mask))["trace"], trace)

    def test_rule_id_decoder_accepts_complete_bounded_ids(self):
        for message, expected in (('[id "1001"]', 1001), ("id:42", 42), ('[id "0"]', 0)):
            with self.subTest(message=message):
                self.assertEqual(self.run_case("rule", message)["rule_id"], expected)

    def test_absent_malformed_or_out_of_range_id_keeps_existing_value(self):
        for message in ("NULL", "no id here", '[id "unterminated', '[id "-2"]',
                        '[id "12suffix"]', '[id "2147483648"]', '[id "' + "9" * 128 + '"]'):
            with self.subTest(message=message):
                self.assertEqual(self.run_case("rule", message)["rule_id"], 73)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
