"""Compile the real error classifier with a recording contract sink.

This proves error-code translation and selection of the owning contract. It
is not a native server, libModSecurity, transport, or end-to-end test.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()

PREAMBLE = r'''
#include "msconnector/modsecurity_engine.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
static unsigned recorded_calls;
static uint64_t recorded_time;
static uint64_t engine_contract_now_ms(void) { return UINT64_C(123456); }
int msconnector_transaction_contract_fail(msconnector_transaction_contract *contract,
        msconnector_transaction_error_class error_class, uint64_t now_ms) {
    if (contract == NULL) { return MSCONNECTOR_TRANSACTION_TRANSITION_INVALID; }
    recorded_calls++;
    recorded_time = now_ms;
    contract->error_class = error_class;
    return MSCONNECTOR_TRANSACTION_TRANSITION_OK;
}
'''

MAIN = r'''
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "check failed: %s at %d\n", #x, __LINE__); return 1; } } while (0)
int main(void) {
    msconnector_modsecurity_transaction tx;
    msconnector_transaction_contract owned;
    msconnector_error error;
    const struct {
        msconnector_error_code code;
        msconnector_transaction_error_class expected;
    } cases[] = {
        {MSCONNECTOR_ERROR_MODSECURITY_FAILURE, MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE},
        {MSCONNECTOR_ERROR_HOST_API_FAILURE, MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR},
        {MSCONNECTOR_ERROR_INTERNAL, MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR},
        {MSCONNECTOR_ERROR_IO, MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR},
        {MSCONNECTOR_ERROR_TIMEOUT, MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT},
        {MSCONNECTOR_ERROR_RUNTIME_UNAVAILABLE, MSCONNECTOR_TRANSACTION_ERROR_ENGINE_UNAVAILABLE},
        {MSCONNECTOR_ERROR_BODY_TOO_LARGE, MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT},
        {MSCONNECTOR_ERROR_EVENT_TOO_LARGE, MSCONNECTOR_TRANSACTION_ERROR_EVENT_LIMIT},
        {MSCONNECTOR_ERROR_LOG_MESSAGE_TOO_LARGE, MSCONNECTOR_TRANSACTION_ERROR_EVENT_LIMIT},
        {MSCONNECTOR_ERROR_HEADER_TOO_LARGE, MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL},
        {MSCONNECTOR_ERROR_PROTOCOL, MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL},
        {MSCONNECTOR_ERROR_PHASE_SEQUENCE, MSCONNECTOR_TRANSACTION_ERROR_PHASE_SEQUENCE},
        /* A failed callback without a usable reason is still a failure. */
        {MSCONNECTOR_ERROR_NONE, MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR},
        {(msconnector_error_code)INT_MAX, MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR}
    };
    unsigned route;
    size_t i;
    for (route = 0; route < 2; route++) {
        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            msconnector_transaction_contract *expected;
            memset(&tx, 0, sizeof(tx));
            memset(&owned, 0, sizeof(owned));
            tx.contract = route ? &owned : NULL;
            expected = route ? &owned : &tx.state.contract;
            error.code = cases[i].code;
            error.message = "fixture failure";
            error.source = "fixture";
            recorded_calls = 0;
            recorded_time = 0;
            fail_contract_from_error(&tx, &error);
            CHECK(recorded_calls == 1);
            CHECK(recorded_time == UINT64_C(123456));
            CHECK(expected->error_class == cases[i].expected);
            CHECK(error.code == cases[i].code);
            if (route) { CHECK(tx.state.contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_NONE); }
        }
    }
    recorded_calls = 0;
    fail_contract_from_error(NULL, &error);
    CHECK(recorded_calls == 0);
    memset(&tx, 0, sizeof(tx));
    fail_contract_from_error(&tx, NULL);
    CHECK(recorded_calls == 1);
    CHECK(tx.state.contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);
    return 0;
}
'''


class NativeErrorClassificationTests(unittest.TestCase):
    def test_real_classifier_preserves_engine_host_and_limit_errors(self) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        self.assertTrue(compiler and shutil.which(compiler[0]), "a C compiler is required")
        source = (source_path('common/src/modsecurity_engine.c', root=ROOT)).read_text(encoding="utf-8")
        definitions = "\n\n".join(
            function_definition(source, name)
            for name in ("canonical_contract", "fail_contract_from_error")
        )
        temporary_root = os.environ.get("TMP_ROOT")
        if temporary_root:
            Path(temporary_root).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="native-error-contract-", dir=temporary_root) as tmp:
            directory = Path(tmp)
            fixture = directory / "classification.c"
            binary = directory / "classification"
            fixture.write_text(PREAMBLE + definitions + MAIN, encoding="utf-8")
            compiled = subprocess.run(
                compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-I",
                            str(source_path('common/include', root=ROOT)), str(fixture), "-o", str(binary)],
                capture_output=True, text=True, timeout=90, check=False,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run(
                [str(binary)], capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)

    def test_all_failed_callback_routes_use_the_classifier(self) -> None:
        source = (source_path('common/src/modsecurity_engine.c', root=ROOT)).read_text(encoding="utf-8")
        for name in ("call_request", "call_response", "call_append", "call_finish"):
            with self.subTest(function=name):
                body = function_definition(source, name)
                self.assertIn("fail_contract_from_error(tx,", body)
                failure = body.index("fail_contract_from_error(tx,")
                self.assertIn("return 0;", body[failure:].split("}", 1)[0])



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
