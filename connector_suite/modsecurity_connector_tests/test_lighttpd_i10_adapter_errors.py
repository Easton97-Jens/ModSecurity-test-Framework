"""Compile exact productive lighttpd callers; replace only host/native seams.

These checks observe host return/status/socket output, not live lighttpd or
client transport reset. Pinned native host headers are not required.
"""
from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path
import os
import runpy
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from modsecurity_connector_tests.c_source_contract import function_definition
MATERIALIZER = runpy.run_path(str(test_root() / "ci/checks/analysis/native-cfamily-recipes.py"))
ROOT = connector_root()
NATIVE = source_path('connectors/lighttpd/module/mod_msconnector.c', root=ROOT)

class LighttpdI10AdapterErrors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="lighttpd-i10-", dir=os.environ.get("RUNNER_TEMP", "/var/tmp/codex/ModSecurity-conector/lighttpd-i10"))
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        source = NATIVE.read_text()
        parts = MATERIALIZER["lighttpd_parts"](native=source)
        MATERIALIZER["write_lighttpd_includes"](parts, cls.directory)
        fixture = (source_path('tests/fixtures/lighttpd_i10_native.c', root=ROOT)).read_text()
        fixture = fixture.replace('#include "native-lighttpd-definitions.inc"', parts["native-lighttpd-definitions.inc"])
        cls.binaries = {}
        variants = {"current": fixture,
                    "swallow-error": fixture.replace("return PLUGIN_BODY_HOOK_ERROR;", "return PLUGIN_BODY_HOOK_CONTINUE;"),
                    "retry-native": fixture.replace("if (ctx != NULL && (ctx->technical_failed || ctx->api_failed)) return PLUGIN_BODY_HOOK_ERROR;", "if (ctx != NULL && ctx->technical_failed) ctx->technical_failed = 0;"),
                    "second-response": fixture.replace("if (r->write_queue.bytes_out > 0 ||", "if (r->write_queue.bytes_out < 0 ||")}
        variants["reset-success"] = fixture.replace("handler_ctx_destroy(ctx_slot);\n    return result;", "handler_ctx_destroy(ctx_slot);\n    (void)result;\n    return HANDLER_GO_ON;")
        for variant, text in variants.items():
            path = cls.directory / (variant + ".c")
            path.write_text(text)
            if variant == "current":
                path = source_path('tests/fixtures/lighttpd_i10_native.c', root=ROOT)
            binary = cls.directory / variant
            command = shlex.split(os.environ.get("CC", "cc")) + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread", "-I", str(cls.directory), "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)), str(path)]
            command += [str(source_path('common/src', root=ROOT) / name) for name in ("decision.c", "decision_action.c", "intervention.c", "block_statuses.c", "error.c", "status.c", "late_intervention.c", "http_status.c", "event.c", "json_escape.c", "transaction_state.c")]
            command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(binary)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            if result.returncode: raise AssertionError(result.stderr)
            cls.binaries[variant] = binary

    @classmethod
    def build_sidecar(cls):
        source = (source_path('connectors/lighttpd/stock_sidecar/stock_sidecar.c', root=ROOT)).read_text()
        parts = MATERIALIZER["lighttpd_parts"](sidecar=source)
        MATERIALIZER["write_lighttpd_includes"](parts, cls.directory)
        text = (source_path('tests/fixtures/lighttpd_i10_sidecar.c', root=ROOT)).read_text()
        for name, content in parts.items():
            text = text.replace('#include "' + name + '"', content)
        variants = {"sidecar-current": text,
                    "sidecar-accept-error": text.replace("state.payload.response_headers.status_code) : 0;", "state.payload.response_headers.status_code) : sidecar_write_non_allow_receipt(&receipt_snapshot);"),
                    "sidecar-ignore-return": text.replace("&state->error) != 1)", "&state->error) == 0)"),
                    "sidecar-second-response": text.replace("if (!state->client_response_started)", "if (state->client_response_started >= 0)")}
        variants["sidecar-late-status"] = text.replace(
            "} else if (state->error.code != MSCONNECTOR_ERROR_NONE) {\n        status =",
            "} else if (sidecar_remaining(&state->deadline) == 0) { status = 504; } else if (state->error.code != MSCONNECTOR_ERROR_NONE) {\n        status =")
        variants["sidecar-late-timeout"] = text.replace(
            "state->error.code == MSCONNECTOR_ERROR_NONE &&",
            "state->error.code >= MSCONNECTOR_ERROR_NONE &&")
        for variant, value in variants.items():
            if variant != "sidecar-current":
                assert value != text, f"{variant} mutation did not alter productive extraction"
        for variant, value in variants.items():
            path = cls.directory / (variant + ".c")
            path.write_text(value)
            if variant == "sidecar-current":
                path = source_path('tests/fixtures/lighttpd_i10_sidecar.c', root=ROOT)
            binary = cls.directory / variant
            command = shlex.split(os.environ.get("CC", "cc")) + ["-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread", "-I", str(cls.directory), "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)), str(path)]
            command += [str(source_path('common/src', root=ROOT) / name) for name in ("error.c", "event.c", "http_status.c", "json_escape.c", "transaction_state.c", "decision.c", "decision_action.c", "intervention.c", "block_statuses.c", "status.c", "late_intervention.c")]
            command += [str(source_path('connectors/profile_registry.c', root=ROOT)), "-o", str(binary)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            if result.returncode: raise AssertionError(result.stderr)
            cls.binaries[variant] = binary

    def test_sidecar_socket_errors_and_exchange_result(self):
        self.build_sidecar()
        for mode in range(3):
            for commitment in range(3):
                for operation in range(3):
                    for fault in (0, 1, 2):
                        if operation == 1 and fault == 0: continue
                        with self.subTest(mode=mode, commitment=commitment, operation=operation, fault=fault):
                            # Sidecar argument order uses fault before operation.
                            result = self.call(mode, commitment, fault, operation, "sidecar-current")
                            self.assertEqual(result.returncode, 0, result.stderr)
        for mode in range(3):
            for fault in (5, 6):
                result = self.call(mode, 0, fault, 3, "sidecar-current")
                self.assertEqual(result.returncode, 0, result.stderr)
        for mode in range(3):
            for commitment in range(3):
                for fault in (0, 1, 2):
                    result = self.call(mode, commitment, fault, 4, "sidecar-current")
                    self.assertEqual(result.returncode, 0, result.stderr)
        for variant, commitment, fault, operation in (("sidecar-late-status", 0, 2, 4), ("sidecar-late-timeout", 0, 2, 4), ("sidecar-accept-error", 0, 1, 2), ("sidecar-ignore-return", 1, 2, 0), ("sidecar-second-response", 1, 1, 1)):
            with self.subTest(mutation=variant):
                result = self.call(1, commitment, fault, operation, variant)
                self.assertNotEqual(result.returncode, 0, "socket mutation escaped executable assertions")

    def test_owned_socket_shutdown_is_once_for_success_and_failure(self):
        source = (source_path('connectors/lighttpd/stock_sidecar/stock_sidecar.c', root=ROOT)).read_text()
        helper = function_definition(source, "sidecar_shutdown_owned_socket")
        harness = r'''
#include <assert.h>
#include <sys/socket.h>
#include <unistd.h>
typedef struct { int attempted; int succeeded; } sidecar_owned_socket_stop;
static int calls;
static int forced_failure;
static int observed_shutdown(int fd, int how) {
    ++calls;
    if (forced_failure) return -1;
    return shutdown(fd, how);
}
#define shutdown observed_shutdown
__HELPER__
int main(void) {
    int pair[2];
    char byte;
    sidecar_owned_socket_stop stop = {0};
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(send(pair[0], "x", 1, 0) == 1);
    assert(sidecar_shutdown_owned_socket(pair[0], &stop) == 1);
    assert(stop.attempted == 1 && stop.succeeded == 1 && calls == 1);
    assert(recv(pair[1], &byte, 1, 0) == 1 && byte == 'x');
    assert(recv(pair[1], &byte, 1, 0) == 0);
    assert(sidecar_shutdown_owned_socket(pair[0], &stop) == 1);
    assert(calls == 1);
    assert(close(pair[0]) == 0 && close(pair[1]) == 0);
    stop = (sidecar_owned_socket_stop){0};
    calls = 0;
    forced_failure = 1;
    assert(sidecar_shutdown_owned_socket(-1, &stop) == 0);
    assert(stop.attempted == 1 && stop.succeeded == 0 && calls == 1);
    forced_failure = 0;
    assert(sidecar_shutdown_owned_socket(-1, &stop) == 0);
    assert(calls == 1);
    return 0;
}
'''
        variants = {"owned-stop": helper,
                    "owned-stop-retry": helper.replace("if (stop->attempted)", "if (0)")}
        self.assertNotEqual(variants["owned-stop"], variants["owned-stop-retry"])
        for variant, body in variants.items():
            path = self.directory / (variant + ".c")
            binary = self.directory / variant
            path.write_text(harness.replace("__HELPER__", body))
            compiled = subprocess.run(shlex.split(os.environ.get("CC", "cc")) +
                ["-std=c17", "-Wall", "-Wextra", "-Werror", str(path), "-o", str(binary)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            if variant == "owned-stop":
                self.assertEqual(result.returncode, 0, result.stderr)
            else:
                self.assertNotEqual(result.returncode, 0, "duplicate syscall mutation survived")

    def call(self, mode, commitment, operation, fault, variant="current"):
        return subprocess.run([str(self.binaries[variant]), str(mode), str(commitment), str(operation), str(fault)], capture_output=True, text=True, timeout=10)

    def test_native_off_safe_errors_and_reentry(self):
        for mode in (0, 1):
            for commitment in (0, 1, 2):
                for operation in range(8):
                    for fault in (1, 2, 4, 5, 6, 7, 8):
                        with self.subTest(mode=mode, commitment=commitment, operation=operation, fault=fault):
                            result = self.call(mode, commitment, operation, fault)
                            self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_allocation_failure_cannot_restart_transaction(self):
        for commitment in range(3):
            result = self.call(1, commitment, 5, 9)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_failed_host_action_or_ack_cannot_restart_or_select_second_response(self):
        for operation, fault in ((8, 10), (9, 11)):
            result = self.call(1, 0, operation, fault)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_reset_finish_ack_failure_is_terminal_after_one_cleanup(self):
        for commitment in range(3):
            for operation, fault in ((10, 12), (11, 13)):
                result = self.call(1, commitment, operation, fault)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_successful_control(self):
        for mode in (0, 1):
            for commitment in (0, 1, 2):
                for operation in range(3):
                    result = self.call(mode, commitment, operation, 0)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_mutations_are_red(self):
        for variant in ("swallow-error", "retry-native", "second-response"):
            with self.subTest(variant=variant):
                result = self.call(1, 2, 1, 1, variant)
                self.assertNotEqual(result.returncode, 0, "mutation escaped executable assertions")
        result = self.call(1, 2, 10, 12, "reset-success")
        self.assertNotEqual(result.returncode, 0, "reset success mutation escaped executable assertions")


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__": unittest.main()
