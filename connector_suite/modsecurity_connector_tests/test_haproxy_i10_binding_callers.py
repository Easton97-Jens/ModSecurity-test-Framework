"""Full HAProxy binding compilation, real Common FSM, controlled native API."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path
from pathlib import Path
import os
import re
import runpy
import subprocess
import tempfile
import unittest
from modsecurity_connector_tests import test_haproxy_libmodsecurity_compat as compat

MATERIALIZER = runpy.run_path(str(test_root() / "ci/checks/analysis/native-cfamily-recipes.py"))
ROOT = connector_root()
BINDING = source_path('connectors/haproxy/src/haproxy_modsecurity_binding.c', root=ROOT)

class HAProxyI10BindingCallers(unittest.TestCase):
    def run_caller(self, source, *, spop=False, runtime_source=None, arguments=()):
        temp_root = Path(os.environ.get("TMPDIR", "/var/tmp/codex/ModSecurity-conector/tmp"))
        temp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="haproxy-i10-native-", dir=temp_root) as directory:
            temp = Path(directory)
            fixture = compat.HAProxyLibModSecurityCompatibilityTests()
            fixture.setUp()
            include, _ = fixture.write_fake_installation(temp / "native",
                optional_declaration=False, optional_symbol=False)
            native_path = temp / "native/fake_modsecurity.c"
            native = "#include <stdio.h>\n" + native_path.read_text()
            control = """
const char *native_failure;
int native_failure_result;
unsigned int native_calls, native_cleanups;
size_t native_request_body_limit = (size_t)-1;
char native_http_version[16];
int native_intervention;
static int test_native(const char *name) {
    native_calls++;
    return native_failure != 0 && strcmp(name, native_failure) == 0 ? native_failure_result : 1;
}
"""
            native = native.replace("struct ModSecurity {", control + "\nstruct ModSecurity {")
            native = native.replace(
                'if (intervention != 0) memset(intervention, 0, sizeof(*intervention)); return 0;',
                'if (intervention != 0) { memset(intervention, 0, sizeof(*intervention)); '
                'if (native_intervention) { intervention->status = 403; intervention->disruptive = 1; '
                'intervention->log = native_intervention == 2 ? '
                '"Response body limit is marked to reject the request" : "[id \\\"123\\\"]"; '
                'return 1; } } return 0;')
            native = native.replace('(void)version; return 1;',
                'snprintf(native_http_version, sizeof(native_http_version), "%s", version); return 1;')
            native = re.sub(r"(int msc_(?:process|append|add)[^\n]+)return 1;", r"\1return test_native(__func__);", native)
            # Common reads retained bytes from the native transaction after an
            # append. Model that state rather than returning a constant length.
            header = include / "modsecurity/modsecurity.h"
            header.write_text(header.read_text() +
                "\nsize_t msc_get_request_body_length(Transaction *);\n")
            native = native.replace("struct Transaction { int value; };",
                "struct Transaction { int value; size_t request_body_length; };")
            native = native.replace("return &TRANSACTION_INSTANCE;",
                "TRANSACTION_INSTANCE.request_body_length = 0; return &TRANSACTION_INSTANCE;")
            append = "int msc_append_request_body(Transaction *value, const unsigned char *data, size_t length) { (void)value; (void)data; (void)length; return test_native(__func__); }"
            self.assertIn(append, native)
            native = native.replace(append, """
int msc_append_request_body(Transaction *value, const unsigned char *data, size_t length) {
    int result = test_native(__func__);
    size_t remaining = native_request_body_limit - value->request_body_length;
    (void)data;
    if (result != 0 && result != 1) return result;
    value->request_body_length += length < remaining ? length : remaining;
    return length > remaining ? 0 : result;
}
size_t msc_get_request_body_length(Transaction *value) { return value->request_body_length; }
int verify_native_request_body_fixture(void) {
    Transaction *value = msc_new_transaction(NULL, NULL, NULL);
    const unsigned char body[] = "abcd";
    if (msc_get_request_body_length(value) != 0) return 1;
    native_request_body_limit = 3;
    if (msc_append_request_body(value, body, 2) != 1 ||
            msc_get_request_body_length(value) != 2) return 2;
    if (msc_append_request_body(value, body, 2) != 0 ||
            msc_get_request_body_length(value) != 3) return 3;
    native_failure = "msc_append_request_body";
    native_failure_result = -1;
    if (msc_append_request_body(value, body, 1) != -1 ||
            msc_get_request_body_length(value) != 3) return 4;
    value = msc_new_transaction(NULL, NULL, NULL);
    if (msc_get_request_body_length(value) != 0) return 5;
    native_failure = NULL;
    native_failure_result = 0;
    native_request_body_limit = (size_t)-1;
    native_calls = 0;
    return 0;
}
""")
            native = native.replace("void msc_transaction_cleanup(Transaction *value) { (void)value; }",
                "void msc_transaction_cleanup(Transaction *value) { (void)value; native_cleanups++; }")
            if spop:
                header = include / "modsecurity/modsecurity.h"
                header.write_text(header.read_text() + "\nint msc_set_request_hostname(Transaction *, const unsigned char *);\nint msc_add_n_request_header(Transaction *, const unsigned char *, size_t, const unsigned char *, size_t);\nint msc_add_n_response_header(Transaction *, const unsigned char *, size_t, const unsigned char *, size_t);\n")
                native += "\nint msc_set_request_hostname(Transaction *t, const unsigned char *h) { (void)t; (void)h; return 1; }\nint msc_add_n_request_header(Transaction *t, const unsigned char *n, size_t nl, const unsigned char *v, size_t vl) { (void)nl; (void)vl; return msc_add_request_header(t,n,v); }\nint msc_add_n_response_header(Transaction *t, const unsigned char *n, size_t nl, const unsigned char *v, size_t vl) { (void)nl; (void)vl; return msc_add_response_header(t,n,v); }\n"
            native_path.write_text(native)
            # Copy only the owned binding TU for mutation, preserving its native includes.
            binding = temp / "binding.c"
            binding.write_text(source)
            harness = temp / "caller.c"
            fixture_name = "haproxy_i10_spop_caller_test.c" if spop else "haproxy_i10_binding_caller_test.c"
            fixture_source = (source_path('tests', root=ROOT) / fixture_name).read_text()
            self.assertIn("int main(int argc, char **argv) {", fixture_source)
            fixture_source = fixture_source.replace("int main(int argc, char **argv) {",
                "int verify_native_request_body_fixture(void);\n"
                "int main(int argc, char **argv) {\n"
                "    if (verify_native_request_body_fixture() != 0) {\n"
                '        fputs("native request body fixture failed\\n", stderr); return 1;\n'
                "    }", 1)
            fixture_source = fixture_source.replace('"PRODUCT_BINDING"', '"' + str(binding) + '"')
            runtime_path = temp / "runtime.c"
            if spop:
                runtime_path.write_text(runtime_source if runtime_source is not None else
                    (source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)).read_text())
                with runtime_path.open("a") as stream:
                    stream.write("\n" + MATERIALIZER["spop_fixture_helper"]() + "\n")
            fixture_source = fixture_source.replace('"PRODUCT_RUNTIME"', '"' + str(runtime_path) + '"')
            fixture_source = fixture_source.replace("PRODUCT_RULES", str(source_path('connectors/haproxy/harness/fixtures/modsecurity-binding-lifecycle.conf', root=ROOT)))
            harness.write_text(fixture_source)
            makefile = (source_path('connectors/haproxy/Makefile', root=ROOT)).read_text()
            sdk = next(line.split(":=", 1)[1].split() for line in makefile.splitlines()
                       if line.startswith("COMMON_SDK_SRCS :="))
            sources = [source_path('common/src', root=ROOT) / item.rsplit("/",1)[1] for item in sdk]
            if spop:
                sources.extend([binding, source_path('common/runtime/msconnector_runtime.c', root=ROOT),
                    source_path('common/runtime/response_companion_transport.c', root=ROOT),
                    source_path('common/runtime/response_companion_client.c', root=ROOT),
                    source_path('connectors/haproxy/src/haproxy_spop_response_companion_backend.c', root=ROOT)])
            command = ["cc", "-std=c17", "-D_POSIX_C_SOURCE=200809L", "-Wall", "-Wextra", "-Werror",
                       "-I", str(include), "-I", str(ROOT), "-I", str(source_path('common/include', root=ROOT)),
                       "-I", str(source_path('connectors/haproxy/src', root=ROOT)), "-I", str(source_path('common/runtime', root=ROOT)),
                       "-pthread", "-ffunction-sections", "-Wl,--gc-sections", str(harness), str(native_path),
                       str(source_path('connectors/haproxy/src/haproxy_modsecurity_mapper.c', root=ROOT)),
                       str(source_path('connectors/profile_registry.c', root=ROOT)), *(str(s) for s in sources),
                       "-o", str(temp / "caller")]
            if os.environ.get("HAPROXY_I10_BINDING_SANITIZERS") == "1":
                command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            compiled = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            return subprocess.run([str(temp / "caller"), *arguments], capture_output=True, text=True, cwd=temp, timeout=30)

    def test_request_only_authorization_finishes_without_response(self):
        result = self.run_caller(BINDING.read_text(), spop=True, arguments=("request-authorization",))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_spop_http_version_reaches_native_api(self):
        result = self.run_caller(BINDING.read_text(), spop=True, arguments=("http-version",))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_spop_missing_unknown_and_conflicting_version_fail_closed(self):
        result = self.run_caller(BINDING.read_text(), spop=True, arguments=("invalid-version",))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_request_authorization_and_native_version_negative_controls(self):
        runtime = (source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)).read_text()
        old = "haproxy_modsecurity_transaction_begin_request_authorization("
        self.assertIn(old, runtime)
        result = self.run_caller(BINDING.read_text(), spop=True,
            runtime_source=runtime.replace(old, "haproxy_modsecurity_transaction_begin("),
            arguments=("request-authorization",))
        self.assertNotEqual(result.returncode, 0, "request scope selection mutation survived")
        result = self.run_caller(BINDING.read_text().replace(
            "safe_uri, safe_method, request->http_version)", 'safe_uri, safe_method, "1.1")'),
            spop=True, arguments=("http-version",))
        self.assertNotEqual(result.returncode, 0, "hardcoded native version mutation survived")

    def test_owner_outcome_writes_physical_common_before_release(self):
        result = self.run_caller(BINDING.read_text(), spop=True, arguments=("owner-events",))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_snapshot_rejects_nondisruptive_nonallow_negative_control(self):
        binding = BINDING.read_text()
        guard = """            (!msconnector_decision_is_disruptive(requested) &&
             requested->kind != MSCONNECTOR_DECISION_KIND_ALLOW) ||
"""
        self.assertIn(guard, binding)
        result = self.run_caller(binding.replace(guard, "", 1),
            spop=True, arguments=("owner-events",))
        self.assertNotEqual(result.returncode, 0, "non-Allow suppression mutation survived")

    def test_owner_event_boundary_mutations_are_detected(self):
        binding = BINDING.read_text()
        runtime = (source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)).read_text()
        mutations = [
            (binding.replace("(msconnector_decision_is_disruptive(requested) &&\n             requested->http_status != transaction->response_companion.native_response_status) ||", ""), runtime),
            (binding.replace("(int)requested->phase != transaction->contract.last_completed_phase ||", ""), runtime),
            (binding.replace("            transaction->response_companion.outcome_recorded ||", ""), runtime),
            (binding.replace("!transaction->response_companion.outcome_recorded ||", ""), runtime),
            (binding.replace("event->decision.rule_id = transaction->contract.rule_id;", "event->decision.rule_id = requested->rule_id;"), runtime),
            (binding, runtime.replace("context->success = spop_bridge_outcome_event_write(context);",
                "(void)spop_bridge_outcome_event_write; context->success = 1;")),
            (binding, runtime.replace("context->command.decision = &context->outcome_decision;",
                "context->command.decision = command->decision;")),
        ]
        for index, (modified_binding, modified_runtime) in enumerate(mutations):
            with self.subTest(mutation=index, binding_changed=modified_binding != binding, runtime_changed=modified_runtime != runtime):
                result = self.run_caller(modified_binding, spop=True, runtime_source=modified_runtime, arguments=("owner-events",))
                self.assertNotEqual(result.returncode, 0, "owner event boundary mutation survived")

    def test_native_response_decisions_accept_host_outcome(self):
        for phase in ("3", "4", "body-limit", "body-limit-logging-failure"):
            with self.subTest(phase=phase):
                result = self.run_caller(BINDING.read_text(), arguments=(phase,))
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_body_limit_logging_failure_negative_control(self):
        source = BINDING.read_text()
        old = 'int result = process_transaction_logging(transaction, decision);'
        self.assertIn(old, source)
        result = self.run_caller(source.replace(old,
            '(void)process_transaction_logging(transaction, decision); int result = 0;'),
            arguments=("body-limit-logging-failure",))
        self.assertNotEqual(result.returncode, 0, "native logging failure was ignored")

    def test_terminal_decision_outcome_negative_control(self):
        source = BINDING.read_text()
        guard = '''(msconnector_transaction_contract_is_terminal(&transaction->contract) &&
                ((transaction->contract.status != MSCONNECTOR_TRANSACTION_STATUS_TERMINAL &&
                  transaction->contract.status != MSCONNECTOR_TRANSACTION_STATUS_COMPLETED) ||
                 (transaction->contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE &&
                  transaction->contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT)))'''
        self.assertIn(guard, source)
        source = source.replace(guard,
            'msconnector_transaction_contract_is_terminal(&transaction->contract)')
        for phase in ("3", "4", "body-limit"):
            with self.subTest(phase=phase):
                result = self.run_caller(source, arguments=(phase,))
                self.assertNotEqual(result.returncode, 0, "terminal outcome rejection survived")

    def test_full_spop_request_caller_and_ack_fail_closed(self):
        result = self.run_caller(BINDING.read_text(), spop=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_spop_native_response_phase_conversion_negative_controls(self):
        source = (source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)).read_text()
        assignment = "context->decision.phase = bridge_phase_from_native_decision(native_decision->phase);"
        self.assertEqual(source.count(assignment), 2)
        mutations = {
            "original-phase-omission": "",
            "numeric-phase-cast": "(void)bridge_phase_from_native_decision(native_decision->phase); context->decision.phase = (enum msconnector_phase)native_decision->phase;",
        }
        for name, replacement in mutations.items():
            with self.subTest(mutation=name):
                # Retain the helper as referenced so omission is detected at runtime,
                # rather than by the compiler's unused-function warning.
                if not replacement:
                    replacement = "(void)bridge_phase_from_native_decision(native_decision->phase);"
                result = self.run_caller(BINDING.read_text(), spop=True,
                    runtime_source=source.replace(assignment, replacement),
                    arguments=("native-decisions",))
                self.assertNotEqual(result.returncode, 0, name + " survived")
                self.assertIn("context.decision.phase == expected_phases[phase]", result.stderr)

    def test_spop_failure_reason_negative_control(self):
        source = (source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)).read_text()
        old = 'runtime_init_decision(decision, retained_phase, "deny", 503, retained_reason);'
        self.assertIn(old, source)
        result = self.run_caller(BINDING.read_text(), spop=True,
            runtime_source=source.replace(old,
                'runtime_init_decision(decision, retained_phase, "deny", 503, reason);'))
        self.assertNotEqual(result.returncode, 0, "borrowed failure reason regression survived")

    def test_spop_request_negative_controls(self):
        source = (source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)).read_text()
        mutations = {
            "native-failure-cause-lost": ("return MSCONNECTOR_ERROR_MODSECURITY_FAILURE;", "return MSCONNECTOR_ERROR_PHASE_SEQUENCE;"),
            "header-failure-cause-lost": ("case MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE: return MSCONNECTOR_ERROR_MODSECURITY_FAILURE;", "case MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE: return MSCONNECTOR_ERROR_PHASE_SEQUENCE;"),
            "technical-fail-open": ('runtime_init_decision(decision, retained_phase, "deny", 503, retained_reason);',
                'runtime_init_decision(decision, retained_phase, "pass", 200, retained_reason);'),
            "ignored-request-terminal-error": ('if (haproxy_modsecurity_transaction_finish_with_decision(transaction, decision) != 0)',
                'if (haproxy_modsecurity_transaction_finish_with_decision(transaction, decision) == 123)'),
            "detect-only-drops-failure-ack": ('return origin != SPOP_ACK_ENGINE_DECISION || mode_enforces(config);',
                'return origin == SPOP_ACK_ENGINE_DECISION || mode_enforces(config);'),
        }
        for name,(old,new) in mutations.items():
            with self.subTest(mutation=name):
                self.assertIn(old,source)
                result = self.run_caller(BINDING.read_text(), spop=True, runtime_source=source.replace(old,new))
                self.assertNotEqual(result.returncode,0,name + " survived")

    def test_real_binding_phase_commit_first_failure_and_reentry(self):
        result = self.run_caller(BINDING.read_text())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_terminal_reentry_and_commit_negative_controls(self):
        source = BINDING.read_text()
        mutations = {
            "technical-outcome-admitted": (
                "transaction->contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE &&",
                "0 &&"),
            "direct-commit-rejected": ("(transaction->response_companion.response_phases_require_companion &&\n                !transaction->response_companion.response_companion_claimed)",
                "!transaction->response_companion.response_companion_claimed"),
            "header-failure-not-terminal": ("MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE, \"msc_add_response_header failed\");",
                "MSCONNECTOR_TRANSACTION_ERROR_NONE, \"msc_add_response_header failed\");"),
        }
        for name, (old, new) in mutations.items():
            with self.subTest(mutation=name):
                self.assertIn(old,source)
                result = self.run_caller(source.replace(old,new))
                self.assertNotEqual(result.returncode,0,name + " survived")


# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
