"""Guard operation-specific native results and every actual caller."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

from pathlib import Path
import re
import os
import shutil
import subprocess
import tempfile
import unittest
from modsecurity_connector_tests.c_source_contract import function_definition, matching_delimiter


ROOT = connector_root()
COMMON_RUNTIME = (source_path('common/runtime/msconnector_runtime.c', root=ROOT)).read_text(encoding="utf-8")
HAPROXY = (source_path('connectors/haproxy/src/haproxy_modsecurity_binding.c', root=ROOT)).read_text(encoding="utf-8")
APACHE_FILTERS = (source_path('connectors/apache/src/msc_filters.c', root=ROOT)).read_text(encoding="utf-8")


NATIVE_RESULT = (source_path('common/include/msconnector/native_result.h', root=ROOT)).read_text(encoding="utf-8")


def requires_success(source: str, operation: str) -> bool:
    """Check every call, with append partial distinct from phase success."""
    source = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.DOTALL)
    calls = list(re.finditer(rf"{re.escape(operation)}\s*\(", source))
    if not calls:
        return False
    helper = ("msconnector_native_body_append_can_continue" if
        "append" in operation else "msconnector_native_phase_succeeded")
    for call in calls:
        opening = source.index("(", call.start())
        closing = matching_delimiter(source, opening, "(", ")")
        prefix = source[max(0, call.start() - 100):call.start()]
        suffix = source[closing + 1:]
        delegated = re.search(rf"!{helper}\s*\(\s*(?:[A-Za-z_]\w*\s*=\s*)?$", prefix) is not None
        direct = re.match(r"\s*!=\s*1\b", suffix) is not None
        if "append" in operation:
            if not delegated:
                return False
        elif not (delegated or direct):
            return False
    return True


class NativeAPIFailClosedContractTests(unittest.TestCase):
    def test_native_helpers_keep_phase_success_and_append_partial_distinct(self) -> None:
        phase = function_definition(NATIVE_RESULT, "msconnector_native_phase_succeeded")
        self.assertRegex(phase, r"return\s+result\s*==\s*1\s*;")
        classifier = function_definition(NATIVE_RESULT, "msconnector_native_body_result_classify")
        self.assertRegex(classifier, r"if\s*\(result == 0\)\s*\{\s*return MSCONNECTOR_NATIVE_BODY_PARTIAL;")
        self.assertRegex(classifier, r"if\s*\(result == 1\)\s*\{\s*return MSCONNECTOR_NATIVE_BODY_SUCCESS;")
        self.assertTrue(classifier.rstrip().endswith("return MSCONNECTOR_NATIVE_BODY_FAILURE;\n}"))
        append = function_definition(NATIVE_RESULT, "msconnector_native_body_append_can_continue")
        self.assertRegex(append, r"return msconnector_native_body_result_classify\(result\) !=\s*MSCONNECTOR_NATIVE_BODY_FAILURE;")

    def test_call_contract_rejects_unchecked_or_wrong_classifier_calls(self) -> None:
        operation = "msc_process_request_body"
        checked = f"if (!msconnector_native_phase_succeeded({operation}(tx))) return 0;"
        self.assertTrue(requires_success(checked, operation))
        self.assertFalse(requires_success(checked + f" {operation}(tx);", operation))
        self.assertFalse(requires_success(checked.replace("phase_succeeded", "body_append_can_continue"), operation))
        append = "msc_append_request_body"
        self.assertFalse(requires_success(f"if ({append}(tx, data, size) != 1) return 0;", append))
        self.assertFalse(requires_success(f"if (!msconnector_native_phase_succeeded({append}(tx, data, size))) return 0;", append))
        assigned = f"if (!msconnector_native_body_append_can_continue(result = {append}(tx, data, size))) return 0;"
        self.assertTrue(requires_success(assigned, append))
        self.assertFalse(requires_success(assigned.replace("!msconnector", "msconnector"), append))
        self.assertFalse(requires_success(assigned + f" result = {append}(tx, data, size);", append))

    def test_common_runtime_rejects_every_boolean_native_failure(self) -> None:
        for operation in ("msc_process_connection", "msc_process_uri", "msc_set_request_hostname", "msc_add_n_request_header", "msc_process_request_headers", "msc_append_request_body", "msc_process_request_body", "msc_add_n_response_header", "msc_process_response_headers", "msc_append_response_body", "msc_process_response_body"):
            with self.subTest(operation=operation):
                self.assertTrue(requires_success(COMMON_RUNTIME, operation))

    def test_haproxy_rejects_failures_with_append_partial_and_exact_eos(self) -> None:
        for operation in ("msc_process_connection", "msc_add_request_header", "msc_process_request_headers", "msc_append_request_body", "msc_process_request_body", "msc_process_uri", "msc_add_response_header", "msc_process_response_headers"):
            with self.subTest(operation=operation):
                self.assertTrue(requires_success(HAPROXY, operation))
        self.assertTrue(requires_success(function_definition(HAPROXY, "append_body_chunk"), "phase->append_body"))
        self.assertTrue(requires_success(function_definition(HAPROXY, "finish_body"), "phase->finish_body"))
        for function, append, finish in (("request_body_phase", "msc_append_request_body", "msc_process_request_body"),
                                        ("response_body_phase", "msc_append_response_body", "msc_process_response_body")):
            route = function_definition(HAPROXY, function)
            self.assertIn(append + ", " + finish, route)

    def test_apache_response_mapping_and_body_paths_classify_failures(self) -> None:
        for operation in ("msc_process_request_body", "msc_append_request_body", "msc_add_response_header", "msc_process_response_headers", "msc_append_response_body", "msc_process_response_body"):
            with self.subTest(operation=operation):
                self.assertTrue(requires_success(APACHE_FILTERS, operation))

    def test_guard_requires_negative_operation_specific_predicate(self) -> None:
        for operation in ("msc_append_request_body", "msc_process_request_body"):
            helper = "msconnector_native_body_append_can_continue" if "append" in operation else "msconnector_native_phase_succeeded"
            original = f"if (!{helper}({operation}(tx))) return 0;"
            self.assertTrue(requires_success(original, operation))
            self.assertFalse(requires_success(original.replace("!" + helper, helper), operation))
            self.assertFalse(requires_success(original.replace(helper, "unchecked_result"), operation))
            self.assertFalse(requires_success("/* " + original + " */", operation))
        self.assertFalse(requires_success("if (msc_append_request_body(tx) != 1) return 0;", "msc_append_request_body"))
        self.assertFalse(requires_success("if (!msconnector_native_body_append_can_continue(msc_process_request_body(tx))) return 0;", "msc_process_request_body"))

    def test_real_native_predicates_reject_unknown_results_and_preserve_partial(self) -> None:
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix="native-results-", dir=os.environ.get("TMPDIR") or os.environ.get("RUNNER_TEMP")) as directory:
            fixture = Path(directory) / "results.c"
            binary = Path(directory) / "results"
            fixture.write_text('#include "msconnector/native_result.h"\nint main(void) { int values[]={-2,-1,0,1,2,17}; for(unsigned i=0;i<6;i++){int r=values[i]; if(msconnector_native_phase_succeeded(r)!=(r==1))return 1; if(msconnector_native_body_append_can_continue(r)!=(r==0||r==1))return 2;} return 0;}\n')
            compiled = subprocess.run([compiler, "-std=c17", "-Wall", "-Wextra", "-Werror", "-I" + str(source_path('common/include', root=ROOT)), str(fixture), "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
