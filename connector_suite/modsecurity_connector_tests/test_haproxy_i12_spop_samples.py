"""Execute native bounded-sample admission and independently targeted mutants.

These are C admission checks, not HAProxy host or lifecycle qualifications.
"""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = connector_root()
SOURCE = source_path('connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c', root=ROOT)
MAIN = r'''
#undef main
int main(void) {
    if (run_spop_notify_failure_self_test() != 0) return 20;
    if (run_spop_sample_typed_arguments_self_test() != 0) return 21;
    runtime_header headers[2] = {{"Content-Length", "4"}, {"Content-Length", "4"}};
    notify_request request = {0};
    request.has_headers_bin = request.has_body = request.has_body_len_arg = 1;
    request.http_metadata.has_http_version = 1;
    strcpy(request.http_metadata.http_version, "1.1");
    if (!notify_request_has_complete_body_sample(&request)) return 1;
    request.has_body_len_arg = 0;
    if (notify_request_has_complete_body_sample(&request)) return 2;
    request.has_body_len_arg = 1;
    /* Known CL=0 isolates the mandatory version-presence guard from the
     * separate HTTP/1-only unframed-empty fallback below. */
    headers[0].value = "0";
    request.headers = headers;
    request.header_count = 1;
    request.http_metadata.has_http_version = 0;
    if (notify_request_has_complete_body_sample(&request)) return 3;
    request.http_metadata.has_http_version = 1;
    request.header_count = 0;
    headers[0].value = "4";
    strcpy(request.http_metadata.http_version, "2.0");
    if (notify_request_has_complete_body_sample(&request)) return 4;
    request.body_len = request.http_metadata.advertised_body_len = 4U;
    if (notify_request_has_complete_body_sample(&request)) return 5;
    request.headers = headers;
    request.header_count = 1;
    if (!notify_request_has_complete_body_sample(&request)) return 6;
    request.http_metadata.advertised_body_len = 3U;
    if (notify_request_has_complete_body_sample(&request)) return 7;
    request.http_metadata.advertised_body_len = 4U;
    request.header_count = 2;
    if (notify_request_has_complete_body_sample(&request)) return 8;
    request.header_count = 1;
    headers[0].value = "4x";
    if (notify_request_has_complete_body_sample(&request)) return 9;
    headers[0].value = "184467440737095516160";
    if (notify_request_has_complete_body_sample(&request)) return 10;
    headers[0].name = "Transfer-Encoding";
    headers[0].value = "chunked";
    if (notify_request_has_complete_body_sample(&request)) return 11;
    request.header_count = 0;
    request.body_len = request.http_metadata.advertised_body_len = 0U;
    strcpy(request.http_metadata.http_version, "1.0");
    if (!notify_request_has_complete_body_sample(&request)) return 12;
    request.has_headers_bin = 0;
    if (notify_request_has_complete_body_sample(&request)) return 13;
    return 0;
}
'''


class HaproxyI12SpopSampleTests(unittest.TestCase):
    def test_native_admission_and_independent_version_framing_mutants(self):
        temporary_root = Path(os.environ.get("RUNNER_TEMP") or os.environ.get("TMPDIR")
                              or "/var/tmp/codex/ModSecurity-conector/tmp")
        temporary_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="i12-spop-samples-", dir=temporary_root) as temporary:
            directory = Path(temporary)
            original = SOURCE.read_text()
            anchor = "request->http_metadata.has_http_version && request->http_metadata.http_version[0] == '1'"
            self.assertEqual(original.count(anchor), 1)
            presence_anchor = "!request->http_metadata.has_http_version ||\n            "
            self.assertEqual(original.count(presence_anchor), 1)
            for name, text, expected in (("current", original, 0),
                                         ("unframed-http2-mutant", original.replace(anchor, "1", 1), 4),
                                         ("missing-version-mutant", original.replace(presence_anchor, "", 1), 3)):
                with self.subTest(mutation=name, expected_native_exit=expected):
                    self.compile_and_run(directory, name, text, expected)

    def compile_and_run(self, directory, name, text, expected):
        source = directory / (name + ".c")
        source.write_text("#define main haproxy_spop_unused_program_main\n" + text + MAIN)
        binary = directory / name
        command = ["cc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-pthread",
                   "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
                   "-I" + str(source_path('common/include', root=ROOT)),
                   "-I" + str(source_path('connectors/haproxy/src', root=ROOT)), str(source),
                   str(source_path('common/src/transaction_state.c', root=ROOT)), "-o", str(binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        result = subprocess.run([str(binary)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, expected, result.stderr)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
