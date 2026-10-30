"""Source-isolated regressions for validated security findings.

The compiled checks exercise the actual small C helpers extracted from the
checkout. Minimal surrounding types and header lookup are test stubs, not a
real host/parser. Some caller-order checks are source contracts only. B09 is
owned and tested by PR #391, not this independent remediation. These tests do
not establish a full live-host deployment acceptance result.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = connector_root()
AUTH = source_path('common/runtime/http_authorization_service.c', root=ROOT)
SIDECAR = source_path('connectors/lighttpd/stock_sidecar/stock_sidecar.c', root=ROOT)
RUNTIME = source_path('common/runtime/msconnector_runtime.c', root=ROOT)


def balanced_block(source: str, opening: int) -> str:
    """Return a C block; ignore brace characters inside comments and strings."""
    if opening >= len(source) or source[opening] != "{":
        raise ValueError("expected opening brace")
    depth = 0
    index = opening
    state = "code"
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line":
            if char == "\n":
                state = "code"
        elif state == "comment":
            if char == "*" and following == "/":
                state = "code"
                index += 1
        elif state in ("'", '"'):
            if char == "\\":
                index += 1
            elif char == state:
                state = "code"
        elif char == "/" and following == "/":
            state = "line"
            index += 1
        elif char == "/" and following == "*":
            state = "comment"
            index += 1
        elif char in ("'", '"'):
            state = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[opening:index + 1]
        index += 1
    raise ValueError("unterminated C block")


def function_body(source: str, name: str) -> str:
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", source)
    if match is None:
        raise ValueError(f"C function definition not found: {name}")
    return balanced_block(source, match.end() - 1)


def macro_line(source: str, name: str) -> str:
    match = re.search(r"^#define[ \t]+" + re.escape(name) + r"[ \t]+[^\n]+", source, re.M)
    if match is None:
        raise ValueError(f"C macro not found: {name}")
    return match.group(0)


class ReportedSecurityRegressions(unittest.TestCase):
    def compile_and_run(self, program: str) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler unavailable; isolated helper regression not executed")
        # The repository's externally configured TMPDIR controls scratch storage.
        with tempfile.TemporaryDirectory(prefix="msconnector-finding-regression-") as temporary:
            root = Path(temporary)
            source = root / "regression.c"
            binary = root / "regression"
            source.write_text(program, encoding="utf-8")
            subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                 str(source), "-o", str(binary)],
                check=True, capture_output=True, text=True, timeout=60,
            )
            subprocess.run(
                [str(binary)], check=True, capture_output=True, text=True, timeout=10,
            )


    def test_b13_authoritative_uri_boundaries_and_no_fallback(self) -> None:
        source = AUTH.read_text(encoding="utf-8")
        limits = (source_path('common/include/msconnector/limits.h', root=ROOT)).read_text(encoding="utf-8")
        program = """
#include <assert.h>
#include <stddef.h>
#include <string.h>
"""
        program += macro_line(limits, "MSCONNECTOR_MAX_HEADER_VALUE_LENGTH") + "\n"
        program += macro_line(source, "AUTH_URI_SIZE") + "\n"
        bound = re.search(r"char uri_override\[([^\]]+)\];", source)
        self.assertIsNotNone(bound)
        assert bound is not None
        program += """
typedef struct {
    const char *name;
    const char *value;
    size_t value_size;
} msconnector_header;
typedef struct {
    msconnector_header *headers;
    size_t header_count;
    char uri_override[URI_OVERRIDE_BOUND];
    char *uri;
} parsed_http_request;
typedef struct {
    const char *const *original_uri_headers;
    size_t original_uri_header_count;
} msconnector_http_authorization_profile;

/* Lookup stub: the production parser/header library is outside this unit. */
static const msconnector_header *msconnector_headers_find_first(
    const msconnector_header *headers, size_t count, const char *name) {
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(headers[i].name, name) == 0) return &headers[i];
    }
    return NULL;
}
""".replace("URI_OVERRIDE_BOUND", bound.group(1))
        program += (
            "static int copy_slice(const char *value, size_t value_size, "
            "char *destination, size_t destination_size) "
            + function_body(source, "copy_slice") + "\n"
        )
        program += (
            "static const char *request_uri(parsed_http_request *request, "
            "const msconnector_http_authorization_profile *profile) "
            + function_body(source, "request_uri") + "\n"
        )
        program += """
int main(void) {
    const char *const names[] = {"X-Forwarded-Uri", "X-Original-Uri"};
    msconnector_http_authorization_profile profile = {names, 2U};
    char path[8194];
    char fallback[] = "/authorize";
    msconnector_header headers[2] = {
        {"X-Forwarded-Uri", path, 0U},
        {"X-Original-Uri", "/secondary", sizeof("/secondary") - 1U}
    };
    parsed_http_request request = {0};
    request.headers = headers;
    request.header_count = 2U;
    request.uri = fallback;
    memset(path, 'a', sizeof(path));
    path[0] = '/';

    const size_t sizes[] = {8191U, 8192U};
    for (size_t i = 0; i < 2U; ++i) {
        headers[0].value_size = sizes[i];
        const char *result = request_uri(&request, &profile);
        assert(result == request.uri_override);
        assert(strlen(result) == sizes[i]);
        assert(memcmp(result, path, sizes[i]) == 0);
    }
    headers[0].value_size = 8193U;
    assert(request_uri(&request, &profile) == NULL);
    headers[0].value_size = 0U;
    assert(request_uri(&request, &profile) == NULL);
    headers[0].value = "invalid";
    headers[0].value_size = sizeof("invalid") - 1U;
    assert(request_uri(&request, &profile) == NULL);
    headers[0].value = NULL;
    assert(request_uri(&request, &profile) == NULL);

    const char embedded_nul[] = {'/', 'a', '\\0', 'b'};
    headers[0].value = embedded_nul;
    headers[0].value_size = sizeof(embedded_nul);
    assert(request_uri(&request, &profile) == NULL);

    request.headers = &headers[1];
    request.header_count = 1U;
    assert(strcmp(request_uri(&request, &profile), "/secondary") == 0);
    request.header_count = 0U;
    assert(request_uri(&request, &profile) == fallback);
    return 0;
}
"""
        self.compile_and_run(program)

    def test_b13_caller_rejects_missing_resolved_uri_before_runtime(self) -> None:
        body = function_body(AUTH.read_text(encoding="utf-8"), "handle_authorization_request")
        resolution = body.index("source.uri = request_uri(")
        check = body.index("if (source.uri == NULL)", resolution)
        invocation = body.index("authorization_process_runtime_request(", resolution)
        self.assertLess(check, invocation)
        failure = balanced_block(body, body.index("{", check))
        self.assertIn("response.status = 400;", failure)
        self.assertIn('response.decision_name = "invalid_request";', failure)
        self.assertIn("parsed_request_destroy(&parsed);", failure)
        self.assertIn("return 0;", failure)


    def test_response_companion_directory_chain_is_canonical_and_fail_closed(self) -> None:
        source = RUNTIME.read_text(encoding="utf-8")
        helper = function_body(
            source, "msconnector_runtime_private_directory_ancestors_are_safe"
        )
        program = r"""
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define RUNTIME_PATH_SIZE 4096U
"""
        program += (
            "static int msconnector_runtime_private_directory_ancestors_are_safe"
            "(const char *path) "
            + helper
            + "\n"
        )
        program += r"""
int main(void)
{
    char safe_root[] = "/tmp/msconnector-safe-XXXXXX";
    char unsafe_root[] = "/tmp/msconnector-unsafe-XXXXXX";
    char safe_child[RUNTIME_PATH_SIZE];
    char unsafe_child[RUNTIME_PATH_SIZE];
    char noncanonical[RUNTIME_PATH_SIZE];

    assert(mkdtemp(safe_root) != NULL);
    assert(snprintf(safe_child, sizeof(safe_child), "%s/private", safe_root) > 0);
    assert(mkdir(safe_child, 0700) == 0);
    assert(msconnector_runtime_private_directory_ancestors_are_safe(safe_child) == 1);
    assert(snprintf(noncanonical, sizeof(noncanonical), "%s/.", safe_child) > 0);
    assert(msconnector_runtime_private_directory_ancestors_are_safe(noncanonical) == 0);

    assert(mkdtemp(unsafe_root) != NULL);
    assert(chmod(unsafe_root, 0777) == 0);
    assert(snprintf(unsafe_child, sizeof(unsafe_child), "%s/private", unsafe_root) > 0);
    assert(mkdir(unsafe_child, 0700) == 0);
    assert(msconnector_runtime_private_directory_ancestors_are_safe(unsafe_child) == 0);

    assert(chmod(unsafe_root, 0700) == 0);
    assert(rmdir(unsafe_child) == 0);
    assert(rmdir(unsafe_root) == 0);
    assert(rmdir(safe_child) == 0);
    assert(rmdir(safe_root) == 0);
    return 0;
}
"""
        self.compile_and_run(program)

    def test_c07_off_branch_records_unapplied_action_not_requested_status(self) -> None:
        """Source contract only; this is not a real event-normalization test."""
        source = SIDECAR.read_text(encoding="utf-8")
        marker = "if (phase4_mode == MSCONNECTOR_PHASE4_MODE_OFF)"
        start = source.index(marker)
        branch = balanced_block(source, source.index("{", start))
        self.assertNotIn("sidecar_record_action(", branch)
        self.assertIn("return msconnector_runtime_transaction_record_host_action(", branch)
        self.assertIn("MSCONNECTOR_DECISION_ACTION_LOG_ONLY", branch)
        self.assertIn('state->payload.response_headers.status_code, "log_only", 0,', branch)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
