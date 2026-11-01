"""NGINX response-limit ownership unit tests and source-wiring contracts.

The compiled test uses the actual planner, metadata expression, and Common
body-policy implementation with small NGINX state doubles. It verifies that
all valid Phase-4 modes leave WAF response limits to libModSecurity while
retaining connector accounting/overflow checks. It is not a native
NGINX/libModSecurity integration or HTTP transport test.
"""

from __future__ import annotations
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool

import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

from modsecurity_connector_tests.c_source_contract import function_definition

ROOT = connector_root()
NGINX_SOURCE = source_path('connectors/nginx/src', root=ROOT)
BODY = NGINX_SOURCE / "ngx_http_modsecurity_body_filter.c"
HEADER = NGINX_SOURCE / "ngx_http_modsecurity_header_filter.c"
PREAMBLE = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "msconnector/body_policy.h"
#include "msconnector/options.h"
#include "msconnector/limits.h"

typedef int ngx_int_t;
#define NGX_OK 0
#define NGX_ERROR (-1)
#define MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT 1
#define MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR 2
typedef struct { int error; } test_contract;
typedef struct {
    size_t response_body_bytes_seen;
    size_t response_body_bytes_inspected;
    int response_body_seen;
    int response_body_truncated;
    test_contract contract;
} ngx_http_modsecurity_ctx_t;
typedef struct {
    unsigned long phase4_mode;
} ngx_http_modsecurity_conf_t;
static int msconnector_transaction_contract_fail(
    test_contract *contract, int error, unsigned long now)
{
    (void)now;
    contract->error = error;
    return 0;
}
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "line %d: %s\n", __LINE__, #condition); \
        return 1; \
    } \
} while (0)
"""
CASES = r"""
int main(int argc, char **argv)
{
    ngx_http_modsecurity_ctx_t ctx = {0};
    ngx_http_modsecurity_conf_t conf = {0};
    size_t allowed = 999U;
    const size_t limit = 1048576U;
    unsigned long modes[] = {
        MSCONNECTOR_PHASE4_MODE_SAFE, MSCONNECTOR_PHASE4_MODE_STRICT
    };
    size_t i;
    CHECK(argc == 2);

    if (strcmp(argv[1], "off-large") == 0) {
        conf.phase4_mode = MSCONNECTOR_PHASE4_MODE_OFF;
        CHECK(ngx_http_modsecurity_account_response_body(
            &ctx, &conf, limit + 1U, &allowed) == NGX_OK);
        CHECK(allowed == limit + 1U);
        CHECK(ctx.response_body_bytes_seen == limit + 1U);
        CHECK(ctx.response_body_seen && !ctx.response_body_truncated);
        CHECK(ctx.contract.error == 0);
        CHECK(ctx.response_body_bytes_inspected == 0U);
    } else if (strcmp(argv[1], "off-multiple") == 0) {
        conf.phase4_mode = MSCONNECTOR_PHASE4_MODE_OFF;
        for (i = 0U; i < 3U; ++i) {
            CHECK(ngx_http_modsecurity_account_response_body(
                &ctx, &conf, limit, &allowed) == NGX_OK);
            CHECK(allowed == limit);
            ctx.response_body_bytes_inspected += allowed;
        }
        CHECK(ctx.response_body_bytes_seen == 3U * limit);
        CHECK(!ctx.response_body_truncated);
    } else if (strcmp(argv[1], "safe-strict-boundary") == 0) {
        for (i = 0U; i < sizeof(modes) / sizeof(modes[0]); ++i) {
            memset(&ctx, 0, sizeof(ctx));
            conf.phase4_mode = modes[i];
                CHECK(ngx_http_modsecurity_account_response_body(
                &ctx, &conf, limit, &allowed) == NGX_OK);
            CHECK(allowed == limit);
            ctx.response_body_bytes_inspected += allowed;
            CHECK(ngx_http_modsecurity_account_response_body(
                &ctx, &conf, 1U, &allowed) == NGX_OK);
            CHECK(allowed == 1U);
            CHECK(ctx.response_body_bytes_seen == limit + 1U);
            CHECK(!ctx.response_body_truncated);
            CHECK(ctx.contract.error == 0);
        }
    } else if (strcmp(argv[1], "safe-strict-large") == 0) {
        for (i = 0U; i < sizeof(modes) / sizeof(modes[0]); ++i) {
            memset(&ctx, 0, sizeof(ctx));
            conf.phase4_mode = modes[i];
            CHECK(ngx_http_modsecurity_account_response_body(
                &ctx, &conf, limit + 1U, &allowed) == NGX_OK);
            CHECK(allowed == limit + 1U);
            CHECK(ctx.response_body_bytes_seen == limit + 1U);
            CHECK(ctx.response_body_bytes_inspected == 0U);
            CHECK(!ctx.response_body_truncated);
            CHECK(ctx.contract.error == 0);
        }
    } else if (strcmp(argv[1], "off-overflow") == 0) {
        conf.phase4_mode = MSCONNECTOR_PHASE4_MODE_OFF;
        ctx.response_body_bytes_seen = SIZE_MAX - 1U;
        ctx.response_body_bytes_inspected = SIZE_MAX - 1U;
        CHECK(ngx_http_modsecurity_account_response_body(
            &ctx, &conf, 2U, &allowed) == NGX_ERROR);
        CHECK(allowed == 0U);
        CHECK(ctx.response_body_bytes_seen == SIZE_MAX - 1U);
        CHECK(ctx.response_body_bytes_inspected == SIZE_MAX - 1U);
        CHECK(!ctx.response_body_truncated);
        CHECK(ctx.contract.error == MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);
    } else if (strcmp(argv[1], "off-invalid-accounting") == 0) {
        conf.phase4_mode = MSCONNECTOR_PHASE4_MODE_OFF;
        ctx.response_body_bytes_inspected = 1U;
        CHECK(ngx_http_modsecurity_account_response_body(
            &ctx, &conf, 1U, &allowed) == NGX_ERROR);
        CHECK(allowed == 0U);
        CHECK(ctx.response_body_bytes_seen == 0U);
        CHECK(!ctx.response_body_truncated);
    } else if (strcmp(argv[1], "null-inputs") == 0) {
        conf.phase4_mode = MSCONNECTOR_PHASE4_MODE_OFF;
        CHECK(ngx_http_modsecurity_account_response_body(
            NULL, &conf, 1U, &allowed) == NGX_ERROR);
        CHECK(allowed == 0U);
        allowed = 999U;
        CHECK(ngx_http_modsecurity_account_response_body(
            &ctx, NULL, 1U, &allowed) == NGX_ERROR);
        CHECK(allowed == 0U);
        CHECK(ngx_http_modsecurity_account_response_body(
            &ctx, &conf, 1U, NULL) == NGX_ERROR);
        CHECK(!ctx.response_body_seen);
    } else if (strcmp(argv[1], "empty") == 0) {
        for (i = 0U; i < 3U; ++i) {
            memset(&ctx, 0, sizeof(ctx));
            conf.phase4_mode = i;
            CHECK(ngx_http_modsecurity_account_response_body(
                &ctx, &conf, 0U, &allowed) == NGX_OK);
            CHECK(allowed == 0U);
            CHECK(!ctx.response_body_seen && !ctx.response_body_truncated);
        }
    } else {
        return 2;
    }
    return 0;
}
"""


def unit_program(body: str, header: str) -> str:
    planner = function_definition(body, "ngx_http_modsecurity_account_response_body")
    return PREAMBLE + "\nstatic ngx_int_t\n" + planner + CASES


class NginxPhase4BudgetUnitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("a C compiler is required for Phase-4 budget unit tests")
        temporary = tempfile.TemporaryDirectory(prefix="nginx-phase4-budget-")
        cls.addClassCleanup(temporary.cleanup)
        source = Path(temporary.name) / "budget.c"
        cls.binary = Path(temporary.name) / "budget"
        source.write_text(unit_program(
            BODY.read_text(encoding="utf-8"),
            HEADER.read_text(encoding="utf-8"),
        ), encoding="utf-8")
        result = subprocess.run(
            compiler + [
                "-std=c17", "-Wall", "-Wextra", "-Werror",
                "-I", str(source_path('common/include', root=ROOT)),
                str(source), str(source_path('common/src/body_policy.c', root=ROOT)),
                "-o", str(cls.binary),
            ],
            text=True, capture_output=True, timeout=30, check=False,
        )
        if result.returncode:
            raise AssertionError(f"budget unit compilation failed:\n{result.stderr}")

    def run_case(self, name: str) -> None:
        result = subprocess.run(
            [str(self.binary), name], text=True, capture_output=True,
            timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_off_allows_large_buffer_and_has_no_secondary_contract_budget(self) -> None:
        self.run_case("off-large")

    def test_off_accounts_for_multiple_buffers_above_configured_budget(self) -> None:
        self.run_case("off-multiple")

    def test_safe_and_strict_do_not_enforce_the_legacy_connector_limit(self) -> None:
        self.run_case("safe-strict-boundary")

    def test_safe_and_strict_accept_a_buffer_above_the_legacy_limit(self) -> None:
        self.run_case("safe-strict-large")

    def test_off_still_rejects_counter_overflow(self) -> None:
        self.run_case("off-overflow")

    def test_off_still_rejects_inconsistent_accounting(self) -> None:
        self.run_case("off-invalid-accounting")

    def test_null_planner_inputs_fail_without_dereferencing(self) -> None:
        self.run_case("null-inputs")

    def test_empty_buffers_do_not_mark_body_started(self) -> None:
        self.run_case("empty")



class NginxPhase4BudgetWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.body = BODY.read_text(encoding="utf-8")

    def test_memory_and_file_buffers_share_mode_aware_planner(self) -> None:
        for name, append_call in (
            ("ngx_http_modsecurity_append_accounted_response_body",
             "return ngx_http_modsecurity_append_response_body_chunk"),
            ("ngx_http_modsecurity_append_file_response_body", "ngx_read_file("),
        ):
            with self.subTest(function=name):
                source = function_definition(self.body, name)
                self.assertLess(
                    source.index("ngx_http_modsecurity_account_response_body("),
                    source.index(append_call),
                )
                self.assertIn("return NGX_ERROR;", source)
        file_source = function_definition(
            self.body, "ngx_http_modsecurity_append_file_response_body"
        )
        self.assertIn("NGX_HTTP_MODSECURITY_PHASE4_FILE_READ_CHUNK", file_source)
        self.assertIn("read_count < 0 || (size_t)read_count != chunk", file_source)

    def test_all_modes_share_common_accounting_without_manual_increment(self) -> None:
        planner = function_definition(
            self.body, "ngx_http_modsecurity_account_response_body"
        )
        self.assertNotIn("msconnector_body_limit_plan_chunk(", planner)
        self.assertNotIn("msconnector_phase4_effective_body_limit(", planner)
        self.assertIn("SIZE_MAX - ctx->response_body_bytes_seen", planner)
        self.assertIn("ctx->response_body_bytes_seen += len;", planner)
        self.assertIn("*allowed = len;", planner)
        self.assertNotIn("mcf->phase4_mode", planner)

    def test_off_does_not_remove_engine_ingestion_or_finalization(self) -> None:
        append = function_definition(
            self.body, "ngx_http_modsecurity_append_response_body_chunk"
        )
        final = function_definition(
            self.body, "ngx_http_modsecurity_process_final_response_body"
        )
        self.assertIn("msc_append_response_body(", append)
        self.assertIn("msconnector_transaction_contract_record_body(", append)
        self.assertLess(
            final.index("msc_process_response_body("),
            final.index("mcf->phase4_mode == MSCONNECTOR_PHASE4_MODE_OFF"),
        )

    def test_missing_configuration_fails_before_phase4_dereferences(self) -> None:
        for name in (
            "ngx_http_modsecurity_phase4_log_event",
            "ngx_http_modsecurity_phase4_handle_intervention",
        ):
            with self.subTest(function=name):
                source = function_definition(self.body, name)
                match = re.search(
                    r"if\s*\(mcf == NULL\)\s*\{\s*return NGX_ERROR;\s*\}",
                    source,
                )
                self.assertIsNotNone(match)
                self.assertLess(match.end(), source.index("mcf->"))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
