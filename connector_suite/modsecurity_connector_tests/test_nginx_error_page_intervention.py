"""Focused B09 regression for the NGINX error-page context boundary.

The compiled C shims exercise policy-aware context recovery, exact configured
block-error destinations, audit ownership, native return values and event sinks. It is not live NGINX,
libmodsecurity, error_page-routing, or transport evidence.
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
SOURCE = source_path('connectors/nginx/src', root=ROOT)


RECOVERY_PREAMBLE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "msconnector/transaction_contract.h"
typedef long ngx_int_t;
typedef unsigned long ngx_uint_t;
typedef unsigned char u_char;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { void *elts; ngx_uint_t nelts; } ngx_array_t;
typedef struct { ngx_str_t value; } ngx_http_complex_value_t;
typedef struct { ngx_int_t status, overwrite; ngx_http_complex_value_t value; } ngx_http_err_page_t;
typedef struct {
    ngx_array_t *error_pages;
    int named;
    ngx_str_t name;
} ngx_http_core_loc_conf_t;
typedef struct ngx_pool_cleanup_s {
    void (*handler)(void *);
    void *data;
    struct ngx_pool_cleanup_s *next;
} ngx_pool_cleanup_t;
typedef struct { ngx_pool_cleanup_t *cleanup; } ngx_pool_t;
typedef struct {
    const void *rules_identity;
    int enable, use_error_log;
    void *transaction_id;
    unsigned phase4_mode, engine_call_budget_ms;
    void *phase4_log_file;
} ngx_http_modsecurity_conf_t;
typedef struct request_s {
    ngx_pool_t *pool;
    ngx_http_modsecurity_conf_t *conf;
    ngx_http_core_loc_conf_t *core;
    void *ctx;
    int internal, err_status, error_page;
    ngx_str_t uri;
} ngx_http_request_t;
typedef struct {
    ngx_http_request_t *r;
    struct {
        ngx_pool_t *pool;
        const ngx_http_modsecurity_conf_t *conf;
        const char *cleanup_method;
        const char *cleanup_uri;
    } lifetime;
    void *modsec_transaction;
    msconnector_transaction_contract contract;
    int intervention_triggered, logged, request_policy_superseded;
    enum msconnector_phase native_event_phase;
    ngx_int_t last_intervention_status;
    ngx_int_t request_error_status;
    struct {
        ngx_str_t target;
        ngx_int_t status;
        ngx_int_t response_status;
    } error_page;
} ngx_http_modsecurity_ctx_t;
enum { NGX_OK = 0, NGX_ERROR = -1, NGX_DECLINED = -5, NGX_HTTP_INTERNAL_SERVER_ERROR = 500 };
#define dd(...) ((void)0)
static int initializations;
#define ngx_http_modsecurity_module 1
#define ngx_http_core_module 2
#define ngx_http_get_module_loc_conf(r, module) \
    ((module) == 1 ? (void *)(r)->conf : (void *)(r)->core)
#define ngx_http_get_module_ctx(r, module) ((r)->ctx)
/* NGINX's macro supplies the terminating semicolon itself. */
#define ngx_http_set_ctx(r, context, module) ((r)->ctx = (context));
#define ngx_strncmp(a,b,length) strncmp((const char *)(a),(const char *)(b),length)
static u_char *ngx_strlchr(u_char *first, u_char *last, u_char c) {
    while (first < last) { if (*first == c) return first; ++first; }
    return NULL;
}
static int ngx_http_complex_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *value, ngx_str_t *result) {
    (void)r; *result = value->value; return NGX_OK;
}
static void ngx_http_modsecurity_cleanup(void *data) { (void)data; }
int msconnector_transaction_contract_supersede_response(
    msconnector_transaction_contract *contract, uint64_t now_ms) {
    (void)now_ms; contract->status = MSCONNECTOR_TRANSACTION_STATUS_TERMINAL;
    return MSCONNECTOR_TRANSACTION_TRANSITION_OK;
}
static int audits, foreign_audits;
static ngx_http_request_t *expected_request;
static int ngx_http_modsecurity_log_context(ngx_http_modsecurity_ctx_t *ctx) {
    if (!ctx->logged) {
        ctx->logged = 1;
        if (ctx->r == expected_request) ++audits; else ++foreign_audits;
    }
    return NGX_OK;
}
"""
RECOVERY_ACCESS_STUBS = r"""
static ngx_int_t ngx_http_modsecurity_request_terminal_status(ngx_http_request_t *r, ngx_int_t status) {
    (void)r; return status;
}
static ngx_int_t ngx_http_modsecurity_initialize_request(ngx_http_request_t *r,
    const ngx_http_modsecurity_conf_t *mcf) {
    (void)r; (void)mcf; ++initializations; return NGX_OK;
}
static ngx_int_t ngx_http_modsecurity_request_result(ngx_http_request_t *r,
    const ngx_http_modsecurity_conf_t *mcf, enum msconnector_phase phase, ngx_int_t result) {
    (void)r; (void)mcf; (void)phase; return result;
}
static ngx_int_t ngx_http_modsecurity_process_request_body(ngx_http_request_t *r,
    const ngx_http_modsecurity_conf_t *mcf) {
    (void)r; (void)mcf; return NGX_DECLINED;
}
"""
RECOVERY_MAIN = r"""
static ngx_str_t text(char *value) {
    ngx_str_t result = {strlen(value), (u_char *)value};
    return result;
}
int main(int argc, char **argv) {
    int identity1, identity2, found;
    ngx_http_modsecurity_conf_t source = {0}, target;
    ngx_http_core_loc_conf_t original_core = {0}, target_core = {0};
    ngx_http_err_page_t page = {403, -1, {{0, NULL}}};
    ngx_array_t pages = {&page, 1};
    ngx_pool_t pool = {NULL};
    ngx_http_request_t request = {0}, foreign = {0};
    ngx_http_modsecurity_ctx_t ctx = {0}, second = {0}, foreign_ctx = {0};
    ngx_pool_cleanup_t cln = {ngx_http_modsecurity_cleanup, &ctx, NULL};
    ngx_pool_cleanup_t cln2 = {ngx_http_modsecurity_cleanup, &second, NULL};
    ngx_pool_cleanup_t other = {ngx_http_modsecurity_cleanup, &foreign_ctx, NULL};
    if (argc != 2) return 2;
    source.rules_identity = &identity1;
    source.enable = 1;
    target = source;
    request.pool = &pool;
    request.conf = &source;
    request.core = &original_core;
    request.uri = text("/request");
    expected_request = &request;
    pool.cleanup = &cln;
    ctx.r = &request;
    ctx.lifetime.conf = &source;
    ctx.modsec_transaction = &ctx;
    ctx.native_event_phase = MSCONNECTOR_PHASE_REQUEST_BODY;
    ctx.last_intervention_status = 403;
    ctx.intervention_triggered = 0;
    ctx.contract.engine_decision = MSCONNECTOR_TRANSACTION_DECISION_BLOCK;
    original_core.error_pages = &pages;
    page.value.value = text(strcmp(argv[1], "named") == 0 ? "@blocked" : "/403.html?reason=waf");
    if (strcmp(argv[1], "error-page-200") == 0) page.overwrite = 200;
    if (strcmp(argv[1], "error-page-auto") == 0) page.overwrite = 0;
    ngx_http_modsecurity_capture_error_page(&request, &ctx, 403);
    request.conf = &target;
    request.core = &target_core;
    if (strcmp(argv[1], "rules") == 0) target.rules_identity = &identity2;
    if (strcmp(argv[1], "mode") == 0) target.phase4_mode = 1;
    if (strcmp(argv[1], "disabled") == 0) target.enable = 0;
    if (strcmp(argv[1], "foreign") == 0) ctx.r = &foreign;
    if (strcmp(argv[1], "same") == 0 || strcmp(argv[1], "rules") == 0 ||
        strcmp(argv[1], "mode") == 0 || strcmp(argv[1], "disabled") == 0 ||
        strcmp(argv[1], "foreign") == 0 || strcmp(argv[1], "access-same") == 0) {
        ctx.contract.engine_decision = MSCONNECTOR_TRANSACTION_DECISION_ALLOW;
    }
    if (strcmp(argv[1], "same-blocked") == 0) {
        ctx.intervention_triggered = request.internal = 1;
        request.err_status = 403;
        request.uri = text("/unrelated");
    }
    if (strcmp(argv[1], "technical") == 0) {
        ctx.request_error_status = 500;
        ctx.contract.error_class = MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR;
    }
    if (strcmp(argv[1], "direct-block") == 0) {
        ctx.intervention_triggered = 1;
        request.ctx = &ctx;
    }
    if (strcmp(argv[1], "error-page") == 0 || strcmp(argv[1], "access-error-page") == 0 ||
        strcmp(argv[1], "wrongtarget") == 0 ||
        strcmp(argv[1], "error-page-200") == 0 || strcmp(argv[1], "error-page-auto") == 0 ||
        strcmp(argv[1], "flag-only") == 0 || strcmp(argv[1], "wrongstatus") == 0 ||
        strcmp(argv[1], "named") == 0) {
        target.rules_identity = &identity2;
        request.internal = request.error_page = ctx.intervention_triggered = 1;
        request.err_status = page.overwrite >= 0 ? (int)page.overwrite : 403;
        request.uri = text("/403.html");
    }
    if (strcmp(argv[1], "wrongtarget") == 0) request.uri = text("/unrelated");
    if (strcmp(argv[1], "wrongstatus") == 0) request.err_status = 404;
    if (strcmp(argv[1], "flag-only") == 0)
        ctx.contract.engine_decision = MSCONNECTOR_TRANSACTION_DECISION_ALLOW;
    if (strcmp(argv[1], "named") == 0) {
        target_core.named = 1;
        target_core.name = text("@blocked");
        request.uri = text("/request");
    }
    if (strcmp(argv[1], "audit-all") == 0) {
        second = ctx;
        second.lifetime.conf = &target;
        foreign_ctx = ctx;
        foreign_ctx.r = &foreign;
        cln.next = &cln2;
        cln2.next = &other;
        ngx_http_modsecurity_log_request_contexts(&request);
        ngx_http_modsecurity_log_request_contexts(&request);
    }
    if (strcmp(argv[1], "access-same") == 0 || strcmp(argv[1], "access-error-page") == 0)
        (void)ngx_http_modsecurity_access_handler(&request);
    found = ngx_http_modsecurity_get_module_ctx(&request) == &ctx;
    printf("%d %d %d %d %ld %d\n", found, request.ctx == &ctx,
        audits, foreign_audits, (long)ctx.error_page.status, initializations);
    return 0;
}
"""


class NginxErrorPageContextContractTests(unittest.TestCase):
    """Execute actual recovery/snapshot/audit-iteration C with host stubs."""

    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("A C17 compiler is required for context regressions")
        temporary = tempfile.TemporaryDirectory(prefix="nginx-context-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        module = (SOURCE / "ngx_http_modsecurity_module.c").read_text(encoding="utf-8")
        functions = (
            ("void", "ngx_http_modsecurity_capture_error_page"),
            ("int", "ngx_http_modsecurity_same_policy"),
            ("int", "ngx_http_modsecurity_is_block_error_page"),
            ("ngx_int_t", "ngx_http_modsecurity_prepare_location"),
            ("ngx_http_modsecurity_ctx_t *", "ngx_http_modsecurity_get_module_ctx"),
            ("ngx_int_t", "ngx_http_modsecurity_log_request_contexts"),
        )
        fixture = directory / "context.c"
        access = (SOURCE / "ngx_http_modsecurity_access.c").read_text(encoding="utf-8")
        fixture.write_text(RECOVERY_PREAMBLE + "\n" + "\n".join(
            result + "\n" + function_definition(module, name) for result, name in functions
        ) + RECOVERY_ACCESS_STUBS + "\nngx_int_t\n" +
            function_definition(access, "ngx_http_modsecurity_access_handler") +
            RECOVERY_MAIN, encoding="utf-8")
        cls.binary = directory / "context"
        build = subprocess.run(compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror",
            "-I", str(source_path('common/include', root=ROOT)), str(fixture), "-o", str(cls.binary)],
            capture_output=True, text=True, timeout=30, check=False)
        if build.returncode:
            raise AssertionError("context regression failed to compile:\n" + build.stderr[-4000:])

    def observe_context(self, scenario: str) -> tuple[int, ...]:
        result = subprocess.run([str(self.binary), scenario], capture_output=True,
                                text=True, check=True, timeout=5)
        return tuple(int(value) for value in result.stdout.split())

    def test_equal_inherited_policy_recovers_and_republishes_original_owner(self) -> None:
        self.assertEqual(self.observe_context("same"), (1, 1, 0, 0, 403, 0))

    def test_different_rules_or_mode_cannot_recover_source_policy(self) -> None:
        for scenario in ("rules", "mode"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.observe_context(scenario)[:2], (0, 0))

    def test_disabled_location_and_subrequest_never_inherit_an_owner(self) -> None:
        for scenario in ("disabled", "foreign"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.observe_context(scenario)[:2], (0, 0))

    def test_exact_configured_block_error_page_can_use_different_target_policy(self) -> None:
        for scenario in ("error-page", "error-page-200", "error-page-auto", "named"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.observe_context(scenario)[:2], (1, 1))

    def test_arbitrary_error_flag_status_or_destination_does_not_authorize_bypass(self) -> None:
        for scenario in ("flag-only", "wrongstatus", "wrongtarget"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.observe_context(scenario)[:2], (0, 0))

    def test_same_policy_unrelated_redirect_cannot_reuse_a_blocked_owner(self) -> None:
        self.assertEqual(self.observe_context("same-blocked")[:2], (0, 0))

    def test_technical_failure_cannot_be_recovered_as_allow(self) -> None:
        self.assertEqual(self.observe_context("technical")[:2], (0, 0))

    def test_current_blocked_context_remains_available_for_original_finalization(self) -> None:
        self.assertEqual(self.observe_context("direct-block")[:2], (1, 1))

    def test_access_reentry_does_not_create_another_transaction_for_equivalent_policy_or_block_page(self) -> None:
        for scenario in ("access-same", "access-error-page"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.observe_context(scenario)[5], 0)

    def test_log_iteration_visits_each_owned_transaction_and_excludes_subrequests(self) -> None:
        self.assertEqual(self.observe_context("audit-all")[2:4], (2, 0))


MODE_PREAMBLE = r"""
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "msconnector/config_parser.h"
typedef long ngx_int_t;
typedef unsigned long ngx_uint_t;
typedef struct { size_t len; unsigned char *data; } ngx_str_t;
typedef struct { void *elts; } ngx_array_t;
typedef struct { ngx_array_t *args; void *pool; } ngx_conf_t;
typedef struct { int unused; } ngx_command_t;
typedef struct {
    enum msconnector_phase4_mode phase4_mode;
    int enable, use_error_log;
} msconnector_config;
typedef struct {
    msconnector_config common_config;
    ngx_int_t enable, use_error_log;
    void *transaction_id, *phase4_log_file, *rules_set;
    ngx_uint_t phase4_mode, engine_call_budget_ms;
    ngx_str_t phase4_log_path;
    const void *rules_identity;
    int rules_configured;
} ngx_http_modsecurity_conf_t;
#define NGX_CONF_OK NULL
#define NGX_CONF_ERROR ((char *)-1)
#define NGX_CONF_UNSET -1
#define NGX_CONF_UNSET_UINT ((ngx_uint_t)-1)
#define NGX_CONF_UNSET_PTR ((void *)-1)
#define ngx_conf_merge_value(c,p,d) if ((c) == NGX_CONF_UNSET) (c) = ((p) == NGX_CONF_UNSET ? (d) : (p))
#define ngx_conf_merge_uint_value(c,p,d) if ((c) == NGX_CONF_UNSET_UINT) (c) = ((p) == NGX_CONF_UNSET_UINT ? (d) : (p))
#define ngx_conf_merge_ptr_value(c,p,d) if ((c) == NGX_CONF_UNSET_PTR) (c) = ((p) == NGX_CONF_UNSET_PTR ? (d) : (p))
#define dd(...) ((void)0)
static char *ngx_str_to_char(ngx_str_t input, void *pool) {
    static char text[32];
    (void)pool;
    if (input.len >= sizeof(text)) return (char *)-1;
    memcpy(text, input.data, input.len); text[input.len] = 0; return text;
}
/* Common's separate merge contract is controlled here. The actual NGINX
 * merger and actual shared mode parser are the behavior under test. */
static int msconnector_config_merge(msconnector_config *out,
    const msconnector_config *parent, const msconnector_config *child) {
    enum msconnector_phase4_mode value = child->phase4_mode;
    out->phase4_mode = value == MSCONNECTOR_PHASE4_MODE_UNSET ? parent->phase4_mode : value;
    return 1;
}
static void msconnector_config_apply_defaults(msconnector_config *config) {
    if (config->phase4_mode == MSCONNECTOR_PHASE4_MODE_UNSET)
        config->phase4_mode = MSCONNECTOR_PHASE4_MODE_OFF;
}
static int msconnector_config_validate(const msconnector_config *config, void *output, size_t length) {
    (void)output; (void)length;
    return config->phase4_mode >= MSCONNECTOR_PHASE4_MODE_OFF &&
        config->phase4_mode <= MSCONNECTOR_PHASE4_MODE_STRICT;
}
static int msc_rules_merge(void *child, void *parent, const char **error) {
    (void)child; (void)parent; (void)error; return 0;
}
"""
MODE_MAIN = r"""
static void init(ngx_http_modsecurity_conf_t *config) {
    memset(config, 0, sizeof(*config));
    config->phase4_mode = NGX_CONF_UNSET_UINT;
    config->common_config.phase4_mode = MSCONNECTOR_PHASE4_MODE_UNSET;
    config->enable = config->use_error_log = NGX_CONF_UNSET;
    config->transaction_id = config->phase4_log_file = NGX_CONF_UNSET_PTR;
    config->rules_identity = config;
    config->engine_call_budget_ms = NGX_CONF_UNSET_UINT;
}
static char *set(ngx_http_modsecurity_conf_t *config, char *value) {
    ngx_str_t args[2] = {{0, NULL}, {strlen(value), (unsigned char *)value}};
    ngx_array_t array = {args};
    ngx_conf_t cf = {&array, NULL};
    return ngx_conf_set_phase4_mode(&cf, NULL, config);
}
int main(int argc, char **argv) {
    ngx_http_modsecurity_conf_t parent, child;
    ngx_conf_t cf = {0};
    char *first, *second = NULL, *merged;
    if (argc != 4) return 2;
    init(&parent); init(&child);
    first = set(&parent, argv[1]);
    if (strcmp(argv[2], "-") != 0) second = set(&parent, argv[2]);
    if (strcmp(argv[3], "-") != 0 && set(&child, argv[3]) != NGX_CONF_OK) return 3;
    merged = ngx_http_modsecurity_merge_conf(&cf, &parent, &child);
    printf("%d %d %d %lu %lu %d %d\n", first == NGX_CONF_OK,
        second != NULL && second != NGX_CONF_ERROR && strcmp(second, "is duplicate") == 0,
        merged == NGX_CONF_OK, parent.phase4_mode, child.phase4_mode,
        (int)parent.common_config.phase4_mode, (int)child.common_config.phase4_mode);
    return 0;
}
"""


class NginxPhase4ModeSetterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("A C17 compiler is required for mode regressions")
        temporary = tempfile.TemporaryDirectory(prefix="nginx-mode-", dir=os.environ.get("RUNNER_TEMP"))
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        module = (SOURCE / "ngx_http_modsecurity_module.c").read_text(encoding="utf-8")
        parser = source_path('common/src/config_parser.c', root=ROOT).read_text(encoding="utf-8")
        fixture = directory / "mode.c"
        fixture.write_text(MODE_PREAMBLE + "\n" + function_definition(parser, "token_equals") +
            "\n" + function_definition(parser, "msconnector_parse_phase4_mode") +
            "\nchar *\n" + function_definition(module, "ngx_conf_set_phase4_mode") +
            "\nchar *\n" + function_definition(module, "ngx_http_modsecurity_merge_conf") +
            MODE_MAIN, encoding="utf-8")
        cls.binary = directory / "mode"
        build = subprocess.run(compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror",
            "-I", str(source_path('common/include', root=ROOT)), str(fixture), "-o", str(cls.binary)],
            capture_output=True, text=True, timeout=30, check=False)
        if build.returncode:
            raise AssertionError("mode regression failed to compile:\n" + build.stderr[-4000:])

    def observe_mode(self, parent: str, duplicate: str = "-", child: str = "-") -> tuple[int, ...]:
        result = subprocess.run([str(self.binary), parent, duplicate, child], capture_output=True,
                                text=True, check=True, timeout=5)
        return tuple(int(value) for value in result.stdout.split())

    def test_same_context_duplicate_is_rejected_without_replacing_first_mode(self) -> None:
        control = self.observe_mode("safe")
        duplicate = self.observe_mode("safe", "strict")
        self.assertEqual(duplicate[:3], (1, 1, 1))
        self.assertEqual(duplicate[3:], control[3:])

    def test_off_safe_strict_and_invalid_modes_share_the_common_parser(self) -> None:
        for mode in ("off", "safe", "strict"):
            with self.subTest(mode=mode):
                observed = self.observe_mode(mode)
                self.assertEqual(observed[:3], (1, 0, 1))
                self.assertEqual(observed[3], observed[4])
                self.assertEqual(observed[3], observed[5])
        self.assertEqual(self.observe_mode("minimal")[0], 0)

    def test_parent_mode_inherits_but_explicit_child_off_and_strict_are_allowed(self) -> None:
        inherited = self.observe_mode("safe")
        for child in ("off", "strict"):
            with self.subTest(child=child):
                observed = self.observe_mode("safe", child=child)
                self.assertEqual(observed[:3], (1, 0, 1))
                self.assertNotEqual(observed[3], observed[4])
                self.assertEqual(observed[4], observed[6])
        self.assertEqual(inherited[3], inherited[4])


class NginxErrorPageInterventionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("A C17 compiler is required for the B09 regression")
        cls.workspace = tempfile.TemporaryDirectory(prefix="nginx-b09-")
        cls.addClassCleanup(cls.workspace.cleanup)
        directory = Path(cls.workspace.name)
        common = (SOURCE / "ngx_http_modsecurity_common.h").read_text(encoding="utf-8")
        access = (SOURCE / "ngx_http_modsecurity_access.c").read_text(encoding="utf-8")
        enum = re.search(
            r"typedef enum \{\s*MSCONNECTOR_NGINX_INTERVENTION_FAILURE,"
            r".*?\} msconnector_nginx_intervention_disposition;",
            common,
            re.DOTALL,
        )
        if enum is None:
            raise AssertionError("Actual intervention enum was not found")
        classifier = function_definition(
            common, "ngx_http_modsecurity_intervention_disposition"
        )
        body = function_definition(
            access, "ngx_http_modsecurity_inspect_request_body"
        )
        tail = body[body.rindex(
            "ret = ngx_http_modsecurity_process_intervention("
        ):]
        headers = function_definition(
            access, "ngx_http_modsecurity_process_request_headers"
        )
        header_tail = headers[headers.rindex(
            "ret = ngx_http_modsecurity_process_intervention("
        ):]
        code = (
            "#include <stdio.h>\n#include <stdlib.h>\n"
            "typedef long ngx_flag_t;\n"
            + enum.group(0)
            + "\nstatic msconnector_nginx_intervention_disposition\n"
            + classifier
            + r"""
typedef struct { int error_page; } ngx_http_request_t;
typedef struct { int unused; } msconnector_transaction_contract;
typedef struct {
    void *modsec_transaction;
    int intervention_triggered;
    msconnector_transaction_contract contract;
} ngx_http_modsecurity_ctx_t;
typedef struct { int unused; } ngx_http_modsecurity_conf_t;
enum {
    MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE = 1,
    NGX_HTTP_INTERNAL_SERVER_ERROR = 500,
    NGX_DECLINED = -5,
    NGX_OK = 0,
    MSCONNECTOR_PHASE_REQUEST_HEADERS = 1,
    MSCONNECTOR_PHASE_REQUEST_BODY = 2
};
static int native_result;
static int event_calls;
static int completion_calls;
static int completion_native_result;
static int msconnector_transaction_contract_fail(
    msconnector_transaction_contract *contract, int error_class, unsigned int rule_id)
{
    (void)contract;
    (void)error_class;
    (void)rule_id;
    return 0;
}
static int ngx_http_modsecurity_process_intervention(
    void *transaction, ngx_http_request_t *r, int early_log)
{
    (void)transaction;
    (void)r;
    (void)early_log;
    return native_result;
}
static void ngx_http_modsecurity_request_intervention_log_event(
    ngx_http_request_t *r, ngx_http_modsecurity_conf_t *mcf,
    int phase, const char *reason)
{
    (void)r;
    (void)mcf;
    (void)phase;
    (void)reason;
    ++event_calls;
}
/* Completion logging only observes the P1 allow continuation. Keep its
 * attempts separate from rule-intervention events without changing the result. */
static void ngx_http_modsecurity_request_completion_log_event(
    ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx,
    ngx_http_modsecurity_conf_t *mcf, int result)
{
    (void)r;
    (void)ctx;
    (void)mcf;
    ++completion_calls;
    completion_native_result = result;
}
static int p2_result(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx, ngx_http_modsecurity_conf_t *mcf)
{
    int ret;
"""
            + tail
            + r"""
static int p1_result(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx, ngx_http_modsecurity_conf_t *mcf)
{
    int ret;
    /* The extracted tail follows successful native P1 processing, independently
     * of the intervention result selected by the fixture's global variable. */
    int native_result = 1;
    msconnector_nginx_intervention_disposition disposition;
"""
            + header_tail
            + r"""
int main(int argc, char **argv)
{
    ngx_http_request_t request = {0};
    ngx_http_modsecurity_ctx_t ctx = {0};
    ngx_http_modsecurity_conf_t config = {0};
    int result;
    int headers;
    int header_events;
    int header_triggered;
    if (argc != 3) return 2;
    native_result = atoi(argv[1]);
    request.error_page = atoi(argv[2]);
    headers = p1_result(&request, &ctx, &config);
    header_events = event_calls;
    header_triggered = ctx.intervention_triggered;
    event_calls = 0;
    ctx.intervention_triggered = 0;
    result = p2_result(&request, &ctx, &config);
    printf("%d %d %d %d %d %d %d %d %d\n",
        (int)ngx_http_modsecurity_intervention_disposition(
            native_result, request.error_page),
        result, ctx.intervention_triggered, event_calls,
        headers, header_triggered, header_events,
        completion_calls, completion_native_result);
    return 0;
}
"""
        )
        source = directory / "regression.c"
        source.write_text(code, encoding="utf-8")
        cls.binary = directory / "regression"
        build = subprocess.run(
            [*compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
             str(source), "-o", str(cls.binary)],
            capture_output=True, text=True, check=False, timeout=60,
        )
        if build.returncode != 0:
            raise AssertionError(f"C regression build failed:\n{build.stderr}")

    def observe(self, native_result: int, error_page: int) -> tuple[int, ...]:
        result = subprocess.run(
            [str(self.binary), str(native_result), str(error_page)],
            capture_output=True, text=True, check=True, timeout=10,
        )
        return tuple(int(value) for value in result.stdout.split())

    def test_positive_decisions_take_precedence_in_both_paths(self) -> None:
        for status in (302, 403, 451):
            for error_page in (0, 1):
                with self.subTest(status=status, error_page=error_page):
                    self.assertEqual(self.observe(status, error_page),
                                     (3, status, 1, 1, status, 1, 1, 0, 0))

    def test_p1_allow_continues_to_p2_even_on_error_pages(self) -> None:
        for error_page in (0, 1):
            with self.subTest(error_page=error_page):
                self.assertEqual(self.observe(0, error_page),
                                 (2, -5, 0, 0, 0, 0, 0, 1, 1))

    def test_native_error_remains_fail_closed_without_a_success_event(self) -> None:
        for error_page in (0, 1):
            with self.subTest(error_page=error_page):
                self.assertEqual(self.observe(-1, error_page),
                                 (0, 500, 1, 0, 500, 1, 0, 0, 0))



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
