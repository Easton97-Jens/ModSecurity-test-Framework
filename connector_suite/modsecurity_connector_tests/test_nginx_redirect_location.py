"""Compile the real NGINX redirect helper against a bounded header-list model.

NGINX keeps relative upstream Location fields in headers_out.headers without
indexing them at headers_out.location.  The model preserves that distinction,
including multi-part lists, so the redirect replacement path is executable
rather than a source-text assertion.
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
MODULE = source_path('connectors/nginx/src/ngx_http_modsecurity_module.c', root=ROOT)

PREAMBLE = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef unsigned char u_char;
typedef unsigned int ngx_uint_t;
typedef int ngx_int_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { ngx_uint_t hash; ngx_str_t key, value; } ngx_table_elt_t;
typedef struct ngx_list_part_s ngx_list_part_t;
struct ngx_list_part_s {
    void *elts;
    ngx_uint_t nelts;
    ngx_list_part_t *next;
};
typedef struct { ngx_list_part_t part; ngx_list_part_t *last; } ngx_list_t;
typedef struct {
    ngx_list_t headers;
    ngx_table_elt_t *location, *content_length, *last_modified, *etag;
    ngx_table_elt_t *accept_ranges, *content_encoding;
    ngx_str_t content_type;
    size_t content_type_len;
} ngx_http_headers_out_t;
typedef struct { void *log; } ngx_connection_t;
typedef struct {
    int header_sent;
    void *pool;
    ngx_connection_t *connection;
    ngx_http_headers_out_t headers_out;
} ngx_http_request_t;
typedef struct {
    unsigned intervention_redirect_location_installed:1;
    unsigned logged:1;
    void *modsec_transaction;
} ngx_http_modsecurity_ctx_t;
typedef struct { char *url; int status; } ModSecurityIntervention;

enum { NGX_HTTP_BAD_REQUEST = 400, NGX_HTTP_INTERNAL_SERVER_ERROR = 500 };
#define NGX_LOG_ERR 4
#define NGX_MAX_SIZE_T_VALUE SIZE_MAX
#define ngx_strlen(value) strlen(value)
#define ngx_memcpy(dest, src, n) memcpy((dest), (src), (n))
#define ngx_strncasecmp(a, b, n) strncasecmp((const char *)(a), (const char *)(b), (n))
#define ngx_str_set(str, literal) do { \
    (str)->len = sizeof(literal) - 1U; (str)->data = (u_char *)(literal); \
} while (0)
#define ngx_str_null(str) do { (str)->len = 0U; (str)->data = NULL; } while (0)
#define ngx_http_clear_location(r) do { \
    if ((r)->headers_out.location != NULL) { \
        (r)->headers_out.location->hash = 0U; (r)->headers_out.location = NULL; \
    } \
} while (0)
#define CLEAR_HEADER(r, name) do { \
    if ((r)->headers_out.name != NULL) { \
        (r)->headers_out.name->hash = 0U; (r)->headers_out.name = NULL; \
    } \
} while (0)
#define ngx_http_clear_content_length(r) CLEAR_HEADER(r, content_length)
#define ngx_http_clear_last_modified(r) CLEAR_HEADER(r, last_modified)
#define ngx_http_clear_etag(r) CLEAR_HEADER(r, etag)
#define ngx_http_clear_accept_ranges(r) CLEAR_HEADER(r, accept_ranges)
#define dd(...) ((void)0)

static void ngx_log_error(int level, void *log, int error, const char *format, ...) {
    (void)level; (void)log; (void)error; (void)format;
}
static void *ngx_pnalloc(void *pool, size_t size) {
    (void)pool; return malloc(size);
}
/* NGINX's list grows by linking parts; two slots force a cross-part scan. */
static void *ngx_list_push(ngx_list_t *list) {
    ngx_list_part_t *part = list->last;
    if (part->nelts == 2U) {
        part->next = calloc(1U, sizeof(*part));
        if (part->next == NULL) return NULL;
        part = part->next;
        part->elts = calloc(2U, sizeof(ngx_table_elt_t));
        if (part->elts == NULL) return NULL;
        list->last = part;
    }
    return &((ngx_table_elt_t *)part->elts)[part->nelts++];
}
static void msc_update_status_code(void *transaction, int status) {
    (void)transaction; (void)status;
}
static ngx_int_t ngx_http_modsecurity_log_handler(ngx_http_request_t *r) {
    (void)r; return 0;
}
'''

MAIN = r'''
static ngx_table_elt_t *add_header(ngx_http_request_t *r,
    const char *name, const char *value, ngx_uint_t hash)
{
    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) return NULL;
    h->hash = hash;
    h->key.len = strlen(name);
    h->key.data = (u_char *)name;
    h->value.len = strlen(value);
    h->value.data = (u_char *)value;
    return h;
}

int main(int argc, char **argv) {
    ngx_connection_t connection = {NULL};
    ngx_http_request_t request = {0};
    ngx_http_modsecurity_ctx_t ctx = {0};
    ModSecurityIntervention intervention = {
        "https://no-crs.invalid/phase3-redirect", 302
    };
    ngx_table_elt_t *upstream = NULL, *other, *first_redirect = NULL;
    ngx_list_part_t *part;
    const char *scenario, *visible = "";
    ngx_uint_t count = 0U, active_other = 0U;
    ngx_int_t result = 200;
    if (argc != 2) return 2;
    scenario = argv[1];
    request.connection = &connection;
    request.headers_out.headers.part.elts = calloc(2U, sizeof(ngx_table_elt_t));
    if (request.headers_out.headers.part.elts == NULL) return 3;
    request.headers_out.headers.last = &request.headers_out.headers.part;
    other = add_header(&request, "X-Unrelated", "retained", 1U);
    if (other == NULL) return 4;

    if (strcmp(scenario, "relative") == 0 ||
        strcmp(scenario, "mixed-case") == 0 ||
        strcmp(scenario, "status-only") == 0 ||
        strcmp(scenario, "upstream-only") == 0 ||
        strcmp(scenario, "duplicate-upstream") == 0 ||
        strcmp(scenario, "duplicate-active") == 0 ||
        strcmp(scenario, "malformed") == 0 ||
        strcmp(scenario, "committed") == 0) {
        upstream = add_header(&request,
            strcmp(scenario, "mixed-case") == 0 ? "lOcAtIoN" : "Location",
            "/encoded%2Ftarget", 1U);
        if (upstream == NULL) return 5;
        /* NGINX deliberately leaves this pointer null for relative values. */
    } else if (strcmp(scenario, "absolute") == 0) {
        upstream = add_header(&request, "Location", "https://upstream.invalid/go", 1U);
        if (upstream == NULL) return 6;
        request.headers_out.location = upstream;
    } else if (strcmp(scenario, "none") != 0 && strcmp(scenario, "repeat") != 0) {
        return 7;
    }
    if (strcmp(scenario, "duplicate-upstream") == 0 ||
        strcmp(scenario, "duplicate-active") == 0) {
        /* NGINX marks a duplicate origin Location inactive during parsing. */
        if (add_header(&request, "LOCATION", "/second",
                strcmp(scenario, "duplicate-upstream") == 0 ? 0U : 1U) == NULL) return 8;
    }
    if (strcmp(scenario, "status-only") == 0) {
        intervention.status = 403;
        result = ngx_http_modsecurity_process_status_intervention(
            &request, &ctx, &intervention, 0);
    } else if (strcmp(scenario, "upstream-only") != 0) {
        if (strcmp(scenario, "malformed") == 0) {
            intervention.url = "https://bad.invalid/\r\nX-Injected: yes";
        }
        if (strcmp(scenario, "committed") == 0) request.header_sent = 1;
        result = ngx_http_modsecurity_process_redirect_intervention(
            &request, &ctx, &intervention);
        if (strcmp(scenario, "repeat") == 0) {
            first_redirect = request.headers_out.location;
            result = ngx_http_modsecurity_process_redirect_intervention(
                &request, &ctx, &intervention);
        }
    }
    for (part = &request.headers_out.headers.part; part != NULL; part = part->next) {
        ngx_table_elt_t *headers = part->elts;
        ngx_uint_t i;
        for (i = 0U; i < part->nelts; i++) {
            if (!headers[i].hash) continue;
            if (headers[i].key.len == sizeof("Location") - 1U &&
                ngx_strncasecmp(headers[i].key.data, (u_char *)"Location",
                    sizeof("Location") - 1U) == 0) {
                count++;
                visible = (const char *)headers[i].value.data;
            }
        }
    }
    active_other = other->hash;
    printf("{\"status\":%d,\"location_count\":%u,\"location\":\"%s\","
        "\"upstream_active\":%u,\"other_active\":%u,\"connector_owned\":%u,"
        "\"first_redirect_active\":%u}\n",
        result, count, visible, upstream == NULL ? 0U : upstream->hash,
        active_other, ctx.intervention_redirect_location_installed,
        first_redirect == NULL ? 0U : first_redirect->hash);
    return 0;
}
'''


class NginxRedirectLocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("a C compiler is required for NGINX redirect regressions")
        temporary = tempfile.TemporaryDirectory(
            prefix="nginx-redirect-location-", dir=os.environ.get("RUNNER_TEMP")
        )
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        cls.binary = directory / "redirect-location"
        source = MODULE.read_text(encoding="utf-8")
        functions = (
            "ngx_http_modsecurity_process_redirect_intervention",
            "ngx_http_modsecurity_process_status_intervention",
        )
        fixture = directory / "redirect-location.c"
        fixture.write_text(
            PREAMBLE
            + "\n"
            + "\n".join("static ngx_int_t\n" + function_definition(source, name) for name in functions)
            + MAIN,
            encoding="utf-8",
        )
        compiled = subprocess.run(
            compiler + ["-std=c17", "-Wall", "-Wextra", "-Werror", str(fixture), "-o", str(cls.binary)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if compiled.returncode:
            raise AssertionError("NGINX redirect fixture failed to compile:\n" + compiled.stderr[-4000:])

    def case(self, scenario: str) -> dict[str, object]:
        run = subprocess.run(
            [str(self.binary), scenario], capture_output=True, text=True, timeout=5, check=False
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_connector_redirect_without_prior_location(self) -> None:
        result = self.case("none")
        self.assertEqual((result["status"], result["location_count"]), (302, 1))
        self.assertEqual(result["location"], "https://no-crs.invalid/phase3-redirect")
        self.assertEqual((result["other_active"], result["connector_owned"]), (1, 1))

    def test_connector_replaces_unindexed_relative_and_mixed_case_location(self) -> None:
        for scenario in ("relative", "mixed-case"):
            with self.subTest(scenario=scenario):
                result = self.case(scenario)
                self.assertEqual((result["status"], result["location_count"]), (302, 1))
                self.assertEqual(result["location"], "https://no-crs.invalid/phase3-redirect")
                self.assertEqual((result["upstream_active"], result["other_active"]), (0, 1))

    def test_connector_replaces_indexed_absolute_location(self) -> None:
        result = self.case("absolute")
        self.assertEqual((result["status"], result["location_count"]), (302, 1))
        self.assertEqual((result["upstream_active"], result["other_active"]), (0, 1))

    def test_status_only_does_not_claim_upstream_location(self) -> None:
        result = self.case("status-only")
        self.assertEqual((result["status"], result["location_count"]), (403, 1))
        self.assertEqual((result["upstream_active"], result["connector_owned"]), (1, 0))

    def test_repeated_redirect_clears_first_connector_location(self) -> None:
        result = self.case("repeat")
        self.assertEqual((result["status"], result["location_count"]), (302, 1))
        self.assertEqual(result["first_redirect_active"], 0)

    def test_upstream_redirect_without_intervention_is_unchanged(self) -> None:
        result = self.case("upstream-only")
        self.assertEqual((result["status"], result["location_count"]), (200, 1))
        self.assertEqual((result["upstream_active"], result["connector_owned"]), (1, 0))

    def test_duplicate_upstream_locations_do_not_revive_or_survive_replacement(self) -> None:
        for scenario in ("duplicate-upstream", "duplicate-active"):
            with self.subTest(scenario=scenario):
                result = self.case(scenario)
                self.assertEqual((result["status"], result["location_count"]), (302, 1))
                self.assertEqual(result["upstream_active"], 0)
                self.assertEqual(result["location"], "https://no-crs.invalid/phase3-redirect")

    def test_invalid_url_and_committed_response_cannot_replace_headers(self) -> None:
        for scenario, status in (("malformed", 400), ("committed", -1)):
            with self.subTest(scenario=scenario):
                result = self.case(scenario)
                self.assertEqual((result["status"], result["location_count"]), (status, 1))
                self.assertEqual((result["upstream_active"], result["connector_owned"]), (1, 0))
                self.assertEqual(result["other_active"], 1)



# Parent default discovery uses the one admitted active-case inventory.
if __import__("os").environ.get("ON_DEMAND_TESTS") != "1":
    def load_tests(loader, standard_tests, pattern):
        from modsecurity_connector_ci.lib.active_test_inventory import module_load_tests
        return module_load_tests(loader, standard_tests, pattern)

if __name__ == "__main__":
    unittest.main()
