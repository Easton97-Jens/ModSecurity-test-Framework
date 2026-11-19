/* Test assertions may carry required side effects; keep assert() active
 * even when a build defines NDEBUG. */
#undef NDEBUG
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

/* TEST_REQUIRE() always evaluates its argument (unlike assert() under
 * NDEBUG), so fixture I/O, resource release and the operation under test
 * still run and are checked. */
#ifndef TEST_REQUIRE
#define TEST_REQUIRE(condition) do { if (!(condition)) { \
    (void)fprintf(stderr, "%s:%d: requirement failed: %s\n", \
        __FILE__, __LINE__, #condition); \
    abort(); } } while (0)
#endif
#include <stdint.h>
#include "connectors/nginx/src/ngx_http_modsecurity_engine_call_budget.h"

int main(void)
{
    ngx_http_modsecurity_engine_call_budget budget;
    struct timespec start = { 10, 0 };
    struct timespec boundary = { 10, 10000000 };
    struct timespec over = { 10, 10000001 };
    struct timespec backwards = { 9, 999999999 };
    TEST_REQUIRE(ngx_http_modsecurity_engine_budget_begin(&budget, 0, NULL) == 0);
    TEST_REQUIRE(ngx_http_modsecurity_engine_budget_finish(&budget, NULL) == 0);
    TEST_REQUIRE(ngx_http_modsecurity_engine_budget_begin(&budget, 10, &start) == 1);
    TEST_REQUIRE(ngx_http_modsecurity_engine_budget_finish(&budget, &boundary) == 1);
    assert(budget.elapsed_ns == UINT64_C(10000000));
    TEST_REQUIRE(ngx_http_modsecurity_engine_budget_finish(&budget, &over) == 2);
    TEST_REQUIRE(ngx_http_modsecurity_engine_budget_finish(&budget, &backwards) == -1);
    TEST_REQUIRE(ngx_http_modsecurity_engine_budget_begin(&budget, UINT64_MAX, &start) == -1);
    start.tv_nsec = 1000000000;
    TEST_REQUIRE(ngx_http_modsecurity_engine_budget_begin(&budget, 10, &start) == -1);
    TEST_REQUIRE(ngx_http_modsecurity_engine_budget_begin(NULL, 0, NULL) == -1);
    return 0;
}
