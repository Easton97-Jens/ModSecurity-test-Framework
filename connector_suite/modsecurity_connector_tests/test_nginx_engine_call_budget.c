#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include "connectors/nginx/src/ngx_http_modsecurity_engine_call_budget.h"

int main(void)
{
    ngx_http_modsecurity_engine_call_budget budget;
    struct timespec start = { 10, 0 };
    struct timespec boundary = { 10, 10000000 };
    struct timespec over = { 10, 10000001 };
    struct timespec backwards = { 9, 999999999 };
    assert(ngx_http_modsecurity_engine_budget_begin(&budget, 0, NULL) == 0);
    assert(ngx_http_modsecurity_engine_budget_finish(&budget, NULL) == 0);
    assert(ngx_http_modsecurity_engine_budget_begin(&budget, 10, &start) == 1);
    assert(ngx_http_modsecurity_engine_budget_finish(&budget, &boundary) == 1);
    assert(budget.elapsed_ns == UINT64_C(10000000));
    assert(ngx_http_modsecurity_engine_budget_finish(&budget, &over) == 2);
    assert(ngx_http_modsecurity_engine_budget_finish(&budget, &backwards) == -1);
    assert(ngx_http_modsecurity_engine_budget_begin(&budget, UINT64_MAX, &start) == -1);
    start.tv_nsec = 1000000000;
    assert(ngx_http_modsecurity_engine_budget_begin(&budget, 10, &start) == -1);
    assert(ngx_http_modsecurity_engine_budget_begin(NULL, 0, NULL) == -1);
    return 0;
}
