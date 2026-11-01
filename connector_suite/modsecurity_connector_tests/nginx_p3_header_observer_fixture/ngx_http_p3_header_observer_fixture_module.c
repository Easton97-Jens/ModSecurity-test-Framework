/*
 * Native-only downstream observer for the NGINX P3 response-header fixture.
 * It is linked only into the dedicated test binary and is intentionally
 * ordered after the real connector in the header-filter chain.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_http_output_header_filter_pt ngx_http_p3_header_observer_next_filter;
static ngx_int_t ngx_http_p3_header_observer_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_p3_header_observer_init(ngx_conf_t *cf);

static ngx_http_module_t ngx_http_p3_header_observer_fixture_module_ctx = {
    NULL,
    ngx_http_p3_header_observer_init,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

ngx_module_t ngx_http_p3_header_observer_fixture_module = {
    NGX_MODULE_V1,
    &ngx_http_p3_header_observer_fixture_module_ctx,
    NULL,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_p3_header_observer_filter(ngx_http_request_t *r)
{
    ngx_table_elt_t *header;

    if (ngx_http_p3_header_observer_next_filter == NULL) {
        return NGX_ERROR;
    }
    header = ngx_list_push(&r->headers_out.headers);
    if (header == NULL) {
        return NGX_ERROR;
    }
    header->hash = 1;
    ngx_str_set(&header->key, "X-P3-Header-Fixture-Downstream");
    ngx_str_set(&header->value, "reached");
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
        "p3-header-observer downstream=1");
    return ngx_http_p3_header_observer_next_filter(r);
}

static ngx_int_t
ngx_http_p3_header_observer_init(ngx_conf_t *cf)
{
    (void) cf;

    ngx_http_p3_header_observer_next_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_p3_header_observer_filter;
    return NGX_OK;
}
