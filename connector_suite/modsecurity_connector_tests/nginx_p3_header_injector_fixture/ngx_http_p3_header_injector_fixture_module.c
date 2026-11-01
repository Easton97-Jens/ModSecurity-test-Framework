/*
 * Native-only fault injector for the NGINX P3 response-header boundary.
 *
 * The wrapper is linked only into the dedicated test NGINX binary. It never
 * changes the connector source or reads a process environment switch. A local
 * configuration directive selects a deterministic fixture mode for one
 * request while the injector surrounds the real connector filter.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <signal.h>

#include "connectors/nginx/src/ngx_http_modsecurity_common.h"

#define P3_HEADER_FIXTURE_BODY "P3-HEADER-FIXTURE\n"
#define P3_HEADER_FIXTURE_BODY_LENGTH (sizeof(P3_HEADER_FIXTURE_BODY) - 1U)

typedef enum {
    P3_HEADER_FIXTURE_NONE = 0,
    P3_HEADER_FIXTURE_SUCCESS,
    P3_HEADER_FIXTURE_ZERO,
    P3_HEADER_FIXTURE_NEGATIVE,
    P3_HEADER_FIXTURE_ZERO_REINVOKE
} ngx_http_p3_header_fixture_mode;

typedef struct {
    ngx_str_t mode;
} ngx_http_p3_header_injector_loc_conf_t;

typedef struct {
    ngx_http_request_t *request;
    ngx_str_t mode;
} ngx_http_p3_header_injector_request_state_t;

static ngx_http_output_header_filter_pt ngx_http_p3_header_injector_next_filter;
static volatile sig_atomic_t ngx_http_p3_header_injector_active_mode;
static volatile sig_atomic_t ngx_http_p3_header_injector_wrapper_hits;

static ngx_int_t ngx_http_p3_header_injector_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_p3_header_injector_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_p3_header_injector_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_p3_header_injector_post_read(ngx_http_request_t *r);
static void ngx_http_p3_header_injector_cleanup(void *data);
static void *ngx_http_p3_header_injector_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_p3_header_injector_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_p3_header_injector_set_mode(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_http_p3_header_fixture_mode ngx_http_p3_header_injector_mode(
    const ngx_str_t *mode);
static void ngx_http_p3_header_injector_log_outcome(ngx_http_request_t *r,
    const ngx_str_t *mode, ngx_int_t first_result, ngx_int_t retry_result);

extern ngx_module_t ngx_http_p3_header_injector_fixture_module;
extern int __real_msc_process_response_headers(Transaction *transaction,
    int status, const char *protocol);

int
__wrap_msc_process_response_headers(Transaction *transaction, int status,
    const char *protocol)
{
    ngx_http_p3_header_injector_wrapper_hits++;
    if (ngx_http_p3_header_injector_active_mode == P3_HEADER_FIXTURE_ZERO ||
        ngx_http_p3_header_injector_active_mode ==
            P3_HEADER_FIXTURE_ZERO_REINVOKE) {
        return 0;
    }
    if (ngx_http_p3_header_injector_active_mode == P3_HEADER_FIXTURE_NEGATIVE) {
        return -1;
    }
    return __real_msc_process_response_headers(transaction, status, protocol);
}

static ngx_command_t ngx_http_p3_header_injector_commands[] = {
    {
        ngx_string("p3_header_fixture"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_p3_header_injector_set_mode,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_p3_header_injector_fixture_module_ctx = {
    NULL,
    ngx_http_p3_header_injector_init,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_p3_header_injector_create_loc_conf,
    ngx_http_p3_header_injector_merge_loc_conf
};

ngx_module_t ngx_http_p3_header_injector_fixture_module = {
    NGX_MODULE_V1,
    &ngx_http_p3_header_injector_fixture_module_ctx,
    ngx_http_p3_header_injector_commands,
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
ngx_http_p3_header_injector_handler(ngx_http_request_t *r)
{
    ngx_buf_t *buffer;
    ngx_chain_t output;
    u_char *body;
    ngx_int_t result;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = P3_HEADER_FIXTURE_BODY_LENGTH;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    result = ngx_http_send_header(r);
    if (result == NGX_ERROR || result > NGX_OK || r->header_only) {
        return result;
    }
    buffer = ngx_pcalloc(r->pool, sizeof(*buffer));
    if (buffer == NULL) {
        return NGX_ERROR;
    }
    body = ngx_pnalloc(r->pool, P3_HEADER_FIXTURE_BODY_LENGTH);
    if (body == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(body, P3_HEADER_FIXTURE_BODY, P3_HEADER_FIXTURE_BODY_LENGTH);
    buffer->pos = body;
    buffer->last = body + P3_HEADER_FIXTURE_BODY_LENGTH;
    buffer->memory = 1;
    buffer->last_buf = 1;
    buffer->last_in_chain = 1;
    output.buf = buffer;
    output.next = NULL;
    return ngx_http_output_filter(r, &output);
}

static ngx_int_t
ngx_http_p3_header_injector_filter(ngx_http_request_t *r)
{
    const ngx_http_p3_header_injector_loc_conf_t *conf;
    ngx_http_p3_header_injector_request_state_t *state;
    ngx_http_p3_header_fixture_mode mode;
    ngx_int_t first_result;
    ngx_int_t retry_result = NGX_DECLINED;

    if (ngx_http_p3_header_injector_next_filter == NULL) {
        return NGX_ERROR;
    }
    conf = ngx_http_get_module_loc_conf(r,
        ngx_http_p3_header_injector_fixture_module);
    state = ngx_http_get_module_ctx(r, ngx_http_p3_header_injector_fixture_module);
    if (conf == NULL || state == NULL) {
        return NGX_ERROR;
    }
    mode = ngx_http_p3_header_injector_mode(&conf->mode);
    if (mode == P3_HEADER_FIXTURE_NONE) {
        return NGX_ERROR;
    }
    state->mode = conf->mode;
    ngx_http_p3_header_injector_active_mode = (sig_atomic_t) mode;
    ngx_http_p3_header_injector_wrapper_hits = 0;
    first_result = ngx_http_p3_header_injector_next_filter(r);
    if (mode == P3_HEADER_FIXTURE_ZERO_REINVOKE) {
        retry_result = ngx_http_p3_header_injector_next_filter(r);
    }
    ngx_http_p3_header_injector_active_mode = P3_HEADER_FIXTURE_NONE;
    ngx_http_p3_header_injector_log_outcome(r, &conf->mode, first_result,
        retry_result);
    if (mode == P3_HEADER_FIXTURE_ZERO_REINVOKE &&
        (first_result != NGX_ERROR || retry_result != NGX_ERROR)) {
        return NGX_ERROR;
    }
    return first_result;
}

static ngx_int_t
ngx_http_p3_header_injector_post_read(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t *cleanup;
    ngx_http_p3_header_injector_request_state_t *state;

    cleanup = ngx_pool_cleanup_add(r->pool, sizeof(*state));
    if (cleanup == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    state = cleanup->data;
    if (state == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    state->request = r;
    state->mode.len = 0U;
    state->mode.data = NULL;
    ngx_http_set_ctx(r, state, ngx_http_p3_header_injector_fixture_module)
    cleanup->handler = ngx_http_p3_header_injector_cleanup;
    cleanup->data = state;
    return NGX_DECLINED;
}

static void
ngx_http_p3_header_injector_cleanup(void *data)
{
    ngx_http_p3_header_injector_request_state_t *state = data;
    const ngx_http_modsecurity_ctx_t *ctx;

    if (state == NULL || state->request == NULL || state->mode.data == NULL) {
        return;
    }
    ctx = ngx_http_modsecurity_get_module_ctx(state->request);
    if (ctx == NULL || !ctx->response_headers_processing_failed) {
        return;
    }
    ngx_log_error(NGX_LOG_NOTICE, state->request->connection->log, 0,
        "p3-header-fixture cleanup mode=%V invalid-engine=%ui headers-seen=%ui cleanup-complete=%ui transaction-null=%ui",
        &state->mode,
        (ngx_uint_t) (ctx->contract.error_class ==
            MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE),
        (ngx_uint_t) ctx->response_headers_seen,
        (ngx_uint_t) ctx->contract.cleanup_complete,
        (ngx_uint_t) (ctx->modsec_transaction == NULL));
}

static void
ngx_http_p3_header_injector_log_outcome(ngx_http_request_t *r,
    const ngx_str_t *mode, ngx_int_t first_result, ngx_int_t retry_result)
{
    const ngx_http_modsecurity_ctx_t *ctx;

    ctx = ngx_http_modsecurity_get_module_ctx(r);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "p3-header-fixture outcome has no ModSecurity context");
        return;
    }
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
        "p3-header-fixture outcome mode=%V wrapper-hits=%i first-result=%i retry-result=%i terminal=%ui invalid-engine=%ui headers-seen=%ui",
        mode, (ngx_int_t) ngx_http_p3_header_injector_wrapper_hits,
        first_result, retry_result,
        (ngx_uint_t) (ctx->contract.status ==
            MSCONNECTOR_TRANSACTION_STATUS_TERMINAL),
        (ngx_uint_t) (ctx->contract.error_class ==
            MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE),
        (ngx_uint_t) ctx->response_headers_seen);
}

static ngx_int_t
ngx_http_p3_header_injector_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *handler;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    handler = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (handler == NULL) {
        return NGX_ERROR;
    }
    *handler = ngx_http_p3_header_injector_post_read;
    ngx_http_p3_header_injector_next_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_p3_header_injector_filter;
    return NGX_OK;
}

static void *
ngx_http_p3_header_injector_create_loc_conf(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool,
        sizeof(ngx_http_p3_header_injector_loc_conf_t));
}

static char *
ngx_http_p3_header_injector_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    (void) cf;
    (void) parent;
    (void) child;
    return NGX_CONF_OK;
}

static char *
ngx_http_p3_header_injector_set_mode(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_p3_header_injector_loc_conf_t *fixture = conf;
    ngx_http_core_loc_conf_t *core;
    const ngx_str_t *value;

    (void) cmd;
    if (fixture->mode.data != NULL) {
        return "is duplicate";
    }
    value = cf->args->elts;
    if (ngx_http_p3_header_injector_mode(&value[1]) == P3_HEADER_FIXTURE_NONE) {
        return "has an unsupported P3 header fixture mode";
    }
    fixture->mode = value[1];
    core = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core->handler = ngx_http_p3_header_injector_handler;
    return NGX_CONF_OK;
}

static ngx_http_p3_header_fixture_mode
ngx_http_p3_header_injector_mode(const ngx_str_t *mode)
{
    if (mode == NULL || mode->data == NULL) {
        return P3_HEADER_FIXTURE_NONE;
    }
    if (mode->len == sizeof("success") - 1U &&
        ngx_strncmp(mode->data, (const u_char *) "success", mode->len) == 0) {
        return P3_HEADER_FIXTURE_SUCCESS;
    }
    if (mode->len == sizeof("zero") - 1U &&
        ngx_strncmp(mode->data, (const u_char *) "zero", mode->len) == 0) {
        return P3_HEADER_FIXTURE_ZERO;
    }
    if (mode->len == sizeof("negative") - 1U &&
        ngx_strncmp(mode->data, (const u_char *) "negative", mode->len) == 0) {
        return P3_HEADER_FIXTURE_NEGATIVE;
    }
    if (mode->len == sizeof("zero-reinvoke") - 1U &&
        ngx_strncmp(mode->data, (const u_char *) "zero-reinvoke", mode->len) == 0) {
        return P3_HEADER_FIXTURE_ZERO_REINVOKE;
    }
    return P3_HEADER_FIXTURE_NONE;
}
