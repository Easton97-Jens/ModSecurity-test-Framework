/*
 * Native-only regression fixture for the NGINX P4 response-buffer boundary.
 *
 * This module is never linked into the connector.  The test runner builds it
 * as a separate static HTTP filter alongside the exact-head connector and
 * drives its handler over loopback.  Its sole purpose is to create real
 * ngx_buf_t representations that ordinary HTTP upstream responses cannot
 * select deterministically.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <errno.h>
#include <signal.h>

#define FIXTURE_BODY "P4-FIXTURE-BODY!"
#define FIXTURE_BODY_LENGTH (sizeof(FIXTURE_BODY) - 1U)
#define FIXTURE_OVER_LIMIT_LENGTH (FIXTURE_BODY_LENGTH + 1U)

typedef struct {
    ngx_str_t mode;
    ngx_str_t file;
    ngx_str_t short_file;
    ngx_str_t mixed_file;
} ngx_http_body_buffer_fixture_loc_conf_t;

typedef struct {
    ngx_file_t *short_file;
} ngx_http_body_buffer_fixture_request_ctx_t;

static ngx_int_t ngx_http_body_buffer_fixture_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_body_buffer_fixture_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_body_buffer_fixture_init(ngx_conf_t *cf);
static void *ngx_http_body_buffer_fixture_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_body_buffer_fixture_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_http_body_buffer_fixture_set_mode(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_body_buffer_fixture_mode_is(
    const ngx_str_t *mode, const char *literal);
static ngx_int_t ngx_http_body_buffer_fixture_needs_file(
    const ngx_str_t *mode);
static ngx_int_t ngx_http_body_buffer_fixture_open_file(ngx_http_request_t *r,
    const ngx_str_t *path, ngx_file_t **file);
static ngx_int_t ngx_http_body_buffer_fixture_add_header(ngx_http_request_t *r,
    const ngx_str_t *mode);
static ngx_int_t ngx_http_body_buffer_fixture_plan_lengths(
    const ngx_str_t *mode, size_t *memory_length, off_t *file_length);
static ngx_int_t ngx_http_body_buffer_fixture_prepare_files(
    ngx_http_request_t *r,
    const ngx_http_body_buffer_fixture_loc_conf_t *conf,
    ngx_file_t **file);
extern ngx_module_t ngx_http_body_buffer_fixture_module;

/* This symbol is linked only into the runner's separately built NGINX test
 * binary with --wrap=ngx_pnalloc.  The production connector source is built
 * into that test binary solely to expose its real allocation boundary; the
 * production connector build neither compiles nor links this wrapper. */
extern void *__real_ngx_pnalloc(ngx_pool_t *pool, size_t size);

/* The test-only content handler and this link-time wrapper run in the same
 * NGINX worker. A process-local flag avoids relying on a mutable environment
 * while keeping allocation injection out of the connector. */
static volatile sig_atomic_t ngx_http_body_buffer_fixture_fail_allocation;
static volatile sig_atomic_t ngx_http_body_buffer_fixture_allocation_wrapper_hits;
static ngx_http_output_body_filter_pt ngx_http_body_buffer_fixture_next_body_filter;

void *
__wrap_ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    if (ngx_http_body_buffer_fixture_fail_allocation != 0 && size == 32768U) {
        ngx_http_body_buffer_fixture_allocation_wrapper_hits++;
        errno = ENOMEM;
        return NULL;
    }
    return __real_ngx_pnalloc(pool, size);
}

static ngx_command_t ngx_http_body_buffer_fixture_commands[] = {
    {
        ngx_string("body_buffer_fixture"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_body_buffer_fixture_set_mode,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("body_buffer_fixture_file"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_body_buffer_fixture_loc_conf_t, file),
        NULL
    },
    {
        ngx_string("body_buffer_fixture_short_file"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_body_buffer_fixture_loc_conf_t, short_file),
        NULL
    },
    {
        ngx_string("body_buffer_fixture_mixed_file"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_body_buffer_fixture_loc_conf_t, mixed_file),
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_body_buffer_fixture_module_ctx = {
    NULL,
    ngx_http_body_buffer_fixture_init,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_body_buffer_fixture_create_loc_conf,
    ngx_http_body_buffer_fixture_merge_loc_conf
};

/* NGINX copy/postpone filters may defer a content handler's output until after
 * ngx_http_output_filter() returns. The fixture is therefore positioned
 * immediately upstream of the static connector and enables the test-only
 * wrapper only while it calls that real connector filter. */
static ngx_int_t
ngx_http_body_buffer_fixture_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_body_buffer_fixture_loc_conf_t *conf;
    ngx_http_body_buffer_fixture_request_ctx_t *fixture_ctx;
    ngx_buf_t *buffer;
    ngx_file_t *original_file;
    ngx_fd_t original_fd;
    off_t original_file_pos;
    off_t original_file_last;
    unsigned original_temporary;
    unsigned original_memory;
    unsigned original_mmap;
    const char *injection = "none";
    const char *representation = "preserved";
    ngx_int_t result;

    if (ngx_http_body_buffer_fixture_next_body_filter == NULL) {
        return NGX_ERROR;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_body_buffer_fixture_module);
    if (in == NULL || conf == NULL) {
        return ngx_http_body_buffer_fixture_next_body_filter(r, in);
    }

    buffer = in->buf;
    if (buffer == NULL) {
        return NGX_ERROR;
    }
    original_file = buffer->file;
    original_file_pos = buffer->file_pos;
    original_file_last = buffer->file_last;
    original_fd = original_file != NULL ? original_file->fd : NGX_INVALID_FILE;
    original_temporary = buffer->temporary;
    original_memory = buffer->memory;
    original_mmap = buffer->mmap;

    if (ngx_http_body_buffer_fixture_mode_is(&conf->mode, "file-within") ||
        ngx_http_body_buffer_fixture_mode_is(&conf->mode, "file-over-limit") ||
        ngx_http_body_buffer_fixture_mode_is(&conf->mode, "invalid-metadata") ||
        ngx_http_body_buffer_fixture_mode_is(&conf->mode, "missing-source") ||
        ngx_http_body_buffer_fixture_mode_is(&conf->mode, "read-error") ||
        ngx_http_body_buffer_fixture_mode_is(&conf->mode, "short-read") ||
        ngx_http_body_buffer_fixture_mode_is(&conf->mode, "allocation-failure")) {
        if (buffer->in_file == 0 || original_file == NULL) {
            return NGX_ERROR;
        }
        representation = "file-only";
        buffer->temporary = 0;
        buffer->memory = 0;
        buffer->mmap = 0;
    }

    if (ngx_http_body_buffer_fixture_mode_is(&conf->mode,
            "allocation-failure")) {
        injection = "allocation-failure";
        ngx_http_body_buffer_fixture_fail_allocation = 1;
        ngx_http_body_buffer_fixture_allocation_wrapper_hits = 0;
    } else if (ngx_http_body_buffer_fixture_mode_is(&conf->mode,
                   "invalid-metadata")) {
        injection = "invalid-metadata";
        buffer->file_pos = 1;
        buffer->file_last = 0;
    } else if (ngx_http_body_buffer_fixture_mode_is(&conf->mode,
                   "missing-source")) {
        injection = "missing-source";
        buffer->file = NULL;
    } else if (ngx_http_body_buffer_fixture_mode_is(&conf->mode,
                   "read-error")) {
        if (original_file == NULL) {
            return NGX_ERROR;
        }
        injection = "read-error";
        original_file->fd = NGX_INVALID_FILE;
    } else if (ngx_http_body_buffer_fixture_mode_is(&conf->mode,
                   "short-read")) {
        fixture_ctx = ngx_http_get_module_ctx(r,
            ngx_http_body_buffer_fixture_module);
        if (fixture_ctx == NULL || fixture_ctx->short_file == NULL) {
            return NGX_ERROR;
        }
        injection = "short-read";
        buffer->file = fixture_ctx->short_file;
    }

    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
        "body-buffer-fixture connector-boundary mode=%V memory=%ui in_file=%ui file_pos=%O file_last=%O representation=%s injection=%s",
        &conf->mode, (ngx_uint_t) ngx_buf_in_memory(buffer),
        (ngx_uint_t) buffer->in_file, buffer->file_pos, buffer->file_last,
        representation, injection);
    result = ngx_http_body_buffer_fixture_next_body_filter(r, in);

    ngx_http_body_buffer_fixture_fail_allocation = 0;
    if (original_file != NULL) {
        original_file->fd = original_fd;
    }
    buffer->file = original_file;
    buffer->file_pos = original_file_pos;
    buffer->file_last = original_file_last;
    buffer->temporary = original_temporary;
    buffer->memory = original_memory;
    buffer->mmap = original_mmap;
    if (ngx_http_body_buffer_fixture_mode_is(&conf->mode,
            "allocation-failure")) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "body-buffer-fixture allocation-wrapper-hits=%i",
            (ngx_int_t) ngx_http_body_buffer_fixture_allocation_wrapper_hits);
    }

    return result;
}

static ngx_int_t
ngx_http_body_buffer_fixture_init(ngx_conf_t *cf)
{
    (void) cf;

    ngx_http_body_buffer_fixture_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_body_buffer_fixture_body_filter;

    return NGX_OK;
}

ngx_module_t ngx_http_body_buffer_fixture_module = {
    NGX_MODULE_V1,
    &ngx_http_body_buffer_fixture_module_ctx,
    ngx_http_body_buffer_fixture_commands,
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
ngx_http_body_buffer_fixture_mode_is(const ngx_str_t *mode, const char *literal)
{
    size_t length;

    length = ngx_strlen(literal);
    return mode != NULL && mode->data != NULL && mode->len == length &&
        ngx_strncmp(mode->data, (const u_char *) literal, length) == 0;
}

static ngx_int_t
ngx_http_body_buffer_fixture_needs_file(const ngx_str_t *mode)
{
    return ngx_http_body_buffer_fixture_mode_is(mode, "file-within") ||
        ngx_http_body_buffer_fixture_mode_is(mode, "file-over-limit") ||
        ngx_http_body_buffer_fixture_mode_is(mode, "mixed-within") ||
        ngx_http_body_buffer_fixture_mode_is(mode, "mixed-over-limit") ||
        ngx_http_body_buffer_fixture_mode_is(mode, "invalid-metadata") ||
        ngx_http_body_buffer_fixture_mode_is(mode, "missing-source") ||
        ngx_http_body_buffer_fixture_mode_is(mode, "read-error") ||
        ngx_http_body_buffer_fixture_mode_is(mode, "short-read") ||
        ngx_http_body_buffer_fixture_mode_is(mode, "allocation-failure");
}

static ngx_int_t
ngx_http_body_buffer_fixture_open_file(ngx_http_request_t *r,
    const ngx_str_t *path, ngx_file_t **file)
{
    ngx_file_t *opened;
    ngx_pool_cleanup_t *cleanup;
    ngx_pool_cleanup_file_t *cleanup_file;

    if (file == NULL || path == NULL || path->len == 0U ||
        path->data == NULL) {
        return NGX_ERROR;
    }

    opened = ngx_pcalloc(r->pool, sizeof(*opened));
    if (opened == NULL) {
        return NGX_ERROR;
    }
    opened->name = *path;
    opened->log = r->connection->log;
    opened->fd = ngx_open_file(opened->name.data, NGX_FILE_RDONLY,
        NGX_FILE_OPEN, 0);
    if (opened->fd == NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    cleanup = ngx_pool_cleanup_add(r->pool, sizeof(*cleanup_file));
    if (cleanup == NULL) {
        (void) ngx_close_file(opened->fd);
        return NGX_ERROR;
    }
    cleanup->handler = ngx_pool_cleanup_file;
    cleanup_file = cleanup->data;
    cleanup_file->fd = opened->fd;
    cleanup_file->name = opened->name.data;
    cleanup_file->log = r->connection->log;
    *file = opened;

    return NGX_OK;
}

static ngx_int_t
ngx_http_body_buffer_fixture_add_header(ngx_http_request_t *r,
    const ngx_str_t *mode)
{
    ngx_table_elt_t *header;

    header = ngx_list_push(&r->headers_out.headers);
    if (header == NULL) {
        return NGX_ERROR;
    }
    header->hash = 1;
    ngx_str_set(&header->key, "X-Nginx-Body-Buffer-Fixture");
    header->value = *mode;
    return NGX_OK;
}

static ngx_int_t
ngx_http_body_buffer_fixture_plan_lengths(const ngx_str_t *mode,
    size_t *memory_length, off_t *file_length)
{
    if (memory_length == NULL || file_length == NULL) {
        return NGX_ERROR;
    }
    *memory_length = 0U;
    *file_length = 0;

    if (ngx_http_body_buffer_fixture_mode_is(mode, "memory-within") ||
        ngx_http_body_buffer_fixture_mode_is(mode, "mixed-within")) {
        *memory_length = FIXTURE_BODY_LENGTH;
    } else if (ngx_http_body_buffer_fixture_mode_is(mode,
                   "memory-over-limit") ||
               ngx_http_body_buffer_fixture_mode_is(mode,
                   "mixed-over-limit")) {
        *memory_length = FIXTURE_OVER_LIMIT_LENGTH;
    }

    if (ngx_http_body_buffer_fixture_mode_is(mode, "file-within") ||
        ngx_http_body_buffer_fixture_mode_is(mode, "mixed-within")) {
        *file_length = (off_t) FIXTURE_BODY_LENGTH;
    } else if (ngx_http_body_buffer_fixture_mode_is(mode,
                   "file-over-limit") ||
               ngx_http_body_buffer_fixture_mode_is(mode,
                   "mixed-over-limit")) {
        *file_length = (off_t) FIXTURE_OVER_LIMIT_LENGTH;
    } else if (ngx_http_body_buffer_fixture_mode_is(mode,
                   "allocation-failure") ||
               ngx_http_body_buffer_fixture_mode_is(mode, "read-error") ||
               ngx_http_body_buffer_fixture_mode_is(mode, "short-read") ||
               ngx_http_body_buffer_fixture_mode_is(mode,
                   "invalid-metadata") ||
               ngx_http_body_buffer_fixture_mode_is(mode, "missing-source")) {
        /* Error cases must reach their own connector checks. */
        *file_length = (off_t) FIXTURE_BODY_LENGTH;
    }

    return *memory_length != 0U || *file_length != 0
        ? NGX_OK : NGX_ERROR;
}

static ngx_int_t
ngx_http_body_buffer_fixture_prepare_files(ngx_http_request_t *r,
    const ngx_http_body_buffer_fixture_loc_conf_t *conf, ngx_file_t **file)
{
    ngx_file_t *short_file = NULL;
    ngx_http_body_buffer_fixture_request_ctx_t *fixture_ctx;
    const ngx_str_t *file_path;

    if (ngx_http_body_buffer_fixture_mode_is(&conf->mode, "mixed-within") ||
        ngx_http_body_buffer_fixture_mode_is(&conf->mode, "mixed-over-limit")) {
        file_path = &conf->mixed_file;
    } else {
        file_path = &conf->file;
    }
    if (ngx_http_body_buffer_fixture_needs_file(&conf->mode) &&
        ngx_http_body_buffer_fixture_open_file(r, file_path, file) != NGX_OK) {
        return NGX_ERROR;
    }
    if (ngx_http_body_buffer_fixture_mode_is(&conf->mode, "short-read")) {
        if (ngx_http_body_buffer_fixture_open_file(r, &conf->short_file,
                &short_file) != NGX_OK) {
            return NGX_ERROR;
        }
        fixture_ctx = ngx_pcalloc(r->pool, sizeof(*fixture_ctx));
        if (fixture_ctx == NULL) {
            return NGX_ERROR;
        }
        fixture_ctx->short_file = short_file;
        ngx_http_set_ctx(r, fixture_ctx, ngx_http_body_buffer_fixture_module)
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_body_buffer_fixture_handler(ngx_http_request_t *r)
{
    ngx_http_body_buffer_fixture_loc_conf_t *conf;
    ngx_buf_t *buffer;
    ngx_chain_t output;
    ngx_file_t *file = NULL;
    u_char *memory;
    size_t memory_length = 0U;
    off_t file_length = 0;
    ngx_int_t result;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    conf = ngx_http_get_module_loc_conf(r, ngx_http_body_buffer_fixture_module);
    if (conf == NULL || conf->mode.len == 0U || conf->mode.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_body_buffer_fixture_fail_allocation = 0;
    ngx_http_body_buffer_fixture_allocation_wrapper_hits = 0;

    if (ngx_http_body_buffer_fixture_plan_lengths(&conf->mode, &memory_length,
            &file_length) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_body_buffer_fixture_prepare_files(r, conf, &file) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = memory_length != 0U
        ? (off_t) memory_length : file_length;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    if (ngx_http_body_buffer_fixture_add_header(r, &conf->mode) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    result = ngx_http_send_header(r);
    if (result == NGX_ERROR || result > NGX_OK || r->header_only) {
        return result;
    }

    buffer = ngx_pcalloc(r->pool, sizeof(*buffer));
    if (buffer == NULL) {
        return NGX_ERROR;
    }
    if (memory_length != 0U) {
        memory = ngx_pnalloc(r->pool, memory_length);
        if (memory == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(memory, FIXTURE_BODY, FIXTURE_BODY_LENGTH);
        if (memory_length > FIXTURE_BODY_LENGTH) {
            memory[FIXTURE_BODY_LENGTH] = 'X';
        }
        buffer->pos = memory;
        buffer->last = memory + memory_length;
        buffer->memory = 1;
    }
    if (file_length != 0) {
        buffer->in_file = 1;
        buffer->file_pos = 0;
        buffer->file_last = file_length;
        buffer->file = file;
    }
    buffer->last_buf = 1;
    buffer->last_in_chain = 1;
    output.buf = buffer;
    output.next = NULL;

    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
        "body-buffer-fixture mode=%V memory=%ui in_file=%ui file_pos=%O file_last=%O memory_length=%uz",
        &conf->mode, (ngx_uint_t) ngx_buf_in_memory(buffer),
        (ngx_uint_t) buffer->in_file, buffer->file_pos, buffer->file_last,
        memory_length);
    result = ngx_http_output_filter(r, &output);
    return result;
}

static void *
ngx_http_body_buffer_fixture_create_loc_conf(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(ngx_http_body_buffer_fixture_loc_conf_t));
}

static char *
ngx_http_body_buffer_fixture_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    (void) cf;
    (void) parent;
    (void) child;
    return NGX_CONF_OK;
}

static char *
ngx_http_body_buffer_fixture_set_mode(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_body_buffer_fixture_loc_conf_t *fixture = conf;
    ngx_http_core_loc_conf_t *core;
    const ngx_str_t *value;
    const char *allowed[] = {
        "memory-within", "memory-over-limit", "file-within",
        "file-over-limit", "mixed-within", "mixed-over-limit",
        "invalid-metadata", "missing-source", "read-error", "short-read",
        "allocation-failure", NULL
    };

    (void) cmd;
    if (fixture->mode.data != NULL) {
        return "is duplicate";
    }
    value = cf->args->elts;
    for (ngx_uint_t index = 0U; allowed[index] != NULL; index++) {
        if (ngx_http_body_buffer_fixture_mode_is(&value[1], allowed[index])) {
            fixture->mode = value[1];
            core = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
            core->handler = ngx_http_body_buffer_fixture_handler;
            return NGX_CONF_OK;
        }
    }
    return "has an unsupported body-buffer fixture mode";
}
