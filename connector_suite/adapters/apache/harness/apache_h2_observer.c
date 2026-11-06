#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/* Test-only independent request-pool cleanup and native HTTP/2 identity witness.
 * Registered before security3, so APR's LIFO cleanup executes after its real
 * transaction cleanup while request_rec/request_config still belong to the pool.
 */
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_strings.h"
#include "apr_optional.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

module AP_MODULE_DECLARE_DATA acceptance_observer_module;
APR_DECLARE_OPTIONAL_FN(char *, http2_var_lookup,
    (apr_pool_t *, server_rec *, conn_rec *, request_rec *, char *));

typedef struct {
    request_rec *request;
    int context_seen;
} observation;

static apr_status_t observe_before_cleanup(void *data);

static int safe_uri(const char *text)
{
    size_t length = text != NULL ? strlen(text) : 0U;
    if (length == 0U || length > 200U) return 0;
    for (size_t i = 0U; i < length; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '/' || c == '-' || c == '_' || c == '.')) return 0;
    }
    return 1;
}

static const module *security_module(void)
{
    return ap_find_linked_module("mod_security3.c");
}

static int append_record(const char *descriptor_text, const char *record, size_t length)
{
    struct stat details;
    char *end = NULL;
    long parsed;
    int descriptor, flags, ok;
    if (descriptor_text == NULL || *descriptor_text == '\0' || strlen(descriptor_text) > 10U) return 0;
    for (const char *digit = descriptor_text; *digit != '\0'; ++digit) {
        if (*digit < '0' || *digit > '9') return 0;
    }
    errno = 0;
    parsed = strtol(descriptor_text, &end, 10);
    if (errno != 0 || *end != '\0' || parsed < 3 || parsed > INT_MAX) return 0;
    descriptor = (int)parsed;
    flags = fcntl(descriptor, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_WRONLY || (flags & O_APPEND) == 0) return 0;
    ok = fstat(descriptor, &details) == 0 && S_ISREG(details.st_mode) &&
        details.st_uid == geteuid() && details.st_nlink == 1 &&
        (details.st_mode & 0777) == 0600 && details.st_size >= 0 &&
        details.st_size <= 1048576 - (off_t)length;
    if (ok) ok = write(descriptor, record, length) == (ssize_t)length;
    return ok;
}

static apr_status_t observe_cleanup(void *data)
{
    observation *item = (observation *)data;
    request_rec *r = item->request;
    const module *security = security_module();
    const char *descriptor_text = getenv("APACHE_ACCEPTANCE_OBSERVER_FD");
    const char *stream = apr_table_get(r->subprocess_env, "H2_STREAM_ID");
    const char *tag = apr_table_get(r->subprocess_env, "H2_STREAM_TAG");
    char record[768];
    int count;
    long stream_id = -1;
    char *end = NULL;
    struct timespec timestamp;
    int cleared = security != NULL && r->request_config != NULL &&
        ap_get_module_config(r->request_config, security) == NULL;
    if (stream != NULL && *stream != '\0') {
        errno = 0;
        stream_id = strtol(stream, &end, 10);
        if (errno != 0 || end == stream || *end != '\0') stream_id = -1;
    }
    if (descriptor_text == NULL || !safe_uri(r->uri) || !safe_uri(tag) ||
        clock_gettime(CLOCK_MONOTONIC, &timestamp) != 0) return APR_EGENERAL;
    count = snprintf(record, sizeof(record),
        "{\"event\":\"native_pool_cleanup\",\"uri\":\"%s\","
        "\"transaction_id\":\"%s\",\"stream_id\":%ld,\"stream_tag\":\"%s\","
        "\"connection_id\":%ld,\"context_seen\":%s,\"native_context_cleared\":%s,"
        "\"monotonic_ns\":%lld}\n", r->uri, r->uri, stream_id, tag,
        r->connection->master != NULL ? r->connection->master->id : r->connection->id,
        item->context_seen ? "true" : "false", cleared ? "true" : "false",
        (long long)timestamp.tv_sec * 1000000000LL + timestamp.tv_nsec);
    if (count <= 0 || (size_t)count >= sizeof(record) ||
        !append_record(descriptor_text, record, (size_t)count)) return APR_EGENERAL;
    return APR_SUCCESS;
}

static int observe_begin(request_rec *r)
{
    observation *item = apr_pcalloc(r->pool, sizeof(*item));
    APR_OPTIONAL_FN_TYPE(http2_var_lookup) *lookup =
        APR_RETRIEVE_OPTIONAL_FN(http2_var_lookup);
    char stream_name[] = "H2_STREAM_ID";
    char tag_name[] = "H2_STREAM_TAG";
    const char *stream;
    const char *tag;
    if (lookup == NULL) return HTTP_INTERNAL_SERVER_ERROR;
    /* mod_http2 normally exports these at fixups, which an early P1 deny
     * never reaches. Read its real optional API before that deny instead of
     * inventing a stream number or silently losing the blocked stream. */
    stream = lookup(r->pool, r->server, r->connection, r, stream_name);
    tag = lookup(r->pool, r->server, r->connection, r, tag_name);
    if (stream == NULL || tag == NULL) return HTTP_INTERNAL_SERVER_ERROR;
    apr_table_setn(r->subprocess_env, "H2_STREAM_ID", stream);
    apr_table_setn(r->subprocess_env, "H2_STREAM_TAG", tag);
    item->request = r;
    ap_set_module_config(r->request_config, &acceptance_observer_module, item);
    apr_pool_pre_cleanup_register(r->pool, item, observe_before_cleanup);
    apr_pool_cleanup_register(r->pool, item, observe_cleanup, apr_pool_cleanup_null);
    return DECLINED;
}

static apr_status_t observe_before_cleanup(void *data)
{
    observation *item = (observation *)data;
    request_rec *r = item->request;
    const module *security = security_module();
    if (item != NULL && security != NULL) {
        item->context_seen = ap_get_module_config(r->request_config, security) != NULL;
    }
    return APR_SUCCESS;
}

static void register_hooks(apr_pool_t *pool)
{
    static const char *const after[] = {"mod_security3.c", NULL};
    /* Apache module.register_hooks requires apr_pool_t *, including when unused. */
    (void)pool;
    ap_hook_post_read_request(observe_begin, NULL, after, APR_HOOK_REALLY_FIRST);
}

module AP_MODULE_DECLARE_DATA acceptance_observer_module = {
    STANDARD20_MODULE_STUFF, NULL, NULL, NULL, NULL, NULL, register_hooks,
    AP_MODULE_FLAG_NONE
};
