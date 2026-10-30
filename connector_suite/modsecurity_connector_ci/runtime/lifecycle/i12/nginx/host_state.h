/* NGINX-only test capture. Observes real state without changing decisions. */
#ifndef I12_NGINX_HOST_STATE_H
#define I12_NGINX_HOST_STATE_H
#include "nginx-host-observation.h"

static inline void
ngxi12_body_state(const ngx_http_modsecurity_ctx_t *ctx, const char *operation,
    const ngx_buf_t *buffer)
{
    int saved = errno;
    const char *setting = getenv("MSCONNECTOR_NGX_HOST_FD");
    char *end = NULL;
    long fd = setting != NULL ? strtol(setting, &end, 10) : -1;
    struct stat info;
    struct timespec mono;
    const ngx_http_request_body_t *body = ctx != NULL && ctx->r != NULL ? ctx->r->request_body : NULL;
    const ngx_temp_file_t *temp = body != NULL ? body->temp_file : NULL;
    const ngx_chain_t *chain = body != NULL ? body->bufs : NULL;
    unsigned int count = 0, last_buf = 0, last_in_chain = 0;
    for (; chain != NULL; chain = chain->next) {
        ++count;
        if (chain->buf != NULL) {
            last_buf += chain->buf->last_buf;
            last_in_chain += chain->buf->last_in_chain;
        }
    }
    if (ctx != NULL && setting != NULL && end != setting && *end == '\0' &&
        fd >= 3 && fd <= 1048576 && fstat((int)fd, &info) == 0 &&
        S_ISREG(info.st_mode) && info.st_nlink == 1 &&
        (fcntl((int)fd, F_GETFL) & O_ACCMODE) != O_RDONLY &&
        clock_gettime(CLOCK_MONOTONIC, &mono) == 0) {
        (void)dprintf((int)fd,
            "{\"pid\":%ld,\"operation\":\"%s\",\"function\":\"%s\","
            "\"allocation_scope_call\":%" PRIu64 ",\"monotonic_ns\":%" PRId64
            ",\"request_body_present\":%u,\"remaining\":%" PRId64
            ",\"temp_file_present\":%u,\"temp_file_offset\":%" PRId64
            ",\"temp_file_fd\":%d,\"chain_count\":%u,\"chain_last_buf_count\":%u"
            ",\"chain_last_in_chain_count\":%u,\"request_body_bytes_seen\":%zu"
            ",\"buffer_present\":%u,\"in_file\":%u,\"memory\":%u,\"temporary\":%u"
            ",\"file_pos\":%" PRId64 ",\"file_last\":%" PRId64
            ",\"last_buf\":%u,\"last_in_chain\":%u}\n",
            (long)getpid(), operation, operation, msconnector_lifecycle_host_scope_call(ctx),
            (int64_t)mono.tv_sec * INT64_C(1000000000) + mono.tv_nsec,
            body != NULL, body != NULL ? (int64_t)body->rest : -1,
            temp != NULL, temp != NULL ? (int64_t)temp->offset : -1,
            temp != NULL ? temp->file.fd : -1, count, last_buf, last_in_chain,
            ctx->request_body_bytes_seen, buffer != NULL,
            buffer != NULL ? (unsigned int)buffer->in_file : 0U,
            buffer != NULL ? (unsigned int)buffer->memory : 0U,
            buffer != NULL ? (unsigned int)buffer->temporary : 0U,
            buffer != NULL ? (int64_t)buffer->file_pos : -1,
            buffer != NULL ? (int64_t)buffer->file_last : -1,
            buffer != NULL ? (unsigned int)buffer->last_buf : 0U,
            buffer != NULL ? (unsigned int)buffer->last_in_chain : 0U);
    }
    errno = saved;
}
#endif
