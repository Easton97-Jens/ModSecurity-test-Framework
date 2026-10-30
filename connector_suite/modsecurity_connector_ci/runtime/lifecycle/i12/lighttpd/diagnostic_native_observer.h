/* Test-only, synchronous snapshots; no host decision or EOS is synthesized. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void i12_diagnostic_host(const request_st *r, const handler_ctx *ctx,
        const char *kind) {
    const int saved_errno = errno;
    const char *path = getenv("MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_HOST");
    struct stat details;
    struct timespec now;
    char record[1536];
    if (path == NULL || strncmp(path, "/task/", 6U) != 0 || ctx == NULL) {
        errno = saved_errno;
        return;
    }
    const uint64_t scope = ctx->transaction == NULL ? 0U :
        msconnector_lifecycle_runtime_scope_call(ctx->transaction);
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        errno = saved_errno;
        return;
    }
    int fd = open(path, O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600);
    if (fd < 0) {
        errno = saved_errno;
        return;
    }
    if (fstat(fd, &details) != 0 || !S_ISREG(details.st_mode) ||
        details.st_uid != geteuid() || (details.st_mode & 0777U) != 0600U ||
        details.st_nlink != 1) goto done;
    uint64_t header_bytes = 0U;
    int headers_valid = r->rqst_headers.used == 0U || r->rqst_headers.data != NULL;
    for (uint32_t index = 0U; headers_valid && index < r->rqst_headers.used; ++index) {
        const data_unset *entry = r->rqst_headers.data[index];
        if (entry == NULL || entry->type != TYPE_STRING) {
            headers_valid = 0;
            break;
        }
        const data_string *header = (const data_string *)entry;
        header_bytes += (uint64_t)buffer_clen(&header->key) + (uint64_t)buffer_clen(&header->value);
    }
    int count = snprintf(record, sizeof(record),
        "{\"schema\":\"lighttpd-stock-diagnostic-host-v1\",\"pid\":%ld,"
        "\"uid\":%ld,\"gid\":%ld,\"kind\":\"%s\","
        "\"runtime_allocation_scope_call\":%" PRIu64 ",\"monotonic_ns\":%" PRIu64 ","
        "\"host_transaction_id\":\"%s\",\"actual_http_status\":%d,"
        "\"actual_output_bytes\":%" PRId64 ",\"actual_response_header_bytes\":%u,"
        "\"actual_request_entity_length\":%" PRId64 ","
        "\"actual_request_header_count\":%u,\"actual_request_header_name_value_bytes\":%" PRIu64 ","
        "\"actual_header_layout_valid\":%d,"
        "\"request_intervened\":%d,\"response_processed\":%d,"
        "\"technical_failed\":%d,\"api_failed\":%d}\n",
        (long)getpid(), (long)geteuid(), (long)getegid(), kind, scope,
        (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec,
        ctx->host_request_id, r->http_status, (int64_t)r->write_queue.bytes_out,
        r->resp_header_len, (int64_t)r->reqbody_length,
        r->rqst_headers.used, header_bytes, headers_valid, ctx->request_intervened,
        ctx->response_processed, ctx->technical_failed, ctx->api_failed);
    if (count > 0 && (size_t)count < sizeof(record)) {
        const ssize_t written = write(fd, record, (size_t)count);
        if (written != count) {
            static const char message[] = "i12 diagnostic host capture incomplete\n";
            (void)write(STDERR_FILENO, message, sizeof(message)-1U);
        }
    }
done:
    (void)close(fd);
    errno = saved_errno;
}
