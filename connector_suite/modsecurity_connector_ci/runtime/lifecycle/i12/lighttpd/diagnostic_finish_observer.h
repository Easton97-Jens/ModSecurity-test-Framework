/* Observe every actual finish invocation, including same-TU cleanup calls. */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void i12_diagnostic_finish(const char *edge, const char *id,
        int actual_return, int actual_error, int finish_attempted) {
    const int saved_errno = errno;
    const char *path = getenv("MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_FINISH_LOG");
    struct timespec now;
    size_t size = id == NULL ? 0U : strlen(id);
    int safe_id = size > 0U && size < 256U;
    for (size_t index = 0U; index < size && safe_id; ++index) {
        const unsigned char ch = (unsigned char)id[index];
        safe_id = isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == ':';
    }
    if (path != NULL && strncmp(path, "/task/", 6U) == 0 &&
            clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        int fd = open(path, O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600);
        if (fd >= 0) {
            struct stat details;
            if (fstat(fd, &details) == 0 && S_ISREG(details.st_mode) &&
                    details.st_uid == geteuid() && details.st_nlink == 1 &&
                    (details.st_mode & 0777U) == 0600U) {
                char row[1024];
                char result[32], error[32];
                if (strcmp(edge, "return") == 0) {
                    (void)snprintf(result, sizeof(result), "%d", actual_return);
                    (void)snprintf(error, sizeof(error), "%d", actual_error);
                } else {
                    (void)snprintf(result, sizeof(result), "null");
                    (void)snprintf(error, sizeof(error), "null");
                }
                int count = snprintf(row, sizeof(row),
                    "{\"schema\":\"lighttpd-diagnostic-actual-runtime-finish-v1\",\"pid\":%ld,"
                    "\"monotonic_ns\":%" PRIu64 ",\"edge\":\"%s\",\"transaction_id\":%s%s%s,"
                    "\"actual_return\":%s,\"actual_error\":%s,\"finish_attempted\":%d,"
                    "\"return_modified\":false}\n", (long)getpid(),
                    (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec,
                    edge, safe_id ? "\"" : "", safe_id ? id : "null", safe_id ? "\"" : "",
                    result, error, finish_attempted);
                if (count > 0 && (size_t)count < sizeof(row)) (void)write(fd, row, (size_t)count);
            }
            (void)close(fd);
        }
    }
    errno = saved_errno;
}
