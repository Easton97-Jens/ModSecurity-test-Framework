/* Read-only actual event serializer observation; never substitute a return. */
#include "msconnector/event_jsonl.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int i12_diagnostic_event_serialize(const msconnector_event *event,
        char *buffer, size_t capacity, int *truncated) {
    const int actual = msconnector_event_write_jsonl_line(event, buffer, capacity, truncated);
    const int saved_errno = errno;
    const char *path = getenv("MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_BUDGET_LOG");
    struct timespec now;
    if (path != NULL && strncmp(path, "/task/", 6U) == 0 &&
            clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        int fd = open(path, O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600);
        if (fd >= 0) {
            struct stat details;
            if (fstat(fd, &details) == 0 && S_ISREG(details.st_mode) &&
                    details.st_uid == geteuid() && details.st_nlink == 1 &&
                    (details.st_mode & 0777U) == 0600U) {
                char row[512];
                int count = snprintf(row, sizeof(row),
                    "{\"schema\":\"lighttpd-diagnostic-actual-event-serializer-v1\",\"pid\":%ld,"
                    "\"monotonic_ns\":%" PRIu64 ",\"actual_result\":%d,\"actual_capacity\":%zu,"
                    "\"actual_truncated\":%d,\"return_modified\":false}\n", (long)getpid(),
                    (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec,
                    actual, capacity, truncated == NULL ? -1 : *truncated);
                if (count > 0 && (size_t)count < sizeof(row)) (void)write(fd, row, (size_t)count);
            }
            (void)close(fd);
        }
    }
    errno = saved_errno;
    return actual;
}
