/* Test-only boundary failures. Native observer retains the REAL SDK return. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int i12_diagnostic_boundary_result_unpreserved(const char *boundary, int actual) {
    static int consumed;
    const char *selected = getenv("MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_FAULT");
    const char *path = getenv("MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_FAULT_LOG");
    int injected = actual;
    if (consumed || selected == NULL || path == NULL ||
        strncmp(path, "/task/", 6U) != 0) return actual;
    if (strcmp(boundary, "request_headers") == 0 &&
        strcmp(selected, "request_headers_error") == 0) injected = -1;
    else if (strcmp(boundary, "request_headers") == 0 &&
        strcmp(selected, "request_headers_invalid") == 0) injected = -7;
    else if (strcmp(boundary, "logging") == 0 &&
        strcmp(selected, "logging_error") == 0) injected = -1;
    if (injected == actual) return actual;
    struct stat details;
    struct timespec now;
    int fd = open(path, O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600);
    if (fd < 0) return actual;
    if (fstat(fd, &details) != 0 || !S_ISREG(details.st_mode) ||
        details.st_uid != geteuid() || (details.st_mode & 0777U) != 0600U ||
        details.st_nlink != 1 || clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        (void)close(fd);
        return actual;
    }
    char record[512];
    int count = snprintf(record, sizeof(record),
        "{\"schema\":\"lighttpd-diagnostic-injected-boundary-v1\",\"pid\":%ld,"
        "\"monotonic_ns\":%" PRIu64 ",\"boundary\":\"%s\","
        "\"real_sdk_return\":%d,\"injected_runtime_boundary_return\":%d,"
        "\"native_observer_not_modified\":true}\n", (long)getpid(),
        (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec,
        boundary, actual, injected);
    int captured = count > 0 && (size_t)count < sizeof(record) &&
        write(fd, record, (size_t)count) == count;
    (void)close(fd);
    if (!captured) return actual;
    consumed = 1;
    return injected;
}

static int i12_diagnostic_boundary_result(const char *boundary, int actual) {
    const int saved_errno = errno;
    const int result = i12_diagnostic_boundary_result_unpreserved(boundary, actual);
    errno = saved_errno;
    return result;
}
