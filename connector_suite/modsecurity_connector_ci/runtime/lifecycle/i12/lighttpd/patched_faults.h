/* Test-only Runtime sink-boundary faults. Filesystem guards remain unchanged. */
#ifndef I12_LIGHTTPD_PATCHED_FAULTS_H
#define I12_LIGHTTPD_PATCHED_FAULTS_H
#include "msconnector/event_jsonl.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int i12_sink_consumed;

static int i12_sink_selected(const char *operation) {
    const char *selected = getenv("MSCONNECTOR_LIGHTTPD_SINK_FAULT");
    return !i12_sink_consumed && selected != NULL && strcmp(selected, operation) == 0;
}

struct i12_sink_fault {
    const char *operation;
    int actual_result;
    int injected_result;
    size_t requested_bytes;
    size_t actual_io_bytes;
};

static int i12_fault_append(const char *row, int size, size_t capacity) {
    const char *path = getenv("MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_FAULT_LOG");
    struct stat details;
    if (path == NULL || strncmp(path, "/task/", 6U) != 0
            || size <= 0 || (size_t)size >= capacity) return 0;
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    if (fstat(fd, &details) != 0 || !S_ISREG(details.st_mode) || details.st_uid != geteuid()
            || details.st_nlink != 1 || (details.st_mode & 0777U) != 0600U) {
        (void)close(fd);
        return 0;
    }
    int captured = write(fd, row, (size_t)size) == size;
    (void)close(fd);
    return captured;
}

static int i12_sink_record(const struct i12_sink_fault *fault) {
    struct timespec now;
    char row[768];
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    int size = snprintf(row, sizeof(row),
        "{\"schema\":\"lighttpd-patched-injected-sink-boundary-v1\",\"pid\":%ld,"
        "\"monotonic_ns\":%" PRIu64 ",\"operation\":\"%s\",\"actual_io_result\":%d,"
        "\"injected_runtime_boundary_result\":%d,\"requested_bytes\":%zu,"
        "\"actual_stdio_bytes_accepted\":%zu,\"kernel_failure_claimed\":false}\n",
        (long)getpid(), (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec,
        fault->operation, fault->actual_result, fault->injected_result,
        fault->requested_bytes, fault->actual_io_bytes);
    int captured = i12_fault_append(row, size, sizeof(row));
    if (captured) i12_sink_consumed = 1;
    return captured;
}

static int i12_pointer_null(const char *boundary, const void *actual, size_t count) {
    static int consumed;
    const char *selected = getenv("MSCONNECTOR_LIGHTTPD_POINTER_FAULT");
    struct timespec now;
    char row[512];
    if (consumed || selected == NULL || actual == NULL || count == 0U
            || strcmp(selected, boundary) != 0 || clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    int size = snprintf(row, sizeof(row),
        "{\"schema\":\"lighttpd-patched-injected-pointer-boundary-v1\",\"pid\":%ld,"
        "\"monotonic_ns\":%" PRIu64 ",\"boundary\":\"%s\",\"actual_pointer_nonnull\":true,"
        "\"injected_pointer_null\":true,\"actual_input_count\":%zu,\"native_sdk_failure_claimed\":false}\n",
        (long)getpid(), (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec,
        boundary, count);
    if (!i12_fault_append(row, size, sizeof(row))) return 0;
    consumed = 1;
    return 1;
}

static int i12_sink_open(const char *path, int *out_fd) {
    int actual = msconnector_open_private_event_file(path, out_fd);
    if (actual && i12_sink_selected("open")) {
        const struct i12_sink_fault fault = {"open", actual, 0, 0U, 0U};
        if (i12_sink_record(&fault)) {
            (void)close(*out_fd);
            *out_fd = -1;
            errno = EIO;
            return 0;
        }
    }
    return actual;
}

static int i12_sink_puts(const char *text, FILE *file) {
    if (i12_sink_selected("write")) {
        const struct i12_sink_fault fault = {"write", 0, EOF, strlen(text), 0U};
        if (i12_sink_record(&fault)) {
            errno = EIO;
            return EOF;
        }
    }
    if (i12_sink_selected("short_write")) {
        const size_t requested = strlen(text);
        const size_t written = fwrite(text, 1U, requested / 2U, file);
        const struct i12_sink_fault fault = {"short_write", (int)written, EOF, requested, written};
        if (!i12_sink_record(&fault)) return EOF;
        errno = EIO;
        return EOF;
    }
    return fputs(text, file);
}

static int i12_sink_flush(FILE *file) {
    const int actual = fflush(file);
    if (i12_sink_selected("flush")) {
        const struct i12_sink_fault fault = {"flush", actual, EOF, 0U, 0U};
        if (i12_sink_record(&fault)) {
            errno = EIO;
            return EOF;
        }
    }
    return actual;
}

static int i12_sink_close(FILE *file) {
    const int actual = fclose(file);
    if (i12_sink_selected("close")) {
        const struct i12_sink_fault fault = {"close", actual, EOF, 0U, 0U};
        if (i12_sink_record(&fault)) {
            errno = EIO;
            return EOF;
        }
    }
    return actual;
}
#endif
