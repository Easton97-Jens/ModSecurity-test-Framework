/* Explicit diagnostic public API caller; no automatic native timer is claimed. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int i12_diagnostic_terminal_control(msconnector_runtime_transaction *transaction,
        msconnector_error *error) {
    static int consumed;
    const char *operation = getenv("MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_CONTROL");
    const char *path = getenv("MSCONNECTOR_LIGHTTPD_DIAGNOSTIC_CONTROL_LOG");
    if (consumed || operation == NULL || path == NULL || strncmp(path, "/task/", 6U) != 0) return 0;
    const int timeout = strcmp(operation, "timeout") == 0;
    if (!timeout && strcmp(operation, "cancel") != 0) return 0;
    struct stat details;
    int fd = open(path, O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    if (fstat(fd, &details) != 0 || !S_ISREG(details.st_mode) || details.st_uid != geteuid()
            || details.st_nlink != 1 || (details.st_mode & 0777U) != 0600U) {
        (void)close(fd);
        return 0;
    }
    consumed = 1;
    const int actual = timeout ? msconnector_runtime_transaction_timeout(transaction, error)
        : msconnector_runtime_transaction_cancel(transaction, 1, error);
    const int saved_errno = errno;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        char row[768];
        int count = snprintf(row, sizeof(row),
            "{\"schema\":\"lighttpd-diagnostic-actual-terminal-api-v1\",\"pid\":%ld,"
            "\"monotonic_ns\":%" PRIu64 ",\"operation\":\"%s\","
            "\"actual_runtime_pointer\":\"%p\",\"actual_return\":%d,\"actual_error\":%d,"
            "\"trigger\":\"explicit_diagnostic_public_api_caller\","
            "\"automatic_sdk_timer_claimed\":false,\"native_body_hook_claimed\":false}\n",
            (long)getpid(), (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec,
            operation, (void *)transaction, actual, error == NULL ? -1 : (int)error->code);
        if (count > 0 && (size_t)count < sizeof(row)) (void)write(fd, row, (size_t)count);
    }
    (void)close(fd);
    errno = saved_errno;
    return actual == 1 ? (timeout ? 1 : 2) : -1;
}
