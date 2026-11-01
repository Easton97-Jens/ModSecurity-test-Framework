/* Private lighttpd test link variant; never a release object.
 * Inject only a securely opened event FILE. Actual and substituted returns
 * remain separate; native SDK returns are never changed by this observer. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

FILE *__real_fdopen(int, const char *);
int __real_fputs(const char *, FILE *);
int __real_fflush(FILE *);
int __real_fclose(FILE *);
int __real_accept(int, struct sockaddr *, socklen_t *);

static int private_event(int fd) {
    char link[64];
    char path[4096];
    struct stat details;
    if (fd < 0 || fstat(fd, &details) != 0 || !S_ISREG(details.st_mode) ||
        details.st_uid != geteuid() || (details.st_mode & 077) != 0 || details.st_nlink != 1) return 0;
    (void)snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t size = readlink(link, path, sizeof(path) - 1);
    if (size <= 0 || (size_t)size >= sizeof(path) - 1) return 0;
    path[size] = '\0';
    size_t length = (size_t)size;
    return strncmp(path, "/task/", 6) == 0 && length >= 13 &&
        strcmp(path + length - 13, "/events.jsonl") == 0;
}

static int selected(int fd, const char *mode) {
    const char *configured = getenv("MSCONNECTOR_LIGHTTPD_SINK_FAULT");
    return configured != NULL && strcmp(configured, mode) == 0 && private_event(fd);
}

static void observation(const char *operation, int called, int actual, int substituted,
    size_t requested, ssize_t physical, int injected_errno) {
    const char *path = getenv("MSCONNECTOR_LIGHTTPD_SINK_FAULT_TRACE");
    struct stat details;
    struct timespec now;
    char row[768];
    char actual_text[32];
    if (path == NULL || strncmp(path, "/task/", 6) != 0 || strstr(path, "..") != NULL) _exit(90);
    int output = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (output < 0 || fstat(output, &details) != 0 || !S_ISREG(details.st_mode) ||
        details.st_uid != geteuid() || (details.st_mode & 077) != 0 || details.st_nlink != 1) _exit(90);
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) _exit(90);
    if (called) (void)snprintf(actual_text, sizeof(actual_text), "%d", actual);
    else (void)snprintf(actual_text, sizeof(actual_text), "null");
    int length = snprintf(row, sizeof(row),
        "{\"producer\":\"lighttpd-private-sink-link-variant\",\"pid\":%ld,\"uid\":%ld,"
        "\"operation\":\"%s\",\"actual_called\":%s,\"actual_return\":%s,"
        "\"substituted_return\":%d,\"injected_errno\":%d,\"requested_bytes\":%zu,"
        "\"actual_direct_write_return\":%zd,\"monotonic_ns\":%llu}\n",
        (long)getpid(), (long)geteuid(), operation, called ? "true" : "false", actual_text,
        substituted, injected_errno, requested, physical,
        (unsigned long long)now.tv_sec * 1000000000ULL + (unsigned long long)now.tv_nsec);
    if (length <= 0 || (size_t)length >= sizeof(row) || write(output, row, (size_t)length) != length) _exit(90);
    if (close(output) != 0) _exit(90);
    errno = injected_errno;
}

FILE *__wrap_fdopen(int fd, const char *mode) {
    if (!selected(fd, "open")) return __real_fdopen(fd, mode);
    observation("fdopen", 0, 0, 0, 0, 0, EIO);
    return NULL;
}

int __wrap_fputs(const char *text, FILE *stream) {
    int fd = fileno(stream);
    if (selected(fd, "write")) {
        observation("fputs", 0, 0, EOF, strlen(text), 0, EIO);
        return EOF;
    }
    if (selected(fd, "short-write")) {
        size_t length = strlen(text);
        ssize_t physical = write(fd, text, length / 2);
        observation("fputs-short-write", 0, 0, EOF, length, physical, EIO);
        return EOF;
    }
    return __real_fputs(text, stream);
}

int __wrap_fflush(FILE *stream) {
    int fault = stream != NULL && selected(fileno(stream), "flush");
    int result = __real_fflush(stream);
    if (!fault) return result;
    observation("fflush", 1, result, EOF, 0, 0, EIO);
    return EOF;
}

int __wrap_fclose(FILE *stream) {
    int fault = selected(fileno(stream), "close");
    int result = __real_fclose(stream);
    if (!fault) return result;
    observation("fclose", 1, result, EOF, 0, 0, EIO);
    return EOF;
}

static int lifetime_stop_requested(void) {
    const char *path = getenv("MSCONNECTOR_LIGHTTPD_SINK_STOP");
    const char *mode = getenv("MSCONNECTOR_LIGHTTPD_SINK_FAULT");
    struct stat details;
    if (path == NULL || mode == NULL || strcmp(mode, "close") != 0 ||
        strncmp(path, "/task/", 6) != 0 || strstr(path, "..") != NULL) return 0;
    int marker = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (marker < 0) return 0;
    int safe = fstat(marker, &details) == 0 && S_ISREG(details.st_mode) &&
        details.st_uid == geteuid() && (details.st_mode & 0777) == 0600 && details.st_nlink == 1;
    (void)close(marker);
    return safe;
}

int __wrap_accept(int listener, struct sockaddr *address, socklen_t *size) {
    int actual = __real_accept(listener, address, size);
    if (actual >= 0 && lifetime_stop_requested()) {
        (void)close(actual);
        observation("capture_lifetime_accept_stop", 1, actual, -1, 0, 0, EBADF);
        return -1;
    }
    return actual;
}
