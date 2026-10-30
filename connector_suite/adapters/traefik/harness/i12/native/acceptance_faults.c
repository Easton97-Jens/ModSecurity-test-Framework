#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
/* Test-only GNU-wrap faults. No product code or native observer is replaced.
 * Exact sink path and selected mapper URI are mandatory admission boundaries.
 * Receipt output uses a separately inherited descriptor, never the event sink.
 */
#include "msconnector/generic_mapper.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

static _Atomic int sink_used;
static _Atomic int mapper_used;
static _Atomic int native_used;
static _Thread_local int target_request;
static _Atomic uintptr_t selected_native;
static _Atomic unsigned int response_append_count;

int i12_acceptance_native_result(const char *operation, int original);
int i12_acceptance_fail_begin(void);

static int selected(const char *name) {
    const char *mode = getenv("I12_ACCEPTANCE_FAULT");
    return mode != NULL && strcmp(mode, name) == 0;
}

static int descriptor_is_sink(int);
static void receipt(const char *, long, int, int);
static void request_input_receipt(const char *, int, const void *, size_t, const void *, size_t);

/* The native UDS service bypasses the HTTP generic mapper. Match its actual
 * parsed request at the runtime boundary without changing/freeing parse ownership. */
const msconnector_request *i12_acceptance_native_request(const msconnector_request *source,
    msconnector_request *changed) {
    const char *uri = getenv("I12_ACCEPTANCE_FAULT_URI");
    target_request = source != NULL && source->uri != NULL && uri != NULL && strcmp(uri, source->uri) == 0;
    if (!target_request || mapper_used || (!selected("mapper-body-null") && !selected("mapper-headers-null"))) {
        return source;
    }
    mapper_used = 1;
    *changed = *source;
    if (selected("mapper-body-null")) { changed->body.data = NULL; changed->body.size = 1U; }
    else { changed->headers = NULL; changed->header_count = 1U; }
    request_input_receipt(selected("mapper-body-null") ? "native-request-body-null-setup" : "native-request-headers-null-setup", 1,
        changed->body.data, changed->body.size, changed->headers, changed->header_count);
    return changed;
}

void i12_acceptance_native_begin_result(const msconnector_request *request, int result) {
    if (target_request && mapper_used && request != NULL &&
            (selected("mapper-body-null") || selected("mapper-headers-null"))) {
        request_input_receipt(selected("mapper-body-null") ? "native-request-body-null" : "native-request-headers-null", result,
            request->body.data, request->body.size, request->headers, request->header_count);
    }
}

void i12_acceptance_native_created(void *transaction) {
    if (target_request && transaction != NULL) {
        atomic_store(&selected_native, (uintptr_t)transaction);
        atomic_store(&response_append_count, 0U);
    }
}

void i12_acceptance_native_released(void *transaction) {
    uintptr_t expected = (uintptr_t)transaction;
    (void)atomic_compare_exchange_strong(&selected_native, &expected, (uintptr_t)0);
}

static int fault_target(void) {
    return getenv("I12_ACCEPTANCE_FAULT_URI") == NULL || target_request;
}

static void write_receipt(int descriptor, const char *line, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        ssize_t written = write(descriptor, line + offset, size - offset);
        if (written < 0 && errno == EINTR) { continue; }
        if (written <= 0) { return; }
        offset += (size_t)written;
    }
}

static void receipt(const char *operation, long result, int injected, int descriptor) {
    const char *value = getenv("I12_ACCEPTANCE_FAULT_FD");
    char line[640];
    int saved_errno = errno;
    struct stat identity;
    int identity_known = descriptor >= 0 && fstat(descriptor, &identity) == 0;
    struct timespec now;
    char *end = NULL;
    long output;
    int size;
    if (value == NULL || *value == '\0') { return; }
    output = strtol(value, &end, 10);
    if (*end != '\0' || output < 3 || output > 1024 || output == descriptor) { return; }
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    size = snprintf(line, sizeof(line),
        "{\"operation\":\"%s\",\"result\":%ld,\"injected\":%s,\"fd\":%d,"
        "\"pid\":%ld,\"errno\":%d,\"monotonic_ns\":%lld,\"device\":%lld,\"inode\":%lld}\n", operation, result,
        injected ? "true" : "false", descriptor, (long)getpid(),
        saved_errno,
        (long long)now.tv_sec * 1000000000LL + now.tv_nsec,
        identity_known ? (long long)identity.st_dev : -1LL, identity_known ? (long long)identity.st_ino : -1LL);
    if (size > 0 && (size_t)size < sizeof(line)) { write_receipt((int)output, line, (size_t)size); }
    errno = saved_errno;
}

static void request_input_receipt(const char *operation, int result, const void *body,
    size_t body_size, const void *headers, size_t header_count) {
    const char *value = getenv("I12_ACCEPTANCE_FAULT_FD");
    char *end = NULL;
    long descriptor;
    char line[512];
    struct timespec now;
    int saved = errno;
    int length;
    if (value == NULL || *value == '\0') { return; }
    descriptor = strtol(value, &end, 10);
    if (*end != '\0' || descriptor < 3 || descriptor > 1024) { errno = saved; return; }
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    length = snprintf(line, sizeof(line),
        "{\"operation\":\"%s\",\"result\":%d,\"injected\":true,\"pid\":%ld,"
        "\"input_size\":%zu,\"body_data_null\":%s,\"header_count\":%zu,\"headers_null\":%s,\"monotonic_ns\":%lld}\n",
        operation, result, (long)getpid(), body_size, body == NULL ? "true" : "false",
        header_count, headers == NULL ? "true" : "false",
        (long long)now.tv_sec * 1000000000LL + now.tv_nsec);
    if (length > 0 && (size_t)length < sizeof(line)) { write_receipt((int)descriptor, line, (size_t)length); }
    errno = saved;
}

static void close_sink_descriptor(int descriptor) {
    int result;
    receipt("owned-event-fd-before-close", 0, 0, descriptor);
    result = close(descriptor);
    receipt("close-owned-event-fd", result, 1, descriptor);
}

static int install_readonly_sink(int descriptor) {
    const char *path = getenv("I12_ACCEPTANCE_EVENT_PATH");
    struct stat original;
    struct stat replacement;
    int recovery;
    int readonly;
    int result;
    if (path == NULL || !descriptor_is_sink(descriptor) || fstat(descriptor, &original) != 0) { return -1; }
    recovery = fcntl(descriptor, F_DUPFD_CLOEXEC, 3);
    receipt("recovery-retain-owned-inode", recovery, 0, recovery);
    if (recovery < 0) { return -1; }
    readonly = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (readonly < 0 || fstat(readonly, &replacement) != 0 ||
            original.st_dev != replacement.st_dev || original.st_ino != replacement.st_ino ||
            replacement.st_uid != geteuid() || !S_ISREG(replacement.st_mode) ||
            !descriptor_is_sink(descriptor)) {
        if (readonly >= 0) { (void)close(readonly); }
        (void)close(recovery);
        return -1;
    }
    /* Original slot stays occupied throughout: atomic replacement of this
     * verified owned inode, no close/reuse window for another thread's FD. */
    result = dup2(readonly, descriptor);
    receipt("fault-install-owned-readonly-fd", result, 1, descriptor);
    (void)close(readonly);
    if (result != descriptor) { (void)close(recovery); return -1; }
    return recovery;
}

static void restore_sink_descriptor(FILE *stream, int descriptor, int recovery) {
    struct stat retained;
    struct stat current;
    int restored;
    int saved = errno;
    if (recovery < 0) { return; }
    /* This slot was never free. Verify the held and current actual inodes,
     * ownership/path and readonly mode before restoring its writable copy. */
    if (descriptor_is_sink(descriptor) && fstat(recovery, &retained) == 0 &&
            fstat(descriptor, &current) == 0 && retained.st_dev == current.st_dev &&
            retained.st_ino == current.st_ino && (fcntl(descriptor, F_GETFL) & O_ACCMODE) == O_RDONLY) {
        restored = dup2(recovery, descriptor);
        receipt("recovery-restore-owned-inode", restored, 0, descriptor);
        if (restored == descriptor) {
            clearerr(stream);
            receipt("recovery-original-owned-fd-restored", restored, 0, descriptor);
        }
    } else { receipt("recovery-identity-rejected", -1, 0, descriptor); }
    (void)close(recovery);
    errno = saved;
}

static int shutdown_is_single_thread(void) {
    DIR *directory = opendir("/proc/self/task");
    const struct dirent *entry;
    int count = 0;
    if (directory == NULL) { return 0; }
    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') { ++count; }
    }
    (void)closedir(directory);
    receipt("shutdown-physical-thread-count", count, 0, -1);
    return count == 1;
}

int i12_acceptance_native_result(const char *operation, int original) {
    if (target_request && !native_used && ((selected("native-invalid-return") && strcmp(operation, "process_request_headers") == 0) ||
            (selected("native-response-invalid-return") && strcmp(operation, "process_response_headers") == 0) ||
            (selected("finish-failure") && strcmp(operation, "process_logging") == 0))) {
        native_used = 1;
        receipt(operation, original, 0, -1);
        receipt(operation, -7, 1, -1);
        return -7;
    }
    return original;
}

/* Native correlation follows the actual allocated transaction across the
 * authorizer and response-observer threads; no thread-local carry is assumed. */
int i12_acceptance_native_transaction_result(void *transaction, const char *operation, int original) {
    if ((uintptr_t)transaction != 0U && atomic_load(&selected_native) == (uintptr_t)transaction) {
        target_request = 1;
        if (selected("native-response-append") && strcmp(operation, "append_response_body") == 0 &&
                atomic_fetch_add(&response_append_count, 1U) == 1U) {
            receipt(operation, original, 0, -1);
            receipt(operation, -7, 1, -1);
            return -7;
        }
        return i12_acceptance_native_result(operation, original);
    }
    return original;
}

int i12_acceptance_fail_begin(void) {
    if (target_request && !native_used && selected("begin-failure")) {
        native_used = 1;
        receipt("native-constructor-NULL-before-allocation", 0, 1, -1);
        return 1;
    }
    return 0;
}

static int descriptor_is_sink(int descriptor) {
    const char *expected = getenv("I12_ACCEPTANCE_EVENT_PATH");
    char proc[64];
    char actual[4096];
    struct stat opened;
    struct stat named;
    ssize_t size;
    if (expected == NULL || expected[0] != '/' || descriptor < 0) { return 0; }
    (void)snprintf(proc, sizeof(proc), "/proc/self/fd/%d", descriptor);
    size = readlink(proc, actual, sizeof(actual) - 1U);
    if (size <= 0 || (size_t)size >= sizeof(actual) - 1U) { return 0; }
    actual[size] = '\0';
    return strcmp(actual, expected) == 0 && fstat(descriptor, &opened) == 0 &&
        lstat(expected, &named) == 0 && S_ISREG(opened.st_mode) &&
        S_ISREG(named.st_mode) && opened.st_uid == geteuid() &&
        opened.st_dev == named.st_dev && opened.st_ino == named.st_ino;
}

/* The test harness supports the Linux x86-64 SysV ABI, as does its ptrace
 * observer. Preserve openat's public variadic type. The assembly entry supplies
 * an explicit zero mode for three-argument calls before entering fixed-arity C;
 * it retains the caller's fourth argument only when libc requires one.
 * A C alias to a four-argument function would not provide that guarantee. */
#if !defined(__linux__) || !defined(__x86_64__)
#error "acceptance openat bridge requires Linux x86-64 SysV ABI"
#endif
_Static_assert(O_CREAT == 64 && O_TMPFILE == 4259840, "Linux openat flag ABI changed");
extern __typeof__(openat) __real_openat;
extern __typeof__(openat) __wrap_openat;
int i12_acceptance_openat(int directory, const char *name, int flags, mode_t mode);
__asm__(
    ".text\n"
    ".globl __wrap_openat\n"
    ".type __wrap_openat,@function\n"
    "__wrap_openat:\n"
    "testl $64,%edx\n"
    "jnz 1f\n"
    "movl %edx,%eax\n"
    "andl $4259840,%eax\n"
    "cmpl $4259840,%eax\n"
    "je 1f\n"
    "xorl %ecx,%ecx\n"
    "1: jmp i12_acceptance_openat\n"
    ".size __wrap_openat,.-__wrap_openat\n");

int i12_acceptance_openat(int directory, const char *name, int flags, mode_t mode) {
    int result;
    result = __real_openat(directory, name, flags, mode);
    /* Deny a second, real open of this exact owned inode through actual mode
     * permissions. The admitted host is nonroot; its real errno is retained. */
    if (result >= 0 && descriptor_is_sink(result) && !sink_used && selected("sink-open")) {
        int saved;
        sink_used = 1;
        if (fchmod(result, 0) != 0) { return result; }
        (void)close(result);
        result = __real_openat(directory, name, flags, mode);
        saved = errno;
        receipt("openat-mode-denied", result, 1, result);
        errno = saved;
        return result;
    }
    return result;
}

extern int __real_setvbuf(FILE *, char *, int, size_t);
int __wrap_setvbuf(FILE *stream, char *buffer, int mode, size_t size) {
    int result;
    int configure = stream != NULL && descriptor_is_sink(fileno(stream)) &&
        (selected("sink-write") || selected("sink-short-write") || selected("sink-flush"));
    /* Intercept the product's initial, pre-I/O configuration call. There is
     * no second/late setvbuf operation and the real libc result is retained. */
    if (configure) {
        mode = selected("sink-flush") ? _IOFBF : _IONBF;
        size = selected("sink-flush") ? 65536U : 0U;
    }
    result = __real_setvbuf(stream, buffer, mode, size);
    if (configure) { receipt("initial-setvbuf", result, 1, fileno(stream)); }
    return result;
}

extern int __real_fputs(const char *, FILE *);
static int limited_fputs(const char *text, FILE *stream, int descriptor, int *applied) {
    struct rlimit previous;
    struct stat before;
    struct stat after;
    struct sigaction ignore;
    struct sigaction original;
    struct rlimit limited;
    if (getrlimit(RLIMIT_FSIZE, &previous) != 0 || fstat(descriptor, &before) != 0) { return __real_fputs(text, stream); }
    limited = previous;
    limited.rlim_cur = (rlim_t)before.st_size + 7U;
    (void)memset(&ignore, 0, sizeof(ignore));
    ignore.sa_handler = SIG_IGN;
    (void)sigemptyset(&ignore.sa_mask);
    if (sigaction(SIGXFSZ, &ignore, &original) != 0) { return __real_fputs(text, stream); }
    if (setrlimit(RLIMIT_FSIZE, &limited) != 0) {
        (void)sigaction(SIGXFSZ, &original, NULL);
        return __real_fputs(text, stream);
    }
    *applied = 1;
    int result = __real_fputs(text, stream);
    int saved = errno;
    (void)setrlimit(RLIMIT_FSIZE, &previous);
    (void)sigaction(SIGXFSZ, &original, NULL);
    if (fstat(descriptor, &after) == 0) {
        receipt("fputs-physical-prefix", (long)(after.st_size - before.st_size), 1, descriptor);
    }
    errno = saved;
    return result;
}

int __wrap_fputs(const char *text, FILE *stream) {
    int descriptor = fileno(stream);
    if (fault_target() && !sink_used && descriptor_is_sink(descriptor) &&
            (selected("sink-write") || selected("sink-short-write"))) {
        sink_used = 1;
        int result;
        int saved;
        int recovery = selected("sink-write") ? install_readonly_sink(descriptor) : -1;
        if (selected("sink-write") && recovery < 0) { return __real_fputs(text, stream); }
        if (selected("sink-short-write")) {
            int applied = 0;
            result = limited_fputs(text, stream, descriptor, &applied);
            if (!applied) { return result; }
            saved = errno;
        } else {
            result = __real_fputs(text, stream);
            saved = errno;
        }
        receipt("fputs", result, 1, descriptor);
        if (selected("sink-write")) { restore_sink_descriptor(stream, descriptor, recovery); }
        else { clearerr(stream); }
        errno = saved;
        return result;
    }
    return __real_fputs(text, stream);
}

extern int __real_fflush(FILE *);
int __wrap_fflush(FILE *stream) {
    if (fault_target() && stream != NULL && !sink_used && selected("sink-flush") && descriptor_is_sink(fileno(stream))) {
        int descriptor = fileno(stream);
        int result;
        int saved;
        int recovery = install_readonly_sink(descriptor);
        if (recovery < 0) { return __real_fflush(stream); }
        sink_used = 1;
        result = __real_fflush(stream);
        saved = errno;
        receipt("fflush", result, 1, descriptor);
        restore_sink_descriptor(stream, descriptor, recovery);
        errno = saved;
        return result;
    }
    return __real_fflush(stream);
}

extern int __real_fclose(FILE *);
int __wrap_fclose(FILE *stream) {
    if (!sink_used && selected("sink-close") && descriptor_is_sink(fileno(stream)) && shutdown_is_single_thread()) {
        int descriptor = fileno(stream);
        int result;
        int saved;
        sink_used = 1;
        close_sink_descriptor(descriptor);
        result = __real_fclose(stream);
        saved = errno;
        receipt("fclose", result, 1, descriptor);
        errno = saved;
        return result;
    }
    return __real_fclose(stream);
}

extern int __real_msconnector_generic_map_request(const msconnector_generic_request_source *,
    const msconnector_request_mapper_contract *, msconnector_request *, char *, size_t);
int __wrap_msconnector_generic_map_request(const msconnector_generic_request_source *source,
    const msconnector_request_mapper_contract *contract, msconnector_request *out,
    char *error, size_t error_len) {
    const char *uri = getenv("I12_ACCEPTANCE_FAULT_URI");
    target_request = source != NULL && source->uri != NULL && uri != NULL && strcmp(uri, source->uri) == 0;
    if (source != NULL && source->uri != NULL && uri != NULL && strcmp(uri, source->uri) == 0 &&
            !mapper_used && (selected("mapper-body-null") || selected("mapper-headers-null"))) {
        msconnector_generic_request_source changed = *source;
        int result;
        mapper_used = 1;
        if (selected("mapper-body-null")) { changed.body.data = NULL; changed.body.size = 1U; }
        else { changed.headers = NULL; changed.header_count = 1U; }
        result = __real_msconnector_generic_map_request(&changed, contract, out, error, error_len);
        request_input_receipt(selected("mapper-body-null") ? "mapper-body-null" : "mapper-headers-null", result,
            changed.body.data, changed.body.size, changed.headers, changed.header_count);
        return result;
    }
    return __real_msconnector_generic_map_request(source, contract, out, error, error_len);
}
