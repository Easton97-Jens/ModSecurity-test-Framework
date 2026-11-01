/* I12-only preload fixture: one owned worker/transaction P2 invalid return.
 * The real SDK always runs first. This file is never part of a product build.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef void *(*new_transaction_fn)(void *, void *, char *, void *);
typedef int (*process_body_fn)(void *);
typedef void (*cleanup_fn)(void *);
static pid_t owned_master;
static char owned_id[33];
static int evidence = -1;
static int armed;
static int spent;
static dev_t evidence_device;
static ino_t evidence_inode;
static void *selected_transaction;

static int descriptor_matches(int require_empty)
{
    struct stat info;
    int flags = fcntl(evidence, F_GETFL);
    return evidence >= 3 && flags >= 0 && (flags & O_ACCMODE) != O_RDONLY &&
        (flags & O_APPEND) != 0 && fstat(evidence, &info) == 0 &&
        S_ISREG(info.st_mode) && info.st_uid == 0 && info.st_nlink == 1 &&
        (info.st_mode & 07777) == 0600 &&
        (!require_empty || info.st_size == 0) &&
        (require_empty || (info.st_dev == evidence_device && info.st_ino == evidence_inode));
}

__attribute__((constructor)) static void bind_owned_master(void)
{
    int saved_errno = errno;
    const char *id = getenv("MSCONNECTOR_I12_INVALID_TXID");
    const char *descriptor = getenv("MSCONNECTOR_I12_INVALID_FD");
    if (getuid() == 0 && geteuid() == 0 && id != NULL && strlen(id) == 32U &&
        strspn(id, "0123456789abcdef") == 32U && descriptor != NULL &&
        strlen(descriptor) > 0U && strlen(descriptor) <= 10U &&
        strspn(descriptor, "0123456789") == strlen(descriptor)) {
        char *end;
        long value;
        errno = 0;
        value = strtol(descriptor, &end, 10);
        if (errno == 0 && *end == '\0' && value >= 3 && value <= INT_MAX) {
            struct stat info;
            evidence = (int)value;
            if (descriptor_matches(1) && fstat(evidence, &info) == 0) {
                evidence_device = info.st_dev;
                evidence_inode = info.st_ino;
                owned_master = getpid();
                memcpy(owned_id, id, sizeof(owned_id));
                armed = 1;
            } else {
                evidence = -1;
            }
        }
    }
    errno = saved_errno;
}

static int owned_worker(void)
{
    return armed && !spent && owned_master > 0 && getuid() == 65534 &&
        geteuid() == 65534 && getppid() == owned_master;
}

void *msc_new_transaction_with_id(void *engine, void *rules, char *id, void *opaque)
{
    new_transaction_fn original;
    void *transaction;
    int saved_errno;
    int entry_errno = errno;
    *(void **)(&original) = dlsym(RTLD_NEXT, "msc_new_transaction_with_id");
    if (original == NULL) _exit(126);
    errno = entry_errno;
    transaction = original(engine, rules, id, opaque);
    saved_errno = errno;
    if (transaction != NULL && owned_worker() && id != NULL &&
        strcmp(id, owned_id) == 0) {
        selected_transaction = transaction;
    }
    errno = saved_errno;
    return transaction;
}

int msc_process_request_body(void *transaction)
{
    process_body_fn original;
    int result;
    int saved_errno;
    int entry_errno = errno;
    *(void **)(&original) = dlsym(RTLD_NEXT, "msc_process_request_body");
    if (original == NULL) _exit(126);
    errno = entry_errno;
    result = original(transaction);
    saved_errno = errno;
    if (transaction != NULL && transaction == selected_transaction &&
        owned_worker() && descriptor_matches(0)) {
        char line[512];
        int length = snprintf(line, sizeof(line),
            "{\"native_operation\":\"msc_process_request_body\",\"phase\":2,"
            "\"original_result\":%d,\"injected_result\":-9,"
            "\"worker_pid\":%ld,\"worker_uid\":%lu,\"master_pid\":%ld,"
            "\"transaction_id\":\"%s\",\"injected\":true}\n",
            result, (long)getpid(), (unsigned long)getuid(),
            (long)getppid(), owned_id);
        spent = 1;
        selected_transaction = NULL;
        if (length > 0 && (size_t)length < sizeof(line) &&
            syscall(SYS_write, evidence, line, (size_t)length) == length) {
            result = -9;
        }
    }
    errno = saved_errno;
    return result;
}

void msc_transaction_cleanup(void *transaction)
{
    cleanup_fn original;
    int entry_errno = errno;
    *(void **)(&original) = dlsym(RTLD_NEXT, "msc_transaction_cleanup");
    if (original == NULL) _exit(126);
    if (transaction == selected_transaction) selected_transaction = NULL;
    errno = entry_errno;
    original(transaction);
}
