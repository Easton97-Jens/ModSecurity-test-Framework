/* Attempt-only post-response native logging failure, with delegated cleanup. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "msconnector/transaction_contract.h"

static pid_t master;
static char wanted[33];
static void *target;
static int evidence = -1;
static int failed;

__attribute__((constructor)) static void bind_attempt(void)
{
    const char *id = getenv("MSCONNECTOR_OWNED_FINISH_TXID");
    const char *descriptor = getenv("MSCONNECTOR_OWNED_FINISH_FD");
    struct stat info;
    if (getuid() != 0 || id == NULL || strlen(id) != 32U ||
        strspn(id, "0123456789abcdef") != 32U || descriptor == NULL ||
        strlen(descriptor) > 5U || strspn(descriptor, "0123456789") != strlen(descriptor)) {
        return;
    }
    evidence = atoi(descriptor);
    if (evidence < 3 || fstat(evidence, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != 0 || info.st_nlink != 1 || (info.st_mode & 0777) != 0600 || info.st_size != 0) {
        evidence = -1;
        return;
    }
    master = getpid();
    memcpy(wanted, id, sizeof(wanted));
}

static int owned(void)
{
    return evidence >= 0 && getuid() == 65534 && getppid() == master;
}

static void observe(const char *operation, int result)
{
    char line[256];
    int length = snprintf(line, sizeof(line),
        "{\"native_operation\":\"%s\",\"observed_return\":%d,\"worker_pid\":%ld,\"transaction_id\":\"%s\"}\n",
        operation, result, (long)getpid(), wanted);
    if (length > 0 && (size_t)length < sizeof(line)) {
        (void)syscall(SYS_write, evidence, line, (size_t)length);
    }
}

void *msc_new_transaction_with_id(void *engine, void *rules, char *id, void *opaque)
{
    typedef void *(*original_fn)(void *, void *, char *, void *);
    original_fn original;
    void *created;
    *(void **)(&original) = dlsym(RTLD_NEXT, "msc_new_transaction_with_id");
    if (original == NULL) {
        _exit(126);
    }
    created = original(engine, rules, id, opaque);
    if (owned() && id != NULL && strcmp(id, wanted) == 0) {
        target = created;
    }
    return created;
}

int msc_process_logging(void *transaction)
{
    typedef int (*original_fn)(void *);
    original_fn original;
    if (owned() && target != NULL && transaction == target && !failed) {
        failed = 1;
        observe("msc_process_logging", -1);
        return -1;
    }
    *(void **)(&original) = dlsym(RTLD_NEXT, "msc_process_logging");
    if (original == NULL) {
        _exit(126);
    }
    return original(transaction);
}

int msconnector_transaction_contract_cleanup(msconnector_transaction_contract *contract, uint64_t now_ms)
{
    typedef int (*original_fn)(msconnector_transaction_contract *, uint64_t);
    original_fn original;
    int result;
    *(void **)(&original) = dlsym(RTLD_NEXT, "msconnector_transaction_contract_cleanup");
    if (original == NULL) {
        _exit(126);
    }
    result = original(contract, now_ms);
    if (owned() && failed && contract != NULL &&
        strcmp(contract->transaction_id, wanted) == 0) {
        observe("msconnector_transaction_contract_cleanup", result);
        observe("cleanup_complete", contract->cleanup_complete);
        observe("native_logging_error_preserved",
            contract->error_class == MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE);
    }
    return result;
}
