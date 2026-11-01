/* Own-worker post-return delay; never interrupts or replaces engine processing. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "msconnector/transaction_contract.h"

static pid_t master;
static char wanted[33];
static void *target;
static int evidence = -1;
static int wanted_phase;
static int delayed;

__attribute__((constructor)) static void bind_attempt(void)
{
    const char *id = getenv("MSCONNECTOR_OWNED_BUDGET_TXID");
    const char *descriptor = getenv("MSCONNECTOR_OWNED_BUDGET_FD");
    const char *phase = getenv("MSCONNECTOR_OWNED_BUDGET_PHASE");
    struct stat info;
    if (getuid() != 0 || id == NULL || strlen(id) != 32U ||
        strspn(id, "0123456789abcdef") != 32U || descriptor == NULL ||
        strlen(descriptor) == 0U || strlen(descriptor) > 5U ||
        strspn(descriptor, "0123456789") != strlen(descriptor) || phase == NULL ||
        (strcmp(phase, "1") != 0 && strcmp(phase, "4") != 0)) {
        return;
    }
    evidence = atoi(descriptor);
    if (evidence < 3 || fstat(evidence, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != 0 || info.st_nlink != 1 || (info.st_mode & 0777) != 0600 || info.st_size != 0) {
        evidence = -1;
        return;
    }
    master = getpid();
    wanted_phase = phase[0] - '0';
    memcpy(wanted, id, sizeof(wanted));
}

static int owned(void *transaction, int phase)
{
    return evidence >= 0 && getuid() == 65534 && getppid() == master &&
        target != NULL && transaction == target && phase == wanted_phase && !delayed;
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
    if (evidence >= 0 && getuid() == 65534 && getppid() == master &&
        id != NULL && strcmp(id, wanted) == 0) {
        target = created;
    }
    return created;
}

static uint64_t nanoseconds(const struct timespec *value)
{
    return (uint64_t)value->tv_sec * UINT64_C(1000000000) + (uint64_t)value->tv_nsec;
}

static int process(void *transaction, int phase, const char *symbol)
{
    typedef int (*original_fn)(void *);
    original_fn original;
    struct timespec start;
    struct timespec end;
    struct timespec wait = { 0, 25000000 };
    char line[512];
    int result;
    int length;
    int retries;
    int active = owned(transaction, phase);
    *(void **)(&original) = dlsym(RTLD_NEXT, symbol);
    if (original == NULL) {
        _exit(126);
    }
    if (active && clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        _exit(126);
    }
    result = original(transaction);
    if (!active) {
        return result;
    }
    delayed = 1;
    for (retries = 0; retries < 5; ++retries) {
        if (nanosleep(&wait, &wait) == 0) {
            break;
        }
        if (errno != EINTR) {
            _exit(126);
        }
    }
    if (retries == 5 || clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
        _exit(126);
    }
    length = snprintf(line, sizeof(line),
        "{\"native_operation\":\"%s\",\"native_phase\":%d,\"observed_return\":%d,"
        "\"worker_pid\":%ld,\"transaction_id\":\"%s\",\"start_ns\":%llu,"
        "\"end_ns\":%llu,\"elapsed_ns\":%llu,\"requested_delay_ns\":25000000}\n",
        symbol, phase, result, (long)getpid(), wanted,
        (unsigned long long)nanoseconds(&start), (unsigned long long)nanoseconds(&end),
        (unsigned long long)(nanoseconds(&end) - nanoseconds(&start)));
    if (length <= 0 || (size_t)length >= sizeof(line) ||
        syscall(SYS_write, evidence, line, (size_t)length) != length) {
        _exit(126);
    }
    return result;
}

int msc_process_request_headers(void *transaction)
{
    return process(transaction, 1, "msc_process_request_headers");
}

int msc_process_response_body(void *transaction)
{
    return process(transaction, 4, "msc_process_response_body");
}

int msconnector_transaction_contract_cleanup(msconnector_transaction_contract *contract, uint64_t now_ms)
{
    typedef int (*original_fn)(msconnector_transaction_contract *, uint64_t);
    typedef const char *(*name_fn)(msconnector_transaction_error_class);
    original_fn original;
    name_fn error_name;
    int result;
    int length;
    char line[512];
    *(void **)(&original) = dlsym(RTLD_NEXT, "msconnector_transaction_contract_cleanup");
    if (original == NULL) {
        _exit(126);
    }
    result = original(contract, now_ms);
    if (evidence < 0 || getuid() != 65534 || getppid() != master || !delayed ||
        contract == NULL || strcmp(contract->transaction_id, wanted) != 0) {
        return result;
    }
    *(void **)(&error_name) = dlsym(RTLD_NEXT, "msconnector_transaction_error_class_name");
    if (error_name == NULL) {
        _exit(126);
    }
    length = snprintf(line, sizeof(line),
        "{\"native_operation\":\"msconnector_transaction_contract_cleanup\",\"observed_return\":%d,"
        "\"worker_pid\":%ld,\"transaction_id\":\"%s\",\"cleanup_complete\":%d,"
        "\"error_class_code\":%d,\"error_class_name\":\"%s\",\"timeout_error_preserved\":%d,"
        "\"timed_phase_completed\":%d}\n",
        result, (long)getpid(), wanted, contract->cleanup_complete,
        (int)contract->error_class, error_name(contract->error_class),
        contract->error_class == MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT,
        (contract->completed_phase_mask & (wanted_phase == 1
            ? MSCONNECTOR_TRANSACTION_PHASE_MASK_P1 : MSCONNECTOR_TRANSACTION_PHASE_MASK_P4)) != 0U);
    if (length <= 0 || (size_t)length >= sizeof(line) ||
        syscall(SYS_write, evidence, line, (size_t)length) != length) {
        _exit(126);
    }
    return result;
}
