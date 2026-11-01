/* Attempt-local native boundary fixture, never installed in a product build.
 * Fail exactly one native transaction allocation in the worker selected by
 * the fixture invocation. No global memory exhaustion, fabricated event, or
 * foreign process mutation is involved.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef void *(*new_transaction_fn)(void *, void *, char *, void *);
static pid_t owned_master;
static char owned_transaction[33];
static int armed;
static int evidence = -1;

__attribute__((constructor)) static void bind_owned_master(void)
{
    if (getuid() == 0 && geteuid() == 0) {
        const char *mode = getenv("MSCONNECTOR_OWNED_BEGIN_FAULT");
        const char *id = getenv("MSCONNECTOR_OWNED_BEGIN_TXID");
        const char *descriptor = getenv("MSCONNECTOR_OWNED_BEGIN_FD");
        struct stat info;
        int flags;
        if (mode != NULL && strcmp(mode, "one-native-allocation-failure") == 0 &&
            id != NULL && strlen(id) == 32U && strspn(id, "0123456789abcdef") == 32U &&
            descriptor != NULL && strlen(descriptor) > 0U && strlen(descriptor) <= 5U &&
            strspn(descriptor, "0123456789") == strlen(descriptor)) {
            evidence = atoi(descriptor);
            flags = fcntl(evidence, F_GETFL);
            if (evidence < 3 || flags < 0 || (flags & O_ACCMODE) == O_RDONLY ||
                fstat(evidence, &info) != 0 || !S_ISREG(info.st_mode) ||
                info.st_uid != 0 || info.st_nlink != 1 ||
                (info.st_mode & 0777) != 0600 || info.st_size != 0) {
                evidence = -1;
                return;
            }
            owned_master = getpid();
            memcpy(owned_transaction, id, sizeof(owned_transaction));
            armed = 1;
        }
    }
}

static int observe_null(void)
{
    char line[320];
    int length = snprintf(line, sizeof(line),
        "{\"native_operation\":\"msc_new_transaction_with_id\",\"observed_return\":null,"
        "\"worker_pid\":%ld,\"worker_uid\":%lu,\"master_pid\":%ld,"
        "\"transaction_id\":\"%s\",\"injected\":true}\n",
        (long)getpid(), (unsigned long)getuid(), (long)getppid(), owned_transaction);
    return length > 0 && (size_t)length < sizeof(line) &&
        syscall(SYS_write, evidence, line, (size_t)length) == length;
}

void *msc_new_transaction_with_id(void *engine, void *rules, char *id,
                                  void *opaque)
{
    static int failed;
    new_transaction_fn original;

    if (!failed && getuid() == 65534 && geteuid() == 65534 && owned_master > 0 &&
        getppid() == owned_master && id != NULL && armed &&
        strcmp(id, owned_transaction) == 0 && observe_null()) {
        failed = 1;
        return NULL;
    }
    /* POSIX specifies this dlsym function-pointer conversion. */
    *(void **)(&original) = dlsym(RTLD_NEXT, "msc_new_transaction_with_id");
    if (original == NULL) {
        _exit(126);
    }
    return original(engine, rules, id, opaque);
}
