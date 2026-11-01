#define _GNU_SOURCE
/* Test-only own-child observer. Never attach to a supplied PID, change a
 * register/syscall/result, read payload buffers, or link into product code. */
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#define MAX_THREADS 128
#define MAX_SOCKETS 128
#define MAX_RECORDS 4096
#define MAX_OUTPUT (2U * 1024U * 1024U)
#define TEST_BYTES (1024U * 1024U)
#define HOST_BINARY "/task/cache/traefik"
#define HOST_CONFIG "/task/runtime/effective-config/traefik-native-static.yaml"
#define AUTH_CASE_SHORT "ac-ef73876b3c669e899482-syscall"
#define AUTH_CASE_BLOCK "ac-9528a3f086fca6429a67-syscall"
#define OBSERVER_MODULE "github.com/Easton97-Jens/ModSecurity-conector/connectors/traefik/response_observer"

struct endpoint { unsigned long long inode; unsigned local; unsigned peer; };
struct pending { int active; int fd; uint64_t started; uint64_t requested; long number; struct endpoint socket; };
struct thread { pid_t id; int newborn; struct pending pending; };
struct flow { unsigned long long inode; int blocked; unsigned short_writes; unsigned would_block; unsigned resumed; };
struct image_identity { dev_t device; ino_t inode; const char *path; };
struct capture {
    FILE *output;
    const char *nonce;
    const char *mode;
    struct image_identity image;
    unsigned local;
    unsigned peer;
    unsigned records;
    size_t bytes;
    int failed;
    int exited;
    int exit_code;
    int signal;
    int test_client;
    int drain;
    int pidfd;
    int test_writev_started;
    pid_t child;
    struct thread threads[MAX_THREADS];
    struct flow flows[MAX_SOCKETS];
};
static volatile sig_atomic_t interrupted;

static uint64_t now_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) { return 0; }
    return (uint64_t)value.tv_sec * 1000000000U + (uint64_t)value.tv_nsec;
}

static void on_signal(int number) { interrupted = number; }

static int auth_case_allowed(const char *value) {
    return value != NULL && (strcmp(value, AUTH_CASE_SHORT) == 0 || strcmp(value, AUTH_CASE_BLOCK) == 0);
}

static int number(const char *text, unsigned minimum, unsigned maximum, unsigned *out) {
    char *end = NULL;
    unsigned long value;
    if (text == NULL || *text == '\0' || strspn(text, "0123456789") != strlen(text)) { return 0; }
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || value < minimum || value > maximum) { return 0; }
    *out = (unsigned)value;
    return 1;
}

static int trusted_component(const struct stat *info, int leaf) {
    int sticky_directory = !leaf && S_ISDIR(info->st_mode) && info->st_uid == 0 && (info->st_mode & S_ISVTX);
    return !S_ISLNK(info->st_mode) && (info->st_uid == 0 || info->st_uid == getuid()) &&
        (!(info->st_mode & 0022) || sticky_directory) && (leaf || S_ISDIR(info->st_mode));
}

/* Walk using held directory descriptors. A rename or symlink replacement in
 * a public sticky ancestor cannot redirect subsequent component resolution. */
static int close_parent(int directory) {
    (void)close(directory);
    return -1;
}

static int private_parent(const char *path, char *leaf, size_t capacity) {
    char copy[PATH_MAX];
    struct stat info;
    char *state = NULL;
    int directory;
    size_t length = strlen(path);
    if (length == 0 || length >= sizeof(copy) || path[0] != '/' || path[length - 1] == '/' || strstr(path, "//") != NULL) { return -1; }
    memcpy(copy, path, length + 1U);
    directory = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) { return -1; }
    for (const char *part = strtok_r(copy, "/", &state); part != NULL; part = strtok_r(NULL, "/", &state)) {
        if (strcmp(part, ".") == 0 || strcmp(part, "..") == 0) { return close_parent(directory); }
        if (*state == '\0') {
            if (strlen(part) >= capacity) { return close_parent(directory); }
            memcpy(leaf, part, strlen(part) + 1U);
            return directory;
        }
        int next = openat(directory, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) { return close_parent(directory); }
        if (fstat(next, &info) != 0 || !trusted_component(&info, 0)) { (void)close(next); return close_parent(directory); }
        (void)close(directory);
        directory = next;
    }
    return close_parent(directory);
}

static int private_path(const char *path, int leaf_required, int require_owned_parent) {
    char leaf[NAME_MAX + 1];
    struct stat info;
    int directory = private_parent(path, leaf, sizeof(leaf));
    int valid = 0;
    if (directory < 0) { return 0; }
    if (!require_owned_parent || (fstat(directory, &info) == 0 && info.st_uid == getuid() && !(info.st_mode & 0077))) {
        if (fstatat(directory, leaf, &info, AT_SYMLINK_NOFOLLOW) == 0) { valid = trusted_component(&info, 1); }
        else { valid = !leaf_required && errno == ENOENT; }
    }
    (void)close(directory);
    return valid;
}

static int create_output(const char *path) {
    char leaf[NAME_MAX + 1];
    struct stat info;
    int directory = private_parent(path, leaf, sizeof(leaf));
    int fd = -1;
    if (directory < 0) { return -1; }
    if (fstat(directory, &info) == 0 && info.st_uid == getuid() && !(info.st_mode & 0077)) {
        fd = openat(directory, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    }
    (void)close(directory);
    return fd;
}

static int admitted_identity(void) {
    FILE *stream;
    char line[256];
    int masks = 0;
    int no_new_privileges = 0;
    if (getuid() == 0 || getuid() != geteuid() || getgid() != getegid()) { return 0; }
    stream = fopen("/proc/self/status", "re");
    if (stream == NULL) { return 0; }
    while (fgets(line, sizeof(line), stream) != NULL) {
        if (strncmp(line, "Cap", 3) == 0 && strchr(line, ':') != NULL) {
            char *end;
            unsigned long long value = strtoull(strchr(line, ':') + 1, &end, 16);
            if (value != 0 || end == strchr(line, ':') + 1) { (void)fclose(stream); return 0; }
            ++masks;
        }
        if (sscanf(line, "NoNewPrivs: %d", &no_new_privileges) == 1) { continue; }
    }
    (void)fclose(stream);
    return masks == 5 && no_new_privileges == 1;
}

static int same_process(pid_t id, pid_t leader) {
    char path[64];
    char line[256];
    FILE *stream;
    int tgid = -1;
    int matched_uid = 0;
    (void)snprintf(path, sizeof(path), "/proc/%ld/status", (long)id);
    stream = fopen(path, "re");
    if (stream == NULL) { return 0; }
    while (fgets(line, sizeof(line), stream) != NULL) {
        unsigned a;
        unsigned b;
        unsigned c;
        unsigned d;
        (void)sscanf(line, "Tgid: %d", &tgid);
        if (sscanf(line, "Uid: %u %u %u %u", &a, &b, &c, &d) == 4) {
            matched_uid = a == getuid() && b == getuid() && c == getuid() && d == getuid();
        }
    }
    (void)fclose(stream);
    return matched_uid && tgid == leader;
}

static unsigned long long socket_inode(pid_t id, int fd) {
    char path[80];
    char link[128];
    char tail;
    ssize_t length;
    unsigned long long inode;
    (void)snprintf(path, sizeof(path), "/proc/%ld/fd/%d", (long)id, fd);
    length = readlink(path, link, sizeof(link) - 1U);
    if (length <= 0 || (size_t)length >= sizeof(link) - 1U) { return 0; }
    link[length] = '\0';
    return sscanf(link, "socket:[%llu]%c", &inode, &tail) == 1 ? inode : 0;
}

static int tcp_endpoint(pid_t id, int fd, struct endpoint *out) {
    char path[80];
    char line[1024];
    FILE *stream;
    unsigned long long inode = socket_inode(id, fd);
    int found = 0;
    if (inode == 0) { return 0; }
    (void)snprintf(path, sizeof(path), "/proc/%ld/net/tcp", (long)id);
    stream = fopen(path, "re");
    if (stream == NULL) { return 0; }
    while (fgets(line, sizeof(line), stream) != NULL) {
        unsigned local_ip;
        unsigned remote_ip;
        unsigned local_port;
        unsigned peer_port;
        unsigned long long row_inode;
        if (sscanf(line, "%*u: %8x:%x %8x:%x %*x %*x:%*x %*x:%*x %*x %*u %*u %llu",
                &local_ip, &local_port, &remote_ip, &peer_port, &row_inode) == 5 &&
                row_inode == inode && local_ip == 0x0100007fU && remote_ip == 0x0100007fU) {
            *out = (struct endpoint){inode, local_port, peer_port}; found = 1; break;
        }
    }
    (void)fclose(stream);
    return found;
}

static const char *operation(long syscall) {
    switch (syscall) {
        case SYS_write: return "write";
        case SYS_writev: return "writev";
        case SYS_sendto: return "sendto";
        case SYS_sendmsg: return "sendmsg";
        case SYS_sendfile: return "sendfile";
        default: return NULL;
    }
}

static uint64_t requested_size(pid_t id, const struct ptrace_syscall_info *info) {
    if (info->entry.nr == SYS_write || info->entry.nr == SYS_sendto) {
        return info->entry.args[2] <= SSIZE_MAX ? info->entry.args[2] : UINT64_MAX;
    }
    if (info->entry.nr == SYS_sendfile) {
        return info->entry.args[3] <= SSIZE_MAX ? info->entry.args[3] : UINT64_MAX;
    }
    if (info->entry.nr == SYS_writev) {
        uint64_t sum = 0;
        uint64_t base = info->entry.args[1];
        uint64_t count = info->entry.args[2];
        const uint64_t user_last = 0x00007fffffffffffULL;
        /* Conservative x86-64 lower canonical user addresses only. Alignment
         * is an observer policy, not a claim about kernel writev validity.
         * Validate the WHOLE iovec metadata span before any remote read.
         * Zero iovcnt requires no pointer and no read. */
        if (count == 0) { return 0; }
        if (count > 64U || base < 4096U || base > user_last || base % 8U != 0 ||
                count * 16U - 1U > user_last - base) { return UINT64_MAX; }
        /* Read only each iov_len metadata word, never its payload pointer/data. */
        for (uint64_t i = 0; i < count; ++i) {
            unsigned long address = (unsigned long)(base + i * 16U + 8U);
            unsigned long length;
            errno = 0;
            length = (unsigned long)ptrace(PTRACE_PEEKDATA, id, (void *)address, NULL);
            if (errno != 0 || length > (uint64_t)SSIZE_MAX - sum) { return UINT64_MAX; }
            sum += length;
        }
        return sum;
    }
    return UINT64_MAX; /* sendmsg length is deliberately unknown, not guessed. */
}

static struct thread *thread_slot(struct capture *capture, pid_t id, int create) {
    struct thread *empty = NULL;
    for (unsigned i = 0; i < MAX_THREADS; ++i) {
        if (capture->threads[i].id == id) { return &capture->threads[i]; }
        if (capture->threads[i].id == 0 && empty == NULL) { empty = &capture->threads[i]; }
    }
    if (!create || empty == NULL) { return NULL; }
    empty->id = id; empty->newborn = 1; return empty;
}

static struct flow *flow_slot(struct capture *capture, unsigned long long inode) {
    struct flow *empty = NULL;
    for (unsigned i = 0; i < MAX_SOCKETS; ++i) {
        if (capture->flows[i].inode == inode) { return &capture->flows[i]; }
        if (capture->flows[i].inode == 0 && empty == NULL) { empty = &capture->flows[i]; }
    }
    if (empty != NULL) { empty->inode = inode; }
    return empty;
}

static void syscall_exit(struct capture *capture, struct thread *thread, long long result) {
    struct pending *pending = &thread->pending;
    struct flow *flow;
    int identity;
    int length;
    char row[1024];
    if (!pending->active) { return; }
    pending->active = 0;
    identity = socket_inode(thread->id, pending->fd) == pending->socket.inode;
    flow = flow_slot(capture, pending->socket.inode);
    if (!identity || flow == NULL || capture->records >= MAX_RECORDS) { capture->failed = 1; return; }
    /* Synthetic reader only: create independent backpressure for writev after
     * the write phase. Host mode never owns a client and never takes this path. */
    if (capture->test_client >= 0 && pending->number == SYS_writev && result > 0 &&
            pending->requested != UINT64_MAX && !capture->test_writev_started) {
        capture->test_writev_started = 1; capture->drain = 0;
    }
    if (result == -EAGAIN) { ++flow->would_block; flow->blocked = 1; capture->drain = 1; }
    if (result > 0 && pending->requested != UINT64_MAX && (uint64_t)result < pending->requested) { ++flow->short_writes; }
    if (result > 0 && flow->blocked) { ++flow->resumed; flow->blocked = 0; }
    length = snprintf(row, sizeof(row),
        "{\"schema\":\"traefik-own-child-syscall-v1\",\"nonce\":\"%s\",\"pid\":%ld,\"tid\":%ld,"
        "\"fd\":%d,\"socket_inode\":%llu,\"local_address\":\"127.0.0.1\",\"local_port\":%u,"
        "\"peer_address\":\"127.0.0.1\",\"peer_port\":%u,\"operation\":\"%s\","
        "\"requested_bytes\":%lld,\"requested_size_known\":%s,\"kernel_result\":%lld,\"errno\":%lld,"
        "\"entry_monotonic_ns\":%llu,\"exit_monotonic_ns\":%llu,\"fd_identity_unchanged\":true}\n",
        capture->nonce, (long)capture->child, (long)thread->id, pending->fd, pending->socket.inode,
        pending->socket.local, pending->socket.peer, operation(pending->number),
        pending->requested == UINT64_MAX ? -1LL : (long long)pending->requested,
        pending->requested == UINT64_MAX ? "false" : "true", result,
        result < 0 ? -result : 0LL, (unsigned long long)pending->started, (unsigned long long)now_ns());
    if (length <= 0 || (size_t)length >= sizeof(row) || capture->bytes + (size_t)length > MAX_OUTPUT ||
            fwrite(row, 1, (size_t)length, capture->output) != (size_t)length || fflush(capture->output) != 0) {
        capture->failed = 1; return;
    }
    capture->bytes += (size_t)length; ++capture->records;
}

static int syscall_stop(struct capture *capture, struct thread *thread) {
    struct ptrace_syscall_info info;
    long length;
    memset(&info, 0, sizeof(info));
    length = ptrace(PTRACE_GET_SYSCALL_INFO, thread->id, sizeof(info), &info);
    if (length < 0 || info.arch != AUDIT_ARCH_X86_64) { return 0; }
    if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
        const char *name = operation((long)info.entry.nr);
        thread->pending.active = 0;
        if (name != NULL && info.entry.args[0] <= INT_MAX) {
            struct endpoint endpoint;
            int fd = (int)info.entry.args[0];
            if (tcp_endpoint(thread->id, fd, &endpoint) && endpoint.local == capture->local &&
                    (capture->peer == 0 || endpoint.peer == capture->peer)) {
                thread->pending = (struct pending){1, fd, now_ns(), requested_size(thread->id, &info),
                    (long)info.entry.nr, endpoint};
            }
        }
    } else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
        syscall_exit(capture, thread, info.exit.rval);
    } else { return 0; }
    return !capture->failed;
}

static void reap_owned(struct capture *capture) {
    uint64_t deadline = now_ns() + 3000000000ULL;
    /* pidfd binds the exact forked process even after numeric PID reuse. */
    if (capture->pidfd >= 0) { (void)syscall(SYS_pidfd_send_signal, capture->pidfd, SIGKILL, NULL, 0); }
    for (unsigned i = 0; i < MAX_THREADS; ++i) {
        if (capture->threads[i].id > 0) { (void)ptrace(PTRACE_CONT, capture->threads[i].id, NULL, (void *)(long)SIGKILL); }
    }
    while (now_ns() < deadline) {
        int status;
        pid_t id = waitpid(-1, &status, __WALL | WNOHANG);
        if (id < 0 && errno == ECHILD) { return; }
        if (id > 0 && WIFSTOPPED(status)) { (void)ptrace(PTRACE_CONT, id, NULL, (void *)(long)SIGKILL); }
        if (id <= 0) { struct timespec pause = {0, 1000000}; (void)nanosleep(&pause, NULL); }
    }
    capture->failed = 1;
}

static int record_exec(struct capture *capture, struct thread *thread, pid_t id) {
    char path[64];
    char row[768];
    struct stat image;
    int length;
    if (id != capture->child || thread->newborn == -1) { return 0; }
    (void)snprintf(path, sizeof(path), "/proc/%ld/exe", (long)id);
    if (stat(path, &image) != 0 || image.st_dev != capture->image.device || image.st_ino != capture->image.inode) { return 0; }
    length = snprintf(row, sizeof(row), "{\"schema\":\"traefik-own-child-exec-v1\",\"nonce\":\"%s\",\"child_pid\":%ld,\"image\":\"%s\",\"mode\":\"%s\",\"opened_image_identity_verified\":true,\"runtime_qualified\":false}\n",
        capture->nonce, (long)id, capture->image.path, capture->mode);
    if (length <= 0 || (size_t)length >= sizeof(row) || capture->bytes + (size_t)length > MAX_OUTPUT ||
            fwrite(row, 1, (size_t)length, capture->output) != (size_t)length || fflush(capture->output) != 0) { return 0; }
    capture->bytes += (size_t)length;
    thread->newborn = -1;
    return 1;
}

static int handle_stop(struct capture *capture, struct thread *thread, pid_t id, int status) {
    unsigned event = (unsigned)status >> 16;
    int delivered = 0;
    if (event == PTRACE_EVENT_CLONE) {
        unsigned long child_id = 0;
        if (ptrace(PTRACE_GETEVENTMSG, id, NULL, &child_id) != 0 || child_id > INT_MAX ||
                !same_process((pid_t)child_id, capture->child) || thread_slot(capture, (pid_t)child_id, 1) == NULL) { return 0; }
    } else if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK) {
        unsigned long rejected = 0;
        if (ptrace(PTRACE_GETEVENTMSG, id, NULL, &rejected) == 0 && rejected <= INT_MAX) { (void)kill((pid_t)rejected, SIGKILL); }
        return 0;
    } else if (event == PTRACE_EVENT_EXEC) {
        if (!record_exec(capture, thread, id)) { return 0; }
    } else if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
        if (!syscall_stop(capture, thread)) { return 0; }
    } else if (thread->newborn == 1 && WSTOPSIG(status) == SIGSTOP) { thread->newborn = 0; }
    else { delivered = WSTOPSIG(status); }
    return ptrace(PTRACE_SYSCALL, id, NULL, (void *)(long)delivered) == 0;
}

static int handle_wait(struct capture *capture, pid_t id, int status) {
    struct thread *thread = thread_slot(capture, id, 0);
    if (thread == NULL && WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP &&
            same_process(id, capture->child)) { thread = thread_slot(capture, id, 1); }
    if (thread == NULL) { return 0; }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        if (id == capture->child) {
            capture->exited = 1;
            capture->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            capture->signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
        }
        memset(thread, 0, sizeof(*thread));
        return 1;
    }
    return WIFSTOPPED(status) && handle_stop(capture, thread, id, status);
}

static int initial_stop(struct capture *capture, uint64_t deadline) {
    unsigned long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK |
        PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;
    int status;
    for (;;) {
        pid_t stopped;
        if (interrupted || now_ns() >= deadline) { return 0; }
        stopped = waitpid(capture->child, &status, WNOHANG);
        if (stopped == capture->child) { break; }
        if (stopped < 0 && errno != EINTR) { return 0; }
        { struct timespec pause = {0, 1000000}; (void)nanosleep(&pause, NULL); }
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP ||
            !same_process(capture->child, capture->child) || getpgid(capture->child) != capture->child ||
            ptrace(PTRACE_SETOPTIONS, capture->child, NULL, (void *)options) != 0) { return 0; }
    thread_slot(capture, capture->child, 1)->newborn = 0;
    if (interrupted || now_ns() >= deadline) { return 0; }
    return ptrace(PTRACE_SYSCALL, capture->child, NULL, NULL) == 0;
}

static void observe(struct capture *capture, unsigned seconds) {
    uint64_t deadline = now_ns() + (uint64_t)seconds * 1000000000ULL;
    if (!initial_stop(capture, deadline)) { capture->failed = 1; return; }
    while (!capture->failed && !capture->exited) {
        pid_t id;
        int status;
        if (interrupted || now_ns() >= deadline) { capture->failed = 1; return; }
        if (capture->drain && capture->test_client >= 0) {
            char buffer[32768];
            while (read(capture->test_client, buffer, sizeof(buffer)) > 0) { /* discard synthetic bytes */ }
        }
        id = waitpid(-1, &status, __WALL | WNOHANG);
        if (id == 0) { struct timespec pause = {0, 1000000}; (void)nanosleep(&pause, NULL); continue; }
        if (id < 0) { if (errno == EINTR) { continue; } capture->failed = 1; return; }
        if (!handle_wait(capture, id, status)) { capture->failed = 1; }
    }
}

static int test_connection(unsigned *local, unsigned *peer, int *client) {
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t length = sizeof(address);
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int accepted;
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            getsockname(listener, (struct sockaddr *)&address, &length) != 0 || listen(listener, 1) != 0) { return -1; }
    *local = ntohs(address.sin_port);
    *client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (*client < 0 || connect(*client, (struct sockaddr *)&address, sizeof(address)) != 0) { (void)close(listener); return -1; }
    accepted = accept4(listener, NULL, NULL, 0);
    (void)close(listener);
    length = sizeof(address);
    if (accepted < 0 || getsockname(*client, (struct sockaddr *)&address, &length) != 0) { return -1; }
    *peer = ntohs(address.sin_port);
    (void)fcntl(*client, F_SETFL, O_NONBLOCK);
    return accepted;
}

static int test_writer(int fd) {
    char data[65536];
    unsigned total = 0;
    int size = 4096;
    uint64_t deadline = now_ns() + 12000000000ULL;
    memset(data, 'T', sizeof(data));
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) != 0 || fcntl(fd, F_SETFL, O_NONBLOCK) != 0) { return 77; }
    {
        struct iovec vectors[65] = {{0}};
        vectors[0].iov_base = data;
        /* Execute the original invalid syscalls unchanged. The observer must
         * neither follow these addresses nor invent requested byte counts. */
        (void)syscall(SYS_writev, fd, NULL, 1);
        (void)syscall(SYS_writev, fd, (void *)(uintptr_t)(UINT64_MAX - 7U), 2);
        (void)syscall(SYS_writev, fd, (void *)(uintptr_t)0x0000800000000000ULL, 1);
        (void)syscall(SYS_writev, fd, (void *)(uintptr_t)0x00007ffffffffff8ULL, 2);
        (void)syscall(SYS_writev, fd, (void *)(uintptr_t)0x10000U, 1);
        (void)syscall(SYS_writev, fd, vectors, UINT64_MAX);
        (void)syscall(SYS_writev, fd, vectors, 65);
        (void)syscall(SYS_writev, fd, (char *)vectors + 1, 1);
        vectors[0].iov_base = NULL;
        vectors[0].iov_len = (size_t)SSIZE_MAX;
        vectors[1].iov_len = 1;
        (void)syscall(SYS_writev, fd, vectors, 2);
        vectors[0].iov_len = (size_t)SSIZE_MAX + 1U;
        (void)syscall(SYS_writev, fd, vectors, 1);
        (void)syscall(SYS_writev, fd, NULL, 0);
    }
    for (unsigned phase = 0; phase < 2; ++phase) {
      total = 0;
      while (total < TEST_BYTES && now_ns() < deadline) {
        size_t wanted = TEST_BYTES - total < sizeof(data) ? TEST_BYTES - total : sizeof(data);
        struct iovec vectors[2] = {{data, wanted / 2}, {data + wanted / 2, wanted - wanted / 2}};
        ssize_t result = phase == 0 ? write(fd, data, wanted) : writev(fd, vectors, 2);
        if (result > 0) { total += (unsigned)result; }
        else if (result < 0 && (errno == EAGAIN || errno == EINTR)) { struct timespec pause = {0, 1000000}; (void)nanosleep(&pause, NULL); }
        else { return 77; }
      }
      if (total != TEST_BYTES) { return 77; }
    }
    (void)close(fd);
    return total == TEST_BYTES ? 0 : 77;
}

static void *test_thread(void *argument) {
    return (void *)(intptr_t)test_writer((int)(intptr_t)argument);
}

static int threaded_test_writer(int fd) {
    pthread_t thread;
    void *result = NULL;
    if (pthread_create(&thread, NULL, test_thread, (void *)(intptr_t)fd) != 0 ||
            pthread_join(thread, &result) != 0) { return 77; }
    return (int)(intptr_t)result;
}

static int executable(const char *path) {
    struct stat info;
    int fd;
    if (!private_path(path, 1, 0)) { return -1; }
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { return -1; }
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != getuid() ||
            info.st_nlink != 1 || !(info.st_mode & S_IXUSR) || (info.st_mode & (S_ISUID | S_ISGID | 0022))) {
        (void)close(fd); return -1;
    }
    return fd;
}

struct arguments {
    const char *output;
    const char *nonce;
    const char *auth_case;
    unsigned seconds;
    int self_test;
};

static int parse_value(struct arguments *args, struct capture *capture, const char *key, const char *value,
        int *seconds_seen, int *peer_seen) {
    if (strcmp(key, "--output") == 0 && args->output == NULL) { args->output = value; return 1; }
    if (strcmp(key, "--auth-case") == 0 && args->auth_case == NULL) { args->auth_case = value; return 1; }
    if (strcmp(key, "--nonce") == 0 && args->nonce == NULL) { args->nonce = value; return 1; }
    if (strcmp(key, "--host-port") == 0 && capture->local == 0) { return number(value, 1, 65535, &capture->local); }
    if (strcmp(key, "--peer-port") == 0 && !*peer_seen) { *peer_seen = 1; return number(value, 0, 65535, &capture->peer); }
    if (strcmp(key, "--seconds") == 0 && !*seconds_seen) { *seconds_seen = 1; return number(value, 1, 300, &args->seconds); }
    return 0;
}

static int parse_arguments(int argc, char **argv, struct arguments *args, struct capture *capture) {
    int seconds_seen = 0;
    int peer_seen = 0;
    unsigned i = 1;
    while (i < (unsigned)argc) {
        const char *key = argv[i];
        ++i;
        if (strcmp(key, "--self-test") == 0 && !args->self_test) { args->self_test = 1; continue; }
        if (i >= (unsigned)argc) { return 0; }
        const char *value = argv[i];
        ++i;
        if (!parse_value(args, capture, key, value, &seconds_seen, &peer_seen)) { return 0; }
    }
    return 1;
}

struct auth_paths {
    char config[320];
    char cwd[256];
    char output[256];
    char log[320];
    char access[320];
    char entry[80];
    char file[384];
};

static int prepare_auth(const struct arguments *args, struct auth_paths *paths, unsigned local) {
    (void)snprintf(paths->entry, sizeof(paths->entry), "--entryPoints.web.address=127.0.0.1:%u", local);
    if (args->auth_case == NULL) { return 1; }
    if (!auth_case_allowed(args->auth_case) || args->nonce == NULL || strcmp(args->nonce, args->auth_case) != 0) { return 0; }
    (void)snprintf(paths->cwd, sizeof(paths->cwd), "/task/cases/%s/runtime", args->auth_case);
    (void)snprintf(paths->config, sizeof(paths->config), "%s/effective-config/traefik-dynamic.yaml", paths->cwd);
    (void)snprintf(paths->output, sizeof(paths->output), "/task/cases/%s/host-syscalls.jsonl", args->auth_case);
    (void)snprintf(paths->log, sizeof(paths->log), "I12_ACCEPTANCE_HOST_LOG=%s/logs/host-lifecycle.jsonl", paths->cwd);
    (void)snprintf(paths->access, sizeof(paths->access), "--accesslog.filepath=%s/logs/traefik-access.log", paths->cwd);
    (void)snprintf(paths->file, sizeof(paths->file), "--providers.file.filename=%s", paths->config);
    return args->self_test || (args->output != NULL && strcmp(args->output, paths->output) == 0);
}

static int open_binary(const struct arguments *args, const char *invocation, char *self,
        const struct auth_paths *paths, struct capture *capture, int *test_fd) {
    if (args->self_test) {
        if (realpath(invocation, self) == NULL || strcmp(invocation, self) != 0) { return -1; }
        int binary = executable(self);
        if (binary < 0) { return -1; }
        *test_fd = test_connection(&capture->local, &capture->peer, &capture->test_client);
        if (*test_fd < 0) { (void)close(binary); return -1; }
        return binary;
    }
    struct stat config;
    const char *config_path = HOST_CONFIG;
    const char *cwd = "/task/runtime";
    if (args->auth_case != NULL) { config_path = paths->config; cwd = paths->cwd; }
    if (chdir(cwd) != 0 || !private_path(config_path, 1, 0) || stat(config_path, &config) != 0 ||
            !S_ISREG(config.st_mode) || config.st_uid != getuid()) { return -1; }
    if (args->auth_case != NULL && !private_path(paths->log + strlen("I12_ACCEPTANCE_HOST_LOG="), 1, 0)) { return -1; }
    return executable(HOST_BINARY);
}

static void execute_child(const struct capture *capture, int binary, int test_fd, int out_fd,
        const struct arguments *args, char *self, struct auth_paths *paths) {
    const int self_test = args->self_test;
    const char *auth_case = args->auth_case;
    char *auth_log = paths->log;
    char *auth_entry = paths->entry;
    char *auth_file = paths->file;
    char *auth_access = paths->access;
    char fd[16];
    char *const test_env[] = {"PATH=/usr/bin:/bin", "LC_ALL=C", "TZ=UTC", NULL};
    char *const host_env[] = {"PATH=/opt/controller:/usr/local/bin:/usr/bin:/usr/sbin:/bin", "HOME=/task", "TMPDIR=/task/tmp", "TMP_ROOT=/task/tmp", "XDG_CACHE_HOME=/task/cache", "XDG_DATA_HOME=/task/rtk-data", "LC_ALL=C", "TZ=UTC", "PYTHONDONTWRITEBYTECODE=1", "CONNECTOR_ROOT=/mnt/src", "BUILD_ROOT=/task/build", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOMODCACHE=/task/go-mod", "GOCACHE=/task/go-cache", "GO=/usr/local/go/bin/go", "GOFLAGS=-mod=readonly", "TRAEFIK_NATIVE_RUNTIME_ROOT=/task/runtime", "TRAEFIK_ENGINE_SOCKET_PARENT=/task/sockets", "TRAEFIK_BIN=" HOST_BINARY, "MSCONNECTOR_RULES_FILE=/task/rules.conf", NULL};
    char *const auth_env[] = {"PATH=/opt/controller:/usr/local/bin:/usr/bin:/usr/sbin:/bin", "HOME=/task", "TMPDIR=/task/tmp", "TMP_ROOT=/task/tmp", "XDG_CACHE_HOME=/task/cache", "XDG_DATA_HOME=/task/rtk-data", "LC_ALL=C", "TZ=UTC", "PYTHONDONTWRITEBYTECODE=1", "CONNECTOR_ROOT=/mnt/src", auth_log, NULL};
    (void)snprintf(fd, sizeof(fd), "%d", test_fd);
    char *const test_argv[] = {self, "--self-test-child", fd, NULL};
    char *const host_argv[] = {HOST_BINARY, "--configFile=" HOST_CONFIG, NULL};
    char *const auth_argv[] = {HOST_BINARY, auth_entry,
        "--experimental.localPlugins.modsecurityResponseObserver.moduleName=" OBSERVER_MODULE,
        "--experimental.localPlugins.modsecurityResponseObserver.settings.useUnsafe=true",
        "--experimental.abortOnPluginFailure=true", auth_file, "--providers.file.watch=false", "--api=false", "--log.level=INFO",
        "--global.sendAnonymousUsage=false", "--global.checkNewVersion=false", "--accesslog=true", auth_access, NULL};
    (void)close(out_fd);
    if (capture->test_client >= 0) { (void)close(capture->test_client); }
    if (setpgid(0, 0) != 0 || ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) { _exit(77); }
    (void)raise(SIGSTOP);
    char *const *selected_argv = host_argv;
    char *const *selected_env = host_env;
    if (auth_case != NULL) { selected_argv = auth_argv; selected_env = auth_env; }
    if (self_test) { selected_argv = test_argv; selected_env = test_env; }
    fexecve(binary, selected_argv, selected_env);
    _exit(77);
}

static int valid_arguments(const struct arguments *args, const struct capture *capture) {
    if (args->output == NULL || args->nonce == NULL) { return 0; }
    size_t length = strlen(args->nonce);
    if (length < 8 || length > 64 || strspn(args->nonce, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != length ||
            !private_path(args->output, 0, 1)) { return 0; }
    return args->self_test || (strncmp(args->output, "/task/", 6) == 0 && capture->local != 0);
}

static int final_receipt(struct capture *capture, int self_test) {
    unsigned shorts = 0;
    unsigned blocked = 0;
    unsigned resumed = 0;
    int complete;
    for (unsigned i = 0; i < MAX_SOCKETS; ++i) { shorts += capture->flows[i].short_writes; blocked += capture->flows[i].would_block; resumed += capture->flows[i].resumed; }
    complete = !capture->failed && capture->exited && capture->exit_code == 0 && capture->signal == 0 && capture->records > 0;
    if (self_test && (!shorts || !blocked || !resumed)) { complete = 0; }
    if (fprintf(capture->output, "{\"schema\":\"traefik-own-child-final-v1\",\"nonce\":\"%s\",\"child_pid\":%ld,\"uid\":%ld,\"capture_complete\":%s,\"kernel_records\":%u,\"short_writes\":%u,\"would_block\":%u,\"resumed_same_inode\":%u,\"child_exit\":%d,\"child_signal\":%d,\"known_target_peer_port\":%u,\"client_receipt_join_required\":true,\"runtime_qualified\":false}\n",
            capture->nonce, (long)capture->child, (long)getuid(), complete ? "true" : "false", capture->records,
            shorts, blocked, resumed, capture->exit_code, capture->signal, capture->peer) < 0 || fclose(capture->output) != 0) { return 77; }
    return complete ? 0 : 77;
}

static int run_capture(struct capture *capture, int binary, int test_fd, int out_fd,
        const struct arguments *args, char *self, struct auth_paths *paths) {
    (void)signal(SIGTERM, on_signal);
    (void)signal(SIGINT, on_signal);
    capture->child = fork();
    if (capture->child == 0) { execute_child(capture, binary, test_fd, out_fd, args, self, paths); }
    (void)close(binary);
    if (test_fd >= 0) { (void)close(test_fd); }
    if (capture->child <= 0) { (void)fclose(capture->output); return 77; }
    capture->pidfd = (int)syscall(SYS_pidfd_open, capture->child, 0);
    if (capture->pidfd < 0) {
        /* Child is still our unreaped initial stop; numeric identity cannot
         * have been recycled. Fail without ever running candidate code. */
        (void)kill(capture->child, SIGKILL);
        (void)waitpid(capture->child, NULL, 0);
        (void)fclose(capture->output);
        return 77;
    }
    observe(capture, args->seconds);
    reap_owned(capture);
    (void)close(capture->pidfd);
    if (capture->test_client >= 0) { (void)close(capture->test_client); }
    return final_receipt(capture, args->self_test);
}

int main(int argc, char **argv) {
    struct capture capture = { .test_client = -1, .pidfd = -1 };
    struct arguments args = { .seconds = 30 };
    struct auth_paths paths = {0};
    char self[PATH_MAX];
    int test_fd = -1;
    struct stat opened_image;
    if (!admitted_identity()) { return 77; }
    if (argc == 3 && strcmp(argv[1], "--self-test-child") == 0) {
        unsigned fd;
        return number(argv[2], 3, 4095, &fd) ? threaded_test_writer((int)fd) : 77;
    }
    if (!parse_arguments(argc, argv, &args, &capture) || !valid_arguments(&args, &capture) ||
            !prepare_auth(&args, &paths, capture.local)) { return 77; }
    int binary = open_binary(&args, argv[0], self, &paths, &capture, &test_fd);
    if (binary < 0) { return 77; }
    if (fstat(binary, &opened_image) != 0) { (void)close(binary); return 77; }
    capture.image.device = opened_image.st_dev;
    capture.image.inode = opened_image.st_ino;
    capture.image.path = HOST_BINARY;
    capture.mode = "native";
    if (args.auth_case != NULL) { capture.mode = "auth"; }
    if (args.self_test) {
        capture.image.path = self;
        capture.mode = args.auth_case == NULL ? "synthetic-native" : "synthetic-auth";
    }
    int out_fd = create_output(args.output);
    if (out_fd < 0) { (void)close(binary); return 77; }
    capture.output = fdopen(out_fd, "w");
    capture.nonce = args.nonce;
    if (capture.output == NULL) { (void)close(out_fd); (void)close(binary); return 77; }
    return run_capture(&capture, binary, test_fd, out_fd, &args, self, &paths);
}
