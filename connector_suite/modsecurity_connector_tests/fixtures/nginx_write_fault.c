/* Private attempt-only native send boundary fixture. No product installation. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static pid_t master;
static int evidence_fd = -1;
static int target_fd = -1;
static int target_port;
static int kind;
static int injected;
static int records;
static char prefix[192];

__attribute__((constructor)) static void bind_attempt(void)
{
    const char *mode = getenv("MSCONNECTOR_OWNED_WRITE_FAULT");
    const char *path = getenv("MSCONNECTOR_OWNED_WRITE_URI");
    const char *port = getenv("MSCONNECTOR_OWNED_WRITE_PORT");
    const char *descriptor = getenv("MSCONNECTOR_OWNED_WRITE_FD");
    struct stat info;
    if (getuid() != 0 || mode == NULL || path == NULL || port == NULL || descriptor == NULL ||
        strlen(path) > 128U || strncmp(path, "/no-crs/sequence/", 17U) != 0 ||
        strspn(path, "/abcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ") != strlen(path) ||
        strlen(port) > 5U || strspn(port, "0123456789") != strlen(port) ||
        strlen(descriptor) > 5U || strspn(descriptor, "0123456789") != strlen(descriptor)) {
        return;
    }
    if (strcmp(mode, "short_write") == 0) {
        kind = 1;
    } else {
        kind = strcmp(mode, "write_would_block") == 0 ? 2 : 0;
    }
    target_port = atoi(port);
    evidence_fd = atoi(descriptor);
    if (kind == 0 || target_port < 1024 || target_port > 65535 || evidence_fd < 3 ||
        fstat(evidence_fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != 0 ||
        info.st_nlink != 1 || (info.st_mode & 0777) != 0600 || info.st_size != 0) {
        evidence_fd = -1;
        return;
    }
    master = getpid();
    (void)snprintf(prefix, sizeof(prefix), "GET %s HTTP/1.1\r\n", path);
}

static int owned_socket(int fd, int *peer_port)
{
    struct sockaddr_in local = {0};
    struct sockaddr_in peer = {0};
    socklen_t size = sizeof(local);
    if (master <= 0 || getuid() != 65534 || getppid() != master ||
        getsockname(fd, (struct sockaddr *)&local, &size) != 0 ||
        size != sizeof(local) || local.sin_family != AF_INET ||
        local.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || ntohs(local.sin_port) != target_port) {
        return 0;
    }
    size = sizeof(peer);
    if (getpeername(fd, (struct sockaddr *)&peer, &size) != 0 ||
        size != sizeof(peer) || peer.sin_family != AF_INET ||
        peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        return 0;
    }
    *peer_port = ntohs(peer.sin_port);
    return 1;
}

ssize_t recv(int fd, void *buffer, size_t size, int flags)
{
    typedef ssize_t (*recv_fn)(int, void *, size_t, int);
    recv_fn original;
    ssize_t received;
    int peer_port;
    *(void **)(&original) = dlsym(RTLD_NEXT, "recv");
    if (original == NULL) {
        _exit(126);
    }
    received = original(fd, buffer, size, flags);
    if (!injected && evidence_fd >= 0 && received > 0 && owned_socket(fd, &peer_port) &&
        (size_t)received >= strlen(prefix) && memcmp(buffer, prefix, strlen(prefix)) == 0) {
        target_fd = fd;
        if (kind == 2) {
            int bytes = 4096;
            (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
        }
    }
    return received;
}

static void observe(int fd, size_t requested, ssize_t returned, int error, int fault)
{
    char line[320];
    int peer_port;
    int length;
    if (evidence_fd < 0 || records >= 16 || !owned_socket(fd, &peer_port)) {
        return;
    }
    length = snprintf(line, sizeof(line),
        "{\"pid\":%ld,\"fd\":%d,\"peer_port\":%d,\"requested_bytes\":%zu,"
        "\"returned_bytes\":%zd,\"errno\":%d,\"fault_triggered\":%s}\n",
        (long)getpid(), fd, peer_port, requested, returned, error, fault ? "true" : "false");
    if (length > 0 && (size_t)length < sizeof(line)) {
        (void)syscall(SYS_write, evidence_fd, line, (size_t)length);
        records++;
    }
}

ssize_t writev(int fd, const struct iovec *vectors, int count)
{
    typedef ssize_t (*writev_fn)(int, const struct iovec *, int);
    writev_fn original;
    ssize_t returned;
    size_t requested = 0U;
    int peer_port;
    int fault = 0;
    int saved;
    *(void **)(&original) = dlsym(RTLD_NEXT, "writev");
    if (original == NULL) {
        _exit(126);
    }
    if (count <= 0 || count > 1024 || vectors == NULL || fd != target_fd ||
        !owned_socket(fd, &peer_port)) {
        return original(fd, vectors, count);
    }
    for (int index = 0; index < count; index++) {
        requested += vectors[index].iov_len;
    }
    if (!injected && requested > 1U) {
        injected = 1;
        fault = 1;
        if (kind == 2) {
            returned = original(fd, vectors, count);
            if (returned >= 0 || errno != EAGAIN) {
                injected = 0;
                fault = 0;
            }
        } else {
            struct iovec short_vector = vectors[0];
            short_vector.iov_len = short_vector.iov_len > 1U ? 1U : short_vector.iov_len;
            returned = original(fd, &short_vector, 1);
        }
    } else {
        returned = original(fd, vectors, count);
    }
    saved = returned < 0 ? errno : 0;
    observe(fd, requested, returned, saved, fault);
    errno = saved;
    return returned;
}
