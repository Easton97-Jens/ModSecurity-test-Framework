/* Private capture only: real client socket results, no result substitution. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "transport_observation_file.h"

extern ssize_t __real_send(int, const void *, size_t, int);
extern ssize_t __real_recv(int, void *, size_t, int);

static unsigned int client_port(int socket_fd) {
    struct sockaddr_in local = {0};
    socklen_t size = sizeof(local);
    if (getsockname(socket_fd, (struct sockaddr *)&local, &size) != 0 ||
        size != sizeof(local) || local.sin_family != AF_INET ||
        ntohl(local.sin_addr.s_addr) != INADDR_LOOPBACK || ntohs(local.sin_port) != 18154U) return UINT_MAX;
    struct sockaddr_in peer = {0};
    size = sizeof(peer);
    if (getpeername(socket_fd, (struct sockaddr *)&peer, &size) != 0 ||
        size != sizeof(peer) || peer.sin_family != AF_INET ||
        ntohl(peer.sin_addr.s_addr) != INADDR_LOOPBACK) return 0U;
    return ntohs(peer.sin_port);
}

static void observe(const char *operation, int socket_fd, unsigned int peer_port,
                    size_t requested, ssize_t result, int actual_errno) {
    if (peer_port == UINT_MAX || result > 0) return;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return;
    int fd = observation_file(getenv("MSCONNECTOR_LIGHTTPD_TRANSPORT_OBSERVER"));
    if (fd < 0) return;
    char record[512];
    char peer_value[16];
    if (peer_port == 0U) (void)snprintf(peer_value, sizeof(peer_value), "null");
    else (void)snprintf(peer_value, sizeof(peer_value), "%u", peer_port);
    int size = snprintf(record, sizeof(record),
        "{\"schema\":\"lighttpd-stock-actual-socket-v1\",\"pid\":%ld,\"uid\":%ld,"
        "\"function\":\"%s\",\"fd\":%d,\"local_port\":18154,\"peer_port\":%s,"
        "\"requested_bytes\":%zu,\"actual_return\":%zd,\"actual_errno\":%d,"
        "\"result_substituted\":false,\"monotonic_ns\":%" PRIu64 "}\n",
        (long)getpid(), (long)geteuid(), operation, socket_fd, peer_value, requested, result,
        result < 0 ? actual_errno : 0,
        (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec);
    if (size > 0 && (size_t)size < sizeof(record)) (void)write(fd, record, (size_t)size);
    (void)close(fd);
}

ssize_t __wrap_send(int fd, const void *data, size_t size, int flags) {
    int entry_errno = errno;
    unsigned int port = client_port(fd);
    errno = entry_errno;
    ssize_t result = __real_send(fd, data, size, flags);
    int actual_errno = errno;
    observe("send", fd, port, size, result, actual_errno);
    errno = actual_errno;
    return result;
}

ssize_t __wrap_recv(int fd, void *data, size_t size, int flags) {
    int entry_errno = errno;
    unsigned int port = client_port(fd);
    errno = entry_errno;
    ssize_t result = __real_recv(fd, data, size, flags);
    int actual_errno = errno;
    observe("recv", fd, port, size, result, actual_errno);
    errno = actual_errno;
    return result;
}
