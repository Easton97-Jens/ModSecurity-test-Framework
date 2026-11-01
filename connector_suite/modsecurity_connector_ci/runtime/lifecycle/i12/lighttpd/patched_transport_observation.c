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
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>



#include "transport_observation_file.h"


extern ssize_t __real_writev(int, const struct iovec *, int);
extern ssize_t __real_write(int, const void *, size_t);
extern ssize_t __real_sendfile64(int, int, off64_t *, size_t);
static unsigned char configured[65536];
static unsigned char shrunk[65536];

static int selected_socket(int fd, struct sockaddr_in *local, struct sockaddr_in *peer) {
    memset(local, 0, sizeof(*local));
    memset(peer, 0, sizeof(*peer));
    const char *selected = getenv("MSCONNECTOR_LIGHTTPD_NETWORK_HOST_PORT");
    if (selected == NULL) return 0;
    char *end;
    unsigned long port = strtoul(selected, &end, 10);
    if (*end != '\0' || port == 0 || port > 65535) return 0;
    socklen_t size = sizeof(*local);
    if (getsockname(fd, (struct sockaddr *)local, &size) != 0 || size != sizeof(*local) ||
        local->sin_family != AF_INET || ntohl(local->sin_addr.s_addr) != INADDR_LOOPBACK ||
        ntohs(local->sin_port) != port) return 0;
    size = sizeof(*peer);
    return getpeername(fd, (struct sockaddr *)peer, &size) == 0 && size == sizeof(*peer) &&
        peer->sin_family == AF_INET && ntohl(peer->sin_addr.s_addr) == INADDR_LOOPBACK;
}

static void record_writev(int fd, size_t requested, ssize_t result, int saved_errno,
        const struct sockaddr_in *local, const struct sockaddr_in *peer, const char *operation) {
    int socket_buffer = -1;
    socklen_t socket_buffer_size = sizeof(socket_buffer);
    int buffer_result = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &socket_buffer, &socket_buffer_size);
    int pending_bytes = -1;
    int queue_result = ioctl(fd, TIOCOUTQ, &pending_bytes);
    const char *path = getenv("MSCONNECTOR_LIGHTTPD_HOST_OBSERVER");
    int output = observation_file(path);
    if (output < 0) return;
    struct timespec now;
    char row[1024];
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        int size = snprintf(row, sizeof(row),
            "{\"schema\":\"lighttpd-physical-host-network-writev-v1\",\"kind\":\"actual_client_socket_write\","
            "\"pid\":%ld,\"uid\":%ld,\"monotonic_ns\":%" PRIu64 ",\"actual_fd\":%d,\"actual_syscall\":\"%s\",\"actual_sendbuffer_bytes\":%d,\"sendbuffer_query_return\":%d,\"actual_sendqueue_bytes_after_call\":%d,\"sendqueue_query_return\":%d,"
            "\"actual_local_port\":%u,\"actual_peer_port\":%u,\"requested_bytes\":%zu,"
            "\"actual_return\":%zd,\"actual_errno\":%d,\"return_substituted\":false}\n",
            (long)getpid(), (long)geteuid(), (uint64_t)now.tv_sec*UINT64_C(1000000000)+(uint64_t)now.tv_nsec,
            fd, operation, socket_buffer, buffer_result, pending_bytes, queue_result, ntohs(local->sin_port), ntohs(peer->sin_port), requested, result, saved_errno);
        if (size > 0 && (size_t)size < sizeof(row)) (void)write(output,row,(size_t)size);
    }
    (void)close(output);
}

ssize_t __wrap_writev(int fd, const struct iovec *vectors, int count) {
    int incoming_errno = errno;
    struct sockaddr_in local;
    struct sockaddr_in peer;
    int selected = selected_socket(fd, &local, &peer);
    if (selected && fd >= 0 && fd < 65536 && !configured[fd]) {
        /* Explicit transport fixture: real socket option, never fake syscall result. */
        int bytes = 16384;
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
        configured[fd] = 1;
    }
    size_t requested = 0;
    if (selected && vectors != NULL && count > 0) {
        for (int index=0; index<count; ++index) requested += vectors[index].iov_len;
    }
    errno = incoming_errno;
    ssize_t result = __real_writev(fd, vectors, count);
    int saved_errno = errno;
    if (selected) record_writev(fd, requested, result, saved_errno, &local, &peer, "writev");
    errno = saved_errno;
    return result;
}

ssize_t __wrap_write(int fd, const void *buffer, size_t count) {
    int incoming_errno = errno;
    struct sockaddr_in local;
    struct sockaddr_in peer;
    int selected = selected_socket(fd, &local, &peer);
    errno = incoming_errno;
    ssize_t result = __real_write(fd, buffer, count);
    int saved_errno = errno;
    if (selected) record_writev(fd, count, result, saved_errno, &local, &peer, "write");
    errno = saved_errno;
    return result;
}

ssize_t __wrap_sendfile64(int output, int input, off64_t *offset, size_t count) {
    int incoming_errno = errno;
    struct sockaddr_in local;
    struct sockaddr_in peer;
    int selected = selected_socket(output, &local, &peer);
    int restore_buffer = 0;
    const char *shrink = getenv("MSCONNECTOR_LIGHTTPD_NETWORK_SHRINK_ON_PENDING");
    if (selected && output >= 0 && output < 65536 && !shrunk[output] && shrink != NULL && strcmp(shrink, "1") == 0) {
        int pending = 0;
        if (ioctl(output, TIOCOUTQ, &pending) == 0 && pending > 8192) {
            int bytes = 256;
            restore_buffer = setsockopt(output, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes)) == 0;
            shrunk[output] = 1;
        }
    }
    errno = incoming_errno;
    ssize_t result = __real_sendfile64(output, input, offset, count);
    int saved_errno = errno;
    if (selected) record_writev(output, count, result, saved_errno, &local, &peer, "sendfile64");
    if (restore_buffer) {
        int bytes = 16384;
        (void)setsockopt(output, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
    }
    errno = saved_errno;
    return result;
}
