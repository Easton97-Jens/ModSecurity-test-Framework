/*
 * Regression smoke for a peer reset while the authorization service is
 * writing its first response.  The child keeps the platform's default
 * SIGPIPE disposition.  This proves reset containment, follow-up service,
 * and cleanup; the source contract separately verifies the local
 * MSG_NOSIGNAL/SO_NOSIGPIPE write policy because a reset can yield either
 * ECONNRESET or EPIPE depending on TCP timing.
 */
#define _POSIX_C_SOURCE 200809L

#include "common/runtime/http_authorization_service.h"

#include "msconnector/decision.h"
#include "msconnector/error.h"
#include "msconnector/request_mapper_contract.h"
#include "fixtures/http_authorization_request_stream_stubs.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct msconnector_runtime { int unused; };
static struct msconnector_runtime fake_runtime;
static int ready_fd = -1;
static int release_fd = -1;
static unsigned int transaction_count;

#define SMOKE_WAIT_TIMEOUT_MS 5000
#define SMOKE_RETRY_COUNT 100
#define SMOKE_RETRY_DELAY_NS 10000000L

static void close_fd(int *fd) {
    if (fd != NULL && *fd >= 0) {
        (void)close(*fd);
        *fd = -1;
    }
}

static int wait_for_events(int fd, short events) {
    struct pollfd descriptor;
    int result;

    if (fd < 0) {
        return 0;
    }
    memset(&descriptor, 0, sizeof(descriptor));
    descriptor.fd = fd;
    descriptor.events = events;
    do {
        result = poll(&descriptor, 1U, SMOKE_WAIT_TIMEOUT_MS);
    } while (result < 0 && errno == EINTR);
    if (result <= 0) {
        return 0;
    }
    if ((events & POLLIN) != 0 &&
        (descriptor.revents & (POLLIN | POLLHUP)) != 0) {
        return 1;
    }
    return (descriptor.revents & events) != 0;
}

static int write_pipe_byte(int fd, char value) {
    ssize_t written;

    do {
        written = write(fd, &value, 1U);
    } while (written < 0 && errno == EINTR);
    return written == 1;
}

static int read_pipe_byte(int fd, char *value) {
    ssize_t received;

    if (value == NULL || !wait_for_events(fd, POLLIN)) {
        return 0;
    }
    do {
        received = read(fd, value, 1U);
    } while (received < 0 && errno == EINTR);
    return received == 1;
}

static int write_all(int fd, const char *data, size_t size) {
    size_t sent = 0U;

    if (fd < 0 || data == NULL) {
        return 0;
    }
    while (sent < size) {
        ssize_t written;

        if (!wait_for_events(fd, POLLOUT)) {
            return 0;
        }
        do {
#ifdef MSG_NOSIGNAL
            written = send(fd, data + sent, size - sent, MSG_NOSIGNAL);
#else
            written = send(fd, data + sent, size - sent, 0);
#endif
        } while (written < 0 && errno == EINTR);
        if (written <= 0) {
            return 0;
        }
        sent += (size_t)written;
    }
    return 1;
}

static int read_complete_response(int fd) {
    char response[512];
    size_t used = 0U;

    for (;;) {
        ssize_t received;

        if (used >= sizeof(response) - 1U || !wait_for_events(fd, POLLIN)) {
            return 0;
        }
        do {
            received = recv(fd, response + used,
                sizeof(response) - 1U - used, 0);
        } while (received < 0 && errno == EINTR);
        if (received < 0) {
            return 0;
        }
        if (received == 0) {
            break;
        }
        used += (size_t)received;
    }
    response[used] = '\0';
    return strstr(response, "HTTP/1.1 200 OK\r\n") != NULL &&
        strstr(response, "content-length: 16\r\n") != NULL &&
        strstr(response, "\r\n\r\nrequest allowed\n") != NULL;
}

static int wait_for_child(pid_t child, int *status) {
    const struct timespec delay = {0, SMOKE_RETRY_DELAY_NS};

    if (child <= 0 || status == NULL) {
        return 0;
    }
    for (int attempt = 0; attempt < SMOKE_RETRY_COUNT; ++attempt) {
        const pid_t waited = waitpid(child, status, WNOHANG);

        if (waited == child) {
            return 1;
        }
        if (waited < 0 && errno != EINTR) {
            return 0;
        }
        (void)nanosleep(&delay, NULL);
    }
    return 0;
}

static void reap_child(pid_t child) {
    int status;

    if (child <= 0) {
        return;
    }
    (void)kill(child, SIGKILL);
    for (;;) {
        const pid_t waited = waitpid(child, &status, 0);

        if (waited >= 0 || errno != EINTR) {
            break;
        }
    }
}

static int map_request(const msconnector_generic_request_source *source,
    const msconnector_request_mapper_contract *contract,
    msconnector_request *request, char *error, size_t error_len) {
    (void)contract;
    if (error != NULL && error_len != 0U) {
        error[0] = '\0';
    }
    if (source == NULL || request == NULL || source->method == NULL ||
        source->uri == NULL) return 0;
    memset(request, 0, sizeof(*request));
    request->method = source->method;
    request->uri = source->uri;
    request->http_version = source->http_version;
    request->hostname = source->hostname;
    request->client = source->client;
    request->server = source->server;
    request->headers = source->headers;
    request->header_count = source->header_count;
    request->body = source->body;
    return 1;
}

int msconnector_runtime_config_check(const char *name, const char *path,
    char *error, size_t error_len) {
    (void)name; (void)path;
    if (error != NULL && error_len != 0U) error[0] = '\0';
    return 1;
}
int msconnector_runtime_create(const char *name, const char *path,
    msconnector_runtime **out, char *error, size_t error_len) {
    (void)name; (void)path;
    if (out == NULL) return 0;
    if (error != NULL && error_len != 0U) error[0] = '\0';
    *out = &fake_runtime;
    return 1;
}
int msconnector_runtime_set_event_integration_mode(msconnector_runtime *runtime,
    const char *mode) {
    if (runtime == NULL || mode == NULL) {
        return 0;
    }
    runtime->unused = 0;
    return 1;
}
int msconnector_runtime_set_transaction_profile(msconnector_runtime *runtime,
    const msconnector_transaction_profile *profile) {
    if (runtime == NULL || profile == NULL) {
        return 0;
    }
    runtime->unused = 0;
    return 1;
}
void msconnector_runtime_destroy(msconnector_runtime **runtime) {
    if (runtime != NULL) *runtime = NULL;
}
void msconnector_runtime_request_contract(const msconnector_runtime *runtime,
    msconnector_request_mapper_contract *contract) {
    (void)runtime; msconnector_request_mapper_contract_init(contract);
    contract->max_header_count = 16U;
}
size_t msconnector_runtime_total_header_limit(const msconnector_runtime *r)
    { (void)r; return 4096U; }
size_t msconnector_runtime_header_count_limit(const msconnector_runtime *r)
    { (void)r; return 16U; }
int msconnector_runtime_error_log_enabled(const msconnector_runtime *r)
    { (void)r; return 0; }
int msconnector_runtime_error_http_status(const msconnector_runtime *r,
    msconnector_error_code code) { (void)r; (void)code; return 500; }

int msconnector_runtime_transaction_begin_request_stream(msconnector_runtime *runtime,
    const msconnector_request *request, const char *request_id,
    msconnector_runtime_transaction **out, msconnector_decision *decision,
    msconnector_error *error) {
    msconnector_runtime_transaction *transaction;
    (void)request_id;
    if (runtime != NULL) {
        runtime->unused = 0;
    }
    if (request == NULL || out == NULL || decision == NULL ||
        request->method == NULL || request->uri == NULL ||
        strcmp(request->method, "GET") != 0 || strcmp(request->uri, "/ok") != 0)
        return 0;
    ++transaction_count;
    transaction = calloc(1U, sizeof(*transaction));
    if (transaction == NULL) return 0;
    *out = transaction; msconnector_decision_set_allow(decision);
    if (error != NULL) msconnector_error_init(error);
    return 1;
}
int msconnector_runtime_transaction_finish(msconnector_runtime_transaction *t,
    msconnector_error *error) {
    char release;

    if (t == NULL || t->finished) return 0;
    t->finished = 1;
    /* This is the last fake-runtime callback before response serialization.
     * It lets the parent send the RST before the service reaches send_all(). */
    if (transaction_count == 1U &&
        (!write_pipe_byte(ready_fd, 'R') || !read_pipe_byte(release_fd, &release))) {
        return 0;
    }
    if (error != NULL) msconnector_error_init(error);
    return 1;
}
const char *msconnector_runtime_transaction_id(
    const msconnector_runtime_transaction *t) { (void)t; return "peer-close"; }
void msconnector_runtime_transaction_destroy(msconnector_runtime_transaction **t)
    { if (t != NULL) { free(*t); *t = NULL; } }

/* This legacy transport fixture has no trusted-provenance producer. */
int msconnector_runtime_transaction_begin_request_stream_with_trusted_provenance(
    msconnector_runtime *runtime, const msconnector_request *request,
    const char *request_id, const msconnector_runtime_trusted_provenance *provenance,
    msconnector_runtime_transaction **out, msconnector_decision *decision,
    msconnector_error *error) {
    if (provenance != NULL) {
        if (out != NULL) *out = NULL;
        msconnector_error_set(error, MSCONNECTOR_ERROR_UNSUPPORTED_PHASE,
            "trusted provenance is outside this legacy fixture", "fixture");
        return 0;
    }
    return msconnector_runtime_transaction_begin_request_stream(runtime, request,
        request_id, out, decision, error);
}
int msconnector_runtime_transaction_finalize_and_snapshot(
    msconnector_runtime_transaction **transaction,
    msconnector_runtime_transaction_snapshot *snapshot, msconnector_error *error) {
    if (transaction == NULL || *transaction == NULL || snapshot == NULL) return 0;
    if (!(*transaction)->finished &&
        msconnector_runtime_transaction_finish(*transaction, error) != 1) return 0;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->finished = (*transaction)->finished;
    snapshot->request_body.bytes_seen = (*transaction)->request_body_bytes;
    snapshot->request_body.finished = (*transaction)->request_body_finished;
    snapshot->contract.cleanup_started = 1;
    snapshot->contract.cleanup_complete = 1;
    snapshot->contract.status = MSCONNECTOR_TRANSACTION_STATUS_CLEANED;
    msconnector_runtime_transaction_destroy(transaction);
    return 1;
}

static const msconnector_transaction_profile transaction_profile = {
    .profile_id = 1U, .profile_name = "peer-close", .connector_id = "peer-close",
    .host_adapter_id = "peer-close", .direct_phase_mask = MSCONNECTOR_TRANSACTION_PHASE_MASK_ALL,
    .companion_phase_mask = 0U, .strict_post_commit_action = 0, .private_default_binding = 1,
};
static const msconnector_http_authorization_profile profile = {
    .connector_name = "peer-close", .integration_mode = "peer-close",
    .transaction_profile = &transaction_profile, .map_request = map_request,
};

static int connect_port(unsigned short port) {
    struct sockaddr_in address = {0}; int fd;
    address.sin_family = AF_INET; address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for (int i = 0; i < SMOKE_RETRY_COUNT; ++i) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0 && connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0)
            return fd;
        if (fd >= 0) close(fd);
        { const struct timespec delay = {0, SMOKE_RETRY_DELAY_NS};
          (void)nanosleep(&delay, NULL); }
    }
    return -1;
}

static int reserve_port(unsigned short *port) {
    int reserve;
    struct sockaddr_in address = {0};
    socklen_t address_size = sizeof(address);

    if (port == NULL) {
        return 0;
    }
    reserve = socket(AF_INET, SOCK_STREAM, 0);
    if (reserve < 0) {
        return 0;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(reserve, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockname(reserve, (struct sockaddr *)&address, &address_size) != 0) {
        (void)close(reserve);
        return 0;
    }
    *port = ntohs(address.sin_port);
    (void)close(reserve);
    return 1;
}

static pid_t start_peer_service(int started[2], int released[2],
    unsigned short port) {
    pid_t child = fork();

    if (child != 0) {
        return child;
    }
    {
        char spec[64];
        char *argv[] = {"peer-close", "--serve", "--config", "ignored",
            "--listen", spec, "--max-requests", "2",
            "--connection-timeout-ms", "1000", NULL};

        ready_fd = started[1];
        release_fd = released[0];
        if (signal(SIGPIPE, SIG_DFL) == SIG_ERR) {
            _exit(1);
        }
        close_fd(&started[0]);
        close_fd(&released[1]);
        (void)snprintf(spec, sizeof(spec), "127.0.0.1:%u", port);
        _exit(msconnector_http_authorization_service_main(10, argv, &profile));
    }
}

static int reset_peer(int *client, int started_fd) {
    const struct linger reset = {1, 0};
    const struct timespec settle = {0, 50000000L};

    if (*client < 0 || !write_all(*client,
            "GET /ok HTTP/1.1\r\nHost: smoke.test\r\nConnection: close\r\n\r\n",
            sizeof("GET /ok HTTP/1.1\r\nHost: smoke.test\r\nConnection: close\r\n\r\n") - 1U) ||
        !read_pipe_byte(started_fd, &(char){0}) ||
        setsockopt(*client, SOL_SOCKET, SO_LINGER, &reset, sizeof(reset)) != 0) {
        return 0;
    }
    close_fd(client);
    (void)nanosleep(&settle, NULL);
    return 1;
}

static int complete_followup(unsigned short port, int release_fd_value,
    int *second, pid_t child, int *status, int *child_reaped, int *probe) {
    const char request[] = "GET /ok HTTP/1.1\r\nHost: smoke.test\r\n"
        "Connection: close\r\n\r\n";

    if (!write_pipe_byte(release_fd_value, 'R')) {
        return 0;
    }
    *second = connect_port(port);
    if (*second < 0 || !write_all(*second, request, sizeof(request) - 1U) ||
        !read_complete_response(*second)) {
        return 0;
    }
    close_fd(second);
    if (!wait_for_child(child, status) || !WIFEXITED(*status) ||
        WEXITSTATUS(*status) != EXIT_SUCCESS) {
        return 0;
    }
    *child_reaped = 1;
    *probe = connect_port(port);
    return *probe < 0;
}

static int run_peer_test(void) {
    int started[2] = {-1, -1};
    int released[2] = {-1, -1};
    int status = 0;
    int client = -1;
    int second = -1;
    int probe = -1;
    int child_reaped = 0;
    int result = EXIT_FAILURE;
    unsigned short port = 0U;
    pid_t child = -1;
    if (pipe(started) != 0 || pipe(released) != 0 ||
        !reserve_port(&port)) goto cleanup;
    child = start_peer_service(started, released, port);
    if (child < 0) goto cleanup;
    close_fd(&started[1]);
    close_fd(&released[0]);
    client = connect_port(port);
    if (client < 0 || !reset_peer(&client, started[0]) ||
        !complete_followup(port, released[1], &second, child, &status,
            &child_reaped, &probe)) goto cleanup;
    result = EXIT_SUCCESS;

cleanup:
    close_fd(&client);
    close_fd(&second);
    close_fd(&probe);
    close_fd(&started[0]);
    close_fd(&started[1]);
    close_fd(&released[0]);
    close_fd(&released[1]);
    if (child > 0 && !child_reaped) {
        reap_child(child);
    }
    return result;
}

int main(void) {
    msconnector_test_request_stream_stubs_smoke();
    const int result = run_peer_test();

    if (result == EXIT_SUCCESS) {
        puts("http authorization peer-close smoke: passed");
    } else {
        fputs("http authorization peer-close smoke: failed\n", stderr);
    }
    return result;
}
