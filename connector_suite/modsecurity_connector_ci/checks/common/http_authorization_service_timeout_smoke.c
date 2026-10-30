#define _POSIX_C_SOURCE 200809L

#include "common/runtime/http_authorization_service.h"
#include "common/runtime/msconnector_runtime.h"

#include "msconnector/decision.h"
#include "msconnector/error.h"
#include "msconnector/request.h"
#include "msconnector/request_mapper_contract.h"
#include "../../../modsecurity_connector_tests/fixtures/http_authorization_runtime_lifecycle_stubs.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef MSCONNECTOR_ACTIVE_GCOV
extern void __gcov_dump(void);
#endif

#define TEST_CONNECTION_TIMEOUT_MS 250UL
#define TEST_DEFAULT_SLOT_TIMEOUT_MS 1000UL
#define TEST_START_TIMEOUT_MS 2000L
#define TEST_RESPONSE_TIMEOUT_MS 1500L
#define TEST_CHILD_TIMEOUT_MS 5000L
#define TEST_STALLED_PEER_SETTLE_MS 25L
#define TEST_PARALLEL_RESPONSE_MAX_MS 200L
#define TEST_DEFAULT_CONNECTION_COUNT 8U
#define TEST_SEQUENTIAL_REQUEST_COUNT 64U
#define TEST_PARALLEL_REQUEST_COUNT 4U

struct msconnector_runtime {
    unsigned int active_transactions;
    int event_integration_configured;
    int transaction_profile_configured;
};

static msconnector_runtime fake_runtime = {0U};

int msconnector_runtime_config_check(
    const char *connector_name,
    const char *config_path,
    char *error,
    size_t error_len) {
    (void)connector_name;
    (void)config_path;
    if (error != NULL && error_len > 0U) {
        error[0] = '\0';
    }
    return 1;
}

int msconnector_runtime_create(
    const char *connector_name,
    const char *config_path,
    msconnector_runtime **out,
    char *error,
    size_t error_len) {
    (void)connector_name;
    (void)config_path;
    if (out == NULL) {
        return 0;
    }
    if (error != NULL && error_len > 0U) {
        error[0] = '\0';
    }
    fake_runtime.active_transactions = 0U;
    fake_runtime.event_integration_configured = 0;
    fake_runtime.transaction_profile_configured = 0;
    *out = &fake_runtime;
    return 1;
}

int msconnector_runtime_set_event_integration_mode(
    msconnector_runtime *runtime,
    const char *integration_mode) {
    if (runtime == NULL || integration_mode == NULL || integration_mode[0] == '\0') {
        return 0;
    }
    runtime->event_integration_configured = 1;
    return 1;
}

int msconnector_runtime_set_transaction_profile(
    msconnector_runtime *runtime,
    const msconnector_transaction_profile *profile) {
    if (runtime == NULL || profile == NULL || profile->profile_id == 0U) {
        return 0;
    }
    runtime->transaction_profile_configured = 1;
    return 1;
}

int msconnector_runtime_error_log_enabled(const msconnector_runtime *runtime) {
    (void)runtime;
    return 0;
}

void msconnector_runtime_destroy(msconnector_runtime **runtime) {
    if (runtime != NULL) {
        *runtime = NULL;
    }
}

void msconnector_runtime_request_contract(
    const msconnector_runtime *runtime,
    msconnector_request_mapper_contract *contract) {
    (void)runtime;
    msconnector_request_mapper_contract_init(contract);
    contract->max_header_count = 64U;

}


size_t msconnector_runtime_total_header_limit(const msconnector_runtime *runtime) {
    (void)runtime;
    return 8192U;
}

size_t msconnector_runtime_header_count_limit(const msconnector_runtime *runtime) {
    (void)runtime;
    return 64U;
}

static int smoke_request_is_supported(const char *method, const char *uri) {
    if (method == NULL || uri == NULL) {
        return 0;
    }
    if (strcmp(method, "GET") == 0) {
        return strcmp(uri, "/ok") == 0 ||
            strcmp(uri, "/redirect-p1") == 0 ||
            strcmp(uri, "/unsafe-redirect") == 0 ||
            strcmp(uri, "/empty-redirect") == 0 ||
            strcmp(uri, "/overlong-redirect") == 0 ||
            strcmp(uri, "/deny") == 0;
    }
    return strcmp(method, "POST") == 0 &&
        (strcmp(uri, "/redirect-p2") == 0 || strcmp(uri, "/stall") == 0);
}

int msconnector_runtime_transaction_begin_request_stream(
    msconnector_runtime *runtime,
    const msconnector_request *request,
    const char *host_request_id,
    msconnector_runtime_transaction **out,
    msconnector_decision *decision,
    msconnector_error *error) {
    msconnector_runtime_transaction *transaction;
    (void)host_request_id;
    if (runtime == NULL || request == NULL || out == NULL || decision == NULL ||
        request->method == NULL || request->uri == NULL ||
        runtime->event_integration_configured == 0 ||
        runtime->transaction_profile_configured == 0 ||
        !smoke_request_is_supported(request->method, request->uri)) {
        return 0;
    }
    transaction = calloc(1U, sizeof(*transaction));
    if (transaction == NULL) {
        return 0;
    }
    transaction->runtime = runtime;
    transaction->finished = 0;
    ++runtime->active_transactions;
    *out = transaction;
    if (strcmp(request->uri, "/redirect-p1") == 0 ||
        strcmp(request->uri, "/redirect-p2") == 0) {
        const char *target = strcmp(request->uri, "/redirect-p1") == 0 ?
            "/redirect-p1-target" : "/redirect-p2-target";
        (void)snprintf(transaction->redirect_url,
            sizeof(transaction->redirect_url), "%s", target);
        msconnector_decision_set_redirect(decision, 302, transaction->redirect_url,
            "redirect-rule", "redirect smoke decision");
    } else if (strcmp(request->uri, "/unsafe-redirect") == 0) {
        (void)snprintf(transaction->redirect_url,
            sizeof(transaction->redirect_url), "%s",
            "/redirect-target\r\nx-injected: rejected");
        msconnector_decision_set_redirect(decision, 302, transaction->redirect_url,
            "redirect-rule", "unsafe redirect smoke decision");
    } else if (strcmp(request->uri, "/empty-redirect") == 0) {
        msconnector_decision_set_redirect(decision, 302, "", "redirect-rule",
            "empty redirect smoke decision");
    } else if (strcmp(request->uri, "/overlong-redirect") == 0) {
        memset(transaction->redirect_url, 'a',
            sizeof(transaction->redirect_url) - 1U);
        transaction->redirect_url[sizeof(transaction->redirect_url) - 1U] = '\0';
        msconnector_decision_set_redirect(decision, 302, transaction->redirect_url,
            "redirect-rule", "overlong redirect smoke decision");
    } else if (strcmp(request->uri, "/deny") == 0) {
        msconnector_decision_set_deny(decision, 403, "deny-rule",
            "deny smoke decision");
    } else {
        msconnector_decision_set_allow(decision);
    }
    if (error != NULL) {
        msconnector_error_init(error);
    }
    return 1;
}

int msconnector_runtime_transaction_finish(
    msconnector_runtime_transaction *transaction,
    msconnector_error *error) {
    if (transaction == NULL || transaction->runtime == NULL) {
        return 0;
    }
    if (transaction->finished != 0) {
        return 1;
    }
    if (transaction->runtime->active_transactions == 0U) {
        return 0;
    }
    /* The service must copy redirect data before finish/destroy. This models
     * the native transaction-owned redirect buffer becoming unavailable once
     * request processing has completed. */
    memset(transaction->redirect_url, 0, sizeof(transaction->redirect_url));
    --transaction->runtime->active_transactions;
    transaction->finished = 1;
    if (error != NULL) {
        msconnector_error_init(error);
    }
    return 1;
}

const char *msconnector_runtime_transaction_id(
    const msconnector_runtime_transaction *transaction) {
    return transaction == NULL ? NULL : "timeout-smoke";
}

static int smoke_map_request(
    const msconnector_generic_request_source *source,
    const msconnector_request_mapper_contract *contract,
    msconnector_request *request,
    char *error,
    size_t error_len) {
    (void)contract;
    if (source == NULL || request == NULL ||
        !smoke_request_is_supported(source->method, source->uri)) {
        if (error != NULL && error_len > 0U) {
            (void)snprintf(error, error_len, "%s", "unexpected smoke request");
        }
        return 0;
    }
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

static const msconnector_transaction_profile smoke_transaction_profile = {
    .profile_id = 1U,
    .profile_name = "timeout-smoke",
    .connector_id = "timeout-smoke",
    .host_adapter_id = "timeout-smoke",
    .direct_phase_mask = MSCONNECTOR_TRANSACTION_PHASE_MASK_ALL,
    .companion_phase_mask = 0U,
    .strict_post_commit_action = 0,
    .private_default_binding = 1,
};

static const msconnector_http_authorization_profile smoke_profile = {
    .connector_name = "timeout-smoke",
    .integration_mode = "timeout-smoke",
    .transaction_profile = &smoke_transaction_profile,
    .original_uri_headers = NULL,
    .original_uri_header_count = 0U,
    .map_request = smoke_map_request,
    .map_response = NULL,
};

static const char *const envoy_redirect_original_uri_headers[] = {
    "x-envoy-original-path",
    "x-forwarded-uri",
    "x-original-uri",
};

static const msconnector_http_authorization_profile envoy_redirect_profile = {
    .connector_name = "envoy",
    .integration_mode = "ext_authz",
    .transaction_profile = &smoke_transaction_profile,
    .original_uri_headers = envoy_redirect_original_uri_headers,
    .original_uri_header_count = sizeof(envoy_redirect_original_uri_headers) /
        sizeof(envoy_redirect_original_uri_headers[0]),
    .map_request = smoke_map_request,
    .map_response = NULL,
    .terminal_response_marker_header = "x-msconnector-terminal-authz",
    .terminal_response_marker_value = "1",
};

static const char *const traefik_redirect_original_uri_headers[] = {
    "X-Forwarded-Uri",
    "X-Original-Uri",
};

static const msconnector_http_authorization_profile traefik_redirect_profile = {
    .connector_name = "traefik",
    .integration_mode = "forwardAuth",
    .transaction_profile = &smoke_transaction_profile,
    .original_uri_headers = traefik_redirect_original_uri_headers,
    .original_uri_header_count = sizeof(traefik_redirect_original_uri_headers) /
        sizeof(traefik_redirect_original_uri_headers[0]),
    .map_request = smoke_map_request,
    .map_response = NULL,
};

static int sleep_milliseconds(long milliseconds) {
    struct timespec duration;
    if (milliseconds < 0L) {
        return 0;
    }
    duration.tv_sec = milliseconds / 1000L;
    duration.tv_nsec = (milliseconds % 1000L) * 1000000L;
    return nanosleep(&duration, NULL) == 0;
}

static long monotonic_milliseconds(void) {
    struct timespec current;
    if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) {
        return -1L;
    }
    return current.tv_sec * 1000L + current.tv_nsec / 1000000L;
}

static int reserve_loopback_port(unsigned short *port) {
    struct sockaddr_in address;
    socklen_t address_size = sizeof(address);
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        return 0;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(0U);
    if (bind(socket_fd, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockname(socket_fd, (struct sockaddr *)&address, &address_size) != 0) {
        (void)close(socket_fd);
        return 0;
    }
    *port = ntohs(address.sin_port);
    (void)close(socket_fd);
    return *port != 0U;
}

static int connect_loopback(unsigned short port, long timeout_ms) {
    const long deadline = monotonic_milliseconds() + timeout_ms;
    struct sockaddr_in address;
    if (deadline < 0L) {
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    while (monotonic_milliseconds() <= deadline) {
        const int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd < 0) {
            return -1;
        }
        if (connect(socket_fd, (const struct sockaddr *)&address, sizeof(address)) == 0) {
            return socket_fd;
        }
        (void)close(socket_fd);
        if (!sleep_milliseconds(10L)) {
            return -1;
        }
    }
    return -1;
}

static int send_all(int socket_fd, const char *data) {
    size_t sent = 0U;
    const size_t size = strlen(data);
    while (sent < size) {
        const ssize_t result = send(socket_fd, data + sent, size - sent, 0);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return 0;
        }
        sent += (size_t)result;
    }
    return 1;
}

static int read_response(int socket_fd, char *response, size_t response_size) {
    struct timeval timeout;
    size_t used = 0U;
    if (response_size == 0U) {
        return 0;
    }
    timeout.tv_sec = TEST_RESPONSE_TIMEOUT_MS / 1000L;
    timeout.tv_usec = (suseconds_t)((TEST_RESPONSE_TIMEOUT_MS % 1000L) * 1000L);
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO,
            &timeout, sizeof(timeout)) != 0) {
        return 0;
    }
    while (used + 1U < response_size) {
        const ssize_t received = recv(socket_fd, response + used,
            response_size - used - 1U, 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        }
        if (received < 0) {
            return 0;
        }
        if (received == 0) {
            break;
        }
        used += (size_t)received;
    }
    response[used] = '\0';
    return used > 0U;
}

static pid_t start_service_with_profile_options(
    const msconnector_http_authorization_profile *profile,
    unsigned short port,
    unsigned long max_requests,
    unsigned long timeout_ms,
    unsigned long max_connections) {
    char listen[64];
    char timeout[32];
    char max_requests_value[32];
    char max_connections_value[32];
    char *argv[13];
    int argc = 0;
    pid_t child;

    if (profile == NULL) {
        return -1;
    }
    child = fork();
    if (child != 0) {
        return child;
    }
    (void)snprintf(listen, sizeof(listen), "127.0.0.1:%u", (unsigned int)port);
    (void)snprintf(timeout, sizeof(timeout), "%lu", timeout_ms);
    (void)snprintf(max_requests_value, sizeof(max_requests_value), "%lu", max_requests);
    argv[argc++] = "timeout-smoke-service";
    argv[argc++] = "--serve";
    argv[argc++] = "--config";
    argv[argc++] = "timeout-smoke.conf";
    argv[argc++] = "--listen";
    argv[argc++] = listen;
    argv[argc++] = "--max-requests";
    argv[argc++] = max_requests_value;
    if (max_connections != 0UL) {
        (void)snprintf(max_connections_value, sizeof(max_connections_value), "%lu",
            max_connections);
        argv[argc++] = "--max-connections";
        argv[argc++] = max_connections_value;
    }
    argv[argc++] = "--connection-timeout-ms";
    argv[argc++] = timeout;
    argv[argc] = NULL;
    const int result = msconnector_http_authorization_service_main(argc, argv, profile);
#ifdef MSCONNECTOR_ACTIVE_GCOV
    /* This fixture intentionally uses _exit, which skips GCC's exit hook.
     * Persist only the real counters from the completed service execution. */
    __gcov_dump();
#endif
    _exit(result);
}

static pid_t start_service_with_options(
    unsigned short port,
    unsigned long max_requests,
    unsigned long timeout_ms,
    unsigned long max_connections) {
    return start_service_with_profile_options(&smoke_profile, port, max_requests,
        timeout_ms, max_connections);
}

static pid_t start_service_with_capacity(
    unsigned short port,
    unsigned long max_requests,
    unsigned long max_connections) {
    return start_service_with_options(port, max_requests,
        TEST_CONNECTION_TIMEOUT_MS, max_connections);
}

static pid_t start_service(unsigned short port) {
    return start_service_with_capacity(port, 2UL, 2UL);
}

static int wait_for_service(pid_t child) {
    const long deadline = monotonic_milliseconds() + TEST_CHILD_TIMEOUT_MS;
    int status = 0;
    if (deadline < 0L) {
        return 0;
    }
    while (monotonic_milliseconds() <= deadline) {
        const pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
        if (result < 0) {
            return 0;
        }
        if (!sleep_milliseconds(10L)) {
            return 0;
        }
    }
    (void)kill(child, SIGTERM);
    (void)waitpid(child, &status, 0);
    return 0;
}

static int response_has_status(const char *response, const char *status) {
    return response != NULL && strncmp(response, status, strlen(status)) == 0;
}

static int request_response(
    unsigned short port,
    const char *request,
    char *response,
    size_t response_size) {
    int socket_fd = connect_loopback(port, TEST_RESPONSE_TIMEOUT_MS);
    int result = 0;

    if (socket_fd >= 0 && send_all(socket_fd, request) &&
        read_response(socket_fd, response, response_size)) {
        result = 1;
    }
    if (socket_fd >= 0) {
        (void)close(socket_fd);
    }
    return result;
}

static int response_has_exact_header_once(const char *response,
    const char *header) {
    const char *first;

    if (response == NULL || header == NULL) {
        return 0;
    }
    first = strstr(response, header);
    return first != NULL && strstr(first + strlen(header), header) == NULL;
}

static int run_redirect_success_cases(
    unsigned short port,
    const char *case_name,
    char *response,
    size_t response_size,
    int expect_terminal_marker) {
    const char redirect_p1_request[] =
        "GET /redirect-p1 HTTP/1.1\r\nHost: redirect.example\r\n\r\n";
    const char redirect_p2_request[] =
        "POST /redirect-p2 HTTP/1.1\r\nHost: redirect.example\r\n"
        "Content-Length: 4\r\n\r\nbody";
    const char location_p1[] = "\r\nlocation: /redirect-p1-target\r\n";
    const char location_p2[] = "\r\nlocation: /redirect-p2-target\r\n";
    const char terminal_marker[] = "\r\nx-msconnector-terminal-authz: 1\r\n";

    if (!request_response(port, redirect_p1_request, response, response_size) ||
        !response_has_status(response, "HTTP/1.1 302") ||
        !response_has_exact_header_once(response, location_p1) ||
        (expect_terminal_marker !=
            (strstr(response, terminal_marker) != NULL))) {
        (void)fprintf(stderr, "%s: P1 redirect response was not preserved\n", case_name);
        return 0;
    }
    if (!request_response(port, redirect_p2_request, response, response_size) ||
        !response_has_status(response, "HTTP/1.1 302") ||
        !response_has_exact_header_once(response, location_p2)) {
        (void)fprintf(stderr, "%s: P2 redirect response was not preserved\n", case_name);
        return 0;
    }
    return 1;
}

static int run_rejected_redirect_cases(
    unsigned short port,
    const char *case_name,
    char *response,
    size_t response_size) {
    const char unsafe_redirect_request[] =
        "GET /unsafe-redirect HTTP/1.1\r\nHost: redirect.example\r\n\r\n";
    const char empty_redirect_request[] =
        "GET /empty-redirect HTTP/1.1\r\nHost: redirect.example\r\n\r\n";
    const char overlong_redirect_request[] =
        "GET /overlong-redirect HTTP/1.1\r\nHost: redirect.example\r\n\r\n";

    if (!request_response(port, unsafe_redirect_request, response, response_size) ||
        !response_has_status(response, "HTTP/1.1 500") ||
        strstr(response, "\r\nlocation:") != NULL ||
        strstr(response, "\r\nx-injected:") != NULL) {
        (void)fprintf(stderr, "%s: unsafe redirect did not fail closed\n", case_name);
        return 0;
    }
    if (!request_response(port, empty_redirect_request, response, response_size) ||
        !response_has_status(response, "HTTP/1.1 500") ||
        strstr(response, "\r\nlocation:") != NULL) {
        (void)fprintf(stderr, "%s: empty redirect did not fail closed\n", case_name);
        return 0;
    }
    if (!request_response(port, overlong_redirect_request, response,
            response_size) ||
        !response_has_status(response, "HTTP/1.1 500") ||
        strstr(response, "\r\nlocation:") != NULL) {
        (void)fprintf(stderr, "%s: overlong redirect did not fail closed\n", case_name);
        return 0;
    }
    return 1;
}

static int run_non_redirect_control_cases(
    unsigned short port,
    const char *case_name,
    char *response,
    size_t response_size) {
    const char allow_request[] =
        "GET /ok HTTP/1.1\r\nHost: redirect.example\r\n\r\n";
    const char deny_request[] =
        "GET /deny HTTP/1.1\r\nHost: redirect.example\r\n\r\n";

    if (!request_response(port, allow_request, response, response_size) ||
        !response_has_status(response, "HTTP/1.1 200") ||
        strstr(response, "\r\nlocation:") != NULL) {
        (void)fprintf(stderr, "%s: allow response unexpectedly carried Location\n", case_name);
        return 0;
    }
    if (!request_response(port, deny_request, response, response_size) ||
        !response_has_status(response, "HTTP/1.1 403") ||
        strstr(response, "\r\nlocation:") != NULL) {
        (void)fprintf(stderr, "%s: deny response unexpectedly carried Location\n", case_name);
        return 0;
    }
    return 1;
}

static int run_redirect_profile_case(const char *case_name,
    const msconnector_http_authorization_profile *profile,
    int expect_terminal_marker) {
    char response[2048];
    unsigned short port;
    pid_t service = -1;
    int result = 0;

    if (!reserve_loopback_port(&port)) {
        (void)fprintf(stderr, "%s: could not reserve loopback port\n", case_name);
        return 0;
    }
    service = start_service_with_profile_options(profile, port, 7UL,
        TEST_CONNECTION_TIMEOUT_MS, 2UL);
    if (service < 0) {
        (void)fprintf(stderr, "%s: could not fork service\n", case_name);
        return 0;
    }
    if (!run_redirect_success_cases(port, case_name, response, sizeof(response),
            expect_terminal_marker) ||
        !run_rejected_redirect_cases(port, case_name, response, sizeof(response)) ||
        !run_non_redirect_control_cases(port, case_name, response,
            sizeof(response))) {
        goto done;
    }
    if (!wait_for_service(service)) {
        (void)fprintf(stderr, "%s: service did not exit cleanly\n", case_name);
        service = -1;
        goto done;
    }
    service = -1;
    result = 1;

done:
    if (service > 0) {
        int status = 0;
        (void)kill(service, SIGTERM);
        (void)waitpid(service, &status, 0);
    }
    return result;
}

static int run_stalled_request_case(const char *case_name, const char *stall_request) {
    const char valid_request[] = "GET /ok HTTP/1.1\r\nHost: valid.example\r\n\r\n";
    char stalled_response[1024];
    char valid_response[1024];
    unsigned short port;
    int stalled_fd = -1;
    int valid_fd = -1;
    int result = 0;
    long valid_started;
    long valid_finished;
    pid_t service;

    if (!reserve_loopback_port(&port)) {
        (void)fprintf(stderr, "%s: could not reserve loopback port\n", case_name);
        return 0;
    }
    service = start_service(port);
    if (service < 0) {
        (void)fprintf(stderr, "%s: could not fork service\n", case_name);
        return 0;
    }
    stalled_fd = connect_loopback(port, TEST_START_TIMEOUT_MS);
    if (stalled_fd < 0 || !send_all(stalled_fd, stall_request)) {
        (void)fprintf(stderr, "%s: could not establish stalled peer\n", case_name);
        goto done;
    }
    if (!sleep_milliseconds((long)TEST_CONNECTION_TIMEOUT_MS + 100L)) {
        (void)fprintf(stderr, "%s: sleep failed\n", case_name);
        goto done;
    }
    valid_started = monotonic_milliseconds();
    valid_fd = connect_loopback(port, TEST_RESPONSE_TIMEOUT_MS);
    if (valid_fd < 0 || !send_all(valid_fd, valid_request) ||
        !read_response(valid_fd, valid_response, sizeof(valid_response))) {
        (void)fprintf(stderr, "%s: valid following request was not served\n", case_name);
        goto done;
    }
    valid_finished = monotonic_milliseconds();
    if (!response_has_status(valid_response, "HTTP/1.1 200") ||
        valid_started < 0L || valid_finished < valid_started ||
        valid_finished - valid_started > TEST_RESPONSE_TIMEOUT_MS) {
        (void)fprintf(stderr, "%s: valid following request did not receive a timely 200\n",
            case_name);
        goto done;
    }
    if (!read_response(stalled_fd, stalled_response, sizeof(stalled_response)) ||
        !response_has_status(stalled_response, "HTTP/1.1 408")) {
        (void)fprintf(stderr, "%s: stalled peer did not receive a bounded 408 response\n",
            case_name);
        goto done;
    }
    if (!wait_for_service(service)) {
        (void)fprintf(stderr, "%s: service did not exit cleanly after the valid mapping\n",
            case_name);
        service = -1;
        goto done;
    }
    service = -1;
    result = 1;

done:
    if (stalled_fd >= 0) {
        (void)close(stalled_fd);
    }
    if (valid_fd >= 0) {
        (void)close(valid_fd);
    }
    if (service > 0) {
        int status = 0;
        (void)kill(service, SIGTERM);
        (void)waitpid(service, &status, 0);
    }
    return result;
}

static int valid_request_is_served(unsigned short port) {
    const char valid_request[] = "GET /ok HTTP/1.1\r\nHost: valid.example\r\n\r\n";
    char response[1024];
    int socket_fd = connect_loopback(port, TEST_RESPONSE_TIMEOUT_MS);
    int result = 0;
    if (socket_fd >= 0 && send_all(socket_fd, valid_request) &&
        read_response(socket_fd, response, sizeof(response)) &&
        response_has_status(response, "HTTP/1.1 200")) {
        result = 1;
    }
    if (socket_fd >= 0) {
        (void)close(socket_fd);
    }
    return result;
}

static int peer_is_rejected_promptly(int socket_fd) {
    struct timeval timeout;
    char byte;
    ssize_t received;
    timeout.tv_sec = TEST_PARALLEL_RESPONSE_MAX_MS / 1000L;
    timeout.tv_usec = (suseconds_t)(
        (TEST_PARALLEL_RESPONSE_MAX_MS % 1000L) * 1000L);
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO,
            &timeout, sizeof(timeout)) != 0) {
        return 0;
    }
    do {
        received = recv(socket_fd, &byte, sizeof(byte), 0);
    } while (received < 0 && errno == EINTR);
    return received == 0 || (received < 0 &&
        (errno == ECONNRESET || errno == ENOTCONN));
}

static int run_parallel_request_case(void) {
    const char stall_request[] = "GET /stall HTTP/1.1\r\nHost: slow.example\r\n";
    const char valid_request[] = "GET /ok HTTP/1.1\r\nHost: valid.example\r\n\r\n";
    char stalled_response[1024];
    char valid_response[1024];
    unsigned short port;
    int stalled_fd = -1;
    int valid_fd = -1;
    int result = 0;
    long valid_started;
    long valid_finished;
    pid_t service = -1;

    if (!reserve_loopback_port(&port)) {
        (void)fprintf(stderr, "parallel_request: could not reserve loopback port\n");
        return 0;
    }
    service = start_service(port);
    if (service < 0) {
        (void)fprintf(stderr, "parallel_request: could not fork service\n");
        return 0;
    }
    stalled_fd = connect_loopback(port, TEST_START_TIMEOUT_MS);
    if (stalled_fd < 0 || !send_all(stalled_fd, stall_request) ||
        !sleep_milliseconds(TEST_STALLED_PEER_SETTLE_MS)) {
        (void)fprintf(stderr, "parallel_request: could not establish stalled peer\n");
        goto done;
    }
    valid_started = monotonic_milliseconds();
    valid_fd = connect_loopback(port, TEST_RESPONSE_TIMEOUT_MS);
    if (valid_fd < 0 || !send_all(valid_fd, valid_request) ||
        !read_response(valid_fd, valid_response, sizeof(valid_response))) {
        (void)fprintf(stderr, "parallel_request: valid peer was not served\n");
        goto done;
    }
    valid_finished = monotonic_milliseconds();
    if (!response_has_status(valid_response, "HTTP/1.1 200") ||
        valid_started < 0L || valid_finished < valid_started ||
        valid_finished - valid_started > TEST_PARALLEL_RESPONSE_MAX_MS) {
        (void)fprintf(stderr,
            "parallel_request: valid peer waited for the stalled peer deadline\n");
        goto done;
    }
    if (!read_response(stalled_fd, stalled_response, sizeof(stalled_response)) ||
        !response_has_status(stalled_response, "HTTP/1.1 408")) {
        (void)fprintf(stderr, "parallel_request: stalled peer did not receive a bounded 408\n");
        goto done;
    }
    if (!wait_for_service(service)) {
        (void)fprintf(stderr, "parallel_request: service did not exit cleanly\n");
        service = -1;
        goto done;
    }
    service = -1;
    result = 1;

done:
    if (stalled_fd >= 0) {
        (void)close(stalled_fd);
    }
    if (valid_fd >= 0) {
        (void)close(valid_fd);
    }
    if (service > 0) {
        int status = 0;
        (void)kill(service, SIGTERM);
        (void)waitpid(service, &status, 0);
    }
    return result;
}

static int run_overload_recovery_case(void) {
    const char stall_request[] = "GET /stall HTTP/1.1\r\nHost: slow.example\r\n";
    char stalled_response[1024];
    unsigned short port;
    int stalled_fd = -1;
    int rejected_fd = -1;
    int result = 0;
    long rejection_started;
    long rejection_finished;
    pid_t service = -1;

    if (!reserve_loopback_port(&port)) {
        (void)fprintf(stderr, "overload_recovery: could not reserve loopback port\n");
        return 0;
    }
    service = start_service_with_capacity(port, 3UL, 1UL);
    if (service < 0) {
        (void)fprintf(stderr, "overload_recovery: could not fork service\n");
        return 0;
    }
    stalled_fd = connect_loopback(port, TEST_START_TIMEOUT_MS);
    if (stalled_fd < 0 || !send_all(stalled_fd, stall_request) ||
        !sleep_milliseconds(TEST_STALLED_PEER_SETTLE_MS)) {
        (void)fprintf(stderr, "overload_recovery: could not establish stalled peer\n");
        goto done;
    }
    rejection_started = monotonic_milliseconds();
    rejected_fd = connect_loopback(port, TEST_RESPONSE_TIMEOUT_MS);
    if (rejected_fd < 0 || !peer_is_rejected_promptly(rejected_fd)) {
        (void)fprintf(stderr, "overload_recovery: excess peer was not rejected promptly\n");
        goto done;
    }
    rejection_finished = monotonic_milliseconds();
    if (rejection_started < 0L || rejection_finished < rejection_started ||
        rejection_finished - rejection_started > TEST_PARALLEL_RESPONSE_MAX_MS) {
        (void)fprintf(stderr, "overload_recovery: excess peer rejection exceeded bound\n");
        goto done;
    }
    if (!read_response(stalled_fd, stalled_response, sizeof(stalled_response)) ||
        !response_has_status(stalled_response, "HTTP/1.1 408") ||
        !valid_request_is_served(port)) {
        (void)fprintf(stderr, "overload_recovery: capacity did not recover\n");
        goto done;
    }
    if (!wait_for_service(service)) {
        (void)fprintf(stderr, "overload_recovery: service did not exit cleanly\n");
        service = -1;
        goto done;
    }
    service = -1;
    result = 1;

done:
    if (stalled_fd >= 0) {
        (void)close(stalled_fd);
    }
    if (rejected_fd >= 0) {
        (void)close(rejected_fd);
    }
    if (service > 0) {
        int status = 0;
        (void)kill(service, SIGTERM);
        (void)waitpid(service, &status, 0);
    }
    return result;
}

static int run_default_capacity_recovery_case(void) {
    const char stall_request[] = "GET /stall HTTP/1.1\r\nHost: slow.example\r\n";
    char stalled_response[1024];
    unsigned short port;
    int stalled_fds[TEST_DEFAULT_CONNECTION_COUNT];
    int rejected_fd = -1;
    int result = 0;
    pid_t service = -1;

    for (size_t index = 0U; index < TEST_DEFAULT_CONNECTION_COUNT; ++index) {
        stalled_fds[index] = -1;
    }
    if (!reserve_loopback_port(&port)) {
        (void)fprintf(stderr, "default_capacity: could not reserve loopback port\n");
        return 0;
    }
    service = start_service_with_options(port,
        (unsigned long)TEST_DEFAULT_CONNECTION_COUNT + 2UL,
        TEST_DEFAULT_SLOT_TIMEOUT_MS, 0UL);
    if (service < 0) {
        (void)fprintf(stderr, "default_capacity: could not fork service\n");
        return 0;
    }
    for (size_t index = 0U; index < TEST_DEFAULT_CONNECTION_COUNT; ++index) {
        stalled_fds[index] = connect_loopback(port, TEST_START_TIMEOUT_MS);
        if (stalled_fds[index] < 0 || !send_all(stalled_fds[index], stall_request) ||
            !sleep_milliseconds(TEST_STALLED_PEER_SETTLE_MS)) {
            (void)fprintf(stderr, "default_capacity: could not establish stalled peer\n");
            goto done;
        }
    }
    rejected_fd = connect_loopback(port, TEST_RESPONSE_TIMEOUT_MS);
    if (rejected_fd < 0 || !peer_is_rejected_promptly(rejected_fd)) {
        (void)fprintf(stderr, "default_capacity: ninth peer was not rejected promptly\n");
        goto done;
    }
    for (size_t index = 0U; index < TEST_DEFAULT_CONNECTION_COUNT; ++index) {
        if (!read_response(stalled_fds[index], stalled_response,
                sizeof(stalled_response)) ||
            !response_has_status(stalled_response, "HTTP/1.1 408")) {
            (void)fprintf(stderr, "default_capacity: stalled peer did not receive 408\n");
            goto done;
        }
    }
    if (!valid_request_is_served(port)) {
        (void)fprintf(stderr, "default_capacity: capacity did not recover\n");
        goto done;
    }
    if (!wait_for_service(service)) {
        (void)fprintf(stderr, "default_capacity: service did not exit cleanly\n");
        service = -1;
        goto done;
    }
    service = -1;
    result = 1;

done:
    for (size_t index = 0U; index < TEST_DEFAULT_CONNECTION_COUNT; ++index) {
        if (stalled_fds[index] >= 0) {
            (void)close(stalled_fds[index]);
        }
    }
    if (rejected_fd >= 0) {
        (void)close(rejected_fd);
    }
    if (service > 0) {
        int status = 0;
        (void)kill(service, SIGTERM);
        (void)waitpid(service, &status, 0);
    }
    return result;
}

static int run_sequential_request_case(void) {
    unsigned short port;
    pid_t service = -1;
    int result = 0;

    if (!reserve_loopback_port(&port)) {
        (void)fprintf(stderr, "sequential_requests: could not reserve loopback port\n");
        return 0;
    }
    service = start_service_with_capacity(port, TEST_SEQUENTIAL_REQUEST_COUNT, 1UL);
    if (service < 0) {
        (void)fprintf(stderr, "sequential_requests: could not fork service\n");
        return 0;
    }
    for (size_t index = 0U; index < TEST_SEQUENTIAL_REQUEST_COUNT; ++index) {
        if (!valid_request_is_served(port)) {
            (void)fprintf(stderr, "sequential_requests: valid request was not served\n");
            goto done;
        }
    }
    if (!wait_for_service(service)) {
        (void)fprintf(stderr, "sequential_requests: service did not exit cleanly\n");
        service = -1;
        goto done;
    }
    service = -1;
    result = 1;

done:
    if (service > 0) {
        int status = 0;
        (void)kill(service, SIGTERM);
        (void)waitpid(service, &status, 0);
    }
    return result;
}

static int run_parallel_complete_request_case(void) {
    const char valid_request[] = "GET /ok HTTP/1.1\r\nHost: valid.example\r\n\r\n";
    char response[1024];
    unsigned short port;
    int sockets[TEST_PARALLEL_REQUEST_COUNT];
    pid_t service = -1;
    int result = 0;

    for (size_t index = 0U; index < TEST_PARALLEL_REQUEST_COUNT; ++index) {
        sockets[index] = -1;
    }
    if (!reserve_loopback_port(&port)) {
        (void)fprintf(stderr, "parallel_complete: could not reserve loopback port\n");
        return 0;
    }
    service = start_service_with_capacity(port,
        TEST_PARALLEL_REQUEST_COUNT, TEST_PARALLEL_REQUEST_COUNT);
    if (service < 0) {
        (void)fprintf(stderr, "parallel_complete: could not fork service\n");
        return 0;
    }
    for (size_t index = 0U; index < TEST_PARALLEL_REQUEST_COUNT; ++index) {
        sockets[index] = connect_loopback(port, TEST_RESPONSE_TIMEOUT_MS);
        if (sockets[index] < 0 || !send_all(sockets[index], valid_request)) {
            (void)fprintf(stderr, "parallel_complete: could not send valid request\n");
            goto done;
        }
    }
    for (size_t index = 0U; index < TEST_PARALLEL_REQUEST_COUNT; ++index) {
        if (!read_response(sockets[index], response, sizeof(response)) ||
            !response_has_status(response, "HTTP/1.1 200")) {
            (void)fprintf(stderr, "parallel_complete: valid request was not served\n");
            goto done;
        }
    }
    if (!wait_for_service(service)) {
        (void)fprintf(stderr, "parallel_complete: service did not exit cleanly\n");
        service = -1;
        goto done;
    }
    service = -1;
    result = 1;

done:
    for (size_t index = 0U; index < TEST_PARALLEL_REQUEST_COUNT; ++index) {
        if (sockets[index] >= 0) {
            (void)close(sockets[index]);
        }
    }
    if (service > 0) {
        int status = 0;
        (void)kill(service, SIGTERM);
        (void)waitpid(service, &status, 0);
    }
    return result;
}

static int run_abrupt_disconnect_case(void) {
    const char partial_request[] = "GET /stall HTTP/1.1\r\nHost: slow.example\r\n";
    unsigned short port;
    int disconnected_fd = -1;
    pid_t service = -1;
    int result = 0;

    if (!reserve_loopback_port(&port)) {
        (void)fprintf(stderr, "abrupt_disconnect: could not reserve loopback port\n");
        return 0;
    }
    service = start_service_with_capacity(port, 2UL, 2UL);
    if (service < 0) {
        (void)fprintf(stderr, "abrupt_disconnect: could not fork service\n");
        return 0;
    }
    disconnected_fd = connect_loopback(port, TEST_START_TIMEOUT_MS);
    if (disconnected_fd < 0 || !send_all(disconnected_fd, partial_request)) {
        (void)fprintf(stderr, "abrupt_disconnect: could not establish peer\n");
        goto done;
    }
    (void)close(disconnected_fd);
    disconnected_fd = -1;
    if (!sleep_milliseconds(TEST_STALLED_PEER_SETTLE_MS) ||
        !valid_request_is_served(port)) {
        (void)fprintf(stderr, "abrupt_disconnect: capacity did not recover\n");
        goto done;
    }
    if (!wait_for_service(service)) {
        (void)fprintf(stderr, "abrupt_disconnect: service did not exit cleanly\n");
        service = -1;
        goto done;
    }
    service = -1;
    result = 1;

done:
    if (disconnected_fd >= 0) {
        (void)close(disconnected_fd);
    }
    if (service > 0) {
        int status = 0;
        (void)kill(service, SIGTERM);
        (void)waitpid(service, &status, 0);
    }
    return result;
}

static int run_stalled_shutdown_case(void) {
    const char stall_request[] = "GET /stall HTTP/1.1\r\nHost: slow.example\r\n";
    unsigned short port;
    int stalled_fd = -1;
    int result = 0;
    pid_t service = -1;

    if (!reserve_loopback_port(&port)) {
        (void)fprintf(stderr, "stalled_shutdown: could not reserve loopback port\n");
        return 0;
    }
    service = start_service_with_capacity(port, 0UL, 1UL);
    if (service < 0) {
        (void)fprintf(stderr, "stalled_shutdown: could not fork service\n");
        return 0;
    }
    stalled_fd = connect_loopback(port, TEST_START_TIMEOUT_MS);
    if (stalled_fd < 0 || !send_all(stalled_fd, stall_request) ||
        !sleep_milliseconds(TEST_STALLED_PEER_SETTLE_MS) ||
        kill(service, SIGTERM) != 0 || !wait_for_service(service)) {
        (void)fprintf(stderr, "stalled_shutdown: service did not stop cleanly\n");
        goto done;
    }
    service = -1;
    result = 1;

done:
    if (stalled_fd >= 0) {
        (void)close(stalled_fd);
    }
    if (service > 0) {
        int status = 0;
        (void)kill(service, SIGTERM);
        (void)waitpid(service, &status, 0);
    }
    return result;
}

static pid_t start_dripping_peer(int socket_fd) {
    const pid_t child = fork();
    if (child != 0) {
        return child;
    }
    for (unsigned int index = 0U; index < 200U; ++index) {
        if (!sleep_milliseconds(20L) || !send_all(socket_fd, "x")) {
            _exit(0);
        }
    }
    _exit(0);
}

static int run_dripping_header_case(void) {
    const char initial_request[] = "GET /stall HTTP/1.1\r\nHost: slow.example";
    const char valid_request[] = "GET /ok HTTP/1.1\r\nHost: valid.example\r\n\r\n";
    char stalled_response[1024];
    char valid_response[1024];
    unsigned short port;
    int stalled_fd = -1;
    int valid_fd = -1;
    int result = 0;
    long valid_started;
    long valid_finished;
    pid_t service = -1;
    pid_t dripper = -1;

    if (!reserve_loopback_port(&port)) {
        (void)fprintf(stderr, "dripping_headers: could not reserve loopback port\n");
        return 0;
    }
    service = start_service(port);
    if (service < 0) {
        (void)fprintf(stderr, "dripping_headers: could not fork service\n");
        return 0;
    }
    stalled_fd = connect_loopback(port, TEST_START_TIMEOUT_MS);
    if (stalled_fd < 0 || !send_all(stalled_fd, initial_request)) {
        (void)fprintf(stderr, "dripping_headers: could not establish stalled peer\n");
        goto done;
    }
    dripper = start_dripping_peer(stalled_fd);
    if (dripper < 0 || !sleep_milliseconds((long)TEST_CONNECTION_TIMEOUT_MS + 100L)) {
        (void)fprintf(stderr, "dripping_headers: could not maintain a slow drip\n");
        goto done;
    }
    valid_started = monotonic_milliseconds();
    valid_fd = connect_loopback(port, TEST_RESPONSE_TIMEOUT_MS);
    if (valid_fd < 0 || !send_all(valid_fd, valid_request) ||
        !read_response(valid_fd, valid_response, sizeof(valid_response))) {
        (void)fprintf(stderr, "dripping_headers: valid following request was not served\n");
        goto done;
    }
    valid_finished = monotonic_milliseconds();
    if (!response_has_status(valid_response, "HTTP/1.1 200") ||
        valid_started < 0L || valid_finished < valid_started ||
        valid_finished - valid_started > TEST_RESPONSE_TIMEOUT_MS) {
        (void)fprintf(stderr, "dripping_headers: valid following request did not receive a timely 200\n");
        goto done;
    }
    if (!read_response(stalled_fd, stalled_response, sizeof(stalled_response)) ||
        !response_has_status(stalled_response, "HTTP/1.1 408")) {
        (void)fprintf(stderr, "dripping_headers: dripped peer did not receive a bounded 408 response\n");
        goto done;
    }
    if (!wait_for_service(service) || !wait_for_service(dripper)) {
        (void)fprintf(stderr, "dripping_headers: service or dripper did not exit cleanly\n");
        service = -1;
        dripper = -1;
        goto done;
    }
    service = -1;
    dripper = -1;
    result = 1;

done:
    if (stalled_fd >= 0) {
        (void)close(stalled_fd);
    }
    if (valid_fd >= 0) {
        (void)close(valid_fd);
    }
    if (dripper > 0) {
        int status = 0;
        (void)kill(dripper, SIGTERM);
        (void)waitpid(dripper, &status, 0);
    }
    if (service > 0) {
        int status = 0;
        (void)kill(service, SIGTERM);
        (void)waitpid(service, &status, 0);
    }
    return result;
}

static int rejects_unbounded_timeout_override(void) {
    char *argv[] = {
        "timeout-smoke-service",
        "--serve",
        "--config",
        "timeout-smoke.conf",
        "--listen",
        "127.0.0.1:18000",
        "--connection-timeout-ms",
        "0",
        NULL,
    };
    return msconnector_http_authorization_service_main(9, argv, &smoke_profile) == 2;
}

static int rejects_missing_option_values(void) {
    char *missing_config[] = {
        "timeout-smoke-service",
        "--serve",
        "--config",
        NULL,
    };
    char *missing_listen[] = {
        "timeout-smoke-service",
        "--serve",
        "--config",
        "timeout-smoke.conf",
        "--listen",
        NULL,
    };
    char *missing_max_requests[] = {
        "timeout-smoke-service",
        "--serve",
        "--config",
        "timeout-smoke.conf",
        "--listen",
        "127.0.0.1:18000",
        "--max-requests",
        NULL,
    };
    char *missing_timeout[] = {
        "timeout-smoke-service",
        "--serve",
        "--config",
        "timeout-smoke.conf",
        "--listen",
        "127.0.0.1:18000",
        "--connection-timeout-ms",
        NULL,
    };
    char *missing_max_connections[] = {
        "timeout-smoke-service",
        "--serve",
        "--config",
        "timeout-smoke.conf",
        "--listen",
        "127.0.0.1:18000",
        "--max-connections",
        NULL,
    };

    return msconnector_http_authorization_service_main(3, missing_config,
               &smoke_profile) == 2 &&
        msconnector_http_authorization_service_main(5, missing_listen,
               &smoke_profile) == 2 &&
        msconnector_http_authorization_service_main(7, missing_max_requests,
               &smoke_profile) == 2 &&
        msconnector_http_authorization_service_main(7, missing_timeout,
               &smoke_profile) == 2 &&
        msconnector_http_authorization_service_main(7, missing_max_connections,
               &smoke_profile) == 2;
}

static int max_connections_option_has_result(const char *value, int expected_result) {
    char value_argument[64];
    char *argv[] = {
        "timeout-smoke-service",
        "--check-config",
        "--config",
        "timeout-smoke.conf",
        "--max-connections",
        value_argument,
        NULL,
    };
    const int written = value == NULL
        ? -1
        : snprintf(value_argument, sizeof(value_argument), "%s", value);
    if (written < 0 || (size_t)written >= sizeof(value_argument)) {
        return 0;
    }
    return msconnector_http_authorization_service_main(6, argv, &smoke_profile) ==
        expected_result;
}

static int accepts_max_connection_boundaries(void) {
    return max_connections_option_has_result("1", 0) &&
        max_connections_option_has_result("64", 0);
}

static int rejects_unknown_or_invalid_option_values(void) {
    char *unknown_option[] = {
        "timeout-smoke-service",
        "--serve",
        "--config",
        "timeout-smoke.conf",
        "--listen",
        "127.0.0.1:18000",
        "--unknown",
        NULL,
    };
    char *invalid_max_requests[] = {
        "timeout-smoke-service",
        "--serve",
        "--config",
        "timeout-smoke.conf",
        "--listen",
        "127.0.0.1:18000",
        "--max-requests",
        "not-a-number",
        NULL,
    };
    char *invalid_max_connections[] = {
        "timeout-smoke-service",
        "--serve",
        "--config",
        "timeout-smoke.conf",
        "--listen",
        "127.0.0.1:18000",
        "--max-connections",
        "0",
        NULL,
    };
    char *excessive_max_connections[] = {
        "timeout-smoke-service",
        "--serve",
        "--config",
        "timeout-smoke.conf",
        "--listen",
        "127.0.0.1:18000",
        "--max-connections",
        "65",
        NULL,
    };
    return msconnector_http_authorization_service_main(7, unknown_option,
               &smoke_profile) == 2 &&
        msconnector_http_authorization_service_main(8, invalid_max_requests,
               &smoke_profile) == 2 &&
        msconnector_http_authorization_service_main(8, invalid_max_connections,
               &smoke_profile) == 2 &&
        msconnector_http_authorization_service_main(8, excessive_max_connections,
               &smoke_profile) == 2 &&
        max_connections_option_has_result("-1", 2) &&
        max_connections_option_has_result("184467440737095516160000000000", 2) &&
        max_connections_option_has_result("1x", 2) &&
        max_connections_option_has_result("", 2);
}

static int run_selected_active_case(int argc, char **argv,
        const char *incomplete_headers, const char *incomplete_body) {
    if (argc == 3 && strcmp(argv[1], "--active-case") == 0) {
        if (strcmp(argv[2], "incomplete-headers") == 0) {
            return run_stalled_request_case("incomplete_headers", incomplete_headers) ? 0 : 1;
        }
        if (strcmp(argv[2], "incomplete-body") == 0) {
            return run_stalled_request_case("incomplete_body", incomplete_body) ? 0 : 1;
        }
    }
    (void)fprintf(stderr, "expected --active-case incomplete-headers|incomplete-body\n");
    return 2;
}

int main(int argc, char **argv) {
    const char incomplete_headers[] =
        "GET /stall HTTP/1.1\r\nHost: slow.example\r\n";
    const char incomplete_body[] =
        "POST /stall HTTP/1.1\r\nHost: slow.example\r\nContent-Length: 4\r\n\r\nx";

    (void)signal(SIGPIPE, SIG_IGN);
    if (argc != 1) {
        return run_selected_active_case(argc, argv, incomplete_headers, incomplete_body);
    }
    msconnector_test_request_stream_stubs_smoke();
    if (!rejects_unbounded_timeout_override()) {
        (void)fprintf(stderr, "timeout override of zero was unexpectedly accepted\n");
        return 1;
    }
    if (!rejects_missing_option_values()) {
        (void)fprintf(stderr, "missing option value was unexpectedly accepted\n");
        return 1;
    }
    if (!rejects_unknown_or_invalid_option_values()) {
        (void)fprintf(stderr, "invalid option was unexpectedly accepted\n");
        return 1;
    }
    if (!accepts_max_connection_boundaries()) {
        (void)fprintf(stderr, "valid max-connections boundary was unexpectedly rejected\n");
        return 1;
    }
    if (!run_redirect_profile_case("envoy_redirect", &envoy_redirect_profile, 1) ||
        !run_redirect_profile_case("traefik_redirect", &traefik_redirect_profile, 0)) {
        return 1;
    }
    if (!run_parallel_request_case() ||
        !run_overload_recovery_case() ||
        !run_default_capacity_recovery_case() ||
        !run_sequential_request_case() ||
        !run_parallel_complete_request_case() ||
        !run_abrupt_disconnect_case() ||
        !run_stalled_shutdown_case() ||
        !run_stalled_request_case("incomplete_headers", incomplete_headers) ||
        !run_stalled_request_case("incomplete_body", incomplete_body) ||
        !run_dripping_header_case()) {
        return 1;
    }
    (void)printf("http_authorization_service_timeout_smoke: pass\n");
    return 0;
}
