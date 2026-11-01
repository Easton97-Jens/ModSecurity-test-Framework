/*
 * Regression for bounded shutdown when a detached authorization worker is
 * held inside an uninterruptible runtime operation.  Build this source with
 * common/runtime/http_authorization_service.c and the Common C sources, then
 * run it under ASan/UBSan.  The service entry point must return after its two
 * configured grace periods without invalidating worker-owned state; the final
 * worker performs the deferred release after the test unblocks the runtime.
 */
#define _POSIX_C_SOURCE 200809L

#include "common/runtime/http_authorization_service.h"
#include "common/runtime/msconnector_runtime.h"

#include "msconnector/decision.h"
#include "msconnector/error.h"
#include "msconnector/request.h"
#include "msconnector/request_mapper_contract.h"
#include "fixtures/http_authorization_runtime_lifecycle_stubs.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define TEST_TIMEOUT_MS 25UL
#define TEST_WAIT_SECONDS 3L
#define TEST_INTEGRATION_MODE "detached-worker-smoke"

struct msconnector_runtime {
    char integration_mode[sizeof(TEST_INTEGRATION_MODE)];
    const msconnector_transaction_profile *transaction_profile;
    int placeholder;
};

static msconnector_runtime fake_runtime = {0};
static pthread_mutex_t test_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t test_changed = PTHREAD_COND_INITIALIZER;
static int mapper_entered = 0;
static int runtime_entered = 0;
static int runtime_release = 0;
static int runtime_destroyed = 0;
static int server_done = 0;
static const msconnector_transaction_profile test_transaction_profile = {
    1U,
    "detached-worker-smoke",
    "detached-worker-smoke",
    "detached-worker-smoke",
    1U,
    1U,
    1,
    1,
};

static void clear_error(char *error, size_t error_len) {
    if (error != NULL && error_len > 0U) {
        error[0] = '\0';
    }
}

static int wait_for_flag(const int *flag) {
    struct timespec deadline;
    int result = 0;
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0 ||
        pthread_mutex_lock(&test_lock) != 0) {
        return 0;
    }
    deadline.tv_sec += TEST_WAIT_SECONDS;
    while (*flag == 0 && result == 0) {
        result = pthread_cond_timedwait(&test_changed, &test_lock, &deadline);
    }
    result = *flag != 0;
    (void)pthread_mutex_unlock(&test_lock);
    return result;
}
static void unblock_runtime(void) {
    if (pthread_mutex_lock(&test_lock) == 0) {
        runtime_release = 1;
        (void)pthread_cond_broadcast(&test_changed);
        (void)pthread_mutex_unlock(&test_lock);
    }
}

static int runtime_setup_was_configured(void) {
    int result = 0;
    if (pthread_mutex_lock(&test_lock) == 0) {
        result = strcmp(fake_runtime.integration_mode, TEST_INTEGRATION_MODE) == 0 &&
            fake_runtime.transaction_profile == &test_transaction_profile;
        (void)pthread_mutex_unlock(&test_lock);
    }
    return result;
}

static int runtime_has_not_entered(void) {
    int result = 0;
    if (pthread_mutex_lock(&test_lock) == 0) {
        result = runtime_entered == 0;
        (void)pthread_mutex_unlock(&test_lock);
    }
    return result;
}

static int mapper_has_not_entered(void) {
    int result = 0;
    if (pthread_mutex_lock(&test_lock) == 0) {
        result = mapper_entered == 0;
        (void)pthread_mutex_unlock(&test_lock);
    }
    return result;
}

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

/* The fixture has no production engine, but it must still reject a service
 * startup that fails to supply the exact adapter-owned #344 configuration. */
int msconnector_runtime_set_event_integration_mode(
    msconnector_runtime *runtime,
    const char *integration_mode) {
    if (runtime != &fake_runtime || integration_mode == NULL ||
        strcmp(integration_mode, TEST_INTEGRATION_MODE) != 0 ||
        pthread_mutex_lock(&test_lock) != 0) {
        return 0;
    }
    memcpy(runtime->integration_mode, integration_mode,
        sizeof(runtime->integration_mode));
    (void)pthread_mutex_unlock(&test_lock);
    return 1;
}

int msconnector_runtime_set_transaction_profile(
    msconnector_runtime *runtime,
    const msconnector_transaction_profile *transaction_profile) {
    if (runtime != &fake_runtime || transaction_profile == NULL ||
        transaction_profile->profile_id != 1U ||
        transaction_profile->profile_name == NULL ||
        transaction_profile->connector_id == NULL ||
        transaction_profile->host_adapter_id == NULL ||
        strcmp(transaction_profile->profile_name, "detached-worker-smoke") != 0 ||
        strcmp(transaction_profile->connector_id, "detached-worker-smoke") != 0 ||
        strcmp(transaction_profile->host_adapter_id, "detached-worker-smoke") != 0 ||
        transaction_profile->direct_phase_mask != 1U ||
        transaction_profile->strict_post_commit_action == 0 ||
        transaction_profile->private_default_binding == 0 ||
        pthread_mutex_lock(&test_lock) != 0) {
        return 0;
    }
    runtime->transaction_profile = transaction_profile;
    (void)pthread_mutex_unlock(&test_lock);
    return 1;
}

int msconnector_runtime_error_log_enabled(const msconnector_runtime *runtime) {
    /* The fake runtime explicitly has diagnostics disabled; requests and
     * response payloads must not be emitted by this fixture. */
    (void)runtime;
    return 0;
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
    clear_error(error, error_len);
    if (pthread_mutex_lock(&test_lock) != 0) {
        return 0;
    }
    memset(&fake_runtime, 0, sizeof(fake_runtime));
    (void)pthread_mutex_unlock(&test_lock);
    *out = &fake_runtime;
    return 1;
}

void msconnector_runtime_destroy(msconnector_runtime **runtime) {
    if (pthread_mutex_lock(&test_lock) == 0) {
        ++runtime_destroyed;
        (void)pthread_cond_broadcast(&test_changed);
        (void)pthread_mutex_unlock(&test_lock);
    }
    if (runtime != NULL) {
        *runtime = NULL;
    }
}

void msconnector_runtime_request_contract(
    const msconnector_runtime *runtime,
    msconnector_request_mapper_contract *contract) {
    (void)runtime;
    msconnector_request_mapper_contract_init(contract);
    contract->max_header_count = 16U;

}


size_t msconnector_runtime_total_header_limit(const msconnector_runtime *runtime) {
    (void)runtime;
    return 4096U;
}

size_t msconnector_runtime_header_count_limit(const msconnector_runtime *runtime) {
    (void)runtime;
    return 16U;
}

int msconnector_runtime_transaction_begin_request_stream(
    msconnector_runtime *runtime,
    const msconnector_request *request,
    const char *host_request_id,
    msconnector_runtime_transaction **out,
    msconnector_decision *decision,
    msconnector_error *error) {
    msconnector_runtime_transaction *transaction;
    (void)runtime;
    (void)host_request_id;
    if (request == NULL || out == NULL || decision == NULL ||
        request->method == NULL || request->uri == NULL ||
        strcmp(request->method, "GET") != 0 || strcmp(request->uri, "/ok") != 0 ||
        pthread_mutex_lock(&test_lock) != 0) {
        return 0;
    }
    runtime->placeholder = 1;
    runtime_entered = 1;
    (void)pthread_cond_broadcast(&test_changed);
    while (runtime_release == 0) {
        if (pthread_cond_wait(&test_changed, &test_lock) != 0) {
            (void)pthread_mutex_unlock(&test_lock);
            return 0;
        }
    }
    (void)pthread_mutex_unlock(&test_lock);
    transaction = calloc(1U, sizeof(*transaction));
    if (transaction == NULL) {
        return 0;
    }
    *out = transaction;
    msconnector_decision_set_allow(decision);
    if (error != NULL) {
        msconnector_error_init(error);
    }
    return 1;
}

int msconnector_runtime_transaction_finish(
    msconnector_runtime_transaction *transaction,
    msconnector_error *error) {
    if (transaction == NULL) {
        return 0;
    }
    transaction->finished = 1;
    if (error != NULL) {
        msconnector_error_init(error);
    }
    return 1;
}

const char *msconnector_runtime_transaction_id(
    const msconnector_runtime_transaction *transaction) {
    return transaction == NULL ? NULL : "detached-worker-smoke";
}

static int map_request(
    const msconnector_generic_request_source *source,
    const msconnector_request_mapper_contract *contract,
    msconnector_request *request,
    char *error,
    size_t error_len) {
    (void)contract;
    if (source == NULL || request == NULL || source->method == NULL ||
        source->uri == NULL) {
        if (error != NULL && error_len > 0U) {
            (void)snprintf(error, error_len, "%s", "invalid smoke request");
        }
        return 0;
    }
    if (pthread_mutex_lock(&test_lock) != 0) {
        if (error != NULL && error_len > 0U) {
            (void)snprintf(error, error_len, "%s", "could not record mapper entry");
        }
        return 0;
    }
    ++mapper_entered;
    (void)pthread_cond_broadcast(&test_changed);
    (void)pthread_mutex_unlock(&test_lock);
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

typedef struct server_thread_args {
    char listen_spec[64];
    int result;
    const msconnector_http_authorization_profile *profile;
} server_thread_args;

static void *run_service(void *argument) {
    server_thread_args *args = argument;
    char *argv[] = {
        "detached-worker-smoke",
        "--serve",
        "--config",
        "ignored.conf",
        "--listen",
        args->listen_spec,
        "--max-requests",
        "3",
        "--connection-timeout-ms",
        "25",
        NULL,
    };
    args->result = msconnector_http_authorization_service_main(10, argv,
        args->profile);
    if (pthread_mutex_lock(&test_lock) == 0) {
        server_done = 1;
        (void)pthread_cond_broadcast(&test_changed);
        (void)pthread_mutex_unlock(&test_lock);
    }
    return NULL;
}

static int reserve_loopback_port(unsigned short *port) {
    struct sockaddr_in address = {0};
    socklen_t address_size = sizeof(address);
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        return 0;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(socket_fd, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        getsockname(socket_fd, (struct sockaddr *)&address, &address_size) != 0) {
        (void)close(socket_fd);
        return 0;
    }
    *port = ntohs(address.sin_port);
    return close(socket_fd) == 0;
}

static int connect_loopback(unsigned short port) {
    struct sockaddr_in address = {0};
    int socket_fd;
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for (int attempt = 0; attempt < 100; ++attempt) {
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd >= 0 &&
            connect(socket_fd, (const struct sockaddr *)&address, sizeof(address)) == 0) {
            return socket_fd;
        }
        if (socket_fd >= 0) {
            (void)close(socket_fd);
        }
        {
            const struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000L};
            (void)nanosleep(&delay, NULL);
        }
    }
    return -1;
}

static int response_starts_with(int socket_fd, const char *expected) {
    struct timeval timeout = {.tv_sec = TEST_WAIT_SECONDS, .tv_usec = 0};
    char response[64];
    const size_t expected_size = expected == NULL ? 0U : strlen(expected);
    size_t used = 0U;

    if (expected_size == 0U || expected_size > sizeof(response) ||
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        return 0;
    }
    while (used < expected_size) {
        const ssize_t received = recv(socket_fd, response + used,
            expected_size - used, 0);
        if (received <= 0) {
            return 0;
        }
        used += (size_t)received;
    }
    return memcmp(response, expected, expected_size) == 0;
}

static int rejected_request_is_preserved(unsigned short port,
    const char *request, size_t request_size, const char *failure_message) {
    int client_fd = connect_loopback(port);
    int valid = client_fd >= 0;

    if (valid) {
        valid = send(client_fd, request, request_size, 0) == (ssize_t)request_size &&
            response_starts_with(client_fd, "HTTP/1.1 400") &&
            mapper_has_not_entered() && runtime_has_not_entered();
    }
    if (client_fd >= 0) {
        (void)close(client_fd);
    }
    if (!valid) {
        (void)fprintf(stderr, "%s\n", failure_message);
    }
    return valid;
}

static int start_test_service(unsigned short *port, server_thread_args *args,
    pthread_t *server) {
    if (!reserve_loopback_port(port) ||
        snprintf(args->listen_spec, sizeof(args->listen_spec), "127.0.0.1:%u",
            (unsigned int)*port) < 0 ||
        pthread_create(server, NULL, run_service, args) != 0) {
        (void)fprintf(stderr, "could not start detached-worker service\n");
        return 0;
    }
    return 1;
}

static int rejected_host_requests_are_preserved(unsigned short port,
    char *oversized_host_request, size_t oversized_host_request_size) {
    static const char missing_host_request[] = "GET /ok HTTP/1.1\r\n"
        "Connection: close\r\n\r\n";
    static const char oversized_host_prefix[] = "GET /ok HTTP/1.1\r\nHost: ";
    static const char oversized_host_suffix[] = "\r\nConnection: close\r\n\r\n";

    memcpy(oversized_host_request, oversized_host_prefix,
        sizeof(oversized_host_prefix) - 1U);
    memset(oversized_host_request + sizeof(oversized_host_prefix) - 1U,
        'a', 1024U);
    memcpy(oversized_host_request + sizeof(oversized_host_prefix) - 1U + 1024U,
        oversized_host_suffix, sizeof(oversized_host_suffix) - 1U);

    if (!rejected_request_is_preserved(port, missing_host_request,
            sizeof(missing_host_request) - 1U,
            "missing Host was not rejected before mapping")) {
        return 0;
    }
    return rejected_request_is_preserved(port, oversized_host_request,
        oversized_host_request_size,
        "oversized Host was not rejected before mapping");
}

static int submit_valid_request_and_join(unsigned short port,
    const char *request, size_t request_size, const server_thread_args *args,
    pthread_t server, int *client_fd, int *server_joined) {
    *client_fd = connect_loopback(port);
    if (!runtime_setup_was_configured()) {
        (void)fprintf(stderr, "runtime profile setup was not enforced\n");
        return 0;
    }
    if (*client_fd < 0 ||
        send(*client_fd, request, request_size, 0) != (ssize_t)request_size ||
        !wait_for_flag(&runtime_entered) || pthread_join(server, NULL) != 0) {
        (void)fprintf(stderr, "service did not reach bounded deferred shutdown\n");
        return 0;
    }
    *server_joined = 1;
    if (args->result != 1) {
        (void)fprintf(stderr, "service did not report deferred shutdown\n");
        return 0;
    }
    return 1;
}

static int deferred_cleanup_finished(void) {
    if (!wait_for_flag(&runtime_destroyed)) {
        (void)fprintf(stderr, "deferred worker cleanup did not finish\n");
        return 0;
    }
    /* The last worker owns the deferred release claim.  Give any accidental
     * duplicate release a chance to surface before declaring the regression
     * fixed; a single Common runtime destroy is the observable contract. */
    {
        const struct timespec delay = {.tv_sec = 0, .tv_nsec = 50000000L};
        (void)nanosleep(&delay, NULL);
    }
    if (runtime_destroyed != 1) {
        (void)fprintf(stderr, "deferred cleanup released the runtime more than once\n");
        return 0;
    }
    return 1;
}

int main(void) {
    msconnector_test_request_stream_stubs_smoke();
    static const char request[] = "GET /ok HTTP/1.1\r\nHost: smoke.test\r\n"
        "Connection: close\r\n\r\n";
    char oversized_host_request[sizeof("GET /ok HTTP/1.1\r\nHost: ") - 1U + 1024U +
        sizeof("\r\nConnection: close\r\n\r\n") - 1U];
    const size_t oversized_host_request_size = sizeof(oversized_host_request);
    char *connector_name = strdup("detached-worker-smoke");
    char *integration_mode = strdup(TEST_INTEGRATION_MODE);
    char *original_uri_header = strdup("X-Original-Uri");
    const char **original_uri_headers = calloc(1U, sizeof(*original_uri_headers));
    msconnector_http_authorization_profile profile = {0};
    server_thread_args args = {{0}, -1, NULL};
    unsigned short port = 0U;
    pthread_t server;
    int client_fd = -1;
    int server_started = 0;
    int server_joined = 0;
    int result = 1;

    if (connector_name == NULL || integration_mode == NULL ||
        original_uri_header == NULL || original_uri_headers == NULL) {
        (void)fprintf(stderr, "could not allocate detached-worker profile\n");
        goto done;
    }
    original_uri_headers[0] = original_uri_header;
    profile.connector_name = connector_name;
    profile.integration_mode = integration_mode;
    profile.transaction_profile = &test_transaction_profile;
    profile.original_uri_headers = original_uri_headers;
    profile.original_uri_header_count = 1U;
    profile.map_request = map_request;
    profile.map_response = NULL;
    args.profile = &profile;
    if (runtime_setup_was_configured()) {
        (void)fprintf(stderr, "runtime fixture was configured before service startup\n");
        goto done;
    }
    if (!start_test_service(&port, &args, &server)) {
        goto done;
    }
    server_started = 1;
    if (!rejected_host_requests_are_preserved(port, oversized_host_request,
            oversized_host_request_size)) {
        goto done;
    }
    if (!submit_valid_request_and_join(port, request, sizeof(request) - 1U,
            &args, server, &client_fd, &server_joined)) {
        goto done;
    }
    (void)close(client_fd);
    client_fd = -1;
    /* The entry point has returned. A detached worker must not retain caller-
     * owned profile strings or the original-header pointer array. */
    free(connector_name);
    connector_name = NULL;
    free(integration_mode);
    integration_mode = NULL;
    free(original_uri_header);
    original_uri_header = NULL;
    free(original_uri_headers);
    original_uri_headers = NULL;
    unblock_runtime();
    if (!deferred_cleanup_finished()) {
        goto done;
    }
    result = 0;

done:
    unblock_runtime();
    if (client_fd >= 0) {
        (void)close(client_fd);
    }
    if (server_started && !server_joined && wait_for_flag(&server_done) &&
        pthread_join(server, NULL) == 0) {
        server_joined = 1;
    }
    if (!server_started || server_joined) {
        free(connector_name);
        free(integration_mode);
        free(original_uri_header);
        free(original_uri_headers);
    }
    if (result == 0) {
        (void)puts("http authorization detached-worker smoke: passed");
    }
    return result;
}
