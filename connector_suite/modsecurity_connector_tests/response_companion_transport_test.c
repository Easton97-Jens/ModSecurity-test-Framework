#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "common/runtime/msconnector_runtime.h"
#include "common/runtime/response_companion_client.h"
#include "common/runtime/response_companion_transport.h"
#include "connectors/profile_registry.h"
#include "tests/transaction_phase_test_support.h"

#define TEST_PATH_SIZE 4096U
#define TEST_FRAME_HEADER_SIZE 12U
#define TEST_RESULT_SIZE 12U
#ifndef MSCONNECTOR_TEST_TEMPORARY_DIRECTORY
#define MSCONNECTOR_TEST_TEMPORARY_DIRECTORY "/tmp"
#endif
#define TEST_TRANSPORT_OPTIONS(connector, socket, headers, bytes, timeout) \
    (&(msconnector_response_companion_transport_options){ \
        (connector), (socket), (headers), (bytes), (timeout) })

static char test_private_root[TEST_PATH_SIZE];

static const char *test_private_directory(void)
{
    struct stat directory_stat;

    if (test_private_root[0] == '\0') {
        assert(snprintf(test_private_root, sizeof(test_private_root),
            "%s/msconnector-response-transport-XXXXXX",
            MSCONNECTOR_TEST_TEMPORARY_DIRECTORY) > 0);
        assert(mkdtemp(test_private_root) != NULL);
        assert(stat(test_private_root, &directory_stat) == 0);
        assert(directory_stat.st_uid == geteuid());
        assert((directory_stat.st_mode & 0777U) == 0700U);
    }
    return test_private_root;
}

enum test_opcode {
    TEST_CLAIM = 1U,
    TEST_RESPONSE_HEADERS = 2U,
    TEST_RESPONSE_BODY = 3U,
    TEST_RESPONSE_EOS = 4U,
    TEST_COMMIT = 5U,
    TEST_CANCEL = 6U,
    TEST_RELEASE = 7U,
    TEST_OUTCOME = 8U,
    TEST_RESULT = 128U
};

typedef struct test_result {
    int success;
    unsigned char decision;
    unsigned short status;
    unsigned short error_code;
} test_result;

typedef struct parallel_client {
    const char *socket_path;
    const char *handle;
    int result;
} parallel_client;

typedef struct transport_exchange_call {
    int socket_fd;
    unsigned char opcode;
    const unsigned char *payload;
    size_t payload_size;
    test_result result;
} transport_exchange_call;

typedef struct mock_backend_observation {
    size_t claims;
    size_t response_headers;
    size_t response_body_chunks;
    size_t response_body_bytes;
    size_t response_eos;
    size_t commits;
    size_t outcomes;
    size_t cancels;
    size_t releases;
    size_t failures;
    int active;
    msconnector_transaction_error_class last_failure;
} mock_backend_observation;

typedef struct mock_backend {
    pthread_mutex_t lock;
    const char *handle;
    int retain_terminal_opaque;
    int use_borrowed_decision;
    int accept_any_outcome;
    int pause_headers;
    atomic_int pause_cancel;
    atomic_int cancel_started;
    char borrowed_rule[64];
    atomic_int callback_active;
    atomic_int expire_during_callback;
    atomic_size_t expires;
    int response_headers;
    int committed;
    int response_eos;
    mock_backend_observation observation;
} mock_backend;

typedef struct mock_transport_setup {
    const char *handle;
    const char *directory_template;
    const char *label;
    size_t max_header_count;
    size_t max_header_bytes;
    unsigned timeout_ms;
    void (*expire)(void *, uint64_t);
} mock_transport_setup;

#define TEST_MOCK_TRANSPORT_SETUP(handle_value, directory_value, label_value, \
    timeout_value, expire_value) \
    (&(mock_transport_setup){ \
        .handle = (handle_value), .directory_template = (directory_value), \
        .label = (label_value), \
        .max_header_count = 32U, .max_header_bytes = 64U, \
        .timeout_ms = (timeout_value), \
        .expire = (expire_value) })

typedef struct transport_stop_call {
    msconnector_response_companion_transport *transport;
    msconnector_error error;
    int result;
} transport_stop_call;

static void write_u16(unsigned char *value, unsigned short number)
{
    value[0] = (unsigned char)(number >> 8U);
    value[1] = (unsigned char)number;
}

static void write_u32(unsigned char *value, uint32_t number)
{
    value[0] = (unsigned char)(number >> 24U);
    value[1] = (unsigned char)(number >> 16U);
    value[2] = (unsigned char)(number >> 8U);
    value[3] = (unsigned char)number;
}

static unsigned short read_u16(const unsigned char *value)
{
    return (unsigned short)(((unsigned short)value[0] << 8U) |
        (unsigned short)value[1]);
}

static uint32_t read_u32(const unsigned char *value)
{
    return ((uint32_t)value[0] << 24U) |
        ((uint32_t)value[1] << 16U) |
        ((uint32_t)value[2] << 8U) |
        (uint32_t)value[3];
}

static void sleep_milliseconds(long milliseconds)
{
    struct timespec delay;

    delay.tv_sec = milliseconds / 1000L;
    delay.tv_nsec = (milliseconds % 1000L) * 1000000L;
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
        /* Retry with the remaining delay after an interrupt. */
    }
}

static void wait_for_listener_stop(const msconnector_response_companion_transport *transport)
{
    assert(transport != NULL);
    for (size_t attempt = 0U; attempt < 500U && atomic_load_explicit(
            &transport->listener.running, memory_order_acquire); ++attempt) {
        sleep_milliseconds(1L);
    }
    assert(!atomic_load_explicit(&transport->listener.running, memory_order_acquire));
}

static int write_all(int socket_fd, const unsigned char *data, size_t size)
{
    size_t offset = 0U;

    while (offset < size) {
        const ssize_t written = send(socket_fd, data + offset, size - offset,
            MSG_NOSIGNAL);
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        return 0;
    }
    return 1;
}

static int read_all(int socket_fd, unsigned char *data, size_t size)
{
    size_t offset = 0U;

    while (offset < size) {
        const ssize_t received = recv(socket_fd, data + offset, size - offset, 0);
        if (received > 0) {
            offset += (size_t)received;
            continue;
        }
        if (received < 0 && errno == EINTR) {
            continue;
        }
        return 0;
    }
    return 1;
}

static int connect_client(const char *socket_path)
{
    struct sockaddr_un address;
    struct timeval timeout;
    int socket_fd;
    size_t size;

    assert(socket_path != NULL);
    size = strlen(socket_path);
    assert(size > 0U && size < sizeof(address.sun_path));
    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(socket_fd >= 0);
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    assert(setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
        sizeof(timeout)) == 0);
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_path, size + 1U);
    assert(connect(socket_fd, (const struct sockaddr *)&address,
        sizeof(address)) == 0);
    return socket_fd;
}

static int exchange(int socket_fd, unsigned char opcode,
    const unsigned char *payload, size_t payload_size, test_result *result)
{
    unsigned char header[TEST_FRAME_HEADER_SIZE];
    unsigned char response_header[TEST_FRAME_HEADER_SIZE];
    unsigned char *response = NULL;
    uint32_t response_size;
    const size_t max_payload_size = opcode == TEST_RESPONSE_HEADERS ?
        MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_MAX_RESPONSE_HEADER_FRAME :
        MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_MAX_FRAME;
    int success = 0;

    if (payload_size > max_payload_size ||
        (payload_size > 0U && payload == NULL) || result == NULL) {
        return 0;
    }
    memset(result, 0, sizeof(*result));
    memset(header, 0, sizeof(header));
    memcpy(header, "MRC1", 4U);
    header[4] = MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_PROTOCOL_VERSION;
    header[5] = opcode;
    write_u32(header + 8U, (uint32_t)payload_size);
    if (!write_all(socket_fd, header, sizeof(header)) ||
        (payload_size > 0U && !write_all(socket_fd, payload, payload_size)) ||
        !read_all(socket_fd, response_header, sizeof(response_header)) ||
        memcmp(response_header, "MRC1", 4U) != 0 || response_header[4] !=
            MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_PROTOCOL_VERSION ||
        response_header[5] != TEST_RESULT || response_header[6] != 0U ||
        response_header[7] != 0U) {
        return 0;
    }
    response_size = read_u32(response_header + 8U);
    if (response_size < TEST_RESULT_SIZE || response_size >
        MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_MAX_FRAME) {
        return 0;
    }
    response = calloc(response_size, 1U);
    if (response != NULL && read_all(socket_fd, response, response_size) &&
        response[0] == opcode && response[3] == 0U &&
        TEST_RESULT_SIZE + read_u16(response + 8U) + read_u16(response + 10U) ==
            response_size) {
        result->success = response[1] == 0U;
        result->decision = response[2];
        result->status = read_u16(response + 4U);
        result->error_code = read_u16(response + 6U);
        success = 1;
    }
    free(response);
    return success;
}

static size_t build_headers(unsigned char *payload, size_t payload_size,
    int status, const char *name, const char *value)
{
    static const char version[] = "HTTP/1.1";
    const size_t name_size = name == NULL ? 0U : strlen(name);
    const size_t value_size = value == NULL ? 0U : strlen(value);
    const size_t required = 2U + 2U + sizeof(version) - 1U + 2U +
        (name == NULL ? 0U : 2U + name_size + 2U + value_size);
    size_t offset = 0U;

    if (payload == NULL || required > payload_size || status < 100 || status > 999 ||
        (name != NULL && value == NULL)) {
        return 0U;
    }
    write_u16(payload + offset, (unsigned short)status);
    offset += 2U;
    write_u16(payload + offset, (unsigned short)(sizeof(version) - 1U));
    offset += 2U;
    memcpy(payload + offset, version, sizeof(version) - 1U);
    offset += sizeof(version) - 1U;
    write_u16(payload + offset, name == NULL ? 0U : 1U);
    offset += 2U;
    if (name != NULL) {
        write_u16(payload + offset, (unsigned short)name_size);
        offset += 2U;
        memcpy(payload + offset, name, name_size);
        offset += name_size;
        write_u16(payload + offset, (unsigned short)value_size);
        offset += 2U;
        memcpy(payload + offset, value, value_size);
        offset += value_size;
    }
    return offset;
}

static size_t build_repeated_headers(unsigned char *payload, size_t payload_size,
    int status, size_t header_count)
{
    static const char version[] = "HTTP/1.1";
    const size_t fixed_size = 2U + 2U + sizeof(version) - 1U + 2U;
    size_t offset = 0U;

    if (payload == NULL || status < 100 || status > 999 ||
        header_count > UINT16_MAX || payload_size < fixed_size ||
        header_count > (payload_size - fixed_size) / 6U) {
        return 0U;
    }
    write_u16(payload + offset, (unsigned short)status);
    offset += 2U;
    write_u16(payload + offset, (unsigned short)(sizeof(version) - 1U));
    offset += 2U;
    memcpy(payload + offset, version, sizeof(version) - 1U);
    offset += sizeof(version) - 1U;
    write_u16(payload + offset, (unsigned short)header_count);
    offset += 2U;
    for (size_t index = 0U; index < header_count; ++index) {
        write_u16(payload + offset, 1U);
        offset += 2U;
        payload[offset++] = 'x';
        write_u16(payload + offset, 1U);
        offset += 2U;
        payload[offset++] = 'v';
    }
    return offset;
}

static size_t build_aggregate_headers(unsigned char *payload, size_t payload_size,
    int status, size_t aggregate_bytes)
{
    static const char version[] = "HTTP/1.1";
    const size_t header_count = 8U;
    const size_t fixed_size = 2U + 2U + sizeof(version) - 1U + 2U;
    size_t value_bytes;
    size_t offset = 0U;

    if (payload == NULL || status < 100 || status > 999 ||
        aggregate_bytes < header_count ||
        aggregate_bytes > header_count * (1U + MSCONNECTOR_MAX_HEADER_VALUE_LENGTH) ||
        payload_size < fixed_size + 4U * header_count ||
        aggregate_bytes > payload_size - fixed_size - 4U * header_count) {
        return 0U;
    }
    write_u16(payload + offset, (unsigned short)status);
    offset += 2U;
    write_u16(payload + offset, (unsigned short)(sizeof(version) - 1U));
    offset += 2U;
    memcpy(payload + offset, version, sizeof(version) - 1U);
    offset += sizeof(version) - 1U;
    write_u16(payload + offset, (unsigned short)header_count);
    offset += 2U;
    value_bytes = aggregate_bytes - header_count;
    for (size_t index = 0U; index < header_count; ++index) {
        const size_t value_size = value_bytes / (header_count - index);

        assert(value_size <= MSCONNECTOR_MAX_HEADER_VALUE_LENGTH);
        write_u16(payload + offset, 1U);
        offset += 2U;
        payload[offset++] = 'x';
        write_u16(payload + offset, (unsigned short)value_size);
        offset += 2U;
        memset(payload + offset, 'v', value_size);
        offset += value_size;
        value_bytes -= value_size;
    }
    assert(value_bytes == 0U);
    return offset;
}

static int claim(int socket_fd, const char *handle)
{
    test_result result;

    if (handle == NULL) {
        return 0;
    }
    return exchange(socket_fd, TEST_CLAIM, (const unsigned char *)handle,
        strlen(handle), &result) && result.success;
}

static int finish_normal(int socket_fd)
{
    unsigned char headers[128];
    test_result result;
    const size_t header_size = build_headers(headers, sizeof(headers), 200, NULL, NULL);

    if (!exchange(socket_fd, TEST_RESPONSE_HEADERS, headers, header_size, &result) ||
        !result.success || result.decision != MSCONNECTOR_DECISION_KIND_ALLOW) {
        return 0;
    }
    if (!exchange(socket_fd, TEST_COMMIT, (const unsigned char *)"\1\0", 2U,
            &result) || !result.success) {
        return 0;
    }
    if (!exchange(socket_fd, TEST_RESPONSE_EOS, NULL, 0U, &result) ||
        !result.success) {
        return 0;
    }
    return exchange(socket_fd, TEST_RELEASE, NULL, 0U, &result) && result.success;
}

static void create_runtime_fixture(char config_path[TEST_PATH_SIZE],
    char event_path[TEST_PATH_SIZE], char rules_path[TEST_PATH_SIZE],
    size_t engine_response_limit, const char *engine_response_limit_action)
{
    const char *directory = test_private_directory();
    FILE *config;
    FILE *rules;
    int config_fd;
    int event_fd;
    int rules_fd;

    assert(snprintf(config_path, TEST_PATH_SIZE,
        "%s/msconnector-response-transport-config-XXXXXX", directory) > 0);
    assert(snprintf(event_path, TEST_PATH_SIZE,
        "%s/msconnector-response-transport-events-XXXXXX", directory) > 0);
    assert(snprintf(rules_path, TEST_PATH_SIZE,
        "%s/msconnector-response-transport-rules-XXXXXX", directory) > 0);
    config_fd = mkstemp(config_path);
    event_fd = mkstemp(event_path);
    rules_fd = mkstemp(rules_path);
    assert(config_fd >= 0 && event_fd >= 0 && rules_fd >= 0);
    assert(close(event_fd) == 0);
    rules = fdopen(rules_fd, "w");
    assert(rules != NULL);
    assert(fprintf(rules, "SecResponseBodyLimit %zu\nSecResponseBodyLimitAction %s\n",
        engine_response_limit, engine_response_limit_action) > 0);
    assert(fputs("SecRuleEngine On\n"
        "SecResponseBodyAccess On\n"
        "SecResponseBodyMimeType text/plain\n"
        "SecRule RESPONSE_HEADERS:X-Mrc-Block \"@streq yes\" "
        "\"id:1200901,phase:3,deny,status:451,log,t:none\"\n", rules) != EOF);
    assert(fclose(rules) == 0);
    config = fdopen(config_fd, "w");
    assert(config != NULL);
    assert(fprintf(config,
        "enabled=on\n"
        "rules_file=%s\n"
        "transaction_id_header=x-request-id\n"
        "request_body_mode=none\n"
        "response_body_mode=streaming\n"
        "phase4_mode=safe\n"
        "default_block_status=403\n"
        "default_error_status=500\n"
        "max_header_count=32\n"
        "max_header_name_size=128\n"
        "max_header_value_size=512\n"
        "max_total_header_bytes=4096\n"
        "max_event_json_bytes=16384\n"
        "event_path=%s\n", rules_path, event_path) > 0);
    assert(fclose(config) == 0);
}

static void handoff(msconnector_runtime *runtime,
    msconnector_runtime_response_companion_registry *registry,
    const char *transaction_id,
    char handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE])
{
    msconnector_runtime_transaction *transaction = NULL;
    msconnector_decision decision;
    msconnector_error error;

    assert(msconnector_test_begin_transaction(runtime, "/response-transport",
        transaction_id, &transaction, &decision, &error));
    assert(msconnector_runtime_response_companion_handoff_with_handle(registry,
        transaction, UINT64_C(3000), handle, &error));
    assert(strlen(handle) == MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE - 1U);
}

static void run_client_transport_interop_test(msconnector_runtime *runtime,
    msconnector_runtime_response_companion_registry *registry,
    const char *socket_path)
{
    char first_handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
    char second_handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
    char third_handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
    msconnector_response_companion_client client;
    msconnector_response_companion_result result;
    msconnector_response response;
    msconnector_header header;
    msconnector_error error;

    assert(runtime != NULL && registry != NULL && socket_path != NULL);
    memset(&client, 0, sizeof(client));
    memset(&result, 0, sizeof(result));
    memset(&response, 0, sizeof(response));
    memset(&header, 0, sizeof(header));
    response.status = 200;
    response.http_version = "HTTP/1.1";
    header.name = ":status";
    header.name_size = sizeof(":status") - 1U;
    header.value = "200";
    header.value_size = sizeof("200") - 1U;
    response.headers = &header;
    response.header_count = 1U;
    handoff(runtime, registry, "mrc1-client-interop-allow", first_handle);
    msconnector_error_init(&error);
    assert(msconnector_response_companion_client_open(&client, socket_path, 1000U,
        geteuid(), getegid(), &error));
    assert((fcntl(client.socket_fd, F_GETFD) & FD_CLOEXEC) != 0);
    assert(msconnector_response_companion_client_claim(&client, first_handle,
        &result, &error));
    assert(!msconnector_response_companion_client_release(&client, &result, &error));
    assert(error.code == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
    assert(msconnector_response_companion_client_response_headers(&client,
        &response, &result, &error));
    assert(result.decision == MSCONNECTOR_DECISION_KIND_ALLOW);
    assert(!msconnector_response_companion_client_release(&client, &result, &error));
    assert(!msconnector_response_companion_client_response_headers(&client,
        &response, &result, &error));
    assert(error.code == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
    assert(msconnector_response_companion_client_commit(&client, 1, 0, &result,
        &error));
    assert(msconnector_response_companion_client_body_eos(&client, &result,
        &error));
    assert(msconnector_response_companion_client_release(&client, &result,
        &error));

    header.name = "X-Mrc-Block";
    header.name_size = sizeof("X-Mrc-Block") - 1U;
    header.value = "yes";
    header.value_size = sizeof("yes") - 1U;
    handoff(runtime, registry, "mrc1-client-interop-deny", second_handle);
    assert(msconnector_response_companion_client_claim(&client, second_handle,
        &result, &error));
    assert(msconnector_response_companion_client_response_headers(&client,
        &response, &result, &error));
    assert(result.decision == MSCONNECTOR_DECISION_KIND_DENY);
    assert(!msconnector_response_companion_client_release(&client, &result, &error));
    assert(msconnector_response_companion_client_outcome(&client,
        MSCONNECTOR_DECISION_ACTION_DENY, 451, 0, &result, &error));
    assert(msconnector_response_companion_client_release(&client, &result,
        &error));
    assert(!client.claimed && !client.outcome_recorded && !client.precommit_terminal_outcome);
    handoff(runtime, registry, "mrc1-client-interop-typed-cancel", third_handle);
    assert(msconnector_response_companion_client_claim(&client, third_handle,
        &result, &error));
    assert(msconnector_response_companion_client_cancel_with_cause(&client,
        MSCONNECTOR_RESPONSE_COMPANION_CANCEL_ENGINE_TIMEOUT, &result, &error));
    msconnector_response_companion_result_destroy(&result);
    assert(msconnector_response_companion_client_close(&client, &error));
}

static void *parallel_normal(void *opaque)
{
    parallel_client *client = opaque;
    const int socket_fd = connect_client(client->socket_path);

    client->result = claim(socket_fd, client->handle) && finish_normal(socket_fd);
    assert(close(socket_fd) == 0);
    return NULL;
}

static void *transport_exchange_in_thread(void *opaque)
{
    transport_exchange_call *call = opaque;

    assert(call != NULL);
    assert(exchange(call->socket_fd, call->opcode, call->payload,
        call->payload_size, &call->result));
    assert(close(call->socket_fd) == 0);
    return NULL;
}

static void assert_metadata_only_events(const char *event_path)
{
    char contents[32768];
    FILE *event_file = fopen(event_path, "r");
    size_t size;

    assert(event_file != NULL);
    size = fread(contents, 1U, sizeof(contents) - 1U, event_file);
    assert(ferror(event_file) == 0);
    assert(fclose(event_file) == 0);
    contents[size] = '\0';
    assert(strstr(contents, "\"event\":\"protocol_error\"") != NULL);
    assert(strstr(contents, "\"event\":\"engine_timeout\"") != NULL);
    assert(strstr(contents, "\"event\":\"client_cancel\"") != NULL);
    assert(strstr(contents, "body_payload") == NULL);
}

/* This backend deliberately has no Runtime or native-engine dependency. It
 * proves that MRC1 owns only wire validation/ordering while an owner-bound
 * host can provide its own synchronized transaction queue behind the vtable. */
static int mock_backend_error(msconnector_error *error, const char *message)
{
    if (error != NULL) {
        msconnector_error_init(error);
        msconnector_error_set(error, MSCONNECTOR_ERROR_PROTOCOL, message,
            "response_companion_transport_test");
    }
    return 0;
}

static int mock_backend_session_is_active(const mock_backend *backend,
    const msconnector_response_companion_backend_session *session)
{
    return backend != NULL && session != NULL && session->opaque == backend &&
        backend->observation.active;
}

static int mock_backend_claim(void *opaque, const char *handle,
    msconnector_response_companion_backend_session *session,
    msconnector_error *error)
{
    mock_backend *backend = opaque;
    int result = 0;

    if (backend == NULL || handle == NULL || session == NULL) {
        return mock_backend_error(error, "mock backend claim arguments are invalid");
    }
    assert(pthread_mutex_lock(&backend->lock) == 0);
    if (!backend->observation.active && session->opaque == NULL &&
        strcmp(handle, backend->handle) == 0) {
        backend->observation.active = 1;
        backend->observation.claims++;
        backend->response_headers = 0;
        backend->committed = 0;
        backend->response_eos = 0;
        session->opaque = backend;
        result = 1;
    }
    assert(pthread_mutex_unlock(&backend->lock) == 0);
    return result ? 1 : mock_backend_error(error,
        "mock backend rejects unknown or already claimed handle");
}

static int mock_backend_process_response_headers(void *opaque,
    const msconnector_response_companion_backend_session *session,
    const msconnector_response *response, msconnector_decision *decision,
    msconnector_error *error)
{
    mock_backend *backend = opaque;
    int result = 0;
    int use_borrowed_decision = 0;

    if (backend == NULL || response == NULL || decision == NULL) {
        return mock_backend_error(error, "mock backend response headers are invalid");
    }
    if (backend->pause_headers) {
        atomic_store_explicit(&backend->callback_active, 1, memory_order_release);
        sleep_milliseconds(350L);
        atomic_store_explicit(&backend->callback_active, 0, memory_order_release);
    }
    assert(pthread_mutex_lock(&backend->lock) == 0);
    if (mock_backend_session_is_active(backend, session) &&
        !backend->response_headers &&
        response->status == 200) {
        backend->response_headers = 1;
        backend->observation.response_headers++;
        use_borrowed_decision = backend->use_borrowed_decision;
        result = 1;
    }
    assert(pthread_mutex_unlock(&backend->lock) == 0);
    if (!result) {
        return mock_backend_error(error, "mock backend response headers are out of order");
    }
    if (use_borrowed_decision) {
        msconnector_decision_set_deny(decision, 451, backend->borrowed_rule,
            "mock borrowed decision");
    } else {
        msconnector_decision_set_allow(decision);
    }
    decision->phase = MSCONNECTOR_PHASE_RESPONSE_HEADERS;
    return 1;
}

static int mock_backend_append_response_body_chunk(void *opaque,
    const msconnector_response_companion_backend_session *session,
    const unsigned char *data, size_t size, msconnector_error *error)
{
    mock_backend *backend = opaque;
    int result = 0;

    if (backend == NULL || (size > 0U && data == NULL)) {
        return mock_backend_error(error, "mock backend response body is invalid");
    }
    assert(pthread_mutex_lock(&backend->lock) == 0);
    if (mock_backend_session_is_active(backend, session) &&
        backend->response_headers && backend->committed &&
        !backend->response_eos) {
        backend->observation.response_body_chunks++;
        backend->observation.response_body_bytes += size;
        result = 1;
    }
    assert(pthread_mutex_unlock(&backend->lock) == 0);
    return result ? 1 : mock_backend_error(error,
        "mock backend response body is out of order");
}

static int mock_backend_finish_response_body(void *opaque,
    const msconnector_response_companion_backend_session *session,
    msconnector_decision *decision, msconnector_error *error)
{
    mock_backend *backend = opaque;
    int result = 0;

    if (backend == NULL || decision == NULL) {
        return mock_backend_error(error, "mock backend response eos is invalid");
    }
    assert(pthread_mutex_lock(&backend->lock) == 0);
    if (mock_backend_session_is_active(backend, session) &&
        backend->response_headers && backend->committed &&
        !backend->response_eos) {
        backend->response_eos = 1;
        backend->observation.response_eos++;
        result = 1;
    }
    assert(pthread_mutex_unlock(&backend->lock) == 0);
    if (!result) {
        return mock_backend_error(error, "mock backend response eos is out of order");
    }
    msconnector_decision_set_allow(decision);
    return 1;
}

static int mock_backend_set_response_commit_state(void *opaque,
    const msconnector_response_companion_backend_session *session, int headers_sent,
    int body_started, msconnector_error *error)
{
    mock_backend *backend = opaque;
    int result = 0;

    if (backend == NULL || !headers_sent || body_started) {
        return mock_backend_error(error, "mock backend commit state is invalid");
    }
    assert(pthread_mutex_lock(&backend->lock) == 0);
    if (mock_backend_session_is_active(backend, session) &&
        backend->response_headers && !backend->committed) {
        backend->committed = 1;
        backend->observation.commits++;
        result = 1;
    }
    assert(pthread_mutex_unlock(&backend->lock) == 0);
    return result ? 1 : mock_backend_error(error,
        "mock backend commit state is out of order");
}

static int mock_backend_record_host_action(void *opaque,
    const msconnector_response_companion_backend_session *session,
    const msconnector_response_companion_host_action *action,
    msconnector_error *error)
{
    mock_backend *backend = opaque;
    int result = 0;

    if (backend == NULL || action == NULL || action->decision == NULL ||
        action->transport_result == NULL) {
        return mock_backend_error(error, "mock backend host outcome is invalid");
    }
    assert(pthread_mutex_lock(&backend->lock) == 0);
    if (mock_backend_session_is_active(backend, session) &&
        (backend->accept_any_outcome || (backend->use_borrowed_decision &&
            action->decision->kind == MSCONNECTOR_DECISION_KIND_DENY &&
            action->actual_action == MSCONNECTOR_DECISION_ACTION_DENY &&
            action->visible_http_status == 451 && !action->connection_aborted &&
            strcmp(action->decision->rule_id, "borrowed-original") == 0 &&
            strcmp(action->transport_result, "http_status") == 0) ||
         (!backend->use_borrowed_decision &&
            action->decision->kind == MSCONNECTOR_DECISION_KIND_ALLOW &&
            action->actual_action == MSCONNECTOR_DECISION_ACTION_ALLOW &&
            action->visible_http_status == 200 && !action->connection_aborted &&
            strcmp(action->transport_result, "http_status") == 0))) {
        backend->observation.outcomes++;
        result = 1;
    }
    assert(pthread_mutex_unlock(&backend->lock) == 0);
    return result ? 1 : mock_backend_error(error,
        "mock backend host outcome is out of order");
}

static int mock_backend_cancel(void *opaque,
    msconnector_response_companion_backend_session *session, int upstream_disconnect,
    msconnector_error *error)
{
    mock_backend *backend = opaque;
    int result = 0;

    if (backend == NULL || upstream_disconnect) {
        return mock_backend_error(error, "mock backend cancel is invalid");
    }
    if (atomic_load_explicit(&backend->pause_cancel, memory_order_acquire)) {
        atomic_store_explicit(&backend->cancel_started, 1, memory_order_release);
        while (atomic_load_explicit(&backend->pause_cancel, memory_order_acquire)) {
            sleep_milliseconds(1L);
        }
    }
    assert(pthread_mutex_lock(&backend->lock) == 0);
    if (mock_backend_session_is_active(backend, session)) {
        backend->observation.active = 0;
        backend->observation.cancels++;
        if (!backend->retain_terminal_opaque) {
            session->opaque = NULL;
        }
        result = 1;
    }
    assert(pthread_mutex_unlock(&backend->lock) == 0);
    return result ? 1 : mock_backend_error(error,
        "mock backend cancel is out of order");
}

static int mock_backend_release(void *opaque,
    msconnector_response_companion_backend_session *session,
    msconnector_error *error)
{
    mock_backend *backend = opaque;
    int result = 0;

    if (backend == NULL) {
        return mock_backend_error(error, "mock backend release is invalid");
    }
    assert(pthread_mutex_lock(&backend->lock) == 0);
    if (mock_backend_session_is_active(backend, session) &&
        (backend->response_eos || (backend->accept_any_outcome &&
         backend->use_borrowed_decision && backend->response_headers))) {
        backend->observation.active = 0;
        backend->observation.releases++;
        if (!backend->retain_terminal_opaque) {
            session->opaque = NULL;
        }
        result = 1;
    }
    assert(pthread_mutex_unlock(&backend->lock) == 0);
    return result ? 1 : mock_backend_error(error,
        "mock backend release is out of order");
}

static void mock_backend_fail(void *opaque,
    msconnector_response_companion_backend_session *session,
    msconnector_transaction_error_class error_class)
{
    mock_backend *backend = opaque;

    if (backend == NULL) {
        return;
    }
    assert(pthread_mutex_lock(&backend->lock) == 0);
    backend->observation.active = 0;
    backend->observation.failures++;
    backend->observation.last_failure = error_class;
    if (session != NULL) {
        session->opaque = NULL;
    }
    assert(pthread_mutex_unlock(&backend->lock) == 0);
}

static void mock_backend_expire(void *opaque, uint64_t now_ms)
{
    mock_backend *backend = opaque;

    (void)now_ms;
    if (backend == NULL) {
        return;
    }
    if (atomic_load_explicit(&backend->callback_active, memory_order_acquire)) {
        atomic_store_explicit(&backend->expire_during_callback, 1,
            memory_order_release);
    }
    (void)atomic_fetch_add_explicit(&backend->expires, 1U, memory_order_relaxed);
}

static void mock_backend_snapshot(mock_backend *backend,
    mock_backend_observation *observation)
{
    assert(backend != NULL && observation != NULL);
    assert(pthread_mutex_lock(&backend->lock) == 0);
    *observation = backend->observation;
    assert(pthread_mutex_unlock(&backend->lock) == 0);
}

static void mock_backend_set_borrowed_rule(mock_backend *backend,
    const char *rule)
{
    assert(backend != NULL && rule != NULL);
    assert(pthread_mutex_lock(&backend->lock) == 0);
    assert(snprintf(backend->borrowed_rule, sizeof(backend->borrowed_rule), "%s",
        rule) > 0);
    assert(pthread_mutex_unlock(&backend->lock) == 0);
}

static void *stop_transport_in_thread(void *opaque)
{
    transport_stop_call *call = opaque;

    assert(call != NULL && call->transport != NULL);
    msconnector_error_init(&call->error);
    call->result = msconnector_response_companion_transport_stop(call->transport,
        &call->error);
    return NULL;
}

static void setup_mock_transport(msconnector_response_companion_transport *transport,
    msconnector_response_companion_backend *vtable, mock_backend *backend,
    const mock_transport_setup *setup,
    char socket_directory[TEST_PATH_SIZE],
    char socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE])
{
    assert(transport != NULL && vtable != NULL && backend != NULL);
    assert(setup != NULL && setup->handle != NULL);
    assert(setup->directory_template != NULL && setup->label != NULL);
    memset(vtable, 0, sizeof(*vtable));
    vtable->claim = mock_backend_claim;
    vtable->process_response_headers = mock_backend_process_response_headers;
    vtable->append_response_body_chunk = mock_backend_append_response_body_chunk;
    vtable->finish_response_body = mock_backend_finish_response_body;
    vtable->set_response_commit_state = mock_backend_set_response_commit_state;
    vtable->record_host_action = mock_backend_record_host_action;
    vtable->cancel = mock_backend_cancel;
    vtable->release = mock_backend_release;
    vtable->fail = mock_backend_fail;
    vtable->expire = setup->expire;
    backend->handle = setup->handle;
    vtable->context = backend;
    assert(pthread_mutex_init(&backend->lock, NULL) == 0);
    assert(snprintf(socket_directory, TEST_PATH_SIZE, "%s/%s",
        test_private_directory(), setup->directory_template) > 0);
    assert(mkdtemp(socket_directory) != NULL);
    assert(chmod(socket_directory, 0700) == 0);
    assert(snprintf(socket_path, MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE,
        "%s/s", socket_directory) > 0);
    msconnector_error error;
    msconnector_error_init(&error);
    assert(msconnector_response_companion_transport_init_with_backend(transport,
        vtable, TEST_TRANSPORT_OPTIONS(setup->label, socket_path,
            setup->max_header_count, setup->max_header_bytes,
            setup->timeout_ms), &error));
    assert(msconnector_response_companion_transport_start(transport, &error));
}

static void run_precommit_outcome_release_mismatch_test(void)
{
    static const char handle[] =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const msconnector_decision_action actions[] = {
        MSCONNECTOR_DECISION_ACTION_ALLOW, MSCONNECTOR_DECISION_ACTION_LOG_ONLY,
        MSCONNECTOR_DECISION_ACTION_DENY};
    msconnector_response_companion_backend vtable;
    msconnector_response_companion_transport transport;
    mock_backend backend = {0};
    char directory[TEST_PATH_SIZE];
    char socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE];
    unsigned char headers[128];
    msconnector_response response = {.status = 200, .http_version = "HTTP/1.1"};
    msconnector_error error;
    backend.use_borrowed_decision = 1;
    /* Mirror a metadata-only owner callback: ACK alone is not sufficient
     * proof that the actual host observation matches native P3 deny. */
    backend.accept_any_outcome = 1;
    setup_mock_transport(&transport, &vtable, &backend,
        TEST_MOCK_TRANSPORT_SETUP(handle, "mrm.XXXXXX", "outcome-match", 1000U, NULL),
        directory, socket_path);
    mock_backend_set_borrowed_rule(&backend, "borrowed-original");
    for (size_t index = 0; index < sizeof(actions) / sizeof(actions[0]); ++index) {
        const int status = index == 2U ? 403 : 451;
        msconnector_response_companion_client client = {0};
        msconnector_response_companion_result result = {0};
        msconnector_error_init(&error);
        assert(msconnector_response_companion_client_open(&client, socket_path,
            1000U, geteuid(), getegid(), &error));
        assert(msconnector_response_companion_client_claim(&client, handle, &result, &error));
        assert(msconnector_response_companion_client_response_headers(&client, &response, &result, &error));
        assert(result.decision == MSCONNECTOR_DECISION_KIND_DENY && result.status == 451);
        assert(msconnector_response_companion_client_outcome(&client, actions[index], status, 0, &result, &error));
        assert(!msconnector_response_companion_client_release(&client, &result, &error));
        assert(error.code == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
        assert(msconnector_response_companion_client_cancel(&client, 0, &result, &error));
        msconnector_response_companion_result_destroy(&result);
        assert(msconnector_response_companion_client_close(&client, &error));

        test_result raw;
        const unsigned char outcome[4] = {(unsigned char)actions[index], 0U,
            (unsigned char)(status >> 8), (unsigned char)status};
        const int fd = connect_client(socket_path);
        assert(claim(fd, handle));
        assert(exchange(fd, TEST_RESPONSE_HEADERS, headers,
            build_headers(headers, sizeof(headers), 200, NULL, NULL), &raw) && raw.success);
        assert(exchange(fd, TEST_OUTCOME, outcome, sizeof(outcome), &raw) && raw.success);
        assert(exchange(fd, TEST_RELEASE, NULL, 0U, &raw));
        assert(!raw.success && raw.error_code == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
        assert(close(fd) == 0);
    }
    assert(msconnector_response_companion_transport_stop(&transport, &error));
    assert(pthread_mutex_destroy(&backend.lock) == 0);
    assert(rmdir(directory) == 0);
}

static void run_response_header_wire_capacity_test(void)
{
    static const char handle[] =
        "76543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba98";
    const mock_transport_setup setup = {
        .handle = handle,
        .directory_template = "mrh.XXXXXX",
        .label = "header-capacity-test",
        .max_header_count = MSCONNECTOR_MAX_HEADER_COUNT,
        .max_header_bytes = MSCONNECTOR_MAX_TOTAL_HEADER_BYTES,
        .timeout_ms = 100U,
        .expire = NULL
    };
    msconnector_response_companion_backend backend_vtable;
    msconnector_response_companion_transport transport;
    msconnector_response_companion_client client;
    msconnector_response_companion_result result;
    msconnector_response response;
    msconnector_header headers[MSCONNECTOR_MAX_HEADER_COUNT];
    char names[MSCONNECTOR_MAX_HEADER_COUNT][8U];
    unsigned char values[MSCONNECTOR_MAX_TOTAL_HEADER_BYTES];
    mock_backend backend;
    mock_backend_observation observation;
    msconnector_error error;
    char socket_directory[TEST_PATH_SIZE];
    char socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE];
    size_t header_bytes = 0U;
    size_t values_offset = 0U;

    assert(strlen(handle) == MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_HANDLE_SIZE - 1U);
    memset(&backend, 0, sizeof(backend));
    atomic_init(&backend.pause_cancel, 0);
    atomic_init(&backend.cancel_started, 0);
    setup_mock_transport(&transport, &backend_vtable, &backend, &setup,
        socket_directory, socket_path);
    memset(&client, 0, sizeof(client));
    memset(&result, 0, sizeof(result));
    memset(&response, 0, sizeof(response));
    memset(headers, 0, sizeof(headers));
    for (size_t index = 0U; index < MSCONNECTOR_MAX_HEADER_COUNT; ++index) {
        assert(snprintf(names[index], sizeof(names[index]), "X-%03zu", index) > 0);
        headers[index].name = names[index];
        headers[index].name_size = strlen(names[index]);
        header_bytes += headers[index].name_size;
    }
    for (size_t index = 0U; index < MSCONNECTOR_MAX_HEADER_COUNT; ++index) {
        const size_t value_size =
            (MSCONNECTOR_MAX_TOTAL_HEADER_BYTES - header_bytes) /
            (MSCONNECTOR_MAX_HEADER_COUNT - index);

        assert(values_offset <= sizeof(values) - value_size);
        memset(values + values_offset, 'v', value_size);
        headers[index].value = (const char *)(values + values_offset);
        headers[index].value_size = value_size;
        header_bytes += value_size;
        values_offset += value_size;
    }
    assert(header_bytes == MSCONNECTOR_MAX_TOTAL_HEADER_BYTES);
    response.status = 200;
    response.http_version = "HTTP/1.1";
    response.headers = headers;
    response.header_count = MSCONNECTOR_MAX_HEADER_COUNT;
    msconnector_error_init(&error);
    assert(msconnector_response_companion_client_open(&client, socket_path, 1000U,
        geteuid(), getegid(), &error));
    assert(msconnector_response_companion_client_claim(&client, handle, &result,
        &error));
    assert(msconnector_response_companion_client_response_headers(&client,
        &response, &result, &error));
    assert(result.decision == MSCONNECTOR_DECISION_KIND_ALLOW);
    mock_backend_snapshot(&backend, &observation);
    assert(observation.claims == 1U);
    assert(observation.response_headers == 1U);
    assert(observation.active);
    assert(msconnector_response_companion_client_cancel(&client, 0, &result,
        &error));
    mock_backend_snapshot(&backend, &observation);
    assert(observation.cancels == 1U);
    assert(!observation.active);
    assert(observation.failures == 0U);
    msconnector_response_companion_result_destroy(&result);
    assert(msconnector_response_companion_client_close(&client, &error));
    assert(msconnector_response_companion_transport_stop(&transport, &error));
    assert(access(socket_path, F_OK) != 0);
    assert(pthread_mutex_destroy(&backend.lock) == 0);
    assert(rmdir(socket_directory) == 0);
}

static void run_response_header_count_contract_test(void)
{
    static const char handle[] =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const mock_transport_setup setup = {
        .handle = handle,
        .directory_template = "mrc.XXXXXX",
        .label = "header-count-test",
        .max_header_count = MSCONNECTOR_MAX_HEADER_COUNT,
        .max_header_bytes = MSCONNECTOR_MAX_TOTAL_HEADER_BYTES,
        .timeout_ms = 100U,
        .expire = NULL
    };
    msconnector_response_companion_backend backend_vtable;
    msconnector_response_companion_transport transport;
    msconnector_response_companion_transport invalid_transport;
    msconnector_response_companion_client client;
    msconnector_response_companion_result result;
    test_result raw_result;
    msconnector_header header = {
        .name = "x", .name_size = 1U, .value = "v", .value_size = 1U};
    msconnector_response response = {
        .status = 200, .http_version = "HTTP/1.1", .headers = &header,
        .header_count = MSCONNECTOR_MAX_HEADER_COUNT + 1U};
    unsigned char oversized_headers[2U + 2U + sizeof("HTTP/1.1") - 1U + 2U +
        (MSCONNECTOR_MAX_HEADER_COUNT + 1U) * 6U];
    unsigned char oversized_aggregate[
        MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_MAX_RESPONSE_HEADER_FRAME];
    mock_backend backend;
    mock_backend_observation observation;
    msconnector_error error;
    char socket_directory[TEST_PATH_SIZE];
    char socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE];
    size_t oversized_header_size;
    size_t oversized_aggregate_size;
    int socket_fd;

    assert(strlen(handle) == MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_HANDLE_SIZE - 1U);
    memset(&backend, 0, sizeof(backend));
    atomic_init(&backend.pause_cancel, 0);
    atomic_init(&backend.cancel_started, 0);
    setup_mock_transport(&transport, &backend_vtable, &backend, &setup,
        socket_directory, socket_path);

    memset(&invalid_transport, 0, sizeof(invalid_transport));
    msconnector_error_init(&error);
    assert(!msconnector_response_companion_transport_init_with_backend(
        &invalid_transport, &backend_vtable,
        TEST_TRANSPORT_OPTIONS("invalid-header-count", socket_path,
            MSCONNECTOR_MAX_HEADER_COUNT + 1U,
            MSCONNECTOR_MAX_TOTAL_HEADER_BYTES, 100U), &error));
    assert(error.code == MSCONNECTOR_ERROR_INVALID_CONFIG);

    memset(&invalid_transport, 0, sizeof(invalid_transport));
    msconnector_error_init(&error);
    assert(!msconnector_response_companion_transport_init_with_backend(
        &invalid_transport, &backend_vtable,
        TEST_TRANSPORT_OPTIONS("invalid-header-bytes", socket_path,
            MSCONNECTOR_MAX_HEADER_COUNT,
            MSCONNECTOR_MAX_TOTAL_HEADER_BYTES + 1U, 100U), &error));
    assert(error.code == MSCONNECTOR_ERROR_INVALID_CONFIG);

    memset(&invalid_transport, 0, sizeof(invalid_transport));
    msconnector_error_init(&error);
    assert(msconnector_response_companion_transport_init_with_backend(
        &invalid_transport, &backend_vtable,
        TEST_TRANSPORT_OPTIONS("start-header-bytes", socket_path,
            MSCONNECTOR_MAX_HEADER_COUNT,
            MSCONNECTOR_MAX_TOTAL_HEADER_BYTES, 100U), &error));
    invalid_transport.config.max_header_bytes = MSCONNECTOR_MAX_TOTAL_HEADER_BYTES + 1U;
    msconnector_error_init(&error);
    assert(!msconnector_response_companion_transport_start(&invalid_transport, &error));
    assert(error.code == MSCONNECTOR_ERROR_INVALID_CONFIG);
    assert(msconnector_response_companion_transport_stop(&invalid_transport, &error));

    memset(&client, 0, sizeof(client));
    memset(&result, 0, sizeof(result));
    msconnector_error_init(&error);
    assert(msconnector_response_companion_client_open(&client, socket_path, 1000U,
        geteuid(), getegid(), &error));
    assert(msconnector_response_companion_client_claim(&client, handle, &result,
        &error));
    msconnector_error_init(&error);
    assert(!msconnector_response_companion_client_response_headers(&client,
        &response, &result, &error));
    assert(error.code == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
    msconnector_error_init(&error);
    assert(msconnector_response_companion_client_cancel(&client, 0, &result,
        &error));
    msconnector_response_companion_result_destroy(&result);
    assert(msconnector_response_companion_client_close(&client, &error));

    /* The parser repeats the Common bound so a corrupt internal configuration
     * cannot turn a valid transport into a wider P3 acceptance boundary. */
    transport.config.max_header_count = MSCONNECTOR_MAX_HEADER_COUNT + 1U;
    oversized_header_size = build_repeated_headers(oversized_headers,
        sizeof(oversized_headers), 200, MSCONNECTOR_MAX_HEADER_COUNT + 1U);
    assert(oversized_header_size > 0U);
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, handle));
    assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, oversized_headers,
        oversized_header_size, &raw_result));
    assert(!raw_result.success && raw_result.error_code == MSCONNECTOR_ERROR_PROTOCOL);
    assert(close(socket_fd) == 0);
    mock_backend_snapshot(&backend, &observation);
    assert(observation.claims == 2U);
    assert(observation.response_headers == 0U);
    assert(observation.failures == 1U);
    assert(!observation.active);

    transport.config.max_header_count = MSCONNECTOR_MAX_HEADER_COUNT;
    transport.config.max_header_bytes = MSCONNECTOR_MAX_TOTAL_HEADER_BYTES + 1U;
    oversized_aggregate_size = build_aggregate_headers(oversized_aggregate,
        sizeof(oversized_aggregate), 200, MSCONNECTOR_MAX_TOTAL_HEADER_BYTES + 1U);
    assert(oversized_aggregate_size > 0U);
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, handle));
    assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, oversized_aggregate,
        oversized_aggregate_size, &raw_result));
    assert(!raw_result.success && raw_result.error_code == MSCONNECTOR_ERROR_HEADER_TOO_LARGE);
    assert(close(socket_fd) == 0);
    mock_backend_snapshot(&backend, &observation);
    assert(observation.claims == 3U);
    assert(observation.response_headers == 0U);
    assert(observation.failures == 2U);
    assert(!observation.active);

    msconnector_error_init(&error);
    assert(msconnector_response_companion_transport_stop(&transport, &error));
    assert(access(socket_path, F_OK) != 0);
    assert(pthread_mutex_destroy(&backend.lock) == 0);
    assert(rmdir(socket_directory) == 0);
}

static void run_explicit_backend_contract_test(void)
{
    static const char handle[] =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    msconnector_response_companion_backend backend_vtable;
    msconnector_response_companion_transport transport;
    mock_backend backend;
    mock_backend_observation observation;
    msconnector_error error;
    char socket_directory[TEST_PATH_SIZE];
    char socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE];
    unsigned char headers[128];
    unsigned char too_large_body[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_MAX_BODY_CHUNK + 1U] = {0};
    test_result result;
    int socket_fd;

    assert(strlen(handle) == MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_HANDLE_SIZE - 1U);
    memset(&backend, 0, sizeof(backend));
    setup_mock_transport(&transport, &backend_vtable, &backend,
        TEST_MOCK_TRANSPORT_SETUP(handle, "mrb.XXXXXX", "backend-test", 100U, NULL),
        socket_directory, socket_path);
    assert((fcntl(transport.listener.listener_fd, F_GETFD) & FD_CLOEXEC) != 0);

    /* CLAIM has only a provisional allow. A raw peer cannot turn it into a
     * host action before P3 has produced a real response decision. */
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, handle));
    assert(exchange(socket_fd, TEST_OUTCOME,
        (const unsigned char *)"\0\0\0\310", 4U, &result));
    assert(!result.success && result.error_code == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
    assert(close(socket_fd) == 0);
    mock_backend_snapshot(&backend, &observation);
    assert(observation.outcomes == 0U);

    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, handle));
    assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, headers,
        build_headers(headers, sizeof(headers), 200, NULL, NULL), &result));
    assert(result.success && result.decision == MSCONNECTOR_DECISION_KIND_ALLOW);
    assert(exchange(socket_fd, TEST_OUTCOME,
        (const unsigned char *)"\0\0\0\310", 4U, &result));
    assert(result.success);
    /* Raw MRC1 peers do not get a weaker lifecycle than the typed client:
     * host-action reporting is one-shot and a duplicate must not emit a
     * second action/event. */
    assert(exchange(socket_fd, TEST_OUTCOME,
        (const unsigned char *)"\0\0\0\310", 4U, &result));
    assert(!result.success && result.error_code == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
    assert(close(socket_fd) == 0);

    /* Even an acknowledged Allow OUTCOME cannot authorize early RELEASE. */
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, handle));
    assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, headers,
        build_headers(headers, sizeof(headers), 200, NULL, NULL), &result));
    assert(result.success && result.decision == MSCONNECTOR_DECISION_KIND_ALLOW);
    assert(exchange(socket_fd, TEST_OUTCOME,
        (const unsigned char *)"\0\0\0\310", 4U, &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_RELEASE, NULL, 0U, &result));
    assert(!result.success && result.error_code == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
    assert(close(socket_fd) == 0);

    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, handle));
    assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, headers,
        build_headers(headers, sizeof(headers), 200, NULL, NULL), &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_COMMIT, (const unsigned char *)"\1\0", 2U,
        &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_RESPONSE_BODY, (const unsigned char *)"abc", 3U,
        &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_RESPONSE_EOS, NULL, 0U, &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_RELEASE, NULL, 0U, &result));
    assert(result.success);

    /* RELEASE resets only the wire/session state: the same private MRC1
     * stream can make a fresh claim without retaining a native transaction. */
    assert(claim(socket_fd, handle));
    assert(finish_normal(socket_fd));
    assert(close(socket_fd) == 0);

    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, handle));
    assert(exchange(socket_fd, TEST_RESPONSE_BODY,
        (const unsigned char *)"invalid", 7U, &result));
    assert(!result.success);
    assert(close(socket_fd) == 0);

    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, handle));
    assert(exchange(socket_fd, TEST_CANCEL, (const unsigned char *)"\0", 1U,
        &result));
    assert(result.success);
    assert(close(socket_fd) == 0);

    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, handle));
    assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, headers,
        build_headers(headers, sizeof(headers), 200, NULL, NULL), &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_COMMIT, (const unsigned char *)"\1\0", 2U,
        &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_RESPONSE_BODY, too_large_body,
        sizeof(too_large_body), &result));
    assert(!result.success);
    assert(close(socket_fd) == 0);

    msconnector_error_init(&error);
    assert(msconnector_response_companion_transport_stop(&transport, &error));
    assert(access(socket_path, F_OK) != 0);
    mock_backend_snapshot(&backend, &observation);
    assert(observation.claims == 8U);
    assert(observation.response_headers == 5U);
    assert(observation.response_body_chunks == 1U);
    assert(observation.response_body_bytes == 3U);
    assert(observation.response_eos == 2U);
    assert(observation.commits == 3U);
    assert(observation.outcomes == 2U);
    assert(observation.cancels == 1U);
    assert(observation.releases == 2U);
    assert(observation.failures == 5U);
    assert(observation.last_failure == MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL);
    assert(!observation.active);
    assert(pthread_mutex_destroy(&backend.lock) == 0);
    assert(rmdir(socket_directory) == 0);
}

static void run_backend_fault_claim_race_test(void)
{
    static const char handle[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    msconnector_response_companion_backend backend_vtable;
    msconnector_response_companion_transport transport;
    mock_backend backend;
    mock_backend_observation observation;
    transport_exchange_call cancel_call;
    transport_exchange_call claim_call;
    pthread_t cancel_thread;
    pthread_t claim_thread;
    msconnector_error error;
    char socket_directory[TEST_PATH_SIZE];
    char socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE];
    int first_socket;

    memset(&backend, 0, sizeof(backend));
    backend.retain_terminal_opaque = 1;
    atomic_init(&backend.pause_cancel, 0);
    atomic_init(&backend.cancel_started, 0);
    setup_mock_transport(&transport, &backend_vtable, &backend,
        TEST_MOCK_TRANSPORT_SETUP(handle, "mrf.XXXXXX", "fault-race-test", 100U, NULL),
        socket_directory, socket_path);
    first_socket = connect_client(socket_path);
    assert(claim(first_socket, handle));

    atomic_store_explicit(&backend.pause_cancel, 1, memory_order_release);
    memset(&cancel_call, 0, sizeof(cancel_call));
    cancel_call.socket_fd = first_socket;
    cancel_call.opcode = TEST_CANCEL;
    cancel_call.payload = (const unsigned char *)"\0";
    cancel_call.payload_size = 1U;
    assert(pthread_create(&cancel_thread, NULL, transport_exchange_in_thread,
        &cancel_call) == 0);
    while (!atomic_load_explicit(&backend.cancel_started, memory_order_acquire)) {
        sleep_milliseconds(1L);
    }

    memset(&claim_call, 0, sizeof(claim_call));
    claim_call.socket_fd = connect_client(socket_path);
    claim_call.opcode = TEST_CLAIM;
    claim_call.payload = (const unsigned char *)handle;
    claim_call.payload_size = strlen(handle);
    assert(pthread_create(&claim_thread, NULL, transport_exchange_in_thread,
        &claim_call) == 0);
    sleep_milliseconds(20L);
    atomic_store_explicit(&backend.pause_cancel, 0, memory_order_release);
    assert(pthread_join(cancel_thread, NULL) == 0);
    assert(pthread_join(claim_thread, NULL) == 0);
    assert(!cancel_call.result.success &&
        cancel_call.result.error_code == MSCONNECTOR_ERROR_INTERNAL);
    assert(!claim_call.result.success &&
        claim_call.result.error_code == MSCONNECTOR_ERROR_RUNTIME_UNAVAILABLE);

    msconnector_error_init(&error);
    assert(msconnector_response_companion_transport_stop(&transport, &error));
    mock_backend_snapshot(&backend, &observation);
    assert(observation.claims == 1U);
    assert(observation.cancels == 1U);
    assert(observation.failures == 1U);
    assert(!observation.active);
    assert(pthread_mutex_destroy(&backend.lock) == 0);
    assert(rmdir(socket_directory) == 0);
}

static void run_typed_cancel_cause_test(void)
{
    static const char handle[] =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    static const struct {
        msconnector_response_companion_cancel_cause cause;
        msconnector_transaction_error_class error_class;
    } cases[] = {
        {MSCONNECTOR_RESPONSE_COMPANION_CANCEL_CONNECTOR_ERROR,
            MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR},
        {MSCONNECTOR_RESPONSE_COMPANION_CANCEL_PROTOCOL_ERROR,
            MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL},
        {MSCONNECTOR_RESPONSE_COMPANION_CANCEL_ENGINE_TIMEOUT,
            MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT},
        {MSCONNECTOR_RESPONSE_COMPANION_CANCEL_ENGINE_UNAVAILABLE,
            MSCONNECTOR_TRANSACTION_ERROR_ENGINE_UNAVAILABLE},
        {MSCONNECTOR_RESPONSE_COMPANION_CANCEL_INVALID_ENGINE_RESPONSE,
            MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE}
    };
    msconnector_response_companion_backend backend_vtable;
    msconnector_response_companion_transport transport;
    mock_backend backend;
    mock_backend_observation observation;
    msconnector_error error;
    char socket_directory[TEST_PATH_SIZE];
    char socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE];
    test_result result;
    int socket_fd;

    memset(&backend, 0, sizeof(backend));
    setup_mock_transport(&transport, &backend_vtable, &backend,
        TEST_MOCK_TRANSPORT_SETUP(handle, "mrtv.XXXXXX", "typed-cancel-test", 100U, NULL),
        socket_directory, socket_path);
    socket_fd = connect_client(socket_path);

    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const unsigned char payload = (unsigned char)cases[index].cause;

        assert(claim(socket_fd, handle));
        assert(exchange(socket_fd, TEST_CANCEL, &payload, 1U, &result));
        assert(result.success);
        assert(result.decision == MSCONNECTOR_DECISION_KIND_ERROR);
        assert(result.status == 0U);
        mock_backend_snapshot(&backend, &observation);
        assert(observation.claims == index + 1U);
        assert(observation.cancels == 0U);
        assert(observation.failures == index + 1U);
        assert(observation.last_failure == cases[index].error_class);
        assert(observation.last_failure !=
            MSCONNECTOR_TRANSACTION_ERROR_UPSTREAM_DISCONNECT);
        assert(!observation.active);
    }

    {
        const unsigned char malformed_cause = 7U;

        assert(claim(socket_fd, handle));
        assert(exchange(socket_fd, TEST_CANCEL, &malformed_cause, 1U, &result));
        assert(!result.success && result.error_code == MSCONNECTOR_ERROR_PROTOCOL);
    }
    assert(close(socket_fd) == 0);
    msconnector_error_init(&error);
    assert(msconnector_response_companion_transport_stop(&transport, &error));
    mock_backend_snapshot(&backend, &observation);
    assert(observation.claims == sizeof(cases) / sizeof(cases[0]) + 1U);
    assert(observation.cancels == 0U);
    assert(observation.failures == sizeof(cases) / sizeof(cases[0]) + 1U);
    assert(observation.last_failure == MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL);
    assert(!observation.active);
    assert(pthread_mutex_destroy(&backend.lock) == 0);
    assert(rmdir(socket_directory) == 0);
}

static void run_transport_security_regression_test(void)
{
    static const char handle[] =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    msconnector_response_companion_backend vtable;
    msconnector_response_companion_transport transport;
    mock_backend backend;
    mock_backend_observation observation;
    msconnector_error error;
    char socket_directory[TEST_PATH_SIZE];
    char socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE];
    unsigned char malformed[TEST_FRAME_HEADER_SIZE];
    unsigned char headers[128];
    unsigned char byte;
    test_result result;
    int socket_fd;

    assert(strlen(handle) == MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_HANDLE_SIZE - 1U);
    memset(&backend, 0, sizeof(backend));
    setup_mock_transport(&transport, &vtable, &backend,
        TEST_MOCK_TRANSPORT_SETUP(handle, "mrs.XXXXXX", "security-test", 100U, NULL),
        socket_directory, socket_path);

    /* A malformed frame after CLAIM is a protocol error, never an upstream
     * disconnect. The worker owns no body payload after this failure. */
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, handle));
    memset(malformed, 0, sizeof(malformed));
    memcpy(malformed, "MRC1", 4U);
    malformed[4] = MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_PROTOCOL_VERSION + 1U;
    malformed[5] = TEST_RESPONSE_HEADERS;
    assert(write_all(socket_fd, malformed, sizeof(malformed)));
    assert(recv(socket_fd, &byte, sizeof(byte), 0) == 0);
    assert(close(socket_fd) == 0);
    msconnector_error_init(&error);
    assert(msconnector_response_companion_transport_stop(&transport, &error));
    mock_backend_snapshot(&backend, &observation);
    assert(observation.claims == 1U);
    assert(observation.failures == 1U);
    assert(observation.last_failure == MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL);
    assert(!observation.active);
    assert(pthread_mutex_destroy(&backend.lock) == 0);
    assert(rmdir(socket_directory) == 0);

    /* Decision fields returned by a backend are borrowed. Once P3 returns,
     * later outcome reporting must use the transport's bounded copy, not the
     * backend's mutable source buffer. */
    memset(&backend, 0, sizeof(backend));
    backend.use_borrowed_decision = 1;
    setup_mock_transport(&transport, &vtable, &backend,
        TEST_MOCK_TRANSPORT_SETUP(handle, "mrd.XXXXXX", "decision-test", 100U, NULL),
        socket_directory, socket_path);
    mock_backend_set_borrowed_rule(&backend, "borrowed-original");
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, handle));
    assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, headers,
        build_headers(headers, sizeof(headers), 200, NULL, NULL), &result));
    assert(result.success && result.decision == MSCONNECTOR_DECISION_KIND_DENY);
    mock_backend_set_borrowed_rule(&backend, "borrowed-mutated");
    assert(exchange(socket_fd, TEST_OUTCOME,
        (const unsigned char *)"\1\0\1\303", 4U, &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_CANCEL, (const unsigned char *)"\0", 1U,
        &result));
    assert(result.success);
    assert(close(socket_fd) == 0);
    msconnector_error_init(&error);
    assert(msconnector_response_companion_transport_stop(&transport, &error));
    mock_backend_snapshot(&backend, &observation);
    assert(observation.outcomes == 1U);
    assert(observation.cancels == 1U);
    assert(observation.failures == 0U);
    assert(pthread_mutex_destroy(&backend.lock) == 0);
    assert(rmdir(socket_directory) == 0);

    /* A backend that falsely acknowledges a terminal cancel is quarantined;
     * it receives fail() while its opaque session is still available, and no
     * subsequent CLAIM can inherit that native ownership. */
    memset(&backend, 0, sizeof(backend));
    backend.retain_terminal_opaque = 1;
    setup_mock_transport(&transport, &vtable, &backend,
        TEST_MOCK_TRANSPORT_SETUP(handle, "mrt.XXXXXX", "terminal-test", 100U, NULL),
        socket_directory, socket_path);
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, handle));
    assert(exchange(socket_fd, TEST_CANCEL, (const unsigned char *)"\0", 1U,
        &result));
    assert(!result.success && result.error_code == MSCONNECTOR_ERROR_INTERNAL);
    assert(close(socket_fd) == 0);
    socket_fd = connect_client(socket_path);
    assert(exchange(socket_fd, TEST_CLAIM, (const unsigned char *)handle,
        strlen(handle), &result));
    assert(!result.success && result.error_code == MSCONNECTOR_ERROR_RUNTIME_UNAVAILABLE);
    assert(close(socket_fd) == 0);
    msconnector_error_init(&error);
    assert(msconnector_response_companion_transport_stop(&transport, &error));
    mock_backend_snapshot(&backend, &observation);
    assert(observation.claims == 1U);
    assert(observation.cancels == 1U);
    assert(observation.failures == 1U);
    assert(observation.last_failure == MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);
    assert(!observation.active);
    assert(pthread_mutex_destroy(&backend.lock) == 0);
    assert(rmdir(socket_directory) == 0);
}

static void run_listener_stop_regression_test(void)
{
    static const char handle[] =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    msconnector_response_companion_backend vtable;
    msconnector_response_companion_transport transport;
    mock_backend backend;
    transport_stop_call stop_call;
    pthread_t stop_thread;
    char socket_directory[TEST_PATH_SIZE];
    char socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE];
    int socket_fd;
    int descriptors[32];

    memset(&backend, 0, sizeof(backend));
    setup_mock_transport(&transport, &vtable, &backend,
        TEST_MOCK_TRANSPORT_SETUP(handle, "mrl.XXXXXX", "listener-test", 100U, NULL),
        socket_directory, socket_path);
    socket_fd = connect_client(socket_path);
    memset(&stop_call, 0, sizeof(stop_call));
    stop_call.transport = &transport;
    assert(pthread_create(&stop_thread, NULL, stop_transport_in_thread,
        &stop_call) == 0);
    for (size_t index = 0U; index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++index) {
        descriptors[index] = open("/dev/null", O_RDONLY);
        assert(descriptors[index] >= 0);
    }
    assert(pthread_join(stop_thread, NULL) == 0);
    assert(stop_call.result);
    for (size_t index = 0U; index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++index) {
        assert(fcntl(descriptors[index], F_GETFD) >= 0);
        assert(close(descriptors[index]) == 0);
    }
    assert(close(socket_fd) == 0);
    assert(access(socket_path, F_OK) != 0);
    assert(pthread_mutex_destroy(&backend.lock) == 0);
    assert(rmdir(socket_directory) == 0);
}

static void run_expire_serialization_regression_test(void)
{
    static const char handle[] =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    msconnector_response_companion_backend vtable;
    msconnector_response_companion_transport transport;
    mock_backend backend;
    msconnector_error error;
    char socket_directory[TEST_PATH_SIZE];
    char socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE];
    unsigned char headers[128];
    test_result result;
    int socket_fd;

    memset(&backend, 0, sizeof(backend));
    backend.pause_headers = 1;
    atomic_init(&backend.callback_active, 0);
    atomic_init(&backend.expire_during_callback, 0);
    atomic_init(&backend.expires, 0U);
    setup_mock_transport(&transport, &vtable, &backend,
        TEST_MOCK_TRANSPORT_SETUP(handle, "mre.XXXXXX", "expire-test", 1000U,
            mock_backend_expire),
        socket_directory, socket_path);
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, handle));
    /* The P3 callback sleeps longer than the listener poll period.  Without
     * transport-level serialization, expire() would observe this callback as
     * active.  A generic owner-bound backend can therefore safely put lease
     * housekeeping in expire() without racing its operation callbacks. */
    assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, headers,
        build_headers(headers, sizeof(headers), 200, NULL, NULL), &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_CANCEL, (const unsigned char *)"\0", 1U,
        &result));
    assert(result.success);
    assert(close(socket_fd) == 0);
    msconnector_error_init(&error);
    assert(msconnector_response_companion_transport_stop(&transport, &error));
    assert(atomic_load_explicit(&backend.expires, memory_order_acquire) >= 2U);
    assert(!atomic_load_explicit(&backend.expire_during_callback,
        memory_order_acquire));
    assert(pthread_mutex_destroy(&backend.lock) == 0);
    assert(rmdir(socket_directory) == 0);
}

static void run_transport_startup_helper_contract_test(void)
{
    msconnector_runtime_response_companion_registry registry;
    msconnector_response_companion_transport transport;
    msconnector_response_companion_transport failed_transport;
    msconnector_response_companion_transport unsafe_ancestor_transport;
    msconnector_error error;
    char socket_directory[TEST_PATH_SIZE];
    char socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE];
    char blocked_directory[TEST_PATH_SIZE];
    char blocked_socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE];
    char unsafe_ancestor[TEST_PATH_SIZE];
    char unsafe_parent[TEST_PATH_SIZE];
    char unsafe_socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE];
    int initialized = 0;
    int ready = 0;
    int failed_initialized = 0;
    int failed_ready = 0;
    int unsafe_initialized = 0;
    int unsafe_ready = 0;
    int inconsistent_initialized = 0;
    int inconsistent_ready = 1;
    int listener_fd;
    int recovery_fd;
    int blocked_fd;

    memset(&transport, 0, sizeof(transport));
    memset(&failed_transport, 0, sizeof(failed_transport));
    memset(&unsafe_ancestor_transport, 0, sizeof(unsafe_ancestor_transport));
    msconnector_runtime_response_companion_registry_init(&registry);
    assert(snprintf(socket_directory, sizeof(socket_directory), "%s/mrs.XXXXXX",
        test_private_directory()) > 0);
    assert(mkdtemp(socket_directory) != NULL);
    assert(chmod(socket_directory, 0700) == 0);
    assert(snprintf(socket_path, sizeof(socket_path), "%s/s", socket_directory) > 0);
    assert(snprintf(blocked_directory, sizeof(blocked_directory), "%s/mrb.XXXXXX",
        test_private_directory()) > 0);
    assert(mkdtemp(blocked_directory) != NULL);
    assert(chmod(blocked_directory, 0700) == 0);
    assert(snprintf(blocked_socket_path, sizeof(blocked_socket_path), "%s/s",
        blocked_directory) > 0);

    msconnector_error_init(&error);
    assert(!msconnector_response_companion_transport_ensure_started(NULL, &registry,
        &initialized, &ready, TEST_TRANSPORT_OPTIONS("startup-test", socket_path,
            32U, 64U, 100U), &error));
    assert(error.code == MSCONNECTOR_ERROR_INVALID_CONFIG);
    assert(!initialized && !ready);
    assert(!msconnector_response_companion_transport_ensure_started(&transport, &registry,
        &inconsistent_initialized, &inconsistent_ready,
        TEST_TRANSPORT_OPTIONS("startup-test", socket_path, 32U, 64U, 100U),
        &error));
    assert(error.code == MSCONNECTOR_ERROR_INVALID_CONFIG);
    assert(!inconsistent_initialized && inconsistent_ready);
    assert(!msconnector_response_companion_transport_ensure_started(&transport, &registry,
        &initialized, &ready, TEST_TRANSPORT_OPTIONS("startup-test", "",
            32U, 64U, 100U), &error));
    assert(error.code == MSCONNECTOR_ERROR_INVALID_CONFIG);
    assert(!initialized && !ready);

    assert(msconnector_response_companion_transport_ensure_started(&transport, &registry,
        &initialized, &ready, TEST_TRANSPORT_OPTIONS("startup-test", socket_path,
            32U, 64U, 100U), &error));
    assert(initialized && ready);
    listener_fd = transport.listener.listener_fd;
    assert(listener_fd >= 0);
    assert(msconnector_response_companion_transport_ensure_started(&transport, &registry,
        &initialized, &ready, TEST_TRANSPORT_OPTIONS("startup-test", socket_path,
            32U, 64U, 100U), &error));
    assert(transport.listener.listener_fd == listener_fd);

    /* A terminal poll path leaves the old descriptor invalid and ends the
     * listener thread.  No descriptor is opened here before Common joins the
     * dead thread, so the test cannot accidentally reuse the stale number. */
    assert(close(listener_fd) == 0);
    wait_for_listener_stop(&transport);
    assert(msconnector_response_companion_transport_ensure_started(&transport, &registry,
        &initialized, &ready, TEST_TRANSPORT_OPTIONS("startup-test", socket_path,
            32U, 64U, 100U), &error));
    assert(atomic_load_explicit(&transport.listener.running, memory_order_acquire));
    recovery_fd = connect_client(socket_path);
    assert(close(recovery_fd) == 0);
    assert(msconnector_response_companion_transport_stop(&transport, &error));
    assert(access(socket_path, F_OK) != 0);

    blocked_fd = open(blocked_socket_path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
        0600);
    assert(blocked_fd >= 0);
    assert(close(blocked_fd) == 0);
    assert(!msconnector_response_companion_transport_ensure_started(&failed_transport,
        &registry, &failed_initialized, &failed_ready,
        TEST_TRANSPORT_OPTIONS("startup-failed", blocked_socket_path,
            32U, 64U, 100U), &error));
    assert(error.code == MSCONNECTOR_ERROR_RUNTIME_UNAVAILABLE);
    assert(failed_initialized && !failed_ready);
    assert(msconnector_response_companion_transport_stop(&failed_transport, &error));
    assert(unlink(blocked_socket_path) == 0);

    /* A mode-0700 leaf must not excuse a writable, non-sticky ancestor. */
    assert(snprintf(unsafe_ancestor, sizeof(unsafe_ancestor), "%s/mru.XXXXXX",
        test_private_directory()) > 0);
    assert(mkdtemp(unsafe_ancestor) != NULL);
    assert(chmod(unsafe_ancestor, 0777) == 0);
    assert(snprintf(unsafe_parent, sizeof(unsafe_parent), "%s/child",
        unsafe_ancestor) > 0);
    assert(mkdir(unsafe_parent, 0700) == 0);
    assert(snprintf(unsafe_socket_path, sizeof(unsafe_socket_path), "%s/s",
        unsafe_parent) > 0);
    assert(!msconnector_response_companion_transport_ensure_started(
        &unsafe_ancestor_transport, &registry, &unsafe_initialized, &unsafe_ready,
        TEST_TRANSPORT_OPTIONS("startup-unsafe-ancestor", unsafe_socket_path,
            32U, 64U, 100U), &error));
    assert(error.code == MSCONNECTOR_ERROR_RUNTIME_UNAVAILABLE);
    assert(unsafe_initialized && !unsafe_ready);
    assert(msconnector_response_companion_transport_stop(
        &unsafe_ancestor_transport, &error));
    assert(chmod(unsafe_ancestor, 0700) == 0);
    assert(rmdir(unsafe_parent) == 0);
    assert(rmdir(unsafe_ancestor) == 0);

    assert(msconnector_runtime_response_companion_registry_shutdown(&registry, &error));
    assert(rmdir(socket_directory) == 0);
    assert(rmdir(blocked_directory) == 0);
}

int main(void)
{
    msconnector_runtime *runtime = NULL;
    msconnector_runtime_response_companion_registry registry;
    msconnector_response_companion_transport transport;
    msconnector_error error;
    char config_path[TEST_PATH_SIZE];
    char event_path[TEST_PATH_SIZE];
    char rules_path[TEST_PATH_SIZE];
    char socket_directory[TEST_PATH_SIZE];
    char socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE];
    char first_handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
    char second_handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
    char third_handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
    char fourth_handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
    char fifth_handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
    char sixth_handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
    char seventh_handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
    char eighth_handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
    char ninth_handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
    pthread_t first_thread;
    pthread_t second_thread;
    parallel_client first_client;
    parallel_client second_client;
    int socket_fd;
    test_result result;
    unsigned char headers[256];
    unsigned char body[9] = {0};

    run_transport_startup_helper_contract_test();
    create_runtime_fixture(config_path, event_path, rules_path, 1048576U, "Reject");
    assert(msconnector_runtime_create("envoy", config_path, &runtime, NULL, 0U));
    assert(msconnector_runtime_set_event_integration_mode(runtime, "ext_authz"));
    assert(msconnector_runtime_set_transaction_profile(runtime,
        msconnector_profile_registry_find("envoy-ext-authz")));
    msconnector_runtime_response_companion_registry_init(&registry);
    assert(snprintf(socket_directory, sizeof(socket_directory),
        "%s/mrc.XXXXXX",
        test_private_directory()) > 0);
    assert(mkdtemp(socket_directory) != NULL);
    assert(chmod(socket_directory, 0700) == 0);
    {
        const int socket_path_size = snprintf(socket_path, sizeof(socket_path),
            "%s/s", socket_directory);
        assert(socket_path_size > 0 && (size_t)socket_path_size <
            sizeof(socket_path));
    }
    msconnector_error_init(&error);
    assert(msconnector_response_companion_transport_init(&transport, &registry,
        TEST_TRANSPORT_OPTIONS("envoy", socket_path, 32U, 64U, 50U), &error));
    assert(msconnector_response_companion_transport_start(&transport, &error));

    handoff(runtime, &registry, "opaque-a", first_handle);
    handoff(runtime, &registry, "opaque-b", second_handle);
    assert(strcmp(first_handle, second_handle) != 0);
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, first_handle));
    assert(finish_normal(socket_fd));
    /* One trusted MRC1 connection may carry sequential transactions, but a
     * RELEASE must fully detach the first one before the next CLAIM. */
    assert(claim(socket_fd, second_handle));
    assert(finish_normal(socket_fd));
    assert(close(socket_fd) == 0);
    socket_fd = connect_client(socket_path);
    assert(exchange(socket_fd, TEST_CLAIM, (const unsigned char *)first_handle,
        strlen(first_handle), &result));
    assert(!result.success);
    assert(close(socket_fd) == 0);

    /* Envoy sends :status as a response pseudoheader.  MRC1 accepts only
     * this one controlled pseudoheader, validates it against the framed
     * status, and does not expose it as an ordinary rule header. */
    handoff(runtime, &registry, "status-pseudoheader", seventh_handle);
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, seventh_handle));
    assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, headers,
        build_headers(headers, sizeof(headers), 200, ":status", "200"), &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_COMMIT, (const unsigned char *)"\1\0", 2U,
        &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_RESPONSE_EOS, NULL, 0U, &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_RELEASE, NULL, 0U, &result));
    assert(result.success);
    assert(close(socket_fd) == 0);

    handoff(runtime, &registry, "invalid-status-pseudoheader", eighth_handle);
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, eighth_handle));
    assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, headers,
        build_headers(headers, sizeof(headers), 200, ":status", "201"), &result));
    assert(!result.success);
    assert(close(socket_fd) == 0);

    handoff(runtime, &registry, "invalid-pseudoheader", ninth_handle);
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, ninth_handle));
    assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, headers,
        build_headers(headers, sizeof(headers), 200, ":path", "/"), &result));
    assert(!result.success);
    assert(close(socket_fd) == 0);

    handoff(runtime, &registry, "invalid-order", third_handle);
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, third_handle));
    assert(exchange(socket_fd, TEST_RESPONSE_EOS, NULL, 0U, &result));
    assert(!result.success);
    assert(close(socket_fd) == 0);

    handoff(runtime, &registry, "header-limit", fourth_handle);
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, fourth_handle));
    assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, headers,
        build_headers(headers, sizeof(headers), 200, "x-limit",
            "this-response-header-value-is-deliberately-longer-than-the-"
            "configured-sixty-four-byte-transport-limit"), &result));
    assert(!result.success);
    assert(close(socket_fd) == 0);

    handoff(runtime, &registry, "body-limit", fifth_handle);
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, fifth_handle));
    assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, headers,
        build_headers(headers, sizeof(headers), 200, NULL, NULL), &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_COMMIT, (const unsigned char *)"\1\0", 2U,
        &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_RESPONSE_BODY, body, 5U, &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_RESPONSE_BODY, body + 5U, 4U, &result));
    assert(result.success);
    assert(close(socket_fd) == 0);

    handoff(runtime, &registry, "timeout", sixth_handle);
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, sixth_handle));
    sleep_milliseconds(125L);
    assert(!exchange(socket_fd, TEST_RESPONSE_HEADERS, headers,
        build_headers(headers, sizeof(headers), 200, NULL, NULL), &result));
    assert(close(socket_fd) == 0);

    handoff(runtime, &registry, "cancel", third_handle);
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, third_handle));
    assert(exchange(socket_fd, TEST_CANCEL, (const unsigned char *)"\0", 1U,
        &result));
    assert(result.success);
    /* CANCEL/RELEASE are cleanup acknowledgements, not engine decisions.
     * MRC1 encodes their successful statusless acknowledgement with the
     * reserved ERROR kind; adapters must accept it only for those opcodes. */
    assert(result.decision == MSCONNECTOR_DECISION_KIND_ERROR);
    assert(result.status == 0U);
    assert(close(socket_fd) == 0);

    /* Raw peers cannot RELEASE a CLAIM, P3 Allow, or unacknowledged P3 deny.
     * These are independently enforced server obligations. */
    for (int stage = 0; stage < 3; ++stage) {
        handoff(runtime, &registry, "early-release-negative", sixth_handle);
        socket_fd = connect_client(socket_path);
        assert(claim(socket_fd, sixth_handle));
        if (stage > 0) {
            assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, headers,
                build_headers(headers, sizeof(headers), 200,
                    stage == 2 ? "X-Mrc-Block" : NULL,
                    stage == 2 ? "yes" : NULL), &result));
            assert(result.success);
        }
        assert(exchange(socket_fd, TEST_RELEASE, NULL, 0U, &result));
        assert(!result.success);
        assert(close(socket_fd) == 0);
    }

    /* A P3 deny is terminal before its actual host outcome. OUTCOME followed
     * by RELEASE performs successful policy cleanup with no typed CANCEL. */
    handoff(runtime, &registry, "p3-terminal", sixth_handle);
    socket_fd = connect_client(socket_path);
    assert(claim(socket_fd, sixth_handle));
    assert(exchange(socket_fd, TEST_RESPONSE_HEADERS, headers,
        build_headers(headers, sizeof(headers), 200, "X-Mrc-Block", "yes"),
        &result));
    assert(result.success);
    assert(result.decision == MSCONNECTOR_DECISION_KIND_DENY);
    assert(exchange(socket_fd, TEST_OUTCOME,
        (const unsigned char *)"\1\0\1\303", 4U, &result));
    assert(result.success);
    assert(exchange(socket_fd, TEST_RELEASE, NULL, 0U,
        &result));
    assert(result.success);
    assert(result.decision == MSCONNECTOR_DECISION_KIND_ERROR);
    assert(result.status == 0U);
    assert(close(socket_fd) == 0);
    socket_fd = connect_client(socket_path);
    assert(exchange(socket_fd, TEST_CLAIM, (const unsigned char *)sixth_handle,
        strlen(sixth_handle), &result));
    assert(!result.success);
    assert(close(socket_fd) == 0);

    handoff(runtime, &registry, "parallel-a", first_handle);
    handoff(runtime, &registry, "parallel-b", second_handle);
    first_client.socket_path = socket_path;
    first_client.handle = first_handle;
    first_client.result = 0;
    second_client.socket_path = socket_path;
    second_client.handle = second_handle;
    second_client.result = 0;
    assert(pthread_create(&first_thread, NULL, parallel_normal, &first_client) == 0);
    assert(pthread_create(&second_thread, NULL, parallel_normal, &second_client) == 0);
    assert(pthread_join(first_thread, NULL) == 0);
    assert(pthread_join(second_thread, NULL) == 0);
    assert(first_client.result && second_client.result);

    run_client_transport_interop_test(runtime, &registry, socket_path);
    msconnector_error_init(&error);
    assert(msconnector_response_companion_transport_stop(&transport, &error));
    assert(access(socket_path, F_OK) != 0);
    assert(msconnector_runtime_response_companion_registry_shutdown(&registry, &error));
    msconnector_runtime_destroy(&runtime);
    assert_metadata_only_events(event_path);
    run_explicit_backend_contract_test();
    run_precommit_outcome_release_mismatch_test();
    run_response_header_wire_capacity_test();
    run_response_header_count_contract_test();
    run_backend_fault_claim_race_test();
    run_typed_cancel_cause_test();
    run_transport_security_regression_test();
    run_listener_stop_regression_test();
    run_expire_serialization_regression_test();
    assert(unlink(config_path) == 0);
    assert(unlink(event_path) == 0);
    assert(unlink(rules_path) == 0);
    assert(rmdir(socket_directory) == 0);
    assert(rmdir(test_private_root) == 0);
    return 0;
}
