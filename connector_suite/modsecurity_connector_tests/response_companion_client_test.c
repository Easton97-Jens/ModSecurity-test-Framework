#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "common/runtime/response_companion_client.h"

#define TEST_FRAME_HEADER_SIZE 12U

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

typedef struct test_server {
    int listener;
    int malformed;
    long request_payload_delay_ms;
    long result_header_delay_ms;
    long result_payload_delay_ms;
    unsigned char delayed_opcode;
    int requests;
    pthread_t thread;
} test_server;

static void write_u16(unsigned char *value, uint16_t number)
{
    value[0] = (unsigned char)(number >> 8U);
    value[1] = (unsigned char)number;
}

static uint32_t read_u32(const unsigned char *value)
{
    return ((uint32_t)value[0] << 24U) | ((uint32_t)value[1] << 16U) |
        ((uint32_t)value[2] << 8U) | value[3];
}

static void write_u32(unsigned char *value, uint32_t number)
{
    value[0] = (unsigned char)(number >> 24U);
    value[1] = (unsigned char)(number >> 16U);
    value[2] = (unsigned char)(number >> 8U);
    value[3] = (unsigned char)number;
}

static void sleep_milliseconds(long milliseconds)
{
    struct timespec delay;

    delay.tv_sec = milliseconds / 1000L;
    delay.tv_nsec = (milliseconds % 1000L) * 1000000L;
    for (;;) {
        if (nanosleep(&delay, &delay) == 0 || errno != EINTR) {
            break;
        }
    }
}

static int read_all(int fd, unsigned char *data, size_t size)
{
    size_t offset = 0U;
    while (offset < size) {
        ssize_t value = recv(fd, data + offset, size - offset, 0);
        if (value > 0) {
            offset += (size_t)value;
        } else if (value < 0 && errno == EINTR) {
            continue;
        } else {
            return 0;
        }
    }
    return 1;
}

static int write_all(int fd, const unsigned char *data, size_t size)
{
    size_t offset = 0U;
    while (offset < size) {
        ssize_t value = send(fd, data + offset, size - offset, MSG_NOSIGNAL);
        if (value > 0) {
            offset += (size_t)value;
        } else if (value < 0 && errno == EINTR) {
            continue;
        } else {
            return 0;
        }
    }
    return 1;
}

static int send_result(int fd, unsigned char request_opcode, int malformed,
    long header_delay_ms, long payload_delay_ms)
{
    unsigned char header[TEST_FRAME_HEADER_SIZE];
    unsigned char payload[12];
    memset(header, 0, sizeof(header));
    memset(payload, 0, sizeof(payload));
    memcpy(header, "MRC1", 4U);
    header[4] = MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_PROTOCOL_VERSION;
    header[5] = TEST_RESULT;
    write_u32(header + 8U, sizeof(payload));
    payload[0] = malformed ? (unsigned char)(request_opcode + 1U) : request_opcode;
    payload[1] = 0U;
    payload[2] = MSCONNECTOR_DECISION_KIND_ALLOW;
    write_u16(payload + 4U, request_opcode == TEST_CANCEL || request_opcode == TEST_RELEASE ? 0U : 200U);
    if (header_delay_ms > 0L) {
        sleep_milliseconds(header_delay_ms);
    }
    if (!write_all(fd, header, sizeof(header))) {
        return 0;
    }
    if (payload_delay_ms > 0L) {
        sleep_milliseconds(payload_delay_ms);
    }
    return write_all(fd, payload, sizeof(payload));
}

static void *server_main(void *argument)
{
    test_server *server = argument;
    int running = 1;
    int fd = accept(server->listener, NULL, NULL);
    assert(fd >= 0);
    while (running) {
        unsigned char header[TEST_FRAME_HEADER_SIZE];
        unsigned char *payload = NULL;
        uint32_t size;
        unsigned char opcode;
        long header_delay_ms;
        long payload_delay_ms;
        if (!read_all(fd, header, sizeof(header))) {
            running = 0;
            continue;
        }
        assert(memcmp(header, "MRC1", 4U) == 0 && header[4] ==
            MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_PROTOCOL_VERSION);
        opcode = header[5];
        size = read_u32(header + 8U);
        assert(size <= MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_MAX_FRAME);
        if (server->request_payload_delay_ms > 0L &&
            (server->delayed_opcode == 0U || opcode == server->delayed_opcode)) {
            sleep_milliseconds(server->request_payload_delay_ms);
        }
        if (size > 0U) {
            payload = calloc(size, 1U);
            assert(payload != NULL && read_all(fd, payload, size));
        }
        free(payload);
        server->requests++;
        header_delay_ms = server->result_header_delay_ms;
        payload_delay_ms = server->result_payload_delay_ms;
        if (server->delayed_opcode != 0U && opcode != server->delayed_opcode) {
            header_delay_ms = 0L;
            payload_delay_ms = 0L;
        }
        if (!send_result(fd, opcode, server->malformed && opcode == TEST_CLAIM,
                header_delay_ms, payload_delay_ms)) {
            running = 0;
        }
    }
    close(fd);
    return NULL;
}

static int start_server(test_server *server, const char *path)
{
    struct sockaddr_un address;
    size_t path_size = strlen(path);
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    assert(path_size < sizeof(address.sun_path));
    assert(snprintf(address.sun_path, sizeof(address.sun_path), "%s", path) > 0);
    server->listener = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(server->listener >= 0);
    assert(bind(server->listener, (const struct sockaddr *)&address, sizeof(address)) == 0);
    assert(listen(server->listener, 4) == 0);
    assert(pthread_create(&server->thread, NULL, server_main, server) == 0);
    return 1;
}

static void stop_server(const test_server *server, const char *path)
{
    assert(pthread_join(server->thread, NULL) == 0);
    assert(close(server->listener) == 0);
    assert(unlink(path) == 0);
}

static void test_normal_lifecycle(const char *path)
{
    msconnector_response_companion_client client;
    msconnector_response_companion_result result;
    msconnector_error error;
    msconnector_response response;
    msconnector_header status_pseudoheader;
    const char *handle = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const char *second_handle = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const unsigned char body[] = "bounded";
    memset(&client, 0, sizeof(client));
    memset(&result, 0, sizeof(result));
    msconnector_error_init(&error);
    assert(msconnector_response_companion_client_open(&client, path, 2000U,
        getuid(), getgid(), &error));
    assert(msconnector_response_companion_client_claim(&client, handle, &result, &error));
    msconnector_response_companion_result_destroy(&result);
    memset(&response, 0, sizeof(response));
    memset(&status_pseudoheader, 0, sizeof(status_pseudoheader));
    status_pseudoheader.name = ":status";
    status_pseudoheader.name_size = sizeof(":status") - 1U;
    status_pseudoheader.value = "200";
    status_pseudoheader.value_size = sizeof("200") - 1U;
    response.status = 200;
    response.http_version = "HTTP/1.1";
    response.headers = &status_pseudoheader;
    response.header_count = 1U;
    assert(msconnector_response_companion_client_response_headers(&client, &response,
        &result, &error));
    assert(!msconnector_response_companion_client_response_headers(&client, &response,
        &result, &error));
    assert(error.code == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
    assert(msconnector_response_companion_client_commit(&client, 1, 0, &result, &error));
    assert(msconnector_response_companion_client_body_chunk(&client, body, sizeof(body) - 1U,
        &result, &error));
    assert(msconnector_response_companion_client_body_eos(&client, &result, &error));
    assert(msconnector_response_companion_client_release(&client, &result, &error));
    msconnector_response_companion_result_destroy(&result);

    /* RELEASE resets only the transaction state; a trusted MRC1 stream may
     * carry a later capability without retaining the earlier transaction. */
    assert(msconnector_response_companion_client_claim(&client, second_handle,
        &result, &error));
    assert(msconnector_response_companion_client_response_headers(&client, &response,
        &result, &error));
    assert(msconnector_response_companion_client_cancel(&client, 0, &result, &error));
    msconnector_response_companion_result_destroy(&result);
    assert(msconnector_response_companion_client_close(&client, &error));
}

static void test_rejects_malformed_result(const char *path)
{
    msconnector_response_companion_client client;
    msconnector_response_companion_result result;
    msconnector_error error;
    const char *handle = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    memset(&client, 0, sizeof(client));
    memset(&result, 0, sizeof(result));
    msconnector_error_init(&error);
    assert(msconnector_response_companion_client_open(&client, path, 2000U,
        getuid(), getgid(), &error));
    assert(!msconnector_response_companion_client_claim(&client, handle, &result, &error));
    assert(error.code == MSCONNECTOR_ERROR_PROTOCOL);
    msconnector_response_companion_result_destroy(&result);
    assert(msconnector_response_companion_client_close(&client, &error));
}

static void test_body_bound(const char *path)
{
    msconnector_response_companion_client client;
    msconnector_response_companion_result result;
    msconnector_error error;
    msconnector_response response;
    const char *handle = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    unsigned char *body = calloc(MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_MAX_BODY_CHUNK + 1U, 1U);
    memset(&client, 0, sizeof(client));
    memset(&result, 0, sizeof(result));
    msconnector_error_init(&error);
    assert(body != NULL);
    assert(msconnector_response_companion_client_open(&client, path, 2000U,
        getuid(), getgid(), &error));
    assert(!msconnector_response_companion_client_body_chunk(&client, body,
        MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_MAX_BODY_CHUNK + 1U, &result, &error));
    assert(error.code == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
    memset(&response, 0, sizeof(response));
    response.status = 200;
    response.http_version = "HTTP/1.1";
    assert(msconnector_response_companion_client_claim(&client, handle, &result, &error));
    assert(msconnector_response_companion_client_response_headers(&client, &response,
        &result, &error));
    assert(msconnector_response_companion_client_commit(&client, 1, 0, &result, &error));
    assert(!msconnector_response_companion_client_body_chunk(&client, body,
        MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_MAX_BODY_CHUNK + 1U, &result, &error));
    assert(error.code == MSCONNECTOR_ERROR_BODY_TOO_LARGE);
    free(body);
    msconnector_response_companion_result_destroy(&result);
    assert(msconnector_response_companion_client_close(&client, &error));
}

static void test_rejects_untrusted_peer(const char *path)
{
    msconnector_response_companion_client client;
    msconnector_error error;
    const uid_t wrong_uid = getuid() == 0U ? 1U : 0U;

    memset(&client, 0, sizeof(client));
    msconnector_error_init(&error);
    assert(!msconnector_response_companion_client_open(&client, path, 2000U,
        wrong_uid, getgid(), &error));
    assert(error.code == MSCONNECTOR_ERROR_PROTOCOL);
    assert(msconnector_response_companion_client_close(&client, &error));
}

static void test_rejects_reopen(const char *path)
{
    msconnector_response_companion_client client;
    msconnector_error error;
    int first_fd;

    memset(&client, 0, sizeof(client));
    msconnector_error_init(&error);
    assert(msconnector_response_companion_client_open(&client, path, 2000U,
        getuid(), getgid(), &error));
    first_fd = client.socket_fd;
    assert(!msconnector_response_companion_client_open(&client, path, 2000U,
        getuid(), getgid(), &error));
    assert(error.code == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
    assert(client.opened && !client.closed && client.socket_fd == first_fd);
    assert(msconnector_response_companion_client_close(&client, &error));
}

static void test_times_out_waiting_for_result(const char *path)
{
    msconnector_response_companion_client client;
    msconnector_response_companion_result result;
    msconnector_error error;
    const char *handle = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    memset(&client, 0, sizeof(client));
    memset(&result, 0, sizeof(result));
    msconnector_error_init(&error);
    assert(msconnector_response_companion_client_open(&client, path, 25U,
        getuid(), getgid(), &error));
    assert(!msconnector_response_companion_client_claim(&client, handle, &result,
        &error));
    assert(error.code == MSCONNECTOR_ERROR_TIMEOUT);
    msconnector_response_companion_result_destroy(&result);
    assert(msconnector_response_companion_client_close(&client, &error));
}

static void test_exchange_uses_one_deadline(const char *path)
{
    msconnector_response_companion_client client;
    msconnector_response_companion_result result;
    msconnector_error error;
    msconnector_response response;
    const char *handle = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    unsigned char *body;
    int send_buffer = 1024;

    memset(&client, 0, sizeof(client));
    memset(&result, 0, sizeof(result));
    memset(&response, 0, sizeof(response));
    msconnector_error_init(&error);
    body = calloc(MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_MAX_BODY_CHUNK, 1U);
    assert(body != NULL);
    assert(msconnector_response_companion_client_open(&client, path, 120U,
        getuid(), getgid(), &error));
    assert(setsockopt(client.socket_fd, SOL_SOCKET, SO_SNDBUF, &send_buffer,
        sizeof(send_buffer)) == 0);
    response.status = 200;
    response.http_version = "HTTP/1.1";
    assert(msconnector_response_companion_client_claim(&client, handle, &result,
        &error));
    assert(msconnector_response_companion_client_response_headers(&client, &response,
        &result, &error));
    assert(msconnector_response_companion_client_commit(&client, 1, 0, &result,
        &error));
    assert(!msconnector_response_companion_client_body_chunk(&client, body,
        MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_MAX_BODY_CHUNK, &result, &error));
    assert(error.code == MSCONNECTOR_ERROR_TIMEOUT);
    free(body);
    msconnector_response_companion_result_destroy(&result);
    assert(msconnector_response_companion_client_close(&client, &error));
}

int main(void)
{
    const char *tmpdir = ".";
    char directory[256];
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    test_server server;
    struct stat directory_stat;
    int path_size;

    assert(snprintf(directory, sizeof(directory),
        "%s/mrc1-client-test-XXXXXX", tmpdir) > 0);
    assert(strlen(directory) < sizeof(directory));
    assert(mkdtemp(directory) != NULL);
    assert(stat(directory, &directory_stat) == 0);
    assert(directory_stat.st_uid == geteuid());
    assert((directory_stat.st_mode & 0777U) == 0700U);
    path_size = snprintf(path, sizeof(path), "%s/s", directory);
    assert(path_size > 0 && (size_t)path_size < sizeof(path));
    memset(&server, 0, sizeof(server));
    start_server(&server, path);
    test_normal_lifecycle(path);
    stop_server(&server, path);

    memset(&server, 0, sizeof(server));
    server.malformed = 1;
    start_server(&server, path);
    test_rejects_malformed_result(path);
    stop_server(&server, path);

    memset(&server, 0, sizeof(server));
    start_server(&server, path);
    test_body_bound(path);
    stop_server(&server, path);

    memset(&server, 0, sizeof(server));
    start_server(&server, path);
    test_rejects_untrusted_peer(path);
    stop_server(&server, path);

    memset(&server, 0, sizeof(server));
    start_server(&server, path);
    test_rejects_reopen(path);
    stop_server(&server, path);

    memset(&server, 0, sizeof(server));
    server.result_header_delay_ms = 100L;
    start_server(&server, path);
    test_times_out_waiting_for_result(path);
    stop_server(&server, path);

    memset(&server, 0, sizeof(server));
    server.result_payload_delay_ms = 100L;
    start_server(&server, path);
    test_times_out_waiting_for_result(path);
    stop_server(&server, path);

    memset(&server, 0, sizeof(server));
    server.request_payload_delay_ms = 80L;
    server.result_header_delay_ms = 80L;
    server.delayed_opcode = TEST_RESPONSE_BODY;
    start_server(&server, path);
    test_exchange_uses_one_deadline(path);
    stop_server(&server, path);
    assert(rmdir(directory) == 0);
    puts("response companion client tests: PASS");
    return 0;
}
