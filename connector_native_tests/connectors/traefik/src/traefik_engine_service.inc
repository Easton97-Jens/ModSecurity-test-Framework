/* Framework-owned native regression definitions. Product source is supplied explicitly by the runner. */

#include "traefik_engine_protocol_helpers.inc"

static int traefik_engine_protocol_self_test(void)
{
    unsigned char begin[256];
    traefik_engine_request_input input;
    traefik_engine_response_input response_input;
    traefik_engine_frame frame;
    uint8_t action;
    uint8_t flags;
    uint16_t visible_status;
    size_t offset = 0U;
    int passed = 1;

    memset(begin, 0, sizeof(begin));
    passed &= traefik_engine_self_test_append_text(begin, sizeof(begin),
        &offset, "GET");
    passed &= traefik_engine_self_test_append_text(begin, sizeof(begin),
        &offset, "/health");
    passed &= traefik_engine_self_test_append_text(begin, sizeof(begin),
        &offset, "HTTP/1.1");
    passed &= traefik_engine_self_test_append_text(begin, sizeof(begin),
        &offset, "example.test");
    passed &= traefik_engine_self_test_append_text(begin, sizeof(begin),
        &offset, "127.0.0.1");
    passed &= traefik_engine_self_test_append_u16(begin, sizeof(begin),
        &offset, 12345U);
    passed &= traefik_engine_self_test_append_text(begin, sizeof(begin),
        &offset, "127.0.0.1");
    passed &= traefik_engine_self_test_append_u16(begin, sizeof(begin),
        &offset, 80U);
    passed &= traefik_engine_self_test_append_text(begin, sizeof(begin),
        &offset, "request-1");
    passed &= traefik_engine_self_test_append_u16(begin, sizeof(begin),
        &offset, 1U);
    passed &= traefik_engine_self_test_append_text(begin, sizeof(begin),
        &offset, "host");
    passed &= traefik_engine_self_test_append_text(begin, sizeof(begin),
        &offset, "example.test");
    if (!passed || !traefik_engine_parse_begin(begin, offset, &input)) {
        return 1;
    }
    passed = input.request.header_count == 1U &&
        strcmp(input.request.method, "GET") == 0 &&
        strcmp(input.request.headers[0].name, "host") == 0;
    traefik_engine_request_input_free(&input);
    if (!passed || traefik_engine_parse_begin(begin, offset - 1U, &input)) {
        return 1;
    }
    {
        const struct {
            const char *name;
            const char *value;
        } invalid_headers[] = {
            {"bad name", "value"},
            {"x-test", "value\r\nInjected: yes"},
            {"x-test", "value\x01"}
        };
        for (size_t index = 0U;
            index < sizeof(invalid_headers) / sizeof(invalid_headers[0]);
            ++index) {
            memset(begin, 0, sizeof(begin));
            offset = 0U;
            if (!traefik_engine_protocol_self_test_begin_with_header(begin,
                    sizeof(begin), &offset, invalid_headers[index].name,
                    invalid_headers[index].value) ||
                traefik_engine_parse_begin(begin, offset, &input)) {
                return 1;
            }
        }
        memset(begin, 0, sizeof(begin));
        offset = 0U;
        if (!traefik_engine_self_test_append_u16(begin, sizeof(begin),
                &offset, 200U) ||
            !traefik_engine_self_test_append_text(begin, sizeof(begin),
                &offset, "HTTP/1.1") ||
            !traefik_engine_self_test_append_u16(begin, sizeof(begin),
                &offset, 1U) ||
            !traefik_engine_self_test_append_text(begin, sizeof(begin),
                &offset, "X-Valid") ||
            !traefik_engine_self_test_append_text(begin, sizeof(begin),
                &offset, "value") ||
            !traefik_engine_parse_response_headers(begin, offset,
                &response_input)) {
            return 1;
        }
        traefik_engine_response_input_free(&response_input);
        for (size_t index = 0U;
            index < sizeof(invalid_headers) / sizeof(invalid_headers[0]);
            ++index) {
            memset(begin, 0, sizeof(begin));
            offset = 0U;
            if (!traefik_engine_self_test_append_u16(begin, sizeof(begin),
                    &offset, 200U) ||
                !traefik_engine_self_test_append_text(begin, sizeof(begin),
                    &offset, "HTTP/1.1") ||
                !traefik_engine_self_test_append_u16(begin, sizeof(begin),
                    &offset, 1U) ||
                !traefik_engine_self_test_append_text(begin, sizeof(begin),
                    &offset, invalid_headers[index].name) ||
                !traefik_engine_self_test_append_text(begin, sizeof(begin),
                    &offset, invalid_headers[index].value) ||
                traefik_engine_parse_response_headers(begin, offset,
                    &response_input)) {
                return 1;
            }
        }
    }
    memset(&frame, 0, sizeof(frame));
    frame.opcode = TRAEFIK_ENGINE_PROTOCOL_OUTCOME;
    frame.payload = begin;
    frame.payload_size = 4U;
    frame.payload[0] = MSCONNECTOR_DECISION_KIND_DENY;
    frame.payload[1] = 2U;
    frame.payload[2] = 0U;
    frame.payload[3] = 0U;
    if (traefik_engine_parse_outcome(&frame, &action, &flags, &visible_status)) {
        return 1;
    }
    frame.payload[1] = 0U;
    if (!traefik_engine_parse_outcome(&frame, &action, &flags, &visible_status) ||
        action != MSCONNECTOR_DECISION_KIND_DENY || flags != 0U ||
        visible_status != 0U) {
        return 1;
    }
    frame.payload[0] = MSCONNECTOR_DECISION_KIND_LOG_ONLY;
    frame.payload[1] = 0U;
    frame.payload[2] = 0U;
    frame.payload[3] = 200U;
    if (!traefik_engine_parse_outcome(&frame, &action, &flags, &visible_status) ||
        action != MSCONNECTOR_DECISION_KIND_LOG_ONLY || flags != 0U ||
        visible_status != 200U) {
        return 1;
    }
    (void)printf("traefik_engine_protocol_self_test=pass\n");
    return 0;
}

static int traefik_engine_self_test_bind_foreign_socket(const char *socket_path)
{
    struct sockaddr_un address;
    int socket_fd;
    size_t path_size;

    if (!traefik_engine_path_is_absolute(socket_path)) {
        return 0;
    }
    path_size = strlen(socket_path);
    if (path_size == 0U || path_size >= sizeof(address.sun_path)) {
        return 0;
    }
    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        return 0;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_path, path_size + 1U);
    if (bind(socket_fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        (void)close(socket_fd);
        return 0;
    }
    (void)close(socket_fd);
    return 1;
}

static int traefik_engine_self_test_pre_bind_foreign_socket(const char *socket_path)
{
    return traefik_engine_self_test_bind_foreign_socket(socket_path);
}

static int traefik_engine_self_test_post_bind_foreign_socket(const char *socket_path)
{
    if (unlink(socket_path) != 0) {
        return 0;
    }
    return traefik_engine_self_test_bind_foreign_socket(socket_path);
}

static int traefik_engine_socket_ownership_self_test(const char *socket_parent)
{
    char directory[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char socket_path[sizeof(directory) + 16U];
    traefik_engine_socket_identity identity;
    struct stat path;
    int listener = -1;
    int result = 1;
    int written;

    memset(directory, 0, sizeof(directory));
    memset(socket_path, 0, sizeof(socket_path));
    memset(&identity, 0, sizeof(identity));
    if (!traefik_engine_private_directory_is_safe(socket_parent)) {
        return 1;
    }
    written = snprintf(directory, sizeof(directory),
        "%s/mct-engine-ownership.XXXXXX", socket_parent);
    if (written < 0 || (size_t)written >= sizeof(directory) ||
        mkdtemp(directory) == NULL || snprintf(socket_path, sizeof(socket_path),
            "%s/engine.sock", directory) < 0 ||
        strlen(socket_path) >= sizeof(socket_path)) {
        goto cleanup;
    }
    traefik_engine_listener_pre_bind_hook =
        traefik_engine_self_test_pre_bind_foreign_socket;
    listener = traefik_engine_create_listener(socket_path, &identity);
    traefik_engine_listener_pre_bind_hook = NULL;
    if (listener >= 0 || lstat(socket_path, &path) != 0 ||
        !S_ISSOCK(path.st_mode) || unlink(socket_path) != 0) {
        goto cleanup;
    }
    traefik_engine_listener_post_bind_hook =
        traefik_engine_self_test_post_bind_foreign_socket;
    listener = traefik_engine_create_listener(socket_path, &identity);
    traefik_engine_listener_post_bind_hook = NULL;
    if (listener >= 0 || lstat(socket_path, &path) != 0 ||
        !S_ISSOCK(path.st_mode) || unlink(socket_path) != 0) {
        goto cleanup;
    }
    traefik_engine_listener_post_probe_hook =
        traefik_engine_self_test_post_bind_foreign_socket;
    listener = traefik_engine_create_listener(socket_path, &identity);
    traefik_engine_listener_post_probe_hook = NULL;
    if (listener >= 0 || lstat(socket_path, &path) != 0 ||
        !S_ISSOCK(path.st_mode) || unlink(socket_path) != 0) {
        goto cleanup;
    }
    listener = traefik_engine_create_listener(socket_path, &identity);
    if (listener < 0 || close(listener) != 0) {
        listener = -1;
        goto cleanup;
    }
    listener = -1;
    if (unlink(socket_path) != 0 ||
        !traefik_engine_self_test_bind_foreign_socket(socket_path) ||
        traefik_engine_remove_owned_socket(socket_path, &identity) ||
        lstat(socket_path, &path) != 0 || !S_ISSOCK(path.st_mode)) {
        goto cleanup;
    }
    result = 0;

cleanup:
    traefik_engine_listener_pre_bind_hook = NULL;
    traefik_engine_listener_post_bind_hook = NULL;
    traefik_engine_listener_post_probe_hook = NULL;
    if (listener >= 0) {
        (void)close(listener);
    }
    if (socket_path[0] != '\0') {
        (void)unlink(socket_path);
    }
    if (directory[0] != '\0') {
        (void)rmdir(directory);
    }
    if (result == 0) {
        (void)printf("traefik_engine_socket_ownership_self_test=pass\n");
    }
    return result;
}
