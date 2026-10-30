/* Execute the production SPOP target parser against real length-delimited data. */
#define main haproxy_spop_runtime_main
#include "connectors/haproxy/src/haproxy_spop_diagnostic_runtime.c"
#undef main

static size_t append_test_varint(unsigned char *out, size_t pos, uint64_t value) {
    if (value < 240U) {
        out[pos++] = (unsigned char)value;
        return pos;
    }
    out[pos++] = (unsigned char)((value & 0xffU) | 240U);
    value = (value - 240U) >> 4U;
    while (value >= 128U) {
        out[pos++] = (unsigned char)((value & 0xffU) | 128U);
        value = (value - 128U) >> 7U;
    }
    out[pos++] = (unsigned char)value;
    return pos;
}

static size_t append_test_bytes(unsigned char *out, size_t pos,
        const unsigned char *value, size_t value_len) {
    pos = append_test_varint(out, pos, value_len);
    memcpy(out + pos, value, value_len);
    return pos + value_len;
}

static size_t build_target_payload(unsigned char *out, const char *key,
        const unsigned char *value, size_t value_len) {
    size_t pos = 0U;
    const unsigned char message[] = "check-request";

    pos = append_test_bytes(out, pos, message, sizeof(message) - 1U);
    out[pos++] = 1U;
    pos = append_test_bytes(out, pos, (const unsigned char *)key, strlen(key));
    out[pos++] = SPOP_DATA_STR;
    return append_test_bytes(out, pos, value, value_len);
}

static int assert_lossless(const char *key, size_t value_len) {
    unsigned char payload[SPOP_FRAME_MAX];
    unsigned char value[MSCONNECTOR_MAX_PATH_LENGTH];
    notify_request request;
    size_t payload_len;

    for (size_t i = 0U; i < value_len; ++i) {
        value[i] = (unsigned char)('a' + (i % 23U));
    }
    payload_len = build_target_payload(payload, key, value, value_len);
    if (parse_notify_payload(payload, payload_len, &request) != 0) {
        return -1;
    }
    if ((strcmp(key, "path") == 0 &&
            (!request.has_path || memcmp(request.path, value, value_len) != 0 ||
             request.path[value_len] != '\0')) ||
            (strcmp(key, "uri") == 0 &&
            (!request.has_uri || memcmp(request.uri, value, value_len) != 0 ||
             request.uri[value_len] != '\0'))) {
        return -1;
    }
    return 0;
}

static int assert_rejected(const char *key, const unsigned char *value,
        size_t value_len) {
    unsigned char payload[SPOP_FRAME_MAX];
    notify_request request;
    size_t payload_len = build_target_payload(payload, key, value, value_len);

    if (parse_notify_payload(payload, payload_len, &request) != -1) {
        return -1;
    }
    return 0;
}

static int assert_marker_reaches_mapper(const char *key) {
    unsigned char payload[SPOP_FRAME_MAX];
    unsigned char value[1024U];
    notify_request request;
    haproxy_modsecurity_request mapped;
    size_t payload_len;

    memset(value, 'a', sizeof(value));
    value[1023U] = 'Z';
    payload_len = build_target_payload(payload, key, value, sizeof(value));
    if (parse_notify_payload(payload, payload_len, &request) != 0) {
        return -1;
    }
    request.http_metadata.has_http_version = 1;
    strcpy(request.http_metadata.http_version, "1.1");
    build_modsecurity_request_from_notify(&request, NULL, &mapped);
    if (mapped.uri == NULL || strlen(mapped.uri) != sizeof(value) ||
        memcmp(mapped.uri, value, sizeof(value)) != 0 ||
        mapped.uri[1023U] != 'Z') {
        return -1;
    }
    return 0;
}

int main(void) {
    unsigned char over_limit[MSCONNECTOR_MAX_PATH_LENGTH + 1U];
    unsigned char embedded_nul[MSCONNECTOR_MAX_PATH_LENGTH];

    memset(over_limit, 'y', sizeof(over_limit));
    memset(embedded_nul, 'x', sizeof(embedded_nul));
    embedded_nul[1024] = '\0';
    if (assert_lossless("path", 1023) != 0 ||
            assert_lossless("path", 1024) != 0 ||
            assert_lossless("path", MSCONNECTOR_MAX_PATH_LENGTH) != 0 ||
            assert_lossless("uri", 1023) != 0 ||
            assert_lossless("uri", 1024) != 0 ||
            assert_lossless("uri", MSCONNECTOR_MAX_PATH_LENGTH) != 0 ||
            assert_marker_reaches_mapper("path") != 0 ||
            assert_marker_reaches_mapper("uri") != 0 ||
            assert_rejected("path", over_limit, sizeof(over_limit)) != 0 ||
            assert_rejected("uri", over_limit, sizeof(over_limit)) != 0 ||
            assert_rejected("path", embedded_nul, sizeof(embedded_nul)) != 0 ||
            assert_rejected("uri", embedded_nul, sizeof(embedded_nul)) != 0) {
        return 1;
    }
    return 0;
}
