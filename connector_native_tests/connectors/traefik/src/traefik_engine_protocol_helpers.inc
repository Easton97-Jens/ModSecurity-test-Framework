/* Shared Framework-only frame builders, byte-identical to their original definitions. */
#ifndef MSCONNECTOR_FRAMEWORK_TRAEFIK_ENGINE_PROTOCOL_HELPERS
#define MSCONNECTOR_FRAMEWORK_TRAEFIK_ENGINE_PROTOCOL_HELPERS

static int traefik_engine_self_test_append_u16(unsigned char *buffer,
    size_t size, size_t *offset, uint16_t value)
{
    if (buffer == NULL || offset == NULL || *offset > size ||
        size - *offset < 2U) {
        return 0;
    }
    traefik_engine_write_u16(buffer + *offset, value);
    *offset += 2U;
    return 1;
}

static int traefik_engine_self_test_append_text(unsigned char *buffer,
    size_t size, size_t *offset, const char *value)
{
    size_t value_size = value == NULL ? 0U : strlen(value);
    if (value_size > UINT16_MAX || !traefik_engine_self_test_append_u16(buffer,
            size, offset, (uint16_t)value_size) || *offset > size ||
        size - *offset < value_size) {
        return 0;
    }
    if (value_size > 0U) {
        memcpy(buffer + *offset, value, value_size);
        *offset += value_size;
    }
    return 1;
}

static int traefik_engine_protocol_self_test_begin_with_header(
    unsigned char *buffer, size_t size, size_t *offset,
    const char *name, const char *value)
{
    return traefik_engine_self_test_append_text(buffer, size, offset, "GET") &&
        traefik_engine_self_test_append_text(buffer, size, offset, "/health") &&
        traefik_engine_self_test_append_text(buffer, size, offset, "HTTP/1.1") &&
        traefik_engine_self_test_append_text(buffer, size, offset, "example.test") &&
        traefik_engine_self_test_append_text(buffer, size, offset, "127.0.0.1") &&
        traefik_engine_self_test_append_u16(buffer, size, offset, 12345U) &&
        traefik_engine_self_test_append_text(buffer, size, offset, "127.0.0.1") &&
        traefik_engine_self_test_append_u16(buffer, size, offset, 80U) &&
        traefik_engine_self_test_append_text(buffer, size, offset, "request-1") &&
        traefik_engine_self_test_append_u16(buffer, size, offset, 1U) &&
        traefik_engine_self_test_append_text(buffer, size, offset, name) &&
        traefik_engine_self_test_append_text(buffer, size, offset, value);
}

#endif
