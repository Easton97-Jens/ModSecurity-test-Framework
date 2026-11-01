#include "msconnector/headers.h"
#include "msconnector/log_sanitize.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define FUZZ_INPUT_LIMIT 8192U

static void require_control(int condition) {
    if (!condition) {
        abort();
    }
}

static void require_no_log_controls(const char *value, size_t value_size) {
    for (size_t index = 0; index < value_size; ++index) {
        const unsigned char character = (unsigned char)value[index];
        require_control(character >= 32U && character != 127U);
    }
}

static void verify_header_parser_controls(void) {
    static const char content_length_name[] = "content-length";
    static const char valid_value[] = "123";
    static const char malformed_value[] = "12x";
    static const char overflow_value[] = "999999999999999999999999999999999999999999999999";
    static const char one_value[] = "1";
    static const char two_value[] = "2";
    const msconnector_header valid_header[] = {
        {content_length_name, sizeof(content_length_name) - 1U, valid_value, sizeof(valid_value) - 1U},
    };
    const msconnector_header malformed_header[] = {
        {content_length_name, sizeof(content_length_name) - 1U, malformed_value, sizeof(malformed_value) - 1U},
    };
    const msconnector_header overflow_header[] = {
        {content_length_name, sizeof(content_length_name) - 1U, overflow_value, sizeof(overflow_value) - 1U},
    };
    const msconnector_header conflicting_headers[] = {
        {content_length_name, sizeof(content_length_name) - 1U, one_value, sizeof(one_value) - 1U},
        {content_length_name, sizeof(content_length_name) - 1U, two_value, sizeof(two_value) - 1U},
    };
    const msconnector_header duplicate_headers[] = {
        {content_length_name, sizeof(content_length_name) - 1U, one_value, sizeof(one_value) - 1U},
        {content_length_name, sizeof(content_length_name) - 1U, one_value, sizeof(one_value) - 1U},
    };
    size_t content_length = 0U;

    require_control(msconnector_headers_parse_content_length(valid_header, 1U, &content_length) == 1);
    require_control(content_length == 123U);
    require_control(msconnector_headers_parse_content_length(malformed_header, 1U, &content_length) == -1);
    require_control(msconnector_headers_parse_content_length(overflow_header, 1U, &content_length) == -1);
    require_control(msconnector_headers_parse_content_length(conflicting_headers, 2U, &content_length) == -1);
    require_control(msconnector_headers_parse_content_length(duplicate_headers, 2U, &content_length) == -1);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const char empty[] = "";
    static const char content_length_name[] = "content-length";
    const char *bytes;
    const char *second_part;
    size_t first_size;
    msconnector_header headers[2];
    char sanitized[128];
    char copied[128];
    size_t sanitized_size;
    size_t inspected_size;
    size_t content_length = 0U;
    int truncated = 0;

    if (size > FUZZ_INPUT_LIMIT) {
        return 0;
    }
    verify_header_parser_controls();

    bytes = size == 0U ? empty : (const char *)data;
    first_size = size / 2U;
    second_part = bytes + first_size;
    headers[0] = (msconnector_header){
        content_length_name,
        sizeof(content_length_name) - 1U,
        bytes,
        first_size,
    };
    headers[1] = (msconnector_header){
        second_part,
        size - first_size,
        bytes,
        first_size,
    };

    (void)msconnector_headers_parse_content_length(headers, 2U, &content_length);
    (void)msconnector_headers_content_type_matches(headers, 2U, "application/json");
    (void)msconnector_headers_copy_value(
        headers, 2U, "content-length", copied, sizeof(copied), &truncated);

    sanitized_size = msconnector_header_sanitize_value_for_log(
        bytes, first_size, sanitized, sizeof(sanitized), &truncated);
    inspected_size = sanitized_size < sizeof(sanitized) - 1U ? sanitized_size : sizeof(sanitized) - 1U;
    require_no_log_controls(sanitized, inspected_size);

    sanitized_size = msconnector_sanitize_log_message(
        second_part, size - first_size, sanitized, sizeof(sanitized), &truncated);
    inspected_size = sanitized_size < sizeof(sanitized) - 1U ? sanitized_size : sizeof(sanitized) - 1U;
    require_no_log_controls(sanitized, inspected_size);
    return 0;
}
