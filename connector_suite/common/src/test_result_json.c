#include "msconnector/test_result_json.h"
#include "msconnector/json_escape.h"
#include <stdio.h>

#define FIELD_SIZE 256U

static void escape_test_field(const char *src, char *dst, size_t dst_size, int *truncated)
{
    const size_t needed = msconnector_json_escape(src, dst, dst_size);

    if (truncated != 0 && (dst_size == 0U || needed >= dst_size)) {
        *truncated = 1;
    }
}

int msconnector_test_result_write_json(
    const msconnector_test_result *result,
    char *dst,
    size_t dst_size,
    int *truncated)
{
    char connector[FIELD_SIZE];
    char case_name[FIELD_SIZE];
    char status[64];
    char reason[FIELD_SIZE];
    int was_truncated = 0;
    int written;

    if (truncated != 0) {
        *truncated = 0;
    }
    if (dst != 0 && dst_size > 0U) {
        dst[0] = '\0';
    }
    if (result == 0 || dst == 0 || dst_size == 0U) {
        return 0;
    }

    escape_test_field(result->connector, connector, sizeof(connector), &was_truncated);
    escape_test_field(result->case_name, case_name, sizeof(case_name), &was_truncated);
    escape_test_field(msconnector_status_name(result->status), status, sizeof(status), &was_truncated);
    escape_test_field(result->reason, reason, sizeof(reason), &was_truncated);

    written = snprintf(
        dst,
        dst_size,
        "{\"connector\":\"%s\",\"case\":\"%s\",\"status\":\"%s\",\"expected_http_status\":%d,\"actual_http_status\":%d,\"reason\":\"%s\"}",
        connector,
        case_name,
        status,
        result->expected_http_status,
        result->actual_http_status,
        reason);
    if (written < 0 || (size_t)written >= dst_size) {
        was_truncated = 1;
    }
    if (truncated != 0) {
        *truncated = was_truncated;
    }
    return was_truncated ? 0 : 1;
}
