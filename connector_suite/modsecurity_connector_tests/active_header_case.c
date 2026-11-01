/* Deterministic framing boundaries selected individually by the active inventory. */
#include "msconnector/headers.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t length = SIZE_MAX;
    if (argc != 2) { return 2; }
    if (strcmp(argv[1], "valid-length") == 0) {
        const msconnector_header header = {"Content-Length", 14U, "42", 2U};
        return msconnector_headers_parse_content_length(&header, 1U, &length) == 1 && length == 42U ? 0 : 1;
    }
    if (strcmp(argv[1], "duplicate-length") == 0) {
        const msconnector_header headers[] = {
            {"Content-Length", 14U, "42", 2U},
            {"content-length", 14U, "42", 2U}
        };
        return msconnector_headers_parse_content_length(headers, 2U, &length) == -1 && length == SIZE_MAX ? 0 : 1;
    }
    if (strcmp(argv[1], "overflow-length") == 0) {
        char decimal[128];
        int count = snprintf(decimal, sizeof(decimal), "%zu0", SIZE_MAX);
        if (count <= 0 || (size_t)count >= sizeof(decimal)) { return 2; }
        const msconnector_header header = {"Content-Length", 14U, decimal, (size_t)count};
        return msconnector_headers_parse_content_length(&header, 1U, &length) == -1 && length == SIZE_MAX ? 0 : 1;
    }
    return 2;
}
