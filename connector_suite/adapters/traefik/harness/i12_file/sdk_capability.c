/* SDK capability receipt only. This executable never calls a host file route. */
#include <stdio.h>
#include <modsecurity/transaction.h>

int main(void) {
    int (*request_file)(Transaction *, const char *) = msc_request_body_from_file;
    int (*request_bytes)(Transaction *, const unsigned char *, size_t) = msc_append_request_body;
    int (*response_bytes)(Transaction *, const unsigned char *, size_t) = msc_append_response_body;
    if (request_file == NULL || request_bytes == NULL || response_bytes == NULL) {
        return 1;
    }
    puts("{\"schema\":\"traefik-sdk-file-capability-v1\","
         "\"request_file_declared_and_linked\":true,"
         "\"request_and_response_byte_append_linked\":true,"
         "\"native_file_api_executed\":false,\"host_route_executed\":false}");
    return 0;
}
