/* Real APR and production Apache mapper boundary probe. This does not start
 * httpd, parse wire bytes, or execute the native ModSecurity engine. */
#include "msc_apache_mapper.h"
#include <apr_general.h>
#include <apr_tables.h>
#include <apr_version.h>
#include <ap_release.h>
#include <stdio.h>
#include <string.h>

static void print_headers(const char *stage, const msconnector_header *headers,
    size_t count)
{
    printf("%s_count=%zu\n", stage, count);
    for (size_t i = 0; i < count; ++i) {
        printf("%s=%.*s\t%.*s\t%zu\t%zu\n", stage,
            (int)headers[i].name_size, headers[i].name,
            (int)headers[i].value_size, headers[i].value,
            headers[i].name_size, headers[i].value_size);
    }
}

int main(int argc, char **argv)
{
    apr_pool_t *pool = NULL;
    request_rec request = {0};
    conn_rec connection = {0};
    server_rec server = {0};
    msconnector_request mapped_request;
    msconnector_response mapped_response;
    msconnector_request_mapper_contract request_contract;
    msconnector_response_mapper_contract response_contract;
    char error[256] = {0};
    int result = 1;
    if (argc < 2 || (argc - 2) % 2 != 0 ||
        (strcmp(argv[1], "raw") != 0 && strcmp(argv[1], "merge") != 0)) return 2;
    if (apr_initialize() != APR_SUCCESS) return 3;
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS) goto cleanup;
    request.pool = pool;
    request.connection = &connection;
    request.server = &server;
    request.method = "GET";
    request.unparsed_uri = "/mapper-boundary";
    request.protocol = "HTTP/1.1";
    connection.client_ip = "127.0.0.1";
    server.server_hostname = "localhost";
    server.port = 8080;
    request.headers_in = apr_table_make(pool, argc);
    request.headers_out = apr_table_make(pool, argc);
    request.err_headers_out = apr_table_make(pool, 1);
    if (request.headers_in == NULL || request.headers_out == NULL ||
        request.err_headers_out == NULL) goto cleanup;
    apr_table_add(request.headers_in, "Host", "localhost");
    for (int i = 2; i < argc; i += 2) {
        apr_table_add(request.headers_in, argv[i], argv[i + 1]);
        apr_table_add(request.headers_out, argv[i], argv[i + 1]);
    }
    if (strcmp(argv[1], "merge") == 0) {
        apr_table_compress(request.headers_in, APR_OVERLAP_TABLES_MERGE);
        apr_table_compress(request.headers_out, APR_OVERLAP_TABLES_MERGE);
    }
    printf("apr=%s\napache_headers=%s\n", apr_version_string(), AP_SERVER_BASEVERSION);
    const apr_array_header_t *array = apr_table_elts(request.headers_in);
    const apr_table_entry_t *entries = (const apr_table_entry_t *)array->elts;
    printf("apr_count=%d\n", array->nelts);
    for (int i = 0; i < array->nelts; ++i) {
        printf("apr_header=%s\t%s\n", entries[i].key, entries[i].val);
    }
    msconnector_request_mapper_contract_init(&request_contract);
    if (!msc_apache_map_request(&request, &request_contract, &mapped_request,
            error, sizeof(error))) goto cleanup;
    print_headers("request_header", mapped_request.headers, mapped_request.header_count);
    request.status = 200;
    request.content_type = "text/plain; charset=utf-8";
    apr_table_add(request.err_headers_out, "X-I12-Error-Table", "retained");
    msconnector_response_mapper_contract_init(&response_contract);
    if (!msc_apache_map_response(&request, &response_contract, &mapped_response,
            error, sizeof(error))) goto cleanup;
    print_headers("response_header", mapped_response.headers, mapped_response.header_count);
    result = 0;
cleanup:
    if (result != 0) fprintf(stderr, "mapper probe failed: %s\n", error);
    if (pool != NULL) apr_pool_destroy(pool);
    apr_terminate();
    return result;
}
