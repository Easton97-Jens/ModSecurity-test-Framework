/* Unit probe of real exported Common validators, not HTTP evidence. */
#include <stdio.h>
#include <string.h>
#include "msconnector/request_helpers.h"
#include "msconnector/request_mapper_contract.h"

int main(int argc, char **argv)
{
    msconnector_request_mapper_contract contract;
    msconnector_request request;
    msconnector_header header = {"Host", 4U, "localhost", 9U};
    unsigned char body[] = "owned";
    char error[128] = {0};
    if (argc != 2) { return 2; }
    msconnector_request_mapper_contract_init(&contract);
    msconnector_request_init(&request);
    request.method = "POST";
    request.uri = "/owned-common-input";
    request.client.address = "127.0.0.1";
    request.server.address = "127.0.0.1";
    request.headers = &header;
    request.header_count = 1U;
    request.body.data = body;
    request.body.size = sizeof(body) - 1U;
    if (strcmp(argv[1], "body") == 0) { request.body.data = NULL; }
    else if (strcmp(argv[1], "unsupported") == 0) {
        request.body.data = NULL; contract.request_body = MSCONNECTOR_MAPPER_UNSUPPORTED;
    }
    else if (strcmp(argv[1], "headers") == 0) { request.headers = NULL; }
    else if (strcmp(argv[1], "empty") == 0) {
        request.headers = NULL; request.header_count = 0U;
        request.body.data = NULL; request.body.size = 0U;
    } else if (strcmp(argv[1], "valid") != 0) { return 2; }
    int mapper = msconnector_request_mapper_validate_output(&contract, &request, error, sizeof(error));
    int validated = msconnector_request_validate(&request);
    printf("%d\n%d\n%s\n", mapper, validated, error);
    return 0;
}
