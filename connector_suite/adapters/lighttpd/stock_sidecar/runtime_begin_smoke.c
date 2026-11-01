#define _POSIX_C_SOURCE 200809L

#include "msconnector_runtime.h"
#include "connectors/profile_registry.h"

#include <stdio.h>
#include <string.h>

/* Component smoke test: unlike a compile-only adapter check this enters the
 * real Common transaction route and therefore catches a connector/profile
 * identity mismatch before deployment. Link it with the repository's normal
 * Common runtime object set and libmodsecurity, then pass a valid runtime
 * configuration path. */
int main(int argc, char **argv) {
    msconnector_runtime *runtime = NULL;
    msconnector_runtime_transaction *transaction = NULL;
    msconnector_request request;
    msconnector_decision decision;
    msconnector_error error;
    char message[256];
    if (argc != 2) return 64;
    if (!msconnector_runtime_create("lighttpd", argv[1], &runtime, message, sizeof(message))) return 78;
    if (!msconnector_runtime_set_event_integration_mode(runtime, "stock-lighttpd-sidecar") ||
        !msconnector_runtime_set_transaction_profile(runtime,
            msconnector_profile_registry_find("lighttpd-stock")) ||
        msconnector_runtime_request_body_mode(runtime) != MSCONNECTOR_BODY_MODE_STREAMING ||
        msconnector_runtime_response_body_mode(runtime) != MSCONNECTOR_BODY_MODE_STREAMING) {
        msconnector_runtime_destroy(&runtime);
        return 78;
    }
    memset(&request, 0, sizeof(request));
    request.method = "GET";
    request.uri = "/";
    request.http_version = "HTTP/1.1";
    request.hostname = "localhost";
    /* This is a synthetic Common-runtime smoke request, not a socket-backed
     * production exchange. Keep its endpoint metadata valid and explicit. */
    request.client.address = "127.0.0.1";
    request.client.port = 49152;
    request.server.address = "127.0.0.1";
    request.server.port = 8080;
    if (!msconnector_runtime_transaction_begin(runtime, &request, NULL, &transaction,
                                                &decision, &error)) {
        msconnector_runtime_destroy(&runtime);
        return 1;
    }
    if (!msconnector_runtime_transaction_finish_request_body(transaction, &decision, &error)) {
        (void)msconnector_runtime_transaction_cancel(transaction, 0, &error);
        (void)msconnector_runtime_transaction_finish(transaction, &error);
        msconnector_runtime_transaction_destroy(&transaction);
        msconnector_runtime_destroy(&runtime);
        return 1;
    }
    (void)msconnector_runtime_transaction_cancel(transaction, 0, &error);
    (void)msconnector_runtime_transaction_finish(transaction, &error);
    msconnector_runtime_transaction_destroy(&transaction);
    msconnector_runtime_destroy(&runtime);
    return 0;
}
