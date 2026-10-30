#define _POSIX_C_SOURCE 200809L

/* Real SDK + public MRC1 client/server + physical JSONL event regression.
 * This is a component integration probe, not a Traefik host receipt. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/runtime/msconnector_runtime.h"
#include "common/runtime/response_companion_client.h"
#include "common/runtime/response_companion_transport.h"
#include "connectors/profile_registry.h"
#include "tests/transaction_phase_test_support.h"

#define CHECK(operation) do { \
    if (!(operation)) { \
        fprintf(stderr, "operation failed at line %d: %s\n", __LINE__, #operation); \
        return 1; \
    } \
} while (0)

static int make_path(char *output, size_t capacity, const char *root,
    const char *name)
{
    int size = snprintf(output, capacity, "%s/%s", root, name);
    return size > 0 && (size_t)size < capacity;
}

static int write_rules(const char *path)
{
    FILE *file = fopen(path, "w");
    if (file == NULL) return 0;
    int written = fputs("SecRuleEngine On\nSecResponseBodyAccess On\n"
        "SecResponseBodyMimeType text/plain\nSecResponseBodyLimit 1024\n"
        "SecResponseBodyLimitAction Reject\n"
        "SecRule RESPONSE_HEADERS:X-I12-Deny \"@streq yes\" "
        "\"id:1999803,phase:3,deny,status:403,log\"\n"
        "SecRule RESPONSE_BODY \"@contains telemetry-marker\" "
        "\"id:1999804,phase:4,deny,status:403,log\"\n", file) != EOF;
    int closed = fclose(file) == 0;
    return written && closed;
}

static int write_config(const char *path, const char *rules_path,
    const char *mode, const char *event_path)
{
    FILE *file = fopen(path, "w");
    if (file == NULL) return 0;
    int written = fprintf(file, "enabled=on\nrules_file=%s\n"
        "request_body_mode=none\nresponse_body_mode=streaming\nphase4_mode=%s\n"
        "event_path=%s\nmax_event_json_bytes=16384\n",
        rules_path, mode, event_path) > 0;
    int closed = fclose(file) == 0;
    return written && closed;
}

int main(int argc, char **argv)
{
    char config_path[4096];
    char rules_path[4096];
    char event_path[4096];
    char socket_path[MSCONNECTOR_RESPONSE_COMPANION_TRANSPORT_SOCKET_SIZE];
    char handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE];
    const char *scenario;
    const char *mode;
    msconnector_runtime *runtime = NULL;
    msconnector_runtime_transaction *transaction = NULL;
    msconnector_runtime_response_companion_registry registry;
    msconnector_response_companion_transport transport;
    msconnector_response_companion_client client = {0};
    msconnector_response_companion_result result = {0};
    msconnector_decision decision;
    msconnector_error error;
    msconnector_response response = {0};
    msconnector_header headers[2] = {0};
    msconnector_response_companion_transport_options options;

    CHECK(argc == 4);
    scenario = argv[2];
    mode = argv[3];
    CHECK(strcmp(mode, "safe") == 0 || strcmp(mode, "off") == 0 ||
        strcmp(mode, "strict") == 0);
    CHECK(make_path(config_path, sizeof(config_path), argv[1], "config"));
    CHECK(make_path(rules_path, sizeof(rules_path), argv[1], "rules"));
    CHECK(make_path(event_path, sizeof(event_path), argv[1], "events"));
    CHECK(make_path(socket_path, sizeof(socket_path), argv[1], "s"));
    CHECK(write_rules(rules_path));
    CHECK(write_config(config_path, rules_path, mode, event_path));
    CHECK(msconnector_runtime_create("traefik", config_path, &runtime, NULL, 0U));
    CHECK(msconnector_runtime_set_event_integration_mode(runtime, "forwardAuth"));
    if (strcmp(mode, "strict") == 0) {
        CHECK(!msconnector_runtime_set_transaction_profile(runtime,
            msconnector_profile_registry_find("traefik-forwardauth")));
        msconnector_runtime_destroy(&runtime);
        puts("strict_profile_rejected=1");
        return 0;
    }
    CHECK(msconnector_runtime_set_transaction_profile(runtime,
        msconnector_profile_registry_find("traefik-forwardauth")));
    msconnector_runtime_response_companion_registry_init(&registry);
    options = (msconnector_response_companion_transport_options){
        "traefik", socket_path, 32U, 4096U, 1000U};
    msconnector_error_init(&error);
    CHECK(msconnector_response_companion_transport_init(&transport, &registry,
        &options, &error));
    CHECK(msconnector_response_companion_transport_start(&transport, &error));
    CHECK(msconnector_test_begin_transaction(runtime, "/i12-companion-metadata",
        scenario, &transaction, &decision, &error));
    CHECK(msconnector_runtime_response_companion_handoff_with_handle(&registry,
        transaction, 5000U, handle, &error));
    CHECK(msconnector_response_companion_client_open(&client, socket_path,
        1000U, geteuid(), getegid(), &error));
    CHECK(msconnector_response_companion_client_claim(&client, handle,
        &result, &error));
    response.status = 200;
    response.http_version = "HTTP/1.1";
    headers[0] = (msconnector_header){"Content-Type", 12U, "text/plain", 10U};
    headers[1] = (msconnector_header){"X-I12-Deny", 10U, "yes", 3U};
    response.headers = headers;
    response.header_count = strcmp(scenario, "precommit") == 0 ? 2U : 1U;
    CHECK(msconnector_response_companion_client_response_headers(&client,
        &response, &result, &error));
    if (strcmp(scenario, "precommit") == 0) {
        CHECK(result.decision == MSCONNECTOR_DECISION_KIND_DENY);
        CHECK(msconnector_response_companion_client_outcome(&client,
            MSCONNECTOR_DECISION_ACTION_DENY, 403, 0, &result, &error));
        CHECK(msconnector_response_companion_client_release(&client, &result, &error));
    } else {
        CHECK(result.decision == MSCONNECTOR_DECISION_KIND_ALLOW);
        CHECK(msconnector_response_companion_client_commit(&client, 1, 0,
            &result, &error));
        if (strcmp(scenario, "technical") == 0) {
            CHECK(msconnector_response_companion_client_cancel_with_cause(&client,
                MSCONNECTOR_RESPONSE_COMPANION_CANCEL_PROTOCOL_ERROR,
                &result, &error));
        } else {
            const unsigned char *body = (const unsigned char *)(
                strcmp(scenario, "late") == 0 ? "telemetry-marker" : "benign");
            size_t size = strlen((const char *)body);
            CHECK(msconnector_response_companion_client_body_chunk(&client,
                body, size / 2U, &result, &error));
            CHECK(msconnector_response_companion_client_body_chunk(&client,
                body + size / 2U, size - size / 2U, &result, &error));
            CHECK(msconnector_response_companion_client_body_eos(&client,
                &result, &error));
            if (strcmp(scenario, "late") == 0) {
                CHECK(result.decision == MSCONNECTOR_DECISION_KIND_DENY);
                CHECK(result.status == 403);
                CHECK(msconnector_response_companion_client_outcome(&client,
                    MSCONNECTOR_DECISION_ACTION_LOG_ONLY, 200, 0, &result, &error));
            } else {
                CHECK(result.decision == MSCONNECTOR_DECISION_KIND_ALLOW);
            }
            CHECK(msconnector_response_companion_client_release(&client,
                &result, &error));
        }
    }
    msconnector_response_companion_result_destroy(&result);
    CHECK(msconnector_response_companion_client_close(&client, &error));
    CHECK(msconnector_response_companion_transport_stop(&transport, &error));
    CHECK(access(socket_path, F_OK) != 0);
    msconnector_runtime_destroy(&runtime);
    printf("scenario=%s mode=%s completed=1\n", scenario, mode);
    return 0;
}
