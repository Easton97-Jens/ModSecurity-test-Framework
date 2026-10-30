#define _POSIX_C_SOURCE 200809L
/* Real HTTP authorization service and TCP parsing/writing; instrumented
 * Runtime/companion callbacks below are explicit ownership models, not native
 * engine or physical downstream Traefik evidence. Genuine Common provenance
 * copying is covered separately by test_runtime_trusted_provenance and the
 * native transaction/companion suite. */
#include "common/runtime/http_authorization_service.h"
#include <strings.h>

#define main legacy_timeout_fixture_main
#define msconnector_runtime_transaction_begin_request_stream model_begin
#define msconnector_runtime_transaction_begin_request_stream_with_trusted_provenance model_trusted_begin
#define msconnector_runtime_transaction_finish model_finish
#define msconnector_runtime_transaction_finalize_and_snapshot model_finalize
#define msconnector_runtime_transaction_destroy model_destroy
#define msconnector_runtime_destroy model_runtime_destroy
#define msconnector_runtime_error_http_status model_error_http_status
#include "modsecurity_connector_ci/checks/common/http_authorization_service_timeout_smoke.c"
#undef main
#undef msconnector_runtime_transaction_begin_request_stream
#undef msconnector_runtime_transaction_begin_request_stream_with_trusted_provenance
#undef msconnector_runtime_transaction_finish
#undef msconnector_runtime_transaction_finalize_and_snapshot
#undef msconnector_runtime_transaction_destroy
#undef msconnector_runtime_destroy
#undef msconnector_runtime_error_http_status

#define PRIVATE_HEADER "X-Msconnector-Trusted-Reservation"
static const char capability[] =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static const char companion_handle[] =
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

typedef struct trusted_case {
    const char *name;
    int status;
    int claim;
    int begin;
    int finish;
    int finalize;
    int handoff;
    int complete;
    int revoke;
    int allocated;
    int freed;
} trusted_case;

static const trusted_case cases[] = {
    {"allow", 200, 1, 1, 1, 1, 0, 1, 0, 1, 1},
    {"deny", 403, 1, 1, 1, 1, 0, 1, 0, 1, 1},
    {"claim-failure", 500, 1, 0, 0, 0, 0, 0, 0, 0, 0},
    {"begin-failure", 500, 1, 1, 0, 0, 0, 1, 0, 0, 0},
    {"mapping-failure", 400, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"finish-failure", 500, 1, 1, 1, 1, 0, 1, 0, 1, 1},
    {"finalize-failure", 500, 1, 1, 1, 1, 0, 1, 0, 1, 1},
    {"handoff", 200, 1, 1, 1, 0, 1, 1, 0, 1, 1},
    {"handoff-failure", 500, 1, 1, 1, 1, 1, 1, 0, 1, 1},
    {"complete-failure", 500, 1, 1, 1, 0, 1, 1, 1, 1, 1},
    {"complete-revoke-failure", 502, 1, 1, 1, 0, 1, 1, 1, 1, 1},
    {"complete-failure-deny", 500, 1, 1, 1, 1, 0, 1, 0, 1, 1},
};

typedef struct {
    int claim;
    int begin;
    int finish;
    int finish_api;
    int finalize;
    int handoff;
    int complete;
    int revoke;
    int allocated;
    int freed;
    int destroy_nonnull;
    int runtime_destroy;
    int shutdown;
} trusted_call_counts;

static struct {
    const trusted_case *test;
    trusted_call_counts calls;
    int claimed;
    int completed;
    int copied;
    int private_removed;
    int headers_restored;
    int violation;
    msconnector_error_code last_error;
    char run[MSCONNECTOR_RUNTIME_PROVENANCE_TEXT_SIZE];
    char transport_case[MSCONNECTOR_RUNTIME_PROVENANCE_TEXT_SIZE];
    char connection[MSCONNECTOR_RUNTIME_PROVENANCE_TEXT_SIZE];
    msconnector_runtime_transaction *owned;
    msconnector_runtime_transaction *retained;
} observed;

static int mode_is(const char *name) {
    return strcmp(observed.test->name, name) == 0;
}

int msconnector_runtime_error_http_status(const msconnector_runtime *runtime,
    msconnector_error_code code) {
    (void)runtime;
    observed.last_error = code;
    /* Distinct statuses make a secondary revoke error replacing the first
     * completion I/O error observable at the real HTTP write boundary. */
    if (mode_is("complete-revoke-failure"))
        return code == MSCONNECTOR_ERROR_IO ? 502 : 503;
    return 500;
}

static int request_has_private_capability(const msconnector_request *request) {
    size_t seen = 0U;
    if (request == NULL) return 0;
    for (size_t i = 0U; i < request->header_count; ++i) {
        const msconnector_header *header = &request->headers[i];
        if (header->name != NULL && header->name_size == sizeof(PRIVATE_HEADER)-1U &&
            strncasecmp(header->name, PRIVATE_HEADER, header->name_size) == 0) {
            if (header->value == NULL || header->value_size != sizeof(capability)-1U ||
                memcmp(header->value, capability, sizeof(capability)-1U) != 0) return 0;
            ++seen;
        }
    }
    return seen == 1U;
}

static int trusted_map_request(const msconnector_generic_request_source *source,
    const msconnector_request_mapper_contract *contract, msconnector_request *request,
    char *error, size_t capacity) {
    if (mode_is("mapping-failure")) {
        if (error != NULL && capacity > 0U) snprintf(error, capacity, "fixture mapping failure");
        return 0;
    }
    return smoke_map_request(source, contract, request, error, capacity);
}

static int trusted_claim(void *userdata, const msconnector_request *request,
    msconnector_http_authorization_provenance_storage *storage, msconnector_error *error) {
    (void)userdata;
    ++observed.calls.claim;
    if (!request_has_private_capability(request)) observed.violation = 1;
    if (mode_is("claim-failure")) {
        msconnector_error_set(error, MSCONNECTOR_ERROR_HOST_API_FAILURE,
            "fixture claim failure", "trusted-binding-smoke");
        return 0;
    }
    observed.claimed = 1;
    strcpy(storage->run_id, "trusted-service-run");
    strcpy(storage->transport_case_id, "trusted-service-case");
    strcpy(storage->connection_id, "trusted-service-connection");
    storage->connection_reused = 0;
    return 1;
}

int msconnector_runtime_transaction_begin_request_stream(
    msconnector_runtime *runtime, const msconnector_request *request,
    const char *host_request_id, msconnector_runtime_transaction **out,
    msconnector_decision *decision, msconnector_error *error) {
    observed.violation = 1; /* A trusted service must not use the old API. */
    return model_begin(runtime, request, host_request_id, out, decision, error);
}

int msconnector_runtime_transaction_begin_request_stream_with_trusted_provenance(
    msconnector_runtime *runtime, const msconnector_request *request,
    const char *host_request_id, const msconnector_runtime_trusted_provenance *provenance,
    msconnector_runtime_transaction **out, msconnector_decision *decision,
    msconnector_error *error) {
    ++observed.calls.begin;
    *out = NULL;
    if (provenance == NULL) {
        observed.violation = 1;
        return 0;
    }
    if (!observed.claimed || request_has_private_capability(request) ||
        strcmp(provenance->run_id, "trusted-service-run") != 0 ||
        strcmp(provenance->transport_case_id, "trusted-service-case") != 0 ||
        strcmp(provenance->connection_id, "trusted-service-connection") != 0 ||
        provenance->connection_reused != 0) observed.violation = 1;
    /* Inspect every header, not merely whether a matching capability value
     * remains: a zeroed/forged private header is forbidden before P1 too. */
    int safe_seen = 0;
    for (size_t i = 0U; i < request->header_count; ++i) {
        const msconnector_header *header = &request->headers[i];
        if (header->name != NULL && header->name_size == sizeof(PRIVATE_HEADER)-1U &&
            strncasecmp(header->name, PRIVATE_HEADER, header->name_size) == 0)
            observed.violation = 1;
        if (header->name != NULL && header->name_size == sizeof("X-Safe")-1U &&
            strncasecmp(header->name, "X-Safe", header->name_size) == 0 &&
            header->value_size == sizeof("retained")-1U &&
            memcmp(header->value, "retained", header->value_size) == 0) ++safe_seen;
    }
    if (safe_seen != 1) observed.violation = 1;
    observed.private_removed = 1;
    strcpy(observed.run, provenance->run_id);
    strcpy(observed.transport_case, provenance->transport_case_id);
    strcpy(observed.connection, provenance->connection_id);
    observed.copied = 1;
    if (mode_is("begin-failure")) {
        msconnector_error_set(error, MSCONNECTOR_ERROR_RUNTIME_UNAVAILABLE,
            "fixture begin failure", "trusted-binding-smoke");
        return 0;
    }
    if (!model_begin(runtime, request, host_request_id, out, decision, error)) return 0;
    observed.owned = *out;
    ++observed.calls.allocated;
    return 1;
}

int msconnector_runtime_transaction_finish(msconnector_runtime_transaction *transaction,
    msconnector_error *error) {
    ++observed.calls.finish_api;
    if (transaction == NULL || transaction != observed.owned) return 0;
    if (!transaction->finished) {
        ++observed.calls.finish;
        if (observed.copied && (strcmp(observed.run, "trusted-service-run") != 0 ||
            strcmp(observed.transport_case, "trusted-service-case") != 0 ||
            strcmp(observed.connection, "trusted-service-connection") != 0)) observed.violation = 1;
    }
    if (mode_is("finish-failure")) {
        /* One failed native finish remains stable; repeated checked cleanup
         * must not turn that attempt into success. */
        transaction->finished = 1;
        msconnector_error_set(error, MSCONNECTOR_ERROR_IO, "fixture finish failure", "fixture");
        return 0;
    }
    return model_finish(transaction, error);
}

void msconnector_runtime_transaction_destroy(msconnector_runtime_transaction **transaction) {
    if (transaction == NULL || *transaction == NULL) return;
    if (*transaction != observed.owned) observed.violation = 1;
    ++observed.calls.destroy_nonnull;
    if (!(*transaction)->finished) (void)msconnector_runtime_transaction_finish(*transaction, NULL);
    /* A failed finish still requires exactly one final free. */
    if (mode_is("finish-failure")) fake_runtime.active_transactions = 0U;
    ++observed.calls.freed;
    observed.owned = NULL;
    model_destroy(transaction);
}

int msconnector_runtime_transaction_finalize_and_snapshot(
    msconnector_runtime_transaction **transaction,
    msconnector_runtime_transaction_snapshot *snapshot, msconnector_error *error) {
    ++observed.calls.finalize;
    if (transaction == NULL || *transaction == NULL || snapshot == NULL ||
        !msconnector_runtime_transaction_finish(*transaction, error)) return 0;
    if (mode_is("finalize-failure")) {
        msconnector_error_set(error, MSCONNECTOR_ERROR_IO, "fixture cleanup failure", "fixture");
        return 0;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->finished = 1;
    snapshot->contract.cleanup_started = 1;
    snapshot->contract.cleanup_complete = 1;
    snapshot->contract.status = MSCONNECTOR_TRANSACTION_STATUS_CLEANED;
    ++observed.calls.freed;
    observed.owned = NULL;
    model_destroy(transaction);
    return 1;
}

void msconnector_runtime_destroy(msconnector_runtime **runtime) {
    ++observed.calls.runtime_destroy;
    if (observed.owned != NULL || observed.retained != NULL ||
        fake_runtime.active_transactions != 0U) observed.violation = 1;
    model_runtime_destroy(runtime);
}

static int companion_handoff(const msconnector_runtime *runtime,
    msconnector_runtime_transaction *transaction, void *userdata,
    char handle[MSCONNECTOR_RUNTIME_RESPONSE_COMPANION_HANDLE_SIZE], msconnector_error *error) {
    (void)runtime; (void)userdata;
    ++observed.calls.handoff;
    if (transaction != observed.owned || observed.retained != NULL || observed.calls.finish != 0)
        observed.violation = 1;
    if (mode_is("handoff-failure")) {
        msconnector_error_set(error, MSCONNECTOR_ERROR_RUNTIME_UNAVAILABLE,
            "fixture handoff failure", "fixture");
        return 0;
    }
    observed.retained = transaction;
    memcpy(handle, companion_handle, sizeof(companion_handle));
    return 1;
}

static int companion_revoke(void *userdata, const char *handle, msconnector_error *error) {
    (void)userdata;
    ++observed.calls.revoke;
    if (observed.retained == NULL || strcmp(handle, companion_handle) != 0) {
        observed.violation = 1;
        return 0;
    }
    if (mode_is("complete-revoke-failure")) {
        msconnector_error_set(error, MSCONNECTOR_ERROR_HOST_API_FAILURE,
            "fixture secondary revoke failure", "fixture");
        return 0; /* The companion retains ownership until shutdown. */
    }
    int result = msconnector_runtime_transaction_finish(observed.retained, error);
    msconnector_runtime_transaction_destroy(&observed.retained);
    return result;
}

static int companion_shutdown(void *userdata, msconnector_error *error) {
    (void)userdata;
    ++observed.calls.shutdown;
    if (observed.retained != NULL) {
        int result = msconnector_runtime_transaction_finish(observed.retained, error);
        msconnector_runtime_transaction_destroy(&observed.retained);
        return result;
    }
    return 1;
}

static int trusted_complete(void *userdata, const msconnector_request *request,
    int status, const char *handle, msconnector_error *error) {
    (void)userdata;
    ++observed.calls.complete;
    if (!observed.claimed) {
        observed.violation = 1;
        msconnector_error_set(error, MSCONNECTOR_ERROR_HOST_API_FAILURE,
            "complete without successful claim", "trusted-binding-smoke");
        return 0;
    }
    if (!request_has_private_capability(request)) observed.violation = 1;
    observed.headers_restored = 1;
    if (status != observed.test->status && !mode_is("complete-failure") &&
        !mode_is("complete-failure-deny") && !mode_is("complete-revoke-failure")) observed.violation = 1;
    if (handle != NULL && (strcmp(handle, companion_handle) != 0 ||
        observed.retained == NULL || observed.calls.finish != 0)) observed.violation = 1;
    if (mode_is("complete-failure") || mode_is("complete-failure-deny") ||
        mode_is("complete-revoke-failure")) {
        msconnector_error_set(error, MSCONNECTOR_ERROR_IO, "fixture complete failure", "fixture");
        return 0;
    }
    observed.completed = 1;
    return 1;
}

static int validate_observations(void) {
    const trusted_case *expected = observed.test;
    const int expected_destroy = (expected->handoff && !mode_is("handoff-failure")) ||
        mode_is("finish-failure") || mode_is("finalize-failure");
    int expected_finish_api = 0;
    if (expected->allocated != 0) expected_finish_api = expected->finalize ? 2 : 1;
    printf("trusted_binding_case=%s claim=%d begin=%d finish=%d finish_api=%d finalize=%d "
        "handoff=%d complete=%d revoke=%d allocated=%d freed=%d destroy_nonnull=%d "
        "runtime_destroy=%d active=%u first_error=%d violation=%d\n", expected->name,
        observed.calls.claim, observed.calls.begin, observed.calls.finish, observed.calls.finish_api, observed.calls.finalize,
        observed.calls.handoff, observed.calls.complete, observed.calls.revoke, observed.calls.allocated, observed.calls.freed,
        observed.calls.destroy_nonnull, observed.calls.runtime_destroy, fake_runtime.active_transactions, observed.last_error,
        observed.violation);
    return observed.calls.claim == expected->claim && observed.calls.begin == expected->begin &&
        observed.calls.finish == expected->finish && observed.calls.finalize == expected->finalize &&
        observed.calls.handoff == expected->handoff && observed.calls.complete == expected->complete &&
        observed.calls.revoke == expected->revoke && observed.calls.allocated == expected->allocated &&
        observed.calls.freed == expected->freed && observed.calls.runtime_destroy == 1 &&
        observed.calls.finish_api == expected_finish_api && observed.calls.destroy_nonnull == expected_destroy &&
        observed.calls.shutdown == (expected->handoff != 0) &&
        (!mode_is("complete-revoke-failure") || observed.last_error == MSCONNECTOR_ERROR_IO) &&
        observed.owned == NULL && observed.retained == NULL &&
        fake_runtime.active_transactions == 0U && !observed.violation &&
        (observed.calls.begin == 0 || observed.private_removed) &&
        (observed.calls.complete == 0 || observed.headers_restored);
}

static pid_t start_trusted_service(unsigned short port, const trusted_case *test) {
    pid_t child = fork();
    if (child != 0) return child;
    memset(&observed, 0, sizeof(observed));
    observed.test = test;
    msconnector_http_authorization_profile profile = smoke_profile;
    profile.map_request = trusted_map_request;
    if (test->handoff) {
        profile.handoff_response_companion = companion_handoff;
        profile.revoke_response_companion = companion_revoke;
        profile.shutdown_response_companion = companion_shutdown;
    }
    msconnector_http_authorization_trusted_binding binding = {
        trusted_claim, NULL, PRIVATE_HEADER, trusted_complete};
    char listen[64];
    snprintf(listen, sizeof(listen), "127.0.0.1:%u", (unsigned int)port);
    char *argv[] = {"trusted-binding-smoke", "--serve", "--config", "fixture.conf",
        "--listen", listen, "--max-requests", "1", "--connection-timeout-ms", "1000", NULL};
    int result = msconnector_http_authorization_service_main_with_trusted_binding(10, argv,
        &profile, &binding);
    int valid = validate_observations();
    fflush(NULL);
    _exit(result == 0 && valid ? 0 : 1);
}

static int run_trusted_case(const trusted_case *test) {
    unsigned short port;
    char request[512];
    char response[4096] = {0};
    char status[32];
    if (!reserve_loopback_port(&port)) return 0;
    /* Deny happens at P1 in the model; ordinary Allow is followed by real
     * authorization_stream_request_body EOS in the service. */
    const char *uri = strcmp(test->name, "deny") == 0 ||
        strcmp(test->name, "complete-failure-deny") == 0 ? "/deny" : "/ok";
    snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: trusted.test\r\n"
        PRIVATE_HEADER ": %s\r\nX-Safe: retained\r\n"
        "X-Msconnector-Run-ID: forged-client-run\r\n"
        "X-Forwarded-Connection-ID: forged-client-connection\r\n\r\n", uri, capability);
    snprintf(status, sizeof(status), "HTTP/1.1 %d", test->status);
    pid_t child = start_trusted_service(port, test);
    if (child < 0) return 0;
    int valid_response = request_response(port, request, response, sizeof(response)) &&
        response_has_status(response, status) && strstr(response, capability) == NULL;
    if (test->status >= 300 && strstr(response, companion_handle) != NULL) valid_response = 0;
    if (strcmp(test->name, "handoff") == 0 && strstr(response, companion_handle) == NULL) valid_response = 0;
    int exited = wait_for_service(child);
    if (!valid_response || !exited) {
        fprintf(stderr, "trusted binding case failed: %s response_ok=%d child_ok=%d\n",
            test->name, valid_response, exited);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    int valid = 1;
    int selected = 0;
    for (size_t i = 0U; i < sizeof(cases)/sizeof(cases[0]); ++i) {
        if (argc == 2 && strcmp(argv[1], cases[i].name) != 0) continue;
        selected = 1;
        if (!run_trusted_case(&cases[i])) valid = 0;
    }
    if (!selected) return 2;
    if (valid) puts("http authorization trusted binding smoke: passed");
    return valid ? 0 : 1;
}
