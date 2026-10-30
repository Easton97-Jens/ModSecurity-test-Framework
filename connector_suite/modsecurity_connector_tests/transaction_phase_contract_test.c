#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "msconnector/event_jsonl.h"
#include "msconnector/integrity_event.h"
#include "msconnector/modsecurity_engine.h"
#include "msconnector/resource_limits.h"
#include "msconnector/transaction_contract.h"
#include "msconnector/transaction_state.h"
#include "connectors/profile_registry.h"

static int failures;

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL:%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)

typedef struct canonical_id_worker {
    const msconnector_transaction_profile *profile;
    msconnector_transaction_contract contract;
    int result;
} canonical_id_worker;

typedef struct direct_engine_probe {
    int create_rules_calls;
    int rules_set_calls;
    int new_transaction_calls;
    int free_transaction_calls;
    int last_transaction_id_was_null;
} direct_engine_probe;

static int direct_engine_start(void *opaque, msconnector_error *error) {
    (void)opaque;
    msconnector_error_init(error);
    return 1;
}

static void *direct_engine_create_rules(void *opaque, msconnector_error *error) {
    direct_engine_probe *probe = opaque;

    ++probe->create_rules_calls;
    msconnector_error_init(error);
    return opaque;
}

static void direct_engine_destroy_rules(void *opaque, void *rules_set) {
    (void)opaque;
    (void)rules_set;
}

static void *direct_engine_new_transaction(void *opaque, void *rules_set,
    const char *transaction_id, msconnector_error *error) {
    direct_engine_probe *probe = opaque;

    CHECK(rules_set == probe);
    ++probe->rules_set_calls;
    msconnector_error_init(error);
    ++probe->new_transaction_calls;
    probe->last_transaction_id_was_null = transaction_id == NULL;
    return probe;
}

static void direct_engine_free_transaction(void *opaque, void *transaction) {
    direct_engine_probe *probe = opaque;

    (void)transaction;
    ++probe->free_transaction_calls;
}

static void *init_duplicate_canonical_id(void *opaque) {
    canonical_id_worker *worker = opaque;

    worker->result = msconnector_transaction_contract_init(&worker->contract,
        worker->profile, "same-host-request-id", NULL, NULL,
        MSCONNECTOR_TRANSACTION_MODE_STRICT, 4242U);
    return NULL;
}

static msconnector_transaction_contract make_contract(const char *solution_id,
    const char *transaction_id) {
    msconnector_transaction_contract contract;
    const msconnector_transaction_profile *profile =
        msconnector_profile_registry_find(solution_id);
    CHECK(profile != NULL);
    CHECK(msconnector_transaction_contract_init(&contract, profile, transaction_id,
        NULL, NULL, MSCONNECTOR_TRANSACTION_MODE_STRICT, 100U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    return contract;
}

static msconnector_transaction_contract make_contract_on_host(
    const char *solution_id, const char *transaction_id, const char *host_id) {
    msconnector_transaction_contract contract;
    const msconnector_transaction_profile *profile =
        msconnector_profile_registry_find(solution_id);

    CHECK(profile != NULL);
    CHECK(msconnector_transaction_contract_init(&contract, profile, transaction_id,
        NULL, host_id, MSCONNECTOR_TRANSACTION_MODE_STRICT, 100U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    return contract;
}

static void complete_direct_phase(msconnector_transaction_contract *contract,
    enum msconnector_phase phase, uint64_t now) {
    CHECK(msconnector_transaction_contract_begin_phase(contract, phase, now) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_complete_phase(contract, phase, now + 1U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
}

static void complete_companion_phase(msconnector_transaction_contract *contract,
    enum msconnector_phase phase, uint64_t now) {
    CHECK(msconnector_transaction_contract_begin_companion_phase(contract, phase, now) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_complete_phase(contract, phase, now + 1U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
}

static void complete_all_direct(msconnector_transaction_contract *contract) {
    complete_direct_phase(contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 110U);
    complete_direct_phase(contract, MSCONNECTOR_PHASE_REQUEST_BODY, 120U);
    complete_direct_phase(contract, MSCONNECTOR_PHASE_RESPONSE_HEADERS, 130U);
    complete_direct_phase(contract, MSCONNECTOR_PHASE_RESPONSE_BODY, 140U);
}

static void test_profiles_and_semantics(void) {
    size_t count = 0U;
    const msconnector_transaction_profile *profiles =
        msconnector_profile_registry_all(&count);
    CHECK(profiles != NULL);
    CHECK(count == 10U);
    CHECK(strcmp(msconnector_transaction_phase_contract_semantics(
        MSCONNECTOR_PHASE_REQUEST_HEADERS),
        "request headers after connection/URI prerequisites and before request commit") == 0);
    CHECK(strcmp(msconnector_transaction_phase_contract_semantics(
        MSCONNECTOR_PHASE_REQUEST_BODY),
        "request body append with one finalization at request end-of-stream") == 0);
    CHECK(strcmp(msconnector_transaction_phase_contract_semantics(
        MSCONNECTOR_PHASE_RESPONSE_HEADERS),
        "response headers before response commitment while status remains original") == 0);
    CHECK(strcmp(msconnector_transaction_phase_contract_semantics(
        MSCONNECTOR_PHASE_RESPONSE_BODY),
        "bounded response body append with one finalization at response end-of-stream") == 0);

    if (profiles != NULL) {
        for (size_t i = 0U; i < count; ++i) {
            CHECK(profiles[i].private_default_binding != 0);
            CHECK(profiles[i].profile_name != NULL);
            CHECK(profiles[i].connector_id != NULL);
            CHECK(profiles[i].host_adapter_id != NULL);
        }
    }
    if (profiles != NULL && count > 4U) {
        CHECK(msconnector_transaction_profile_phase_route(&profiles[4],
            MSCONNECTOR_PHASE_RESPONSE_HEADERS) ==
            MSCONNECTOR_TRANSACTION_PHASE_ROUTE_COMPANION_REQUIRED);
    }
    {
        const msconnector_transaction_profile *spop =
            msconnector_profile_registry_find("haproxy-spoe-spop");
        CHECK(spop != NULL);
        CHECK(msconnector_transaction_profile_phase_route(spop,
            MSCONNECTOR_PHASE_REQUEST_HEADERS) ==
            MSCONNECTOR_TRANSACTION_PHASE_ROUTE_DIRECT);
        CHECK(msconnector_transaction_profile_phase_route(spop,
            MSCONNECTOR_PHASE_REQUEST_BODY) ==
            MSCONNECTOR_TRANSACTION_PHASE_ROUTE_DIRECT);
        CHECK(msconnector_transaction_profile_phase_route(spop,
            MSCONNECTOR_PHASE_RESPONSE_HEADERS) ==
            MSCONNECTOR_TRANSACTION_PHASE_ROUTE_COMPANION_REQUIRED);
        CHECK(msconnector_transaction_profile_phase_route(spop,
            MSCONNECTOR_PHASE_RESPONSE_BODY) ==
            MSCONNECTOR_TRANSACTION_PHASE_ROUTE_COMPANION_REQUIRED);
    }
    CHECK(msconnector_transaction_profile_phase_route(&profiles[6],
        MSCONNECTOR_PHASE_RESPONSE_BODY) ==
        MSCONNECTOR_TRANSACTION_PHASE_ROUTE_COMPANION_REQUIRED);
    CHECK(msconnector_transaction_profile_phase_route(&profiles[8],
        MSCONNECTOR_PHASE_REQUEST_BODY) ==
        MSCONNECTOR_TRANSACTION_PHASE_ROUTE_DIRECT);
    {
        const msconnector_transaction_profile *stock_native =
            msconnector_profile_registry_find_route("lighttpd",
                "stock-lighttpd");
        CHECK(stock_native != NULL);
        CHECK(msconnector_transaction_profile_phase_route(stock_native,
            MSCONNECTOR_PHASE_REQUEST_HEADERS) ==
            MSCONNECTOR_TRANSACTION_PHASE_ROUTE_DIRECT);
        CHECK(msconnector_transaction_profile_phase_route(stock_native,
            MSCONNECTOR_PHASE_REQUEST_BODY) ==
            MSCONNECTOR_TRANSACTION_PHASE_ROUTE_UNSUPPORTED);
        CHECK(msconnector_transaction_profile_phase_route(stock_native,
            MSCONNECTOR_PHASE_RESPONSE_HEADERS) ==
            MSCONNECTOR_TRANSACTION_PHASE_ROUTE_DIRECT);
        CHECK(msconnector_transaction_profile_phase_route(stock_native,
            MSCONNECTOR_PHASE_RESPONSE_BODY) ==
            MSCONNECTOR_TRANSACTION_PHASE_ROUTE_UNSUPPORTED);
    }
}

static void test_valid_sequence_and_metadata(void) {
    msconnector_transaction_contract contract = make_contract("apache", "tx-valid");
    CHECK(msconnector_transaction_contract_record_request_metadata(&contract, "POST", "/x",
        "application/json", 3U, 120U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_record_response_metadata(&contract, 200,
        "text/plain", 2U, 80U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    complete_all_direct(&contract);
    CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_COMPLETED);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_RESPONSE_BODY, 145U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_AFTER_TERMINAL);
    CHECK(msconnector_transaction_contract_cancel(&contract, 0, 146U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_AFTER_TERMINAL);
    CHECK(msconnector_transaction_contract_timeout(&contract, 147U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_AFTER_TERMINAL);
    CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_COMPLETED);
    CHECK(msconnector_transaction_contract_set_response_committed(&contract, 1) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_set_response_committed(&contract, 0) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_INVALID);
    CHECK(contract.response_committed == 1);
    CHECK(msconnector_transaction_contract_finish(&contract, 150U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_cleanup(&contract, 151U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_CLEANED);
}

static void test_content_type_metadata_uses_header_value_bound(void) {
    char accepted[MSCONNECTOR_MAX_HEADER_VALUE_LENGTH + 1U];
    char rejected[MSCONNECTOR_MAX_HEADER_VALUE_LENGTH + 2U];
    msconnector_transaction_contract contract = make_contract("apache",
        "tx-content-type-bound");

    memset(accepted, 'a', sizeof(accepted) - 1U);
    accepted[sizeof(accepted) - 1U] = '\0';
    memset(rejected, 'b', sizeof(rejected) - 1U);
    rejected[sizeof(rejected) - 1U] = '\0';

    CHECK(sizeof(contract.request_content_type) ==
        MSCONNECTOR_MAX_HEADER_VALUE_LENGTH + 1U);
    CHECK(sizeof(contract.response_content_type) ==
        MSCONNECTOR_MAX_HEADER_VALUE_LENGTH + 1U);
    CHECK(msconnector_transaction_contract_record_request_metadata(&contract,
        "GET", "/content-type", accepted, 1U, 128U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(strcmp(contract.request_content_type, accepted) == 0);
    CHECK(msconnector_transaction_contract_record_response_metadata(&contract,
        200, accepted, 1U, 128U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(strcmp(contract.response_content_type, accepted) == 0);

    contract = make_contract("apache", "tx-content-type-too-large");
    CHECK(msconnector_transaction_contract_record_request_metadata(&contract,
        "GET", "/content-type", rejected, 1U, 128U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_INVALID);
    CHECK(contract.request_content_type[0] == '\0');
}

static void test_profile_lifecycle_routes(void) {
    static const char *const direct_profiles[] = {
        "apache",
        "nginx",
        "haproxy-htx",
        "envoy-ext-proc",
        "traefik-native-uds",
        "lighttpd-patched"
    };
    static const char *const companion_profiles[] = {
        "haproxy-spoe-spop",
        "envoy-ext-authz",
        "traefik-forwardauth"
    };
    msconnector_transaction_contract contract;

    for (size_t index = 0U; index < sizeof(direct_profiles) / sizeof(direct_profiles[0]);
         ++index) {
        contract = make_contract(direct_profiles[index], "tx-direct-profile");
        complete_all_direct(&contract);
        CHECK(msconnector_transaction_contract_finish(&contract, 200U + index) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        CHECK(msconnector_transaction_contract_cleanup(&contract, 220U + index) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    }

    for (size_t index = 0U;
         index < sizeof(companion_profiles) / sizeof(companion_profiles[0]); ++index) {
        contract = make_contract(companion_profiles[index], "tx-companion-profile");
        complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 300U + index);
        complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_BODY, 320U + index);
        CHECK(msconnector_transaction_contract_handoff_response_companion(&contract,
            340U + index) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        CHECK(msconnector_transaction_contract_claim_response_companion(&contract,
            360U + index) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        complete_companion_phase(&contract, MSCONNECTOR_PHASE_RESPONSE_HEADERS,
            380U + index);
        complete_companion_phase(&contract, MSCONNECTOR_PHASE_RESPONSE_BODY,
            400U + index);
        CHECK(msconnector_transaction_contract_finish(&contract, 420U + index) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        CHECK(msconnector_transaction_contract_cleanup(&contract, 440U + index) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    }

    {
        const msconnector_transaction_profile *stock_native =
            msconnector_profile_registry_find_route("lighttpd",
                "stock-lighttpd");
        CHECK(stock_native != NULL);
        CHECK(msconnector_transaction_contract_init(&contract, stock_native,
            "tx-stock-unsupported", NULL, NULL,
            MSCONNECTOR_TRANSACTION_MODE_STRICT, 500U) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    }
    complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 500U);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_REQUEST_BODY, 510U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_UNSUPPORTED_PHASE);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_RESPONSE_BODY, 520U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_UNSUPPORTED_PHASE);
    CHECK(msconnector_transaction_contract_cleanup(&contract, 530U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_PREMATURE_CLEANUP);

    /* The named Stock solution uses its selected traffic-owning sidecar
     * route; its direct native P1/P3 translation above remains explicit. */
    contract = make_contract("lighttpd-stock", "tx-stock-sidecar");
    complete_all_direct(&contract);
    CHECK(msconnector_transaction_contract_finish(&contract, 550U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_cleanup(&contract, 560U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
}

static void test_active_phase_timeout_and_cancel(void) {
    msconnector_transaction_contract contract = make_contract("apache", "tx-p1-timeout");

    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_REQUEST_HEADERS, 1U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_timeout(&contract, 2U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(contract.engine_decision == MSCONNECTOR_TRANSACTION_DECISION_ENGINE_TIMEOUT);
    CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_TERMINAL);
    CHECK(msconnector_transaction_contract_cleanup(&contract, 3U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);

    contract = make_contract("apache", "tx-p2-cancel");
    complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 10U);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_REQUEST_BODY, 12U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_cancel(&contract, 0, 13U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(contract.engine_decision == MSCONNECTOR_TRANSACTION_DECISION_CLIENT_CANCEL);
    CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_TERMINAL);
    CHECK(msconnector_transaction_contract_cleanup(&contract, 14U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);

    contract = make_contract("apache", "tx-p3-disconnect");
    complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 20U);
    complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_BODY, 22U);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_RESPONSE_HEADERS, 24U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_cancel(&contract, 1, 25U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(contract.engine_decision == MSCONNECTOR_TRANSACTION_DECISION_UPSTREAM_DISCONNECT);
    CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_TERMINAL);
    CHECK(msconnector_transaction_contract_cleanup(&contract, 26U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);

    contract = make_contract("apache", "tx-p4-timeout");
    complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 30U);
    complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_BODY, 32U);
    complete_direct_phase(&contract, MSCONNECTOR_PHASE_RESPONSE_HEADERS, 34U);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_RESPONSE_BODY, 36U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_timeout(&contract, 37U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(contract.engine_decision == MSCONNECTOR_TRANSACTION_DECISION_ENGINE_TIMEOUT);
    CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_TERMINAL);
    CHECK(msconnector_transaction_contract_cleanup(&contract, 38U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
}

static void test_canonical_transaction_id_boundary(void) {
    msconnector_transaction_contract contract;
    const msconnector_transaction_profile *profile =
        msconnector_profile_registry_find("apache");
    char oversized[MSCONNECTOR_MAX_TRANSACTION_ID_LENGTH + 1U];

    CHECK(profile != NULL);
    CHECK(msconnector_transaction_contract_init(&contract, profile,
        "host-request_123:stream/7", NULL, NULL,
        MSCONNECTOR_TRANSACTION_MODE_STRICT, 100U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(strcmp(contract.transaction_id, "host-request_123:stream/7") == 0);

    /* Quotes and backslashes remain distinct canonical bytes; the event
     * serializer owns JSON escaping and no correlation key is rewritten. */
    CHECK(msconnector_transaction_contract_init(&contract, profile,
        "request\"-\\-7", NULL, NULL,
        MSCONNECTOR_TRANSACTION_MODE_STRICT, 100U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(strcmp(contract.transaction_id, "request\"-\\-7") == 0);

    CHECK(msconnector_transaction_contract_init(&contract, profile,
        "request\n-7", NULL, NULL,
        MSCONNECTOR_TRANSACTION_MODE_STRICT, 100U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_INVALID);
    CHECK(msconnector_transaction_contract_init(&contract, profile,
        " request-7", NULL, NULL,
        MSCONNECTOR_TRANSACTION_MODE_STRICT, 100U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_INVALID);

    memset(oversized, 'x', sizeof(oversized) - 1U);
    oversized[sizeof(oversized) - 1U] = '\0';
    CHECK(msconnector_transaction_contract_init(&contract, profile, oversized,
        NULL, NULL, MSCONNECTOR_TRANSACTION_MODE_STRICT, 100U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_INVALID);
}

static void test_exact_length_transaction_id_validation(void) {
    static const char valid[] = "nginx-request_123:stream/7";
    static const char leading_space[] = " nginx-request";
    static const char trailing_space[] = "nginx-request ";
    static const char embedded_nul[] = {'n', 'g', '\0', 'x'};
    static const char control[] = {'n', 'g', '\n', 'x'};
    static const char non_ascii[] = {'n', (char)0x80, 'x'};
    char oversized[MSCONNECTOR_MAX_TRANSACTION_ID_LENGTH];

    memset(oversized, 'x', sizeof(oversized));
    CHECK(msconnector_transaction_contract_validate_transaction_id_bytes(
        valid, sizeof(valid) - 1U) == 1);
    CHECK(msconnector_transaction_contract_validate_transaction_id_bytes(
        NULL, 0U) == 0);
    CHECK(msconnector_transaction_contract_validate_transaction_id_bytes(
        valid, 0U) == 0);
    CHECK(msconnector_transaction_contract_validate_transaction_id_bytes(
        leading_space, sizeof(leading_space) - 1U) == 0);
    CHECK(msconnector_transaction_contract_validate_transaction_id_bytes(
        trailing_space, sizeof(trailing_space) - 1U) == 0);
    CHECK(msconnector_transaction_contract_validate_transaction_id_bytes(
        embedded_nul, sizeof(embedded_nul)) == 0);
    CHECK(msconnector_transaction_contract_validate_transaction_id_bytes(
        control, sizeof(control)) == 0);
    CHECK(msconnector_transaction_contract_validate_transaction_id_bytes(
        non_ascii, sizeof(non_ascii)) == 0);
    CHECK(msconnector_transaction_contract_validate_transaction_id_bytes(
        oversized, sizeof(oversized)) == 0);
}

static void test_canonical_transaction_id_uniqueness(void) {
    enum { WORKER_COUNT = 8 };
    const msconnector_transaction_profile *profile =
        msconnector_profile_registry_find("envoy-ext-authz");
    canonical_id_worker workers[WORKER_COUNT];
    pthread_t threads[WORKER_COUNT];

    CHECK(profile != NULL);
    for (size_t index = 0U; index < WORKER_COUNT; ++index) {
        workers[index].profile = profile;
        workers[index].result = MSCONNECTOR_TRANSACTION_TRANSITION_INVALID;
        CHECK(pthread_create(&threads[index], NULL, init_duplicate_canonical_id,
            &workers[index]) == 0);
    }
    for (size_t index = 0U; index < WORKER_COUNT; ++index) {
        CHECK(pthread_join(threads[index], NULL) == 0);
        CHECK(workers[index].result == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        CHECK(strcmp(workers[index].contract.transaction_id,
            "same-host-request-id") == 0);
        CHECK(strncmp(workers[index].contract.canonical_transaction_id, "txc-", 4U) == 0);
        for (size_t previous = 0U; previous < index; ++previous) {
            CHECK(strcmp(workers[index].contract.canonical_transaction_id,
                workers[previous].contract.canonical_transaction_id) != 0);
        }
    }
}

static void test_sequence_failures(void) {
    msconnector_transaction_contract contract = make_contract("nginx", "tx-sequence");
    CHECK(msconnector_transaction_contract_begin_phase(&contract, MSCONNECTOR_PHASE_REQUEST_BODY,
        1U) == MSCONNECTOR_TRANSACTION_TRANSITION_SKIPPED_PHASE);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_REQUEST_HEADERS, 2U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_REQUEST_HEADERS, 3U) == MSCONNECTOR_TRANSACTION_TRANSITION_PHASE_ACTIVE);
    CHECK(msconnector_transaction_contract_complete_phase(&contract,
        MSCONNECTOR_PHASE_REQUEST_BODY, 4U) == MSCONNECTOR_TRANSACTION_TRANSITION_PHASE_ACTIVE);
    CHECK(msconnector_transaction_contract_complete_phase(&contract,
        MSCONNECTOR_PHASE_REQUEST_HEADERS, 5U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_REQUEST_HEADERS, 6U) == MSCONNECTOR_TRANSACTION_TRANSITION_DUPLICATE_PHASE);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_RESPONSE_HEADERS, 7U) == MSCONNECTOR_TRANSACTION_TRANSITION_SKIPPED_PHASE);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_REQUEST_BODY, 8U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_complete_phase(&contract,
        MSCONNECTOR_PHASE_REQUEST_BODY, 9U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_REQUEST_HEADERS, 10U) == MSCONNECTOR_TRANSACTION_TRANSITION_DUPLICATE_PHASE);
    CHECK(msconnector_transaction_contract_set_response_committed(&contract, 1) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_SKIPPED_PHASE);

    CHECK(msconnector_transaction_contract_cancel(&contract, 0, 11U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_CLIENT_CANCEL);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_RESPONSE_HEADERS, 12U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_AFTER_TERMINAL);
    CHECK(msconnector_transaction_contract_cleanup(&contract, 13U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_RESPONSE_BODY, 14U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_AFTER_CLEANUP);

    contract = make_contract("apache", "tx-premature");
    complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 1U);
    CHECK(msconnector_transaction_contract_cleanup(&contract, 2U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_PREMATURE_CLEANUP);
    CHECK(contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_CLEANUP_INCOMPLETE);
    CHECK(contract.engine_decision == MSCONNECTOR_TRANSACTION_DECISION_CONNECTOR_ERROR);
    CHECK(contract.action == MSCONNECTOR_DECISION_ACTION_DENY);
    CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_CLEANED);

    {
        const msconnector_transaction_profile *profile =
            msconnector_profile_registry_find("apache");

        CHECK(profile != NULL);
        CHECK(msconnector_transaction_contract_init(&contract, profile,
            "tx-premature-safe", NULL, NULL, MSCONNECTOR_TRANSACTION_MODE_SAFE, 1U) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 2U);
        CHECK(msconnector_transaction_contract_cleanup(&contract, 4U) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_PREMATURE_CLEANUP);
        CHECK(contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_CLEANUP_INCOMPLETE);
        CHECK(contract.engine_decision == MSCONNECTOR_TRANSACTION_DECISION_CONNECTOR_ERROR);
        CHECK(contract.action == MSCONNECTOR_DECISION_ACTION_DENY);
        CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_CLEANED);
    }

    contract = make_contract("envoy-ext-authz", "tx-handoff-cleanup");
    complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 5U);
    complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_BODY, 7U);
    CHECK(msconnector_transaction_contract_handoff_response_companion(&contract, 9U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_cleanup(&contract, 10U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_PREMATURE_CLEANUP);
    CHECK(contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_CLEANUP_INCOMPLETE);
    CHECK(contract.engine_decision == MSCONNECTOR_TRANSACTION_DECISION_CONNECTOR_ERROR);
    CHECK(contract.action == MSCONNECTOR_DECISION_ACTION_DENY);
    CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_CLEANED);
}

static void test_limits_and_decisions(void) {
    msconnector_transaction_contract contract = make_contract("apache", "tx-limits");
    CHECK(msconnector_transaction_contract_record_request_metadata(&contract, "POST", "/",
        NULL, 0U, 0U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 1U);
    CHECK(msconnector_transaction_contract_record_decision(&contract,
        MSCONNECTOR_TRANSACTION_DECISION_ALLOW, "1101999", 1U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_record_body(&contract, 0, 1U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_LATE_PHASE);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_REQUEST_BODY, 2U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_record_body(&contract, 0, 5U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    contract.request_body_bytes = SIZE_MAX;
    CHECK(msconnector_transaction_contract_record_body(&contract, 0, 1U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_INVALID);
    CHECK(contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);
    CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_TERMINAL);

    {
        msconnector_decision decision;
        msconnector_event event;

        msconnector_decision_set_body_limit(&decision, 403, "native request body limit");
        CHECK(msconnector_decision_is_body_limit(&decision));
        CHECK(decision.rule_id == NULL);
        CHECK(msconnector_decision_to_event(&decision, &event, "apache", "tx-limits") != 0);
        CHECK(strcmp(event.meta.message_id, MSCONN_EVENT_BODY_LIMIT) == 0);
        decision.body_limit = -1;
        CHECK(!msconnector_decision_is_body_limit(&decision));
        decision.body_limit = 1;
        decision.rule_id = "1101999";
        CHECK(!msconnector_decision_is_body_limit(&decision));
    }

    contract = make_contract("apache", "tx-response-limit");
    CHECK(msconnector_transaction_contract_record_response_metadata(&contract, 200, NULL,
        0U, 0U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 1U);
    complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_BODY, 2U);
    complete_direct_phase(&contract, MSCONNECTOR_PHASE_RESPONSE_HEADERS, 3U);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_RESPONSE_BODY, 4U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_record_body(&contract, 1, 5U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    contract.response_body_bytes = SIZE_MAX;
    CHECK(msconnector_transaction_contract_record_body(&contract, 1, 1U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_INVALID);
    CHECK(contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);

    contract = make_contract("apache", "tx-header-limit");
    CHECK(msconnector_transaction_contract_record_request_metadata(&contract, "GET", "/",
        NULL, MSCONNECTOR_MAX_HEADER_COUNT + 1U, 0U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_INVALID);
    CHECK(contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL);
    CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_TERMINAL);

    contract = make_contract("apache", "tx-decision");
    msconnector_transaction_decision_policy policy;
    CHECK(msconnector_transaction_contract_decision_policy(&contract,
        MSCONNECTOR_TRANSACTION_DECISION_RATE_LIMIT, &policy) != 0);
    CHECK(policy.host_action == MSCONNECTOR_DECISION_ACTION_RATE_LIMIT);
    CHECK(policy.terminal != 0);
    CHECK(policy.fail_policy == MSCONNECTOR_TRANSACTION_FAIL_CLOSED);
    CHECK(msconnector_transaction_contract_record_decision(&contract,
        MSCONNECTOR_TRANSACTION_DECISION_BLOCK, NULL, 2U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_INVALID);
    CHECK(contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE);
    CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_TERMINAL);

    contract = make_contract("apache", "tx-timeout");
    CHECK(msconnector_transaction_contract_timeout(&contract, 5U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT);
    CHECK(contract.action == MSCONNECTOR_DECISION_ACTION_DENY);
    /* A terminal transaction must reject any later failure mutation.  The
     * contract currently reports this as INVALID (rather than a dedicated
     * AFTER_TERMINAL code) but it must never return OK. */
    CHECK(msconnector_transaction_contract_fail(&contract,
        MSCONNECTOR_TRANSACTION_ERROR_EVENT_LIMIT, 6U) !=
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);

    contract = make_contract("apache", "tx-event-limit");
    CHECK(msconnector_transaction_contract_fail(&contract,
        MSCONNECTOR_TRANSACTION_ERROR_EVENT_LIMIT, 7U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_EVENT_LIMIT);
    CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_TERMINAL);
}

static void test_pre_p4_terminal_rule_decisions(void) {
    static const struct {
        msconnector_transaction_decision_kind kind;
        msconnector_decision_action action;
        const char *rule_id;
    } cases[] = {
        {MSCONNECTOR_TRANSACTION_DECISION_BLOCK,
            MSCONNECTOR_DECISION_ACTION_DENY, "2190406"},
        {MSCONNECTOR_TRANSACTION_DECISION_REDIRECT,
            MSCONNECTOR_DECISION_ACTION_REDIRECT, "2190407"},
        {MSCONNECTOR_TRANSACTION_DECISION_RATE_LIMIT,
            MSCONNECTOR_DECISION_ACTION_RATE_LIMIT, "2190408"}
    };

    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        msconnector_transaction_contract contract = make_contract("apache",
            "tx-pre-p4-terminal-rule");

        complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_HEADERS,
            100U + index);
        complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_BODY,
            200U + index);
        complete_direct_phase(&contract, MSCONNECTOR_PHASE_RESPONSE_HEADERS,
            300U + index);
        CHECK(msconnector_transaction_contract_record_decision(&contract,
            cases[index].kind, cases[index].rule_id, 400U + index) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_TERMINAL);
        CHECK(contract.engine_decision == cases[index].kind);
        CHECK(contract.action == cases[index].action);
        CHECK(strcmp(contract.rule_id, cases[index].rule_id) == 0);
        CHECK(msconnector_transaction_contract_finish(&contract, 500U + index) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        CHECK(msconnector_transaction_contract_cleanup(&contract, 600U + index) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    }

    {
        char maximum_rule_id[MSCONNECTOR_MAX_RULE_ID_LENGTH];
        msconnector_transaction_contract contract = make_contract("apache",
            "tx-pre-p4-terminal-rule-maximum");

        memset(maximum_rule_id, '9', sizeof(maximum_rule_id) - 1U);
        maximum_rule_id[sizeof(maximum_rule_id) - 1U] = '\0';
        complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 700U);
        complete_direct_phase(&contract, MSCONNECTOR_PHASE_REQUEST_BODY, 710U);
        complete_direct_phase(&contract, MSCONNECTOR_PHASE_RESPONSE_HEADERS, 720U);
        CHECK(msconnector_transaction_contract_record_decision(&contract,
            MSCONNECTOR_TRANSACTION_DECISION_BLOCK, maximum_rule_id, 730U) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        CHECK(strcmp(contract.rule_id, maximum_rule_id) == 0);
        CHECK(msconnector_transaction_contract_finish(&contract, 740U) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        CHECK(msconnector_transaction_contract_cleanup(&contract, 750U) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    }
}

static void test_business_phase_rule_decisions_stop_later_phases(void) {
    static const struct {
        enum msconnector_phase phase;
        msconnector_transaction_decision_kind kind;
        msconnector_decision_action action;
        const char *rule_id;
    } cases[] = {
        {MSCONNECTOR_PHASE_REQUEST_HEADERS,
            MSCONNECTOR_TRANSACTION_DECISION_BLOCK,
            MSCONNECTOR_DECISION_ACTION_DENY, "p1-block"},
        {MSCONNECTOR_PHASE_REQUEST_HEADERS,
            MSCONNECTOR_TRANSACTION_DECISION_REDIRECT,
            MSCONNECTOR_DECISION_ACTION_REDIRECT, "p1-redirect"},
        {MSCONNECTOR_PHASE_REQUEST_BODY,
            MSCONNECTOR_TRANSACTION_DECISION_BLOCK,
            MSCONNECTOR_DECISION_ACTION_DENY, "p2-block"},
        {MSCONNECTOR_PHASE_RESPONSE_HEADERS,
            MSCONNECTOR_TRANSACTION_DECISION_BLOCK,
            MSCONNECTOR_DECISION_ACTION_DENY, "p3-block"},
        {MSCONNECTOR_PHASE_RESPONSE_BODY,
            MSCONNECTOR_TRANSACTION_DECISION_BLOCK,
            MSCONNECTOR_DECISION_ACTION_DENY, "p4-block"}
    };

    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        msconnector_transaction_contract contract = make_contract("apache",
            "tx-business-phase-terminal");
        for (enum msconnector_phase phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
            phase <= cases[index].phase; ++phase) {
            complete_direct_phase(&contract, phase,
                1000U + (index * 100U) + ((uint64_t)phase * 10U));
        }
        CHECK(msconnector_transaction_contract_record_decision(&contract,
            cases[index].kind, cases[index].rule_id,
            1050U + (index * 100U)) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        CHECK(contract.status == MSCONNECTOR_TRANSACTION_STATUS_TERMINAL);
        CHECK(contract.last_completed_phase == (int)cases[index].phase);
        CHECK(contract.engine_decision == cases[index].kind);
        CHECK(contract.action == cases[index].action);
        CHECK(strcmp(contract.rule_id, cases[index].rule_id) == 0);
        if (cases[index].phase < MSCONNECTOR_PHASE_RESPONSE_BODY) {
            CHECK(msconnector_transaction_contract_begin_phase(&contract,
                (enum msconnector_phase)(cases[index].phase + 1),
                1060U + (index * 100U)) != MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        }
        CHECK(msconnector_transaction_contract_finish(&contract,
            1070U + (index * 100U)) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        CHECK(msconnector_transaction_contract_cleanup(&contract,
            1080U + (index * 100U)) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        CHECK(msconnector_transaction_contract_cleanup(&contract,
            1090U + (index * 100U)) != MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    }
}

typedef struct decision_policy_expectation {
    msconnector_transaction_decision_kind kind;
    msconnector_decision_action safe_action;
    msconnector_decision_action strict_action;
    const char *safe_event_type;
    const char *strict_event_type;
    int rule_correlation_required;
    msconnector_transaction_fail_policy safe_fail_policy;
    msconnector_transaction_fail_policy strict_fail_policy;
    int safe_terminal;
    int strict_terminal;
} decision_policy_expectation;

static void test_decision_policy_matrix(void) {
    static const decision_policy_expectation expectations[] = {
        {MSCONNECTOR_TRANSACTION_DECISION_ALLOW,
            MSCONNECTOR_DECISION_ACTION_ALLOW, MSCONNECTOR_DECISION_ACTION_ALLOW,
            "allow", "allow", 0, MSCONNECTOR_TRANSACTION_FAIL_NONE,
            MSCONNECTOR_TRANSACTION_FAIL_NONE, 0, 0},
        {MSCONNECTOR_TRANSACTION_DECISION_BLOCK,
            MSCONNECTOR_DECISION_ACTION_DENY, MSCONNECTOR_DECISION_ACTION_DENY,
            "rule_block", "rule_block", 1, MSCONNECTOR_TRANSACTION_FAIL_CLOSED,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED, 1, 1},
        {MSCONNECTOR_TRANSACTION_DECISION_REDIRECT,
            MSCONNECTOR_DECISION_ACTION_REDIRECT, MSCONNECTOR_DECISION_ACTION_REDIRECT,
            "rule_redirect", "rule_redirect", 1,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED, 1, 1},
        {MSCONNECTOR_TRANSACTION_DECISION_RATE_LIMIT,
            MSCONNECTOR_DECISION_ACTION_RATE_LIMIT,
            MSCONNECTOR_DECISION_ACTION_RATE_LIMIT,
            "rule_rate_limit", "rule_rate_limit", 1,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED, 1, 1},
        {MSCONNECTOR_TRANSACTION_DECISION_LOG_ONLY,
            MSCONNECTOR_DECISION_ACTION_LOG_ONLY,
            MSCONNECTOR_DECISION_ACTION_LOG_ONLY,
            "log_only", "log_only", 0, MSCONNECTOR_TRANSACTION_FAIL_NONE,
            MSCONNECTOR_TRANSACTION_FAIL_NONE, 0, 0},
        {MSCONNECTOR_TRANSACTION_DECISION_ENFORCE,
            MSCONNECTOR_DECISION_ACTION_LOG_ONLY, MSCONNECTOR_DECISION_ACTION_DENY,
            "enforce_downgraded_log_only", "enforce", 1,
            MSCONNECTOR_TRANSACTION_FAIL_OPEN,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED, 0, 1},
        {MSCONNECTOR_TRANSACTION_DECISION_ENGINE_TIMEOUT,
            MSCONNECTOR_DECISION_ACTION_DENY, MSCONNECTOR_DECISION_ACTION_DENY,
            "engine_timeout", "engine_timeout", 0,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED, 1, 1},
        {MSCONNECTOR_TRANSACTION_DECISION_ENGINE_UNAVAILABLE,
            MSCONNECTOR_DECISION_ACTION_DENY, MSCONNECTOR_DECISION_ACTION_DENY,
            "engine_unavailable", "engine_unavailable", 0,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED, 1, 1},
        {MSCONNECTOR_TRANSACTION_DECISION_INVALID_ENGINE_RESPONSE,
            MSCONNECTOR_DECISION_ACTION_DENY, MSCONNECTOR_DECISION_ACTION_DENY,
            "invalid_engine_response", "invalid_engine_response", 0,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED, 1, 1},
        {MSCONNECTOR_TRANSACTION_DECISION_CONNECTOR_ERROR,
            MSCONNECTOR_DECISION_ACTION_DENY, MSCONNECTOR_DECISION_ACTION_DENY,
            "connector_error", "connector_error", 0,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED, 1, 1},
        {MSCONNECTOR_TRANSACTION_DECISION_PROTOCOL_ERROR,
            MSCONNECTOR_DECISION_ACTION_DENY, MSCONNECTOR_DECISION_ACTION_DENY,
            "protocol_error", "protocol_error", 0,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED,
            MSCONNECTOR_TRANSACTION_FAIL_CLOSED, 1, 1},
        {MSCONNECTOR_TRANSACTION_DECISION_CLIENT_CANCEL,
            MSCONNECTOR_DECISION_ACTION_ABORT_CONNECTION,
            MSCONNECTOR_DECISION_ACTION_ABORT_CONNECTION,
            "client_cancel", "client_cancel", 0,
            MSCONNECTOR_TRANSACTION_FAIL_STOP_IO,
            MSCONNECTOR_TRANSACTION_FAIL_STOP_IO, 1, 1},
        {MSCONNECTOR_TRANSACTION_DECISION_UPSTREAM_DISCONNECT,
            MSCONNECTOR_DECISION_ACTION_ABORT_CONNECTION,
            MSCONNECTOR_DECISION_ACTION_ABORT_CONNECTION,
            "upstream_disconnect", "upstream_disconnect", 0,
            MSCONNECTOR_TRANSACTION_FAIL_STOP_IO,
            MSCONNECTOR_TRANSACTION_FAIL_STOP_IO, 1, 1}
    };

    for (size_t index = 0U; index < sizeof(expectations) / sizeof(expectations[0]);
         ++index) {
        const decision_policy_expectation *expected = &expectations[index];
        msconnector_transaction_contract safe = make_contract("apache", "policy-safe");
        msconnector_transaction_contract strict = make_contract("apache", "policy-strict");
        msconnector_transaction_decision_policy safe_policy;
        msconnector_transaction_decision_policy strict_policy;
        const char *rule_id = expected->rule_correlation_required ? "1001001" : NULL;

        strict.mode = MSCONNECTOR_TRANSACTION_MODE_STRICT;
        safe.mode = MSCONNECTOR_TRANSACTION_MODE_SAFE;
        CHECK(msconnector_transaction_contract_decision_policy(&safe, expected->kind,
            &safe_policy) != 0);
        CHECK(msconnector_transaction_contract_decision_policy(&strict, expected->kind,
            &strict_policy) != 0);
        CHECK(safe_policy.host_action == expected->safe_action);
        CHECK(strict_policy.host_action == expected->strict_action);
        CHECK(strcmp(safe_policy.event_type, expected->safe_event_type) == 0);
        CHECK(strcmp(strict_policy.event_type, expected->strict_event_type) == 0);
        CHECK(safe_policy.rule_correlation_required == expected->rule_correlation_required);
        CHECK(strict_policy.rule_correlation_required == expected->rule_correlation_required);
        CHECK(safe_policy.fail_policy == expected->safe_fail_policy);
        CHECK(strict_policy.fail_policy == expected->strict_fail_policy);
        CHECK(safe_policy.terminal == expected->safe_terminal);
        CHECK(strict_policy.terminal == expected->strict_terminal);
        CHECK(safe_policy.cleanup_required != 0 ||
            expected->kind == MSCONNECTOR_TRANSACTION_DECISION_ALLOW);
        CHECK(strict_policy.cleanup_required != 0 ||
            expected->kind == MSCONNECTOR_TRANSACTION_DECISION_ALLOW);
        CHECK(msconnector_transaction_contract_record_decision(&safe, expected->kind,
            rule_id, 1000U + index) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        CHECK(msconnector_transaction_contract_record_decision(&strict, expected->kind,
            rule_id, 2000U + index) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        CHECK(safe.action == expected->safe_action);
        CHECK(strict.action == expected->strict_action);
        if (expected->rule_correlation_required) {
            CHECK(strcmp(safe.rule_id, rule_id) == 0);
            CHECK(strcmp(strict.rule_id, rule_id) == 0);
        }
        if (expected->safe_terminal) {
            CHECK(safe.status == MSCONNECTOR_TRANSACTION_STATUS_TERMINAL);
            CHECK(msconnector_transaction_contract_cleanup(&safe, 3000U + index) ==
                MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        }
        if (expected->strict_terminal) {
            CHECK(strict.status == MSCONNECTOR_TRANSACTION_STATUS_TERMINAL);
            CHECK(msconnector_transaction_contract_cleanup(&strict, 4000U + index) ==
                MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        }
    }

    {
        msconnector_transaction_contract committed = make_contract("apache", "policy-postcommit");
        msconnector_transaction_decision_policy policy;

        complete_direct_phase(&committed, MSCONNECTOR_PHASE_REQUEST_HEADERS, 5000U);
        complete_direct_phase(&committed, MSCONNECTOR_PHASE_REQUEST_BODY, 5001U);
        complete_direct_phase(&committed, MSCONNECTOR_PHASE_RESPONSE_HEADERS, 5002U);
        CHECK(msconnector_transaction_contract_set_response_committed(&committed, 1) ==
            MSCONNECTOR_TRANSACTION_TRANSITION_OK);
        CHECK(msconnector_transaction_contract_decision_policy(&committed,
            MSCONNECTOR_TRANSACTION_DECISION_ENFORCE, &policy) != 0);
        CHECK(policy.host_action == MSCONNECTOR_DECISION_ACTION_LOG_ONLY);
        CHECK(strcmp(policy.event_type, "enforce_downgraded_log_only") == 0);
        CHECK(policy.fail_policy == MSCONNECTOR_TRANSACTION_FAIL_OPEN);
        CHECK(policy.terminal != 0);
    }
}

static void test_header_and_event_limits(void) {
    msconnector_resource_limits limits;
    msconnector_header header;
    msconnector_event event;
    char name[MSCONNECTOR_MAX_HEADER_NAME_LENGTH + 2U];
    char value[MSCONNECTOR_MAX_HEADER_VALUE_LENGTH + 2U];
    char event_line[MSCONNECTOR_MAX_EVENT_JSON_BYTES + 2U];
    char small_line[128];
    int truncated = 0;

    memset(name, 'n', sizeof(name));
    memset(value, 'v', sizeof(value));
    msconnector_resource_limits_init(&limits);
    header.name = name;
    header.name_size = MSCONNECTOR_MAX_HEADER_NAME_LENGTH + 1U;
    header.value = value;
    header.value_size = 1U;
    CHECK(msconnector_resource_limits_headers_ok(&header, 1U, &limits) == 0);
    header.name_size = 1U;
    header.value_size = MSCONNECTOR_MAX_HEADER_VALUE_LENGTH + 1U;
    CHECK(msconnector_resource_limits_headers_ok(&header, 1U, &limits) == 0);
    header.value_size = 2U;
    limits.max_total_header_bytes = 3U;
    header.name_size = 2U;
    CHECK(msconnector_resource_limits_headers_ok(&header, 1U, &limits) == 0);
    limits.max_total_header_bytes = MSCONNECTOR_MAX_TOTAL_HEADER_BYTES;
    CHECK(msconnector_resource_limits_headers_ok(&header, 1U, &limits) != 0);
    limits.max_header_count = MSCONNECTOR_MAX_HEADER_COUNT + 1U;
    CHECK(msconnector_resource_limits_validate(&limits) == 0);
    limits.max_header_count = MSCONNECTOR_MAX_HEADER_COUNT;
    limits.max_header_name_size = MSCONNECTOR_MAX_HEADER_NAME_LENGTH + 1U;
    CHECK(msconnector_resource_limits_validate(&limits) == 0);
    limits.max_header_name_size = MSCONNECTOR_MAX_HEADER_NAME_LENGTH;
    limits.max_header_value_size = MSCONNECTOR_MAX_HEADER_VALUE_LENGTH + 1U;
    CHECK(msconnector_resource_limits_validate(&limits) == 0);
    limits.max_header_value_size = MSCONNECTOR_MAX_HEADER_VALUE_LENGTH;
    limits.max_total_header_bytes = MSCONNECTOR_MAX_TOTAL_HEADER_BYTES + 1U;
    CHECK(msconnector_resource_limits_validate(&limits) == 0);
    limits.max_total_header_bytes = MSCONNECTOR_MAX_TOTAL_HEADER_BYTES;
    limits.max_event_json_bytes = MSCONNECTOR_MAX_EVENT_JSON_BYTES + 1U;
    CHECK(msconnector_resource_limits_validate(&limits) == 0);
    limits.max_event_json_bytes = MSCONNECTOR_MAX_EVENT_JSON_BYTES;

    msconnector_event_init(&event);
    event.meta.timestamp = "2026-08-25T00:00:00Z";
    event.meta.message = "bounded event metadata";
    event.meta.event = "decision";
    event.meta.connector = "common";
    event.meta.transaction_id = "event-limit";
    event.decision.phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
    event.decision.status = MSCONNECTOR_STATUS_OK;
    event.decision.action = "allow";
    event.decision.requested_action = "allow";
    event.decision.actual_action = "allow";
    event.http.http_reason_phrase = "OK";
    event.http.http_default_message = "request completed";
    event.flags.redacted = 1;
    event.flags.truncated = 0;
    event.integrity.event_hash = msconnector_integrity_event_hash(&event, 0U);
    CHECK(msconnector_integrity_event_chain_verify(0U,
        event.integrity.event_hash, &event));
    event.meta.message = "tampered metadata";
    CHECK(!msconnector_integrity_event_chain_verify(0U,
        event.integrity.event_hash, &event));
    event.meta.message = "bounded event metadata";
    event.decision.requested_action = "deny";
    CHECK(!msconnector_integrity_event_chain_verify(0U,
        event.integrity.event_hash, &event));
    event.decision.requested_action = "allow";
    event.decision.actual_action = "log_only";
    CHECK(!msconnector_integrity_event_chain_verify(0U,
        event.integrity.event_hash, &event));
    event.decision.actual_action = "allow";
    event.http.http_reason_phrase = "Created";
    CHECK(!msconnector_integrity_event_chain_verify(0U,
        event.integrity.event_hash, &event));
    event.http.http_reason_phrase = "OK";
    event.http.http_default_message = "tampered default";
    CHECK(!msconnector_integrity_event_chain_verify(0U,
        event.integrity.event_hash, &event));
    event.http.http_default_message = "request completed";
    event.flags.redacted = 0;
    CHECK(!msconnector_integrity_event_chain_verify(0U,
        event.integrity.event_hash, &event));
    event.flags.redacted = 1;
    event.flags.truncated = 1;
    CHECK(!msconnector_integrity_event_chain_verify(0U,
        event.integrity.event_hash, &event));
    event.flags.truncated = 0;
    event.flags.late_intervention = 1;
    event.flags.late_intervention_mode = "safe";
    event.integrity.event_hash = msconnector_integrity_event_hash(&event, 0U);
    CHECK(msconnector_integrity_event_chain_verify(0U,
        event.integrity.event_hash, &event));
    event.flags.late_intervention_mode = "strict";
    CHECK(!msconnector_integrity_event_chain_verify(0U,
        event.integrity.event_hash, &event));
    event.flags.late_intervention_mode = "safe";
    CHECK(msconnector_event_write_jsonl_line(&event, event_line,
        sizeof(event_line), &truncated) != 0);
    CHECK(truncated == 0);
    CHECK(strlen(event_line) <= MSCONNECTOR_MAX_EVENT_JSON_BYTES);
    CHECK(strstr(event_line, "body_payload") == NULL);
    truncated = 0;
    CHECK(msconnector_event_write_jsonl_line(&event, small_line,
        sizeof(small_line), &truncated) == 0);
    CHECK(truncated != 0);
    CHECK(strchr(small_line, '\n') == NULL);
}

static void prepare_companion_request(msconnector_transaction_contract *contract) {
    complete_direct_phase(contract, MSCONNECTOR_PHASE_REQUEST_HEADERS, 101U);
    complete_direct_phase(contract, MSCONNECTOR_PHASE_REQUEST_BODY, 102U);
}

typedef struct registry_register_worker {
    msconnector_transaction_correlation_registry *registry;
    const msconnector_transaction_contract *transaction;
    int result;
} registry_register_worker;

static void *register_companion_request(void *opaque) {
    registry_register_worker *worker = opaque;

    worker->result = msconnector_transaction_correlation_register_request(
        worker->registry, worker->transaction, 10U, 100U);
    return NULL;
}

static void test_correlation_registry(void) {
    msconnector_transaction_correlation_registry registry;
    msconnector_transaction_contract first = make_contract_on_host(
        "envoy-ext-authz", "tx-corr-1", "ext_authz@127.0.0.1:9191");
    msconnector_transaction_contract second = make_contract_on_host(
        "traefik-forwardauth", "tx-corr-2", "forwardAuth@127.0.0.1:9192");
    msconnector_transaction_contract claimed;
    msconnector_transaction_contract wrong;

    prepare_companion_request(&first);
    prepare_companion_request(&second);
    msconnector_transaction_correlation_registry_init(&registry);
    CHECK(msconnector_transaction_correlation_claim_response(&registry, "missing", "envoy",
        "ext_authz@127.0.0.1:9191", 100U, &claimed) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_CORRELATION_MISSING);
    CHECK(msconnector_transaction_correlation_register_request(&registry, &first, 200U, 50U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_correlation_register_request(&registry, &first, 200U, 50U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_DUPLICATE_PHASE);
    CHECK(msconnector_transaction_correlation_claim_response(&registry, "tx-corr-1", "traefik",
        "forwardAuth@127.0.0.1:9192", 201U, &claimed) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_CORRELATION_MISMATCH);
    CHECK(msconnector_transaction_correlation_claim_response(&registry, "tx-corr-1", "envoy",
        "ext_authz@127.0.0.1:9191", 202U, &claimed) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(claimed.transaction_id[0] != '\0');
    complete_companion_phase(&claimed, MSCONNECTOR_PHASE_RESPONSE_HEADERS, 203U);
    complete_companion_phase(&claimed, MSCONNECTOR_PHASE_RESPONSE_BODY, 204U);
    CHECK(msconnector_transaction_contract_finish(&claimed, 205U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_correlation_release(&registry, &claimed, 206U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_correlation_register_request(&registry, &first, 207U, 50U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_correlation_claim_response(&registry, "tx-corr-1", "envoy",
        "ext_authz@127.0.0.1:9191", 208U, &claimed) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    wrong = claimed;
    memcpy(wrong.host_id, "wrong-host", sizeof("wrong-host"));
    CHECK(msconnector_transaction_correlation_release(&registry, &wrong, 209U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_CORRELATION_MISMATCH);
    CHECK(msconnector_transaction_contract_cancel(&claimed, 0, 210U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_correlation_release(&registry, &claimed, 211U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);

    CHECK(msconnector_transaction_correlation_register_request(&registry, &second, 300U, 10U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_correlation_claim_response(&registry, "tx-corr-2", "traefik",
        "forwardAuth@127.0.0.1:9192", 311U, &claimed) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_CORRELATION_EXPIRED);
    CHECK(msconnector_transaction_correlation_expire(&registry, 400U) == 0U);
}

static void test_parallel_and_stream_reuse(void) {
    msconnector_transaction_correlation_registry registry;
    msconnector_transaction_contract a = make_contract("envoy-ext-authz", "stream-a");
    msconnector_transaction_contract b = make_contract("envoy-ext-authz", "stream-b");
    msconnector_transaction_contract claimed;
    registry_register_worker first = {&registry, &a, MSCONNECTOR_TRANSACTION_TRANSITION_INVALID};
    registry_register_worker second = {&registry, &b, MSCONNECTOR_TRANSACTION_TRANSITION_INVALID};
    pthread_t first_thread;
    pthread_t second_thread;

    prepare_companion_request(&a);
    prepare_companion_request(&b);
    msconnector_transaction_correlation_registry_init(&registry);
    CHECK(pthread_create(&first_thread, NULL, register_companion_request, &first) == 0);
    CHECK(pthread_create(&second_thread, NULL, register_companion_request, &second) == 0);
    CHECK(pthread_join(first_thread, NULL) == 0);
    CHECK(pthread_join(second_thread, NULL) == 0);
    CHECK(first.result == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(second.result == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_correlation_claim_response(&registry, "stream-b", "envoy",
        "ext_authz", 11U, &claimed) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_correlation_release(&registry, &claimed, 12U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_PREMATURE_CLEANUP);
    CHECK(msconnector_transaction_correlation_release(&registry, &a, 13U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_PREMATURE_CLEANUP);
    CHECK(msconnector_transaction_contract_cancel(&claimed, 0, 14U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_correlation_release(&registry, &claimed, 15U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_correlation_revoke_request(&registry, "stream-a", "envoy",
        "ext_authz", 16U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_correlation_register_request(&registry, &a, 17U, 100U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
}

static void test_companion_handoff_and_copy_isolation(void) {
    msconnector_transaction_correlation_registry registry;
    msconnector_transaction_contract request = make_contract("envoy-ext-authz", "tx-handoff");
    msconnector_transaction_contract response;

    prepare_companion_request(&request);
    msconnector_transaction_correlation_registry_init(&registry);
    CHECK(msconnector_transaction_correlation_register_request(&registry, &request, 10U, 5U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_handoff_response_companion(&request, 10U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(request.status == MSCONNECTOR_TRANSACTION_STATUS_HANDED_OFF);
    CHECK(msconnector_transaction_contract_finish(&request, 11U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_SKIPPED_PHASE);
    CHECK(request.status == MSCONNECTOR_TRANSACTION_STATUS_TERMINAL);
    CHECK(msconnector_transaction_correlation_claim_response(&registry, "tx-handoff", "envoy",
        "ext_authz", 12U, &response) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_correlation_expire(&registry, 16U) == 1U);
    complete_companion_phase(&response, MSCONNECTOR_PHASE_RESPONSE_HEADERS, 17U);
    complete_companion_phase(&response, MSCONNECTOR_PHASE_RESPONSE_BODY, 18U);
    CHECK(msconnector_transaction_contract_finish(&response, 19U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_correlation_release(&registry, &response, 20U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_CORRELATION_MISSING);
}

static void test_live_companion_claim(void) {
    msconnector_transaction_contract contract = make_contract_on_host(
        "envoy-ext-authz", "tx-live-handoff", "ext_authz@127.0.0.1:9191");

    prepare_companion_request(&contract);
    CHECK(msconnector_transaction_contract_handoff_response_companion(&contract, 10U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_begin_companion_phase(&contract,
        MSCONNECTOR_PHASE_RESPONSE_HEADERS, 11U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_AFTER_TERMINAL);
    CHECK(msconnector_transaction_contract_claim_response_companion(&contract, 12U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    complete_companion_phase(&contract, MSCONNECTOR_PHASE_RESPONSE_HEADERS, 13U);
    complete_companion_phase(&contract, MSCONNECTOR_PHASE_RESPONSE_BODY, 14U);
    CHECK(msconnector_transaction_contract_finish(&contract, 15U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_cleanup(&contract, 16U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
}

static void test_missing_timestamps_are_normalized(void) {
    msconnector_transaction_contract contract;
    msconnector_transaction_state legacy;
    const msconnector_transaction_profile *profile =
        msconnector_profile_registry_find("apache");

    CHECK(profile != NULL);
    CHECK(msconnector_transaction_contract_init(&contract, profile, "timestamp-zero",
        NULL, NULL, MSCONNECTOR_TRANSACTION_MODE_STRICT, 0U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(contract.created_at_ms > 0U);
    CHECK(msconnector_transaction_contract_begin_phase(&contract,
        MSCONNECTOR_PHASE_REQUEST_HEADERS, 0U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(contract.phase_started_at_ms >= contract.created_at_ms);
    CHECK(msconnector_transaction_contract_complete_phase(&contract,
        MSCONNECTOR_PHASE_REQUEST_HEADERS, 0U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(contract.completed_at_ms >= contract.phase_started_at_ms);
    CHECK(msconnector_transaction_contract_record_decision(&contract,
        MSCONNECTOR_TRANSACTION_DECISION_BLOCK, "930001", 0U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(msconnector_transaction_contract_cleanup(&contract, 0U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_OK);
    CHECK(contract.cleanup_at_ms >= contract.completed_at_ms);

    CHECK(msconnector_transaction_state_init(&legacy, "legacy-timestamp-zero"));
    CHECK(legacy.contract.created_at_ms > 0U);
    CHECK(msconnector_transaction_state_begin_phase(&legacy,
        MSCONNECTOR_PHASE_REQUEST_HEADERS));
    CHECK(msconnector_transaction_state_complete_phase(&legacy,
        MSCONNECTOR_PHASE_REQUEST_HEADERS));
    CHECK(legacy.contract.phase_started_at_ms >= legacy.contract.created_at_ms);
    CHECK(legacy.contract.completed_at_ms >= legacy.contract.phase_started_at_ms);
    CHECK(msconnector_transaction_contract_cleanup(&legacy.contract, 0U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_PREMATURE_CLEANUP);
    CHECK(legacy.contract.cleanup_at_ms >= legacy.contract.completed_at_ms);
}

static void test_invalid_legacy_admission_never_reaches_native_engine(void) {
    msconnector_transaction_contract failed_contract;
    msconnector_transaction_state failed_state;
    msconnector_transaction_state null_state;
    msconnector_modsecurity_engine engine;
    msconnector_modsecurity_engine_ops ops;
    msconnector_modsecurity_transaction transaction;
    msconnector_error error;
    direct_engine_probe probe;

    memset(&failed_contract, 0, sizeof(failed_contract));
    CHECK(msconnector_transaction_contract_init(&failed_contract, NULL, "",
        "common", "engine", MSCONNECTOR_TRANSACTION_MODE_SAFE, 0U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_INVALID);
    CHECK(msconnector_transaction_contract_record_request_metadata(&failed_contract,
        "GET", "/", NULL, 0U, 0U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_INVALID);
    CHECK(msconnector_transaction_contract_record_decision(&failed_contract,
        MSCONNECTOR_TRANSACTION_DECISION_ALLOW, NULL, 0U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_INVALID);
    CHECK(msconnector_transaction_contract_begin_phase(&failed_contract,
        MSCONNECTOR_PHASE_REQUEST_HEADERS, 0U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_INVALID);
    CHECK(msconnector_transaction_contract_cleanup(&failed_contract, 0U) ==
        MSCONNECTOR_TRANSACTION_TRANSITION_INVALID);
    CHECK(!msconnector_transaction_state_init(&failed_state, ""));
    CHECK(!failed_state.initialized);
    CHECK(!msconnector_transaction_state_begin_phase(&failed_state,
        MSCONNECTOR_PHASE_REQUEST_HEADERS));
    CHECK(!msconnector_transaction_state_complete_phase(&failed_state,
        MSCONNECTOR_PHASE_REQUEST_HEADERS));
    CHECK(!msconnector_transaction_state_note_phase(&failed_state,
        MSCONNECTOR_PHASE_REQUEST_HEADERS));
    CHECK(!msconnector_transaction_state_mark_phase(&failed_state,
        MSCONNECTOR_PHASE_CONNECTION));
    CHECK(!msconnector_transaction_state_phase_processed(&failed_state,
        MSCONNECTOR_PHASE_REQUEST_HEADERS));
    CHECK(msconnector_transaction_state_init(&null_state, NULL));
    CHECK(strcmp(null_state.contract.transaction_id, "common-transaction") == 0);

    memset(&probe, 0, sizeof(probe));
    memset(&ops, 0, sizeof(ops));
    ops.userdata = &probe;
    ops.init = direct_engine_start;
    ops.create_rules_set = direct_engine_create_rules;
    ops.destroy_rules_set = direct_engine_destroy_rules;
    ops.new_transaction = direct_engine_new_transaction;
    ops.free_transaction = direct_engine_free_transaction;
    msconnector_modsecurity_engine_init(&engine, &ops);
    msconnector_error_init(&error);
    CHECK(msconnector_modsecurity_engine_start(&engine, &error));
    CHECK(msconnector_modsecurity_engine_create_rules(&engine, &error));
    CHECK(probe.create_rules_calls == 1);

    msconnector_error_init(&error);
    CHECK(!msconnector_modsecurity_transaction_init(&transaction, &engine, "", &error));
    CHECK(error.code == MSCONNECTOR_ERROR_INVALID_CONFIG);
    CHECK(probe.new_transaction_calls == 0);
    CHECK(transaction.native_transaction == NULL);
    CHECK(!msconnector_modsecurity_process_request_headers(&transaction, NULL,
        NULL, &error));
    CHECK(probe.new_transaction_calls == 0);
    msconnector_modsecurity_transaction_cleanup(&transaction);
    CHECK(probe.free_transaction_calls == 0);

    msconnector_error_init(&error);
    CHECK(!msconnector_modsecurity_transaction_init(&transaction, &engine,
        "bad\nidentifier", &error));
    CHECK(error.code == MSCONNECTOR_ERROR_INVALID_CONFIG);
    CHECK(probe.new_transaction_calls == 0);

    msconnector_error_init(&error);
    CHECK(msconnector_modsecurity_transaction_init(&transaction, &engine,
        "direct-valid:/\\\"identifier", &error));
    CHECK(probe.new_transaction_calls == 1);
    CHECK(probe.rules_set_calls == 1);
    CHECK(!probe.last_transaction_id_was_null);
    CHECK(transaction.state.initialized);
    msconnector_modsecurity_transaction_cleanup(&transaction);
    CHECK(probe.free_transaction_calls == 1);

    msconnector_error_init(&error);
    CHECK(msconnector_modsecurity_transaction_init(&transaction, &engine, NULL, &error));
    CHECK(probe.new_transaction_calls == 2);
    CHECK(probe.rules_set_calls == 2);
    CHECK(probe.last_transaction_id_was_null);
    CHECK(strcmp(transaction.state.contract.transaction_id,
        "common-transaction") == 0);
    msconnector_modsecurity_transaction_cleanup(&transaction);
    CHECK(probe.free_transaction_calls == 2);
    msconnector_modsecurity_engine_cleanup(&engine);
}

int main(void) {
    test_profiles_and_semantics();
    test_valid_sequence_and_metadata();
    test_content_type_metadata_uses_header_value_bound();
    test_profile_lifecycle_routes();
    test_active_phase_timeout_and_cancel();
    test_canonical_transaction_id_boundary();
    test_exact_length_transaction_id_validation();
    test_canonical_transaction_id_uniqueness();
    test_sequence_failures();
    test_limits_and_decisions();
    test_pre_p4_terminal_rule_decisions();
    test_business_phase_rule_decisions_stop_later_phases();
    test_decision_policy_matrix();
    test_header_and_event_limits();
    test_correlation_registry();
    test_parallel_and_stream_reuse();
    test_companion_handoff_and_copy_isolation();
    test_live_companion_claim();
    test_missing_timestamps_are_normalized();
    test_invalid_legacy_admission_never_reaches_native_engine();
    if (failures != 0) {
        fprintf(stderr, "%d contract test assertion(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    puts("transaction phase contract tests: PASS");
    return EXIT_SUCCESS;
}