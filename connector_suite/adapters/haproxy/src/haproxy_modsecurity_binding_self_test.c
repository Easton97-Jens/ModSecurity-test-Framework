#include "haproxy_modsecurity_binding.h"
#include "msconnector/transaction_contract.h"

#include <stdio.h>
#include <string.h>

static void print_usage(const char *program) {
    fprintf(stderr, "usage: %s --describe|--self-test LIFECYCLE_RULES|--self-test-crs PREAMBLE\n",
        program);
}

static int lifecycle_failure(
        haproxy_modsecurity_decision *decision,
        const char *label) {
    if (decision != 0) {
        snprintf(decision->log_message, sizeof(decision->log_message),
            "body wrapper lifecycle self-test failed: %s", label);
    }
    return 1;
}

static int expect_failure(
        int rc,
        const haproxy_modsecurity_decision *observed,
        int expected_phase,
        const char *expected_message,
        const char *label,
        haproxy_modsecurity_decision *decision) {
    if (rc != 1 || observed == 0 || observed->phase != expected_phase ||
            strcmp(observed->log_message, expected_message) != 0) {
        if (decision != NULL && observed != NULL) {
            snprintf(decision->log_message, sizeof(decision->log_message),
                "body wrapper lifecycle self-test failed: %s phase=%d/%d rc=%d message=%.96s",
                label, observed->phase, expected_phase, rc, observed->log_message);
        }
        return 1;
    }
    return 0;
}

static int expect_non_disruptive(
        int rc,
        const haproxy_modsecurity_decision *observed,
        int expected_phase,
        const char *label,
        haproxy_modsecurity_decision *decision) {
    if (rc != 0 || observed == 0 || observed->phase != expected_phase ||
            observed->disruptive != 0 || observed->rule_id != 0) {
        return lifecycle_failure(decision, label);
    }
    return 0;
}

static int expect_disruptive_rule_id(
        int rc,
        const haproxy_modsecurity_decision *observed,
        int expected_phase,
        int expected_rule_id,
        const char *label,
        haproxy_modsecurity_decision *decision) {
    if (rc != 0 || observed == 0 || observed->phase != expected_phase ||
            observed->disruptive == 0 || observed->status != 403 ||
            strcmp(observed->action, "deny") != 0 || observed->rule_id != expected_rule_id) {
        return lifecycle_failure(decision, label);
    }
    return 0;
}

static int expect_invalid_request_id(
        int rc,
        const haproxy_modsecurity_transaction *transaction,
        const haproxy_modsecurity_decision *observed,
        const char *label,
        haproxy_modsecurity_decision *decision) {
    if (rc != 1 || transaction != 0 || observed == 0 ||
            observed->phase != 1 || observed->disruptive == 0 ||
            observed->status != 500 || strcmp(observed->action, "deny") != 0 ||
            strcmp(observed->log_message, "invalid HAProxy transaction id") != 0) {
        return lifecycle_failure(decision, label);
    }
    return 0;
}

static int run_request_id_boundary_self_test(
        haproxy_modsecurity_engine *engine,
        haproxy_modsecurity_request *request,
        haproxy_modsecurity_decision *observed,
        haproxy_modsecurity_decision *decision) {
    char accepted[MSCONNECTOR_MAX_TRANSACTION_ID_LENGTH];
    char oversized[MSCONNECTOR_MAX_TRANSACTION_ID_LENGTH + 1U];
    const char *saved_request_id = request->request_id;
    haproxy_modsecurity_transaction *transaction = 0;
    int rc;
    int result = 1;

    memset(accepted, 'a', sizeof(accepted) - 1U);
    accepted[sizeof(accepted) - 1U] = '\0';
    request->request_id = accepted;
    rc = haproxy_modsecurity_transaction_begin_request_with_profile(engine, request,
        "haproxy-htx", observed, &transaction);
    if (expect_non_disruptive(rc, observed, 1,
            "maximum-length transaction id", decision) != 0 || transaction == 0) {
        goto done;
    }
    haproxy_modsecurity_transaction_abort(transaction);
    transaction = 0;

    memset(oversized, 'b', sizeof(oversized) - 1U);
    oversized[sizeof(oversized) - 1U] = '\0';
    request->request_id = oversized;
    rc = haproxy_modsecurity_transaction_begin_request_with_profile(engine, request,
        "haproxy-htx", observed, &transaction);
    if (expect_invalid_request_id(rc, transaction, observed,
            "overlong transaction id", decision) != 0) {
        goto done;
    }

    request->request_id = "invalid\ntransaction-id";
    rc = haproxy_modsecurity_transaction_begin_request_with_profile(engine, request,
        "haproxy-htx", observed, &transaction);
    if (expect_invalid_request_id(rc, transaction, observed,
            "control-character transaction id", decision) != 0) {
        goto done;
    }
    result = 0;

done:
    if (transaction != 0) {
        haproxy_modsecurity_transaction_abort(transaction);
    }
    request->request_id = saved_request_id;
    return result;
}

typedef int (*body_append_function)(
    haproxy_modsecurity_transaction *transaction,
    const unsigned char *body,
    unsigned int body_len,
    haproxy_modsecurity_decision *decision);

typedef int (*body_finish_function)(
    haproxy_modsecurity_transaction *transaction,
    haproxy_modsecurity_decision *decision);

struct body_wrapper_lifecycle {
    int phase;
    const char *missing_transaction_message;
    const char *missing_body_message;
    const char *append_after_eos_message;
    const char *finish_twice_message;
    const unsigned char *body;
    unsigned int body_len;
    body_append_function append;
    body_finish_function finish;
};

static int check_null_body_transaction(
        const struct body_wrapper_lifecycle *phase,
        haproxy_modsecurity_decision *observed,
        haproxy_modsecurity_decision *decision) {
    int rc = phase->append(0, phase->body, phase->body_len, observed);

    return expect_failure(rc, observed, phase->phase,
        phase->missing_transaction_message, "null body transaction", decision);
}

static int run_body_lifecycle(
        const struct body_wrapper_lifecycle *phase,
        haproxy_modsecurity_transaction *transaction,
        haproxy_modsecurity_decision *observed,
        haproxy_modsecurity_decision *decision) {
    int rc = phase->append(transaction, phase->body, phase->body_len, observed);

    if (expect_non_disruptive(rc, observed, phase->phase, "body append",
            decision) != 0) {
        return 1;
    }
    rc = phase->finish(transaction, observed);
    return expect_non_disruptive(rc, observed, phase->phase, "body finish", decision);
}

struct body_wrapper_lifecycle_test_context {
    haproxy_modsecurity_engine *engine;
    haproxy_modsecurity_transaction **transaction;
    haproxy_modsecurity_request *request;
    haproxy_modsecurity_response *response;
    const struct body_wrapper_lifecycle *request_phase;
    const struct body_wrapper_lifecycle *response_phase;
    haproxy_modsecurity_decision *observed;
    haproxy_modsecurity_decision *decision;
};

static int prepare_terminal_body_case(struct body_wrapper_lifecycle_test_context *test,
        const char *profile, int failure_kind)
{
    int rc;
    if (failure_kind == 0) {
        return 0;
    }
    rc = test->request_phase->finish(*test->transaction, test->observed);
    if (rc != 0 || failure_kind < 3) {
        return rc;
    }
    if (strcmp(profile, "haproxy-spoe-spop") == 0) {
        rc = haproxy_modsecurity_transaction_handoff_response_companion(*test->transaction);
        if (rc != 0) {
            return rc;
        }
        rc = haproxy_modsecurity_transaction_claim_response_companion(*test->transaction);
        if (rc != 0) {
            return rc;
        }
    }
    if (failure_kind == 3) {
        return 0;
    }
    rc = haproxy_modsecurity_transaction_process_response_headers(*test->transaction,
        test->response, test->observed);
    if (rc != 0 || failure_kind == 4) {
        return rc;
    }
    return test->response_phase->finish(*test->transaction, test->observed);
}

static int run_terminal_body_case(struct body_wrapper_lifecycle_test_context *test,
        const char *profile, int failure_kind)
{
    const struct body_wrapper_lifecycle *phase = failure_kind < 3 ?
        test->request_phase : test->response_phase;
    const char *message;
    const char *label;
    int rc;

    rc = haproxy_modsecurity_transaction_begin_request_with_profile(test->engine,
        test->request, profile, test->observed, test->transaction);
    if (expect_non_disruptive(rc, test->observed, 1, "negative request begin",
            test->decision) != 0 || *test->transaction == NULL) {
        return 1;
    }
    rc = prepare_terminal_body_case(test, profile, failure_kind);
    if (rc != 0) {
        return lifecycle_failure(test->decision, "negative lifecycle preparation");
    }
    if (failure_kind == 0 || failure_kind == 4) {
        rc = phase->append(*test->transaction, NULL, 1U, test->observed);
        message = phase->missing_body_message;
        label = "null nonzero body chunk";
    } else if (failure_kind == 2 || failure_kind == 6) {
        rc = phase->finish(*test->transaction, test->observed);
        message = phase->phase == 4 ? "transaction is terminal" : phase->finish_twice_message;
        label = "body finish twice";
    } else {
        rc = phase->append(*test->transaction, phase->body, phase->body_len, test->observed);
        message = phase->phase == 4 ? "transaction is terminal" : phase->append_after_eos_message;
        if (failure_kind == 3) {
            message = "response headers must be processed before response body chunks";
        }
        label = failure_kind == 3 ? "response append before headers" : "body append after eos";
    }
    if (expect_failure(rc, test->observed, phase->phase, message, label, test->decision) != 0) {
        return 1;
    }
    {
        const msconnector_transaction_error_class cause = failure_kind == 0 || failure_kind == 4 ?
            MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR : MSCONNECTOR_TRANSACTION_ERROR_PHASE_SEQUENCE;
        if (test->observed->error_class != cause || test->observed->body_limit ||
                test->observed->status != 500 || strcmp(test->observed->action, "error") != 0 ||
                haproxy_modsecurity_transaction_error(*test->transaction) != cause) {
            return lifecycle_failure(test->decision, "original terminal cause");
        }
        if (phase->append(*test->transaction, phase->body, phase->body_len, test->observed) == 0 ||
                test->observed->error_class != cause || test->observed->phase != phase->phase) {
            return lifecycle_failure(test->decision, "terminal error survives reentry");
        }
    }
    haproxy_modsecurity_transaction_abort(*test->transaction);
    *test->transaction = NULL;
    return 0;
}

static int begin_body_lifecycle(struct body_wrapper_lifecycle_test_context *test,
        const char *profile, const char *begin_label, const char *owner_label)
{
    int rc = haproxy_modsecurity_transaction_begin_request_with_profile(
        test->engine, test->request, profile, test->observed, test->transaction);
    if (expect_non_disruptive(rc, test->observed, 1, begin_label,
            test->decision) != 0 || *test->transaction == NULL) {
        return lifecycle_failure(test->decision, owner_label);
    }
    return 0;
}

static int run_direct_body_lifecycle(
        struct body_wrapper_lifecycle_test_context *test) {
    int rc;
    for (int kind = 0; kind < 7; ++kind) {
        if (run_terminal_body_case(test, "haproxy-htx", kind) != 0) {
            return 1;
        }
    }
    if (begin_body_lifecycle(test, "haproxy-htx", "request begin",
            "request begin transaction") != 0) {
        return 1;
    }
    if (run_body_lifecycle(test->request_phase, *test->transaction,
            test->observed, test->decision) != 0) {
        return 1;
    }
    rc = haproxy_modsecurity_transaction_process_response_headers(
        *test->transaction, test->response, test->observed);
    if (expect_non_disruptive(rc, test->observed, 3, "response headers",
            test->decision) != 0 ||
        run_body_lifecycle(test->response_phase, *test->transaction,
            test->observed, test->decision) != 0) {
        return 1;
    }
    if (haproxy_modsecurity_transaction_finish(*test->transaction) != 0) {
        lifecycle_failure(test->decision, "direct transaction completion");
        *test->transaction = 0;
        return 1;
    }
    *test->transaction = 0;
    return 0;
}

static int run_spop_body_lifecycle(
        struct body_wrapper_lifecycle_test_context *test) {
    int rc;
    for (int kind = 0; kind < 7; ++kind) {
        if (run_terminal_body_case(test, "haproxy-spoe-spop", kind) != 0) {
            return 1;
        }
    }
    if (begin_body_lifecycle(test, "haproxy-spoe-spop", "SPOP request begin",
            "SPOP request transaction") != 0) {
        return 1;
    }
    if (run_body_lifecycle(test->request_phase, *test->transaction,
            test->observed, test->decision) != 0 ||
        haproxy_modsecurity_transaction_handoff_response_companion(
            *test->transaction) != 0 ||
        haproxy_modsecurity_transaction_claim_response_companion(
            *test->transaction) != 0) {
        lifecycle_failure(test->decision, "SPOP response companion handoff/claim");
        return 1;
    }
    rc = haproxy_modsecurity_transaction_process_response_headers(
        *test->transaction, test->response, test->observed);
    if (expect_non_disruptive(rc, test->observed, 3,
            "SPOP companion response headers", test->decision) != 0 ||
        run_body_lifecycle(test->response_phase, *test->transaction,
            test->observed, test->decision) != 0) {
        return 1;
    }
    if (haproxy_modsecurity_transaction_finish(*test->transaction) != 0) {
        lifecycle_failure(test->decision,
            "SPOP companion transaction completion");
        *test->transaction = 0;
        return 1;
    }
    *test->transaction = 0;
    return 0;
}

static int run_body_wrapper_lifecycle_self_test(
        const char *rules_file,
        haproxy_modsecurity_decision *decision) {
    static const unsigned char request_body[] = "token=allow";
    static const unsigned char response_body[] = "response=allow";
    const struct body_wrapper_lifecycle request_phase = {
        .phase = 2,
        .missing_transaction_message = "missing transaction or request body",
        .missing_body_message =
            "request body pointer is required when length is nonzero",
        .append_after_eos_message = "request body append after end-of-stream",
        .finish_twice_message = "request body may only be finalized once",
        .body = request_body,
        .body_len = (unsigned int)(sizeof(request_body) - 1U),
        .append = haproxy_modsecurity_transaction_append_request_body_chunk,
        .finish = haproxy_modsecurity_transaction_finish_request_body
    };
    const struct body_wrapper_lifecycle response_phase = {
        .phase = 4,
        .missing_transaction_message = "missing transaction or response body",
        .missing_body_message =
            "response body pointer is required when length is nonzero",
        .append_after_eos_message = "response body append after end-of-stream",
        .finish_twice_message = "response body may only be finalized once",
        .body = response_body,
        .body_len = (unsigned int)(sizeof(response_body) - 1U),
        .append = haproxy_modsecurity_transaction_append_response_body_chunk,
        .finish = haproxy_modsecurity_transaction_finish_response_body
    };
    haproxy_modsecurity_engine_config config;
    haproxy_modsecurity_engine *engine = 0;
    haproxy_modsecurity_transaction *transaction = 0;
    haproxy_modsecurity_header request_headers[4];
    haproxy_modsecurity_header response_headers[1];
    haproxy_modsecurity_request request;
    haproxy_modsecurity_response response;
    haproxy_modsecurity_decision observed;
    int result = 1;
    int rc;

    if (rules_file == 0 || rules_file[0] == '\0') {
        return lifecycle_failure(decision, "missing lifecycle rules file");
    }
    request_headers[0].name = "Host";
    request_headers[0].value = "localhost";
    request_headers[1].name = "Content-Type";
    request_headers[1].value = "application/x-www-form-urlencoded";
    request_headers[2].name = "Content-Length";
    request_headers[2].value = "11";
    request_headers[3].name = "X-Haproxy-Rule-Id";
    request_headers[3].value = "block";
    memset(&request, 0, sizeof(request));
    request.method = "POST";
    request.http_version = "1.1";
    request.uri = "/haproxy-binding-lifecycle-self-test";
    request.headers = request_headers;
    request.header_count = 4U;

    response_headers[0].name = "Content-Type";
    response_headers[0].value = "text/plain";
    memset(&response, 0, sizeof(response));
    response.status = 200;
    response.protocol = "HTTP/1.1";
    response.headers = response_headers;
    response.header_count = 1U;

    memset(&config, 0, sizeof(config));
    config.rules_file = rules_file;
    rc = haproxy_modsecurity_engine_create(&config, &engine, &observed);
    if (rc != 0 || engine == 0) {
        return lifecycle_failure(decision, "engine creation");
    }

    if (check_null_body_transaction(&request_phase, &observed, decision) != 0) {
        goto cleanup;
    }
    if (check_null_body_transaction(&response_phase, &observed, decision) != 0) {
        goto cleanup;
    }

    rc = haproxy_modsecurity_transaction_begin_request_with_profile(engine, &request,
        "haproxy-htx", &observed, &transaction);
    if (expect_failure(rc, &observed, 0, "missing client endpoint",
            "missing endpoint metadata", decision) != 0) {
        goto cleanup;
    }
    request.client_ip = "192.0.2.10";
    request.client_port = 12345;
    request.server_ip = "198.51.100.20";
    request.server_port = 8080;

    rc = haproxy_modsecurity_transaction_begin_request_with_profile(engine, &request,
        "haproxy-htx", &observed, &transaction);
    if (expect_disruptive_rule_id(rc, &observed, 1, 1000004,
            "phase-1 Rule-ID fallback block", decision) != 0) {
        goto cleanup;
    }
    haproxy_modsecurity_transaction_abort(transaction);
    transaction = 0;

    request_headers[3].value = "allow";
    rc = haproxy_modsecurity_transaction_begin_request_with_profile(engine, &request,
        "haproxy-htx", &observed, &transaction);
    if (expect_non_disruptive(rc, &observed, 1,
            "phase-1 Rule-ID fallback allow isolation", decision) != 0) {
        goto cleanup;
    }
    haproxy_modsecurity_transaction_abort(transaction);
    transaction = 0;

    if (run_request_id_boundary_self_test(engine, &request, &observed, decision) != 0) {
        goto cleanup;
    }

    {
        struct body_wrapper_lifecycle_test_context test = {
            engine, &transaction, &request, &response, &request_phase,
            &response_phase, &observed, decision
        };
        if (run_direct_body_lifecycle(&test) != 0) {
            goto cleanup;
        }
    }

    /* The SPOP profile deliberately cannot consume direct P3/P4 callbacks.
     * Exercise the owner-preserving handoff/claim sequence here without
     * pretending that this binding-only test is a HAProxy UDS bridge. */
    {
        struct body_wrapper_lifecycle_test_context test = {
            engine, &transaction, &request, &response, &request_phase,
            &response_phase, &observed, decision
        };
        if (run_spop_body_lifecycle(&test) != 0) {
            goto cleanup;
        }
    }
    result = 0;

cleanup:
    if (transaction != 0) {
        haproxy_modsecurity_transaction_finish(transaction);
    }
    haproxy_modsecurity_engine_destroy(engine);
    return result;
}

int main(int argc, char **argv) {
    haproxy_modsecurity_decision decision;
    int rc;

    if (argc == 2 && strcmp(argv[1], "--describe") == 0) {
        printf("%s\n", haproxy_modsecurity_binding_scope());
        printf("limitations: self-test only; live enforcement requires make smoke-haproxy; no RESPONSE_BODY verification\n");
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--self-test-crs") == 0) {
        rc = haproxy_modsecurity_crs_sqli_self_test(argv[2], &decision);
        if (rc == 0) {
            printf("haproxy_modsecurity_binding_crs_self_test: PASS\n");
            printf("modsecurity_binding_status: crs-self-test-verified\n");
            printf("runtime_verified: false\n");
            printf("runtime_status: blocked\n");
            printf("response_body_verified: false\n");
            printf("crs_verified: self-test-only\n");
            printf("verified_case: crs_sqli_anomaly_block\n");
            printf("crs_preamble_file: %s\n", argv[2]);
            printf("decision_status: %d\n", decision.status);
            printf("decision_disruptive: %d\n", decision.disruptive);
            return 0;
        }
        printf("haproxy_modsecurity_binding_crs_self_test: BLOCKED\n");
        printf("modsecurity_binding_status: blocked\n");
        printf("runtime_verified: false\n");
        printf("runtime_status: blocked\n");
        printf("response_body_verified: false\n");
        printf("crs_verified: false\n");
        if (decision.log_message[0] != '\0') {
            printf("reason: %s\n", decision.log_message);
        } else {
            printf("reason: CRS binding/load path missing\n");
        }
        return 77;
    }
    if (argc != 3 || strcmp(argv[1], "--self-test") != 0) {
        print_usage(argv[0]);
        return 2;
    }

    rc = haproxy_modsecurity_phase1_header_self_test(&decision);
    if (rc == 0) {
        rc = haproxy_modsecurity_request_body_self_test(&decision);
    }
    if (rc == 0) {
        rc = run_body_wrapper_lifecycle_self_test(argv[2], &decision);
    }
    if (rc == 0) {
        printf("haproxy_modsecurity_binding_self_test: PASS\n");
        printf("modsecurity_binding_status: self-test-verified\n");
        printf("runtime_verified: false\n");
        printf("runtime_status: blocked\n");
        printf("response_body_verified: false\n");
        printf("crs_verified: false\n");
        printf("request_body_verified: self-test-only\n");
        printf("request_body_lifecycle_verified: self-test-only\n");
        printf("response_body_lifecycle_verified: self-test-only\n");
        printf("decision_status: %d\n", decision.status);
        printf("decision_disruptive: %d\n", decision.disruptive);
        return 0;
    }

    printf("haproxy_modsecurity_binding_self_test: BLOCKED\n");
    printf("modsecurity_binding_status: blocked\n");
    printf("runtime_verified: false\n");
    printf("runtime_status: blocked\n");
    printf("response_body_verified: false\n");
    printf("crs_verified: false\n");
    if (decision.log_message[0] != '\0') {
        printf("reason: %s\n", decision.log_message);
    } else {
        printf("reason: modsecurity binding missing or not buildable\n");
    }
    return 77;
}
