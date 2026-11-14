#include <stdio.h>

#include "msconnector/intervention.h"
#include "msconnector/phase.h"

static int failures;

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL:%s:%d: %s\\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)

/* Sonar's deliberate historical Product input has the old two-argument
 * signature. Compile both typed interfaces without supplying replacement
 * behavior; running the legacy predicate still fails these new assertions. */
typedef int (*legacy_response_limit)(enum msconnector_phase,
    const msconnector_intervention *);
typedef int (*stateful_response_limit)(enum msconnector_phase,
    const msconnector_intervention *, const char *, int, int);

static inline int call_legacy_response_limit(legacy_response_limit predicate,
    enum msconnector_phase phase, const msconnector_intervention *intervention,
    const char *rule_id, int append_active, int body_eos)
{
    (void)rule_id;
    (void)append_active;
    (void)body_eos;
    return predicate(phase, intervention);
}

static inline int call_stateful_response_limit(stateful_response_limit predicate,
    enum msconnector_phase phase, const msconnector_intervention *intervention,
    const char *rule_id, int append_active, int body_eos)
{
    return predicate(phase, intervention, rule_id, append_active, body_eos);
}

#define RESPONSE_LIMIT(...) \
    _Generic(&msconnector_intervention_is_response_body_limit_rejection, \
        legacy_response_limit: call_legacy_response_limit, \
        stateful_response_limit: call_stateful_response_limit)( \
            &msconnector_intervention_is_response_body_limit_rejection, __VA_ARGS__)

static void check_response_limit_boundary(void)
{
    msconnector_intervention limit = msconnector_intervention_make(1, 403, NULL, NULL);
    const char *messages[] = {MSCONNECTOR_RESPONSE_BODY_LIMIT_REJECTION_LOG,
        "changed engine diagnostic", "", NULL};

    for (size_t i = 0; i < sizeof(messages) / sizeof(messages[0]); ++i) {
        limit.log_message = messages[i];
        CHECK(RESPONSE_LIMIT(
            MSCONNECTOR_PHASE_RESPONSE_BODY, &limit, NULL, 1, 0) == 1);
    }
    CHECK(RESPONSE_LIMIT(
        MSCONNECTOR_PHASE_RESPONSE_BODY, &limit, "", 1, 0) == 1);
    CHECK(RESPONSE_LIMIT(
        MSCONNECTOR_PHASE_REQUEST_BODY, &limit, NULL, 1, 0) == 0);
    CHECK(RESPONSE_LIMIT(
        MSCONNECTOR_PHASE_RESPONSE_BODY, NULL, NULL, 1, 0) == 0);
    CHECK(RESPONSE_LIMIT(
        MSCONNECTOR_PHASE_RESPONSE_BODY, &limit, "910001", 1, 0) == 0);
    CHECK(RESPONSE_LIMIT(
        MSCONNECTOR_PHASE_RESPONSE_BODY, &limit, NULL, 0, 0) == 0);
    CHECK(RESPONSE_LIMIT(
        MSCONNECTOR_PHASE_RESPONSE_BODY, &limit, NULL, 1, 1) == 0);
    CHECK(RESPONSE_LIMIT(
        MSCONNECTOR_PHASE_RESPONSE_BODY, &limit, NULL, 2, 0) == 0);
    CHECK(RESPONSE_LIMIT(
        MSCONNECTOR_PHASE_RESPONSE_BODY, &limit, NULL, 1, 2) == 0);
    limit.redirect_url = "";
    CHECK(RESPONSE_LIMIT(
        MSCONNECTOR_PHASE_RESPONSE_BODY, &limit, NULL, 1, 0) == 0);
    limit.redirect_url = "/redirect";
    CHECK(RESPONSE_LIMIT(
        MSCONNECTOR_PHASE_RESPONSE_BODY, &limit, NULL, 1, 0) == 0);
    limit.redirect_url = NULL;
    limit.status = 413;
    CHECK(RESPONSE_LIMIT(
        MSCONNECTOR_PHASE_RESPONSE_BODY, &limit, NULL, 1, 0) == 0);
    limit.status = 403;
    limit.disruptive = 0;
    CHECK(RESPONSE_LIMIT(
        MSCONNECTOR_PHASE_RESPONSE_BODY, &limit, NULL, 1, 0) == 0);
    limit.disruptive = 2;
    CHECK(RESPONSE_LIMIT(
        MSCONNECTOR_PHASE_RESPONSE_BODY, &limit, NULL, 1, 0) == 0);
}

int main(void)
{
    const msconnector_intervention native_request_body_limit =
        msconnector_intervention_make(1, 403, NULL,
            MSCONNECTOR_REQUEST_BODY_LIMIT_REJECTION_LOG);
    const msconnector_intervention native_request_body_limit_with_url =
        msconnector_intervention_make(1, 403, "",
            MSCONNECTOR_REQUEST_BODY_LIMIT_REJECTION_LOG);
    const msconnector_intervention native_request_body_limit_with_status =
        msconnector_intervention_make(1, 413, NULL,
            MSCONNECTOR_REQUEST_BODY_LIMIT_REJECTION_LOG);
    const msconnector_intervention native_request_body_limit_with_log =
        msconnector_intervention_make(1, 403, NULL, "ordinary rule intervention");

    CHECK(msconnector_intervention_has_redirect_url(NULL) == 0);
    CHECK(msconnector_intervention_has_redirect_url("") == 0);
    CHECK(msconnector_intervention_has_redirect_url("/blocked") == 1);

    CHECK(msconnector_intervention_normalize_status(NULL, 403, 451) == 403);
    CHECK(msconnector_intervention_normalize_status(NULL, 429, 451) == 429);
    CHECK(msconnector_intervention_normalize_status(NULL, 200, 451) == 451);
    CHECK(msconnector_intervention_normalize_status(NULL, 204, 451) == 451);
    CHECK(msconnector_intervention_normalize_status(NULL, 299, 451) == 451);
    CHECK(msconnector_intervention_normalize_status(NULL, 302, 451) == 451);
    CHECK(msconnector_intervention_normalize_status(NULL, 600, 451) == 451);
    CHECK(msconnector_intervention_normalize_status(NULL, 200, 299) == 403);

    CHECK(msconnector_intervention_normalize_status("/blocked", 301, 451) == 301);
    CHECK(msconnector_intervention_normalize_status("/blocked", 399, 451) == 399);
    CHECK(msconnector_intervention_normalize_status("/blocked", 200, 451) == 302);
    CHECK(msconnector_intervention_normalize_status("/blocked", 204, 451) == 302);
    CHECK(msconnector_intervention_normalize_status("/blocked", 299, 451) == 302);
    CHECK(msconnector_intervention_normalize_status("/blocked", 600, 451) == 302);

    CHECK(msconnector_intervention_is_request_body_limit_rejection(
        MSCONNECTOR_PHASE_REQUEST_BODY, &native_request_body_limit) == 1);
    CHECK(msconnector_intervention_is_request_body_limit_rejection(
        MSCONNECTOR_PHASE_REQUEST_HEADERS, &native_request_body_limit) == 0);
    CHECK(msconnector_intervention_is_request_body_limit_rejection(
        MSCONNECTOR_PHASE_REQUEST_BODY,
        &native_request_body_limit_with_url) == 0);
    CHECK(msconnector_intervention_is_request_body_limit_rejection(
        MSCONNECTOR_PHASE_REQUEST_BODY,
        &native_request_body_limit_with_status) == 1);
    CHECK(msconnector_intervention_is_request_body_limit_rejection(
        MSCONNECTOR_PHASE_REQUEST_BODY,
        &native_request_body_limit_with_log) == 0);

    msconnector_intervention request_bad_status = native_request_body_limit;
    request_bad_status.status = 451;
    CHECK(msconnector_intervention_is_request_body_limit_rejection(
        MSCONNECTOR_PHASE_REQUEST_BODY, &request_bad_status) == 0);
    request_bad_status.status = 403;
    request_bad_status.disruptive = 0;
    CHECK(msconnector_intervention_is_request_body_limit_rejection(
        MSCONNECTOR_PHASE_REQUEST_BODY, &request_bad_status) == 0);

    check_response_limit_boundary();

    return failures == 0 ? 0 : 1;
}
