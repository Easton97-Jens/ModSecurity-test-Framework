#include <stddef.h>
#include <string.h>
#include "ngx_http_modsecurity_response_body_limit.h"

/* Sonar's explicit historical Product input still exposes the three-argument
 * predicate. Keep this fixture compilable there while the paired Product
 * regression always exercises the state-aware five-argument implementation.
 * Legacy execution remains red on the changed/missing-log and EOS assertions;
 * no production behavior is supplied or replaced by these typed adapters. */
typedef int (*legacy_limit_predicate)(enum msconnector_phase,
    const msconnector_intervention *, const char *);
typedef int (*stateful_limit_predicate)(enum msconnector_phase,
    const msconnector_intervention *, const char *, int, int);

static inline int
call_legacy_limit(legacy_limit_predicate predicate, enum msconnector_phase phase,
    const msconnector_intervention *intervention, const char *rule_id,
    int append_active, int body_eos)
{
    (void)append_active;
    (void)body_eos;
    return predicate(phase, intervention, rule_id);
}

static inline int
call_stateful_limit(stateful_limit_predicate predicate,
    enum msconnector_phase phase, const msconnector_intervention *intervention,
    const char *rule_id, int append_active, int body_eos)
{
    return predicate(phase, intervention, rule_id, append_active, body_eos);
}

#define CALL_LIMIT(...) \
    _Generic(&ngx_http_modsecurity_is_response_body_limit_rejection, \
        legacy_limit_predicate: call_legacy_limit, \
        stateful_limit_predicate: call_stateful_limit)( \
            &ngx_http_modsecurity_is_response_body_limit_rejection, __VA_ARGS__)

int main(void)
{
    msconnector_intervention native = {1, 403, NULL,
        "Response body limit is marked to reject the request"};
    msconnector_intervention changed;
    const char *log_variants[] = {NULL, "", "Request body limit is marked to reject the request",
        "Response body limit is marked to reject the reques",
        "Response body limit is marked to reject the request!",
        "Invalid engine response"};

#define MATCH(value, rule) CALL_LIMIT( \
    MSCONNECTOR_PHASE_RESPONSE_BODY, (value), (rule), 1, 0)
    if (!MATCH(&native, NULL) || !MATCH(&native, "")) return 1;
    if (MATCH(NULL, NULL) || MATCH(&native, "1100301")) return 2;
    for (enum msconnector_phase phase = MSCONNECTOR_PHASE_CONNECTION;
         phase <= MSCONNECTOR_PHASE_LOGGING; phase++) {
        if (phase != MSCONNECTOR_PHASE_RESPONSE_BODY &&
            CALL_LIMIT(phase, &native, NULL, 1, 0)) return 3;
    }
    changed = native;
    changed.status = 500;
    if (MATCH(&changed, NULL)) return 4;
    changed.status = 413;
    if (MATCH(&changed, NULL)) return 5;
    changed = native;
    changed.disruptive = 0;
    if (MATCH(&changed, NULL)) return 6;
    changed.disruptive = 2;
    if (MATCH(&changed, NULL)) return 7;
    changed = native;
    changed.redirect_url = "";
    if (MATCH(&changed, NULL)) return 8;
    changed.redirect_url = "https://example.invalid/";
    if (MATCH(&changed, NULL)) return 9;
    for (size_t i = 0; i < sizeof(log_variants) / sizeof(log_variants[0]); i++) {
        changed = native;
        changed.log_message = log_variants[i];
        if (!MATCH(&changed, NULL)) return 10;
    }
    /* EOS rules, stale phase state and ProcessPartial (non-disruptive)
     * cannot inherit the native limit classification. */
    if (CALL_LIMIT(
            MSCONNECTOR_PHASE_RESPONSE_BODY, &native, NULL, 0, 0)) return 11;
    if (CALL_LIMIT(
            MSCONNECTOR_PHASE_RESPONSE_BODY, &native, NULL, 1, 1)) return 12;
    return 0;
}
