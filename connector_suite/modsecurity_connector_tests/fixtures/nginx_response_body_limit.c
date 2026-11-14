#include <stddef.h>
#include <string.h>
#include "ngx_http_modsecurity_response_body_limit.h"

int main(void)
{
    msconnector_intervention native = {1, 403, NULL,
        "Response body limit is marked to reject the request"};
    msconnector_intervention changed;
    const char *log_variants[] = {NULL, "", "Request body limit is marked to reject the request",
        "Response body limit is marked to reject the reques",
        "Response body limit is marked to reject the request!",
        "Invalid engine response"};

#define MATCH(value, rule) ngx_http_modsecurity_is_response_body_limit_rejection( \
    MSCONNECTOR_PHASE_RESPONSE_BODY, (value), (rule), 1, 0)
    if (!MATCH(&native, NULL) || !MATCH(&native, "")) return 1;
    if (MATCH(NULL, NULL) || MATCH(&native, "1100301")) return 2;
    for (enum msconnector_phase phase = MSCONNECTOR_PHASE_CONNECTION;
         phase <= MSCONNECTOR_PHASE_LOGGING; phase++) {
        if (phase != MSCONNECTOR_PHASE_RESPONSE_BODY &&
            ngx_http_modsecurity_is_response_body_limit_rejection(phase, &native, NULL, 1, 0)) return 3;
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
    if (ngx_http_modsecurity_is_response_body_limit_rejection(
            MSCONNECTOR_PHASE_RESPONSE_BODY, &native, NULL, 0, 0)) return 11;
    if (ngx_http_modsecurity_is_response_body_limit_rejection(
            MSCONNECTOR_PHASE_RESPONSE_BODY, &native, NULL, 1, 1)) return 12;
    return 0;
}
