#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "ngx_http_modsecurity_phase4_observation.h"
#include "msconnector/event_jsonl.h"

int main(void)
{
    msconnector_transaction_contract contract = {0};
    msconnector_event event;
    char reason[128];
    char json[8192];
    int truncated = 0;
    int result;
    const ngx_http_modsecurity_phase4_counters counters = {64, 65, 65, 2};
    contract.active_phase = -1;
    contract.last_completed_phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
    contract.completed_phase_mask = MSCONNECTOR_TRANSACTION_PHASE_MASK_P4;
#define MAKE(native, retained, seen, supplied, calls) \
    ngx_http_modsecurity_phase4_observation(&event, reason, sizeof(reason), \
        (native), &contract, &(const ngx_http_modsecurity_phase4_counters){ \
            (retained), (seen), (supplied), (calls)}, "text/plain")
    msconnector_event_init(&event);
    if (!MAKE(1, 64, 65, 65, 2)) return 1;
    event.meta.connector = "nginx";
    event.meta.integration_mode = "native-nginx-http-module";
    result = msconnector_event_write_jsonl_line(&event, json, sizeof(json), &truncated);
    if (!result || truncated) return 2;
    fputs(json, stdout);
    if (!MAKE(1, 0, 0, 0, 0)) return 11;
    if (MAKE(0, 64, 65, 65, 2) || MAKE(-1, 64, 65, 65, 2) ||
        MAKE(2, 64, 65, 65, 2)) return 3;
    if (MAKE(1, 66, 65, 65, 2) || MAKE(1, 64, 64, 65, 2) ||
        MAKE(1, 64, 65, 65, 0)) return 4;
    if (MAKE(1, UINT64_MAX, UINT64_MAX, UINT64_MAX, 2) ||
        MAKE(1, 64, 65, 65, UINT64_MAX)) return 5;
    contract.completed_phase_mask = 0;
    if (MAKE(1, 64, 65, 65, 2)) return 6;
    contract.completed_phase_mask = MSCONNECTOR_TRANSACTION_PHASE_MASK_P3;
    if (MAKE(1, 64, 65, 65, 2)) return 12;
    contract.completed_phase_mask = MSCONNECTOR_TRANSACTION_PHASE_MASK_P4;
    contract.last_completed_phase = MSCONNECTOR_PHASE_REQUEST_BODY;
    if (MAKE(1, 64, 65, 65, 2)) return 7;
    contract.last_completed_phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
    contract.active_phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
    if (MAKE(1, 64, 65, 65, 2)) return 8;
    contract.active_phase = -1;
    if (ngx_http_modsecurity_phase4_observation(&event, reason, 8, 1,
        &contract, &counters, "text/plain")) return 9;
    if (ngx_http_modsecurity_phase4_observation(NULL, reason, sizeof(reason),
        1, &contract, &counters, NULL) ||
        ngx_http_modsecurity_phase4_observation(&event, NULL, sizeof(reason),
        1, &contract, &counters, NULL) ||
        ngx_http_modsecurity_phase4_observation(&event, reason, sizeof(reason),
        1, NULL, &counters, NULL)) return 13;
    event.flags.eos_seen = 0;
    event.meta.event = "sentinel";
    if (MAKE(2, 64, 65, 65, 2) || event.flags.eos_seen ||
        strcmp(event.meta.event, "sentinel") != 0) return 14;
    if (ngx_http_modsecurity_phase4_observation(&event, reason, sizeof(reason),
        1, &contract, NULL, "text/plain") || event.flags.eos_seen ||
        strcmp(event.meta.event, "sentinel") != 0) return 15;
    return 0;
}
