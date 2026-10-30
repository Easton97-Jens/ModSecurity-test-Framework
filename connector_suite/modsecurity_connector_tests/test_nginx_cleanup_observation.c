#include <assert.h>
#include <string.h>
#include "connectors/nginx/src/ngx_http_modsecurity_cleanup_observation.h"
#include "msconnector/transaction_state.h"

static void init_contract(msconnector_transaction_contract *contract)
{
    msconnector_transaction_state state;
    assert(msconnector_transaction_state_init(&state, "cleanup-test-tx"));
    *contract = state.contract;
}

static void complete_contract(msconnector_transaction_contract *contract)
{
    for (enum msconnector_phase phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
         phase <= MSCONNECTOR_PHASE_RESPONSE_BODY; phase++) {
        assert(msconnector_transaction_contract_begin_phase(contract, phase, 1) == 0);
        assert(msconnector_transaction_contract_complete_phase(contract, phase, 2) == 0);
    }
    assert(msconnector_transaction_contract_finish(contract, 3) == 0);
}

int main(void)
{
    msconnector_transaction_contract contract;
    msconnector_transaction_contract saved_contract;
    msconnector_event event = {0};
    msconnector_event before;
    char reason[256];
    int result;

    init_contract(&contract);
    complete_contract(&contract);
    result = msconnector_transaction_contract_cleanup(&contract, 4);
    assert(result == 0);
    assert(ngx_http_modsecurity_cleanup_observation(&event, reason, sizeof(reason), result, &contract, true));
    assert(strcmp(reason, "common_return=0;common_complete=1;native_cleanup_completed=1;error_class=none") == 0);
    assert(strcmp(event.meta.event, "transaction_cleanup") == 0);
    assert(strcmp(event.meta.message_id, "MSCONN_TRANSACTION_CLEANUP") == 0);
    assert(event.decision.phase == MSCONNECTOR_PHASE_LOGGING);
    assert(event.decision.status == MSCONNECTOR_STATUS_OK);
    assert(strcmp(event.decision.action, "allow") == 0);
    assert(strcmp(event.decision.actual_action, "allow") == 0);
    assert(strcmp(event.flags.cleanup_reason, "normal") == 0);
    assert(event.decision.rule_id == NULL && event.meta.transaction_id == NULL);
    assert(event.meta.connector == NULL && event.request.uri == NULL);
    assert(ngx_http_modsecurity_cleanup_observation(&event, reason, sizeof(reason), result, &contract, false));
    assert(strstr(reason, "native_cleanup_completed=0;") != NULL);
    assert(event.decision.status == MSCONNECTOR_STATUS_OK);

    result = msconnector_transaction_contract_cleanup(&contract, 5);
    assert(result == MSCONNECTOR_TRANSACTION_TRANSITION_AFTER_CLEANUP);
    assert(ngx_http_modsecurity_cleanup_observation(&event, reason, sizeof(reason), result, &contract, false));
    assert(event.decision.status == MSCONNECTOR_STATUS_ERROR);
    assert(strcmp(event.decision.actual_action, "error") == 0);
    assert(contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_NONE);

    init_contract(&contract);
    assert(ngx_http_modsecurity_cleanup_observation(&event, reason, sizeof(reason), 0, &contract, false));
    assert(event.decision.status == MSCONNECTOR_STATUS_ERROR);
    assert(strstr(reason, "common_complete=0;") != NULL);
    result = msconnector_transaction_contract_cleanup(&contract, 4);
    assert(result == MSCONNECTOR_TRANSACTION_TRANSITION_PREMATURE_CLEANUP);
    assert(ngx_http_modsecurity_cleanup_observation(&event, reason, sizeof(reason), result, &contract, true));
    assert(event.decision.status == MSCONNECTOR_STATUS_ERROR);
    assert(strcmp(event.flags.cleanup_reason, "cleanup_incomplete") == 0);
    assert(strstr(reason, "error_class=cleanup_incomplete") != NULL);

    init_contract(&contract);
    assert(msconnector_transaction_contract_timeout(&contract, 4) == 0);
    result = msconnector_transaction_contract_cleanup(&contract, 5);
    assert(result == 0);
    assert(ngx_http_modsecurity_cleanup_observation(&event, reason, sizeof(reason), result, &contract, true));
    assert(event.decision.status == MSCONNECTOR_STATUS_OK);
    assert(strcmp(event.flags.cleanup_reason, "engine_timeout") == 0);
    assert(strstr(reason, "error_class=engine_timeout") != NULL);
    assert(contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT);

    saved_contract = contract;
    assert(ngx_http_modsecurity_cleanup_observation(&event, reason, strlen(reason) + 1, result, &contract, true));
    assert(memcmp(&contract, &saved_contract, sizeof(contract)) == 0);

    before = event;
    assert(!ngx_http_modsecurity_cleanup_observation(NULL, reason, sizeof(reason), 0, &contract, true));
    assert(!ngx_http_modsecurity_cleanup_observation(&event, NULL, sizeof(reason), 0, &contract, true));
    assert(!ngx_http_modsecurity_cleanup_observation(&event, reason, 0, 0, &contract, true));
    assert(!ngx_http_modsecurity_cleanup_observation(&event, reason, sizeof(reason), 0, NULL, true));
    assert(!ngx_http_modsecurity_cleanup_observation(&event, reason, 8, 0, &contract, true));
    assert(reason[0] == '\0');
    assert(memcmp(&event, &before, sizeof(event)) == 0);
    return 0;
}
