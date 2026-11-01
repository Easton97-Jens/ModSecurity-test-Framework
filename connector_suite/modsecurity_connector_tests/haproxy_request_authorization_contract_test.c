#include <assert.h>
#include <string.h>
#include "msconnector/transaction_contract.h"
#include "connectors/profile_registry.h"

static msconnector_transaction_contract request_contract(int request_only) {
    const msconnector_transaction_profile *registered =
        msconnector_profile_registry_find("haproxy-spoe-spop");
    assert(registered != NULL);
    msconnector_transaction_profile declared = *registered;
    if (request_only) declared.companion_phase_mask = 0U;
    msconnector_transaction_contract c;
    assert(msconnector_transaction_contract_init(&c, &declared, "finite-auth",
        declared.connector_id, declared.host_adapter_id,
        MSCONNECTOR_TRANSACTION_MODE_STRICT, 1U) == 0);
    return c;
}
static void phase(msconnector_transaction_contract *c, int index) {
    assert(msconnector_transaction_contract_begin_phase(c, index, 2U) == 0);
    assert(msconnector_transaction_contract_complete_phase(c, index, 3U) == 0);
}
static void request_phases(msconnector_transaction_contract *c) {
    phase(c, MSCONNECTOR_PHASE_REQUEST_HEADERS);
    phase(c, MSCONNECTOR_PHASE_REQUEST_BODY);
    assert(c->completed_phase_mask == 3U);
}
int main(void) {
    msconnector_transaction_contract c = request_contract(1);
    request_phases(&c);
    assert(msconnector_transaction_contract_finish_request_authorization(&c, 4U) == 0);
    assert(c.completed_phase_mask == 3U && c.status == MSCONNECTOR_TRANSACTION_STATUS_COMPLETED);
    assert(msconnector_transaction_contract_begin_phase(&c, MSCONNECTOR_PHASE_RESPONSE_HEADERS, 5U) != 0);
    assert(msconnector_transaction_contract_begin_companion_phase(&c, MSCONNECTOR_PHASE_RESPONSE_HEADERS, 5U) != 0);
    assert(msconnector_transaction_contract_handoff_response_companion(&c, 5U) != 0);
    assert(msconnector_transaction_contract_claim_response_companion(&c, 5U) != 0);
    assert(msconnector_transaction_contract_cleanup(&c, 6U) == 0);
    assert(c.completed_phase_mask == 3U && c.error_class == MSCONNECTOR_TRANSACTION_ERROR_NONE);
    assert(msconnector_transaction_contract_cleanup(&c, 7U) == MSCONNECTOR_TRANSACTION_TRANSITION_AFTER_CLEANUP);
    assert(msconnector_transaction_contract_finish_request_authorization(&c, 7U) == MSCONNECTOR_TRANSACTION_TRANSITION_AFTER_CLEANUP);

    c = request_contract(1); request_phases(&c);
    assert(msconnector_transaction_contract_finish(&c, 4U) != 0); /* Generic finish stays full. */
    assert(c.error_class == MSCONNECTOR_TRANSACTION_ERROR_PHASE_SEQUENCE);
    assert(msconnector_transaction_contract_cleanup(&c, 5U) == 0);
    c = request_contract(0); request_phases(&c);
    assert(msconnector_transaction_contract_finish_request_authorization(&c, 4U) != 0);
    assert(c.error_class == MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL);
    c = request_contract(1); phase(&c, MSCONNECTOR_PHASE_REQUEST_HEADERS);
    assert(msconnector_transaction_contract_finish_request_authorization(&c, 4U) != 0);
    assert(c.completed_phase_mask == 1U);
    c = request_contract(1); request_phases(&c);
    assert(msconnector_transaction_contract_cleanup(&c, 4U) == MSCONNECTOR_TRANSACTION_TRANSITION_PREMATURE_CLEANUP);
    assert(c.error_class == MSCONNECTOR_TRANSACTION_ERROR_CLEANUP_INCOMPLETE);

    for (int failure = 0; failure < 3; ++failure) {
        c = request_contract(1); phase(&c, MSCONNECTOR_PHASE_REQUEST_HEADERS);
        if (failure == 0) assert(msconnector_transaction_contract_cancel(&c, 0, 4U) == 0);
        else if (failure == 1) assert(msconnector_transaction_contract_timeout(&c, 4U) == 0);
        else assert(msconnector_transaction_contract_fail(&c, MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE, 4U) == 0);
        msconnector_transaction_error_class first = c.error_class;
        assert(first != MSCONNECTOR_TRANSACTION_ERROR_NONE);
        assert(msconnector_transaction_contract_fail(&c, MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR, 5U) != 0);
        assert(c.error_class == first);
        assert(msconnector_transaction_contract_finish_request_authorization(&c, 6U) == 0);
        assert(msconnector_transaction_contract_cleanup(&c, 7U) == 0);
        assert(c.completed_phase_mask == 1U && c.error_class == first);
    }
    return 0;
}
