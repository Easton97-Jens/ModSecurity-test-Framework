/* Independent productive MSE1 outcome control. Only the Runtime recording
 * seam is replaced; this fixture does not claim an SDK or host execution. */
#define _GNU_SOURCE
#include "common/runtime/msconnector_runtime.h"
#include <assert.h>
#include <string.h>

static int recorded_late;
static msconnector_decision_action recorded_action;
static int observe_host_action(const msconnector_runtime_transaction *transaction,
    const msconnector_decision *decision, msconnector_decision_action action,
    int status, const char *transport, int aborted, msconnector_error *error);
#define msconnector_runtime_transaction_record_host_action observe_host_action
#define main traefik_i12_unused_engine_main
#include "connectors/traefik/src/traefik_engine_service.c"
#undef main
#undef msconnector_runtime_transaction_record_host_action

static int observe_host_action(const msconnector_runtime_transaction *transaction,
    const msconnector_decision *decision, msconnector_decision_action action,
    int status, const char *transport, int aborted, msconnector_error *error)
{
    /* Successful Runtime recording clears its mutable error output. */
    msconnector_error_init(error);
    assert(transaction != NULL && decision != NULL && transport != NULL);
    assert(!aborted && (status == 200 || status == 403));
    recorded_late = decision->late_intervention;
    recorded_action = action;
    return 1;
}

int main(void)
{
    traefik_engine_service service = {0};
    assert(pthread_mutex_init(&service.runtime_lock, NULL) == 0);
    for (int scenario = 0; scenario < 3; ++scenario) {
        traefik_engine_session session = {0};
        traefik_engine_frame frame = {0};
        msconnector_decision decision;
        unsigned char payload[4] = {0};
        uint8_t result_code = 0;
        int committed = scenario == 0;
        session.service = &service;
        session.transaction = (msconnector_runtime_transaction *)&session;
        session.begun = 1;
        session.response_headers_sent = committed;
        session.response_status = 200;
        session.pending_result.pending_disruptive = 1;
        session.pending_result.pending_action = MSCONNECTOR_DECISION_KIND_DENY;
        session.pending_result.pending_status = 403;
        session.pending_result.pending_phase = scenario == 2 ?
            MSCONNECTOR_PHASE_RESPONSE_HEADERS : MSCONNECTOR_PHASE_RESPONSE_BODY;
        msconnector_decision_set_deny(&session.pending_decision, 403, "1999804", "control");
        session.pending_decision.phase = session.pending_result.pending_phase;
        frame.opcode = TRAEFIK_ENGINE_PROTOCOL_OUTCOME;
        frame.payload = payload;
        frame.payload_size = sizeof(payload);
        payload[0] = committed ? MSCONNECTOR_DECISION_KIND_LOG_ONLY :
            MSCONNECTOR_DECISION_KIND_DENY;
        payload[1] = committed ? 0 : TRAEFIK_ENGINE_PROTOCOL_OUTCOME_HOST_ACTION_APPLIED;
        payload[2] = committed ? 0 : 1;
        payload[3] = committed ? 200 : 147;
        msconnector_decision_init(&decision);
        recorded_late = -1;
        assert(traefik_engine_handle_outcome(&session, &frame, &decision, &result_code) == 1);
        assert(recorded_late == committed);
        assert(decision.late_intervention == committed);
        assert(recorded_action == (committed ? MSCONNECTOR_DECISION_ACTION_LOG_ONLY :
            MSCONNECTOR_DECISION_ACTION_DENY));
    }
    assert(pthread_mutex_destroy(&service.runtime_lock) == 0);
    return 0;
}
