/* The productive MRC1 handler must validate an outcome before annotating a
 * retained decision. Observe the rejected decision at its backend-fail seam. */
#include "common/runtime/response_companion_transport.c"
#include <assert.h>

static int fail_calls;
static int outcome_calls;
static int late_at_failure;

static void observe_failure(void *opaque,
    msconnector_response_companion_backend_session *session,
    msconnector_transaction_error_class error_class)
{
    const response_companion_session_state *state = opaque;
    assert(error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE);
    ++fail_calls;
    late_at_failure = state->latest_decision.late_intervention;
    session->opaque = NULL;
}

static int observe_outcome(void *opaque,
    const msconnector_response_companion_backend_session *session,
    const msconnector_response_companion_host_action *action,
    msconnector_error *error)
{
    (void)opaque;
    (void)session;
    msconnector_error_init(error);
    assert(action->decision->late_intervention);
    ++outcome_calls;
    return 1;
}

int main(void)
{
    for (int scenario = 0; scenario < 4; ++scenario) {
        msconnector_response_companion_transport transport = {0};
        msconnector_response_companion_transport_worker worker = {0};
        response_companion_session_state state;
        response_companion_frame frame = {0};
        unsigned char payload[4] = {MSCONNECTOR_DECISION_ACTION_LOG_ONLY, 0, 0, 200};
        int sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
        transport.config.operation_timeout_ms = 1000U;
        transport.config.backend.context = &state;
        transport.config.backend.allow_parallel_callbacks = 1;
        transport.config.backend.fail = observe_failure;
        transport.config.backend.record_host_action = observe_outcome;
        worker.transport = &transport;
        worker.socket_fd = sockets[0];
        response_companion_reset_session_state(&state);
        state.claimed = 1;
        state.response_headers = scenario == 2 ? 0 : 1;
        state.committed = 1;
        state.response_eos = 1;
        state.has_decision = 1;
        state.outcome_recorded = scenario == 1;
        state.session.opaque = &state;
        msconnector_decision_set_deny(&state.latest_decision, 403, "1999804", "control");
        state.latest_decision.phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
        frame.opcode = RESPONSE_COMPANION_OUTCOME;
        frame.payload = payload;
        frame.payload_size = scenario == 0 ? 3U : sizeof(payload);
        fail_calls = 0;
        outcome_calls = 0;
        late_at_failure = -1;
        if (scenario == 3) {
            assert(response_companion_handle_outcome(&worker, &state, &frame));
            assert(outcome_calls == 1 && fail_calls == 0);
            assert(state.latest_decision.late_intervention);
        } else {
            assert(!response_companion_handle_outcome(&worker, &state, &frame));
            assert(outcome_calls == 0 && fail_calls == 1);
            assert(late_at_failure == 0);
        }
        assert(close(sockets[0]) == 0);
        assert(close(sockets[1]) == 0);
    }
    return 0;
}
