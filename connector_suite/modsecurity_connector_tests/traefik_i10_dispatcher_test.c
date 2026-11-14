/* Productive Traefik dispatcher: invalid Common returns and terminal reentry.
 */
#define _GNU_SOURCE
#include "common/runtime/msconnector_runtime.h"
#include <assert.h>
static int calls;
static int native_result;
static int typed_decision;
static int native_response_kind;
static msconnector_error_code test_error_code;
int test_begin(const msconnector_runtime *runtime,
               const msconnector_request *request, const char *host_request_id,
               msconnector_runtime_transaction **out,
               msconnector_decision *decision, msconnector_error *error);
#define msconnector_runtime_transaction_begin_request_stream test_begin
int test_append_request_body_chunk(
    const msconnector_runtime_transaction *transaction,
    const unsigned char *data, size_t size, msconnector_error *error);
#define msconnector_runtime_transaction_append_request_body_chunk              \
  test_append_request_body_chunk
int test_finish_request_body(const msconnector_runtime_transaction *transaction,
                             msconnector_decision *decision,
                             msconnector_error *error);
#define msconnector_runtime_transaction_finish_request_body                    \
  test_finish_request_body
int test_process_response_headers(
    const msconnector_runtime_transaction *transaction,
    const msconnector_response *response, msconnector_decision *decision,
    msconnector_error *error);
#define msconnector_runtime_transaction_process_response_headers               \
  test_process_response_headers
int test_append_response_body_chunk(
    const msconnector_runtime_transaction *transaction,
    const unsigned char *data, size_t size, msconnector_error *error);
#define msconnector_runtime_transaction_append_response_body_chunk             \
  test_append_response_body_chunk
int test_finish_response_body(
    const msconnector_runtime_transaction *transaction,
    msconnector_decision *decision, msconnector_error *error);
#define msconnector_runtime_transaction_finish_response_body                   \
  test_finish_response_body
int test_finish(const msconnector_runtime_transaction *transaction,
                msconnector_error *error);
#define msconnector_runtime_transaction_finish test_finish
int test_record_host_action(const msconnector_runtime_transaction *transaction,
                            const msconnector_decision *decision,
                            msconnector_decision_action actual_action,
                            int visible_http_status,
                            const char *transport_result,
                            int connection_aborted, msconnector_error *error);
#define msconnector_runtime_transaction_record_host_action                     \
  test_record_host_action
int test_set_response_commit_state_checked(const msconnector_runtime_transaction *transaction,
    int headers_sent, int body_started, msconnector_error *error);
#define msconnector_runtime_transaction_set_response_commit_state_checked test_set_response_commit_state_checked
#define main traefik_engine_service_program_main
#include "connectors/traefik/src/traefik_engine_service.c"
#undef main
#include "connectors/traefik/src/traefik_engine_protocol_helpers.inc"
#undef msconnector_runtime_transaction_begin_request_stream
#undef msconnector_runtime_transaction_append_request_body_chunk
#undef msconnector_runtime_transaction_finish_request_body
#undef msconnector_runtime_transaction_process_response_headers
#undef msconnector_runtime_transaction_append_response_body_chunk
#undef msconnector_runtime_transaction_finish_response_body
#undef msconnector_runtime_transaction_finish
#undef msconnector_runtime_transaction_record_host_action
#undef msconnector_runtime_transaction_set_response_commit_state_checked
int test_begin(const msconnector_runtime *runtime,
               const msconnector_request *request, const char *host_request_id,
               msconnector_runtime_transaction **out,
               msconnector_decision *decision, msconnector_error *error) {
  (void)runtime;
  (void)request;
  (void)host_request_id;
  (void)out;
  (void)decision;
  if (typed_decision) {
    msconnector_decision_set_error(decision, 500,
                                   "injected typed technical decision");
  } else if (native_result != 1) {
    msconnector_decision_set_redirect(decision, 302, "/stale-rule", "old-rule",
                                      "stale");
  }
  calls++;
  msconnector_error_set(error, test_error_code, "injected", "fixture");
  return native_result;
}
int test_append_request_body_chunk(
    const msconnector_runtime_transaction *transaction,
    const unsigned char *data, size_t size, msconnector_error *error) {
  (void)transaction;
  (void)data;
  (void)size;
  calls++;
  msconnector_error_set(error, test_error_code, "injected", "fixture");
  return native_result;
}
int test_finish_request_body(const msconnector_runtime_transaction *transaction,
                             msconnector_decision *decision,
                             msconnector_error *error) {
  (void)transaction;
  (void)decision;
  if (typed_decision) {
    msconnector_decision_set_error(decision, 500,
                                   "injected typed technical decision");
  } else if (native_result != 1) {
    msconnector_decision_set_redirect(decision, 302, "/stale-rule", "old-rule",
                                      "stale");
  }
  calls++;
  msconnector_error_set(error, test_error_code, "injected", "fixture");
  return native_result;
}
int test_process_response_headers(
    const msconnector_runtime_transaction *transaction,
    const msconnector_response *response, msconnector_decision *decision,
    msconnector_error *error) {
  (void)transaction;
  (void)response;
  (void)decision;
  if (typed_decision) {
    msconnector_decision_set_error(decision, 500,
                                   "injected typed technical decision");
  } else if (native_result != 1) {
    msconnector_decision_set_redirect(decision, 302, "/stale-rule", "old-rule",
                                      "stale");
  }
  calls++;
  msconnector_error_set(error, test_error_code, "injected", "fixture");
  return native_result;
}
int test_append_response_body_chunk(
    const msconnector_runtime_transaction *transaction,
    const unsigned char *data, size_t size, msconnector_error *error) {
  (void)transaction;
  (void)data;
  (void)size;
  calls++;
  msconnector_error_set(error, test_error_code, "injected", "fixture");
  return native_result;
}
int test_finish_response_body(
    const msconnector_runtime_transaction *transaction,
    msconnector_decision *decision, msconnector_error *error) {
  (void)transaction;
  (void)decision;
  if (native_response_kind == 1) {
    msconnector_decision_set_response_body_limit(decision, "native Reject");
  } else if (native_response_kind == 2) {
    msconnector_decision_set_deny(decision, 403, "900007", "genuine P4 rule");
    decision->phase = MSCONNECTOR_PHASE_RESPONSE_BODY;
  } else if (typed_decision) {
    msconnector_decision_set_error(decision, 500,
                                   "injected typed technical decision");
  } else if (native_result != 1) {
    msconnector_decision_set_redirect(decision, 302, "/stale-rule", "old-rule",
                                      "stale");
  }
  calls++;
  msconnector_error_set(error, test_error_code, "injected", "fixture");
  return native_result;
}
int test_finish(const msconnector_runtime_transaction *transaction,
                msconnector_error *error) {
  (void)transaction;
  calls++;
  msconnector_error_set(error, test_error_code, "injected", "fixture");
  return native_result;
}
int test_record_host_action(const msconnector_runtime_transaction *transaction,
                            const msconnector_decision *decision,
                            msconnector_decision_action actual_action,
                            int visible_http_status,
                            const char *transport_result,
                            int connection_aborted, msconnector_error *error) {
  (void)transaction;
  (void)decision;
  (void)actual_action;
  (void)visible_http_status;
  (void)transport_result;
  (void)connection_aborted;
  calls++;
  msconnector_error_set(error, test_error_code, "injected", "fixture");
  return native_result;
}

int test_set_response_commit_state_checked(const msconnector_runtime_transaction *transaction,
    int headers_sent, int body_started, msconnector_error *error) {
  (void)transaction;
  (void)headers_sent;
  (void)body_started;
  calls++;
  msconnector_error_set(error, test_error_code, "injected", "fixture");
  return native_result;
}

static void prepare_failure_frame(traefik_engine_session *session,
                                  traefik_engine_frame *frame,
                                  unsigned char *payload, size_t payload_size) {
  size_t offset = 0;
  frame->payload = payload;
  if (frame->opcode == 1) {
    session->begun = 0;
    assert(traefik_engine_protocol_self_test_begin_with_header(
        payload, payload_size, &offset, "Host", "example.test"));
    frame->payload_size = offset;
  }
  if (frame->opcode == 2 || frame->opcode == 3)
    session->request_eos = 0;
  if (frame->opcode == 2 || frame->opcode == 5)
    frame->payload_size = 1;
  if (frame->opcode == 4) {
    session->response_headers = 0;
    assert(traefik_engine_self_test_append_u16(payload, payload_size, &offset,
                                               200));
    assert(traefik_engine_self_test_append_text(payload, payload_size, &offset,
                                                "HTTP/1.1"));
    assert(
        traefik_engine_self_test_append_u16(payload, payload_size, &offset, 0));
    frame->payload_size = offset;
  }
  if (frame->opcode == 7) {
    payload[0] = 1;
    payload[1] = 1;
    frame->payload_size = 2;
  }
  if (frame->opcode == 8)
    session->response_eos = 1;
  if (frame->opcode == 10) {
    session->transaction = (msconnector_runtime_transaction *)session;
    session->pending_result.pending_phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
    session->pending_result.pending_disruptive = 1;
    session->pending_result.pending_action = MSCONNECTOR_DECISION_KIND_DENY;
    session->pending_result.pending_status = 403;
    payload[0] = session->pending_result.pending_action;
    payload[1] = 1;
    traefik_engine_write_u16(payload + 2, 403);
    frame->payload_size = 4;
  }
}

static void run_dispatch_case(msconnector_runtime *runtime,
                              unsigned char opcode, int invalid, int committed,
                              msconnector_error_code cause) {
  test_error_code = cause;
  traefik_engine_service service = {0};
  traefik_engine_session session = {0};
  traefik_engine_frame frame = {0};
  msconnector_decision decision;
  uint8_t code;
  unsigned char payload[256] = {0};
  assert(pthread_mutex_init(&service.runtime_lock, NULL) == 0);
  service.request_body_mode = MSCONNECTOR_BODY_MODE_BUFFERED;
  service.response_body_mode = MSCONNECTOR_BODY_MODE_BUFFERED;
  session.response_headers_sent = committed > 0;
  session.response_body_started = committed > 1;
  service.runtime = runtime;
  session.service = &service;
  session.begun = 1;
  session.request_eos = 1;
  session.response_headers = 1;
  frame.opcode = opcode;
  prepare_failure_frame(&session, &frame, payload, sizeof(payload));
  typed_decision = invalid == 2;
  native_result = 1;
  if (invalid < 2)
    native_result = invalid ? -1 : 0;
  if (invalid == 4)
    native_result = 2;
  calls = 0;
  if (invalid == 3) {
    assert(traefik_engine_dispatch(&session, &frame, &decision, &code) == 1);
    assert(code == TRAEFIK_ENGINE_PROTOCOL_RESULT_OK && calls == 1 &&
           !session.failed);
  } else {
    assert(traefik_engine_dispatch(&session, &frame, &decision, &code) == -1);
    assert(code != TRAEFIK_ENGINE_PROTOCOL_RESULT_OK && calls == 1 &&
           session.failed);
    assert(!session.pending_result.pending_disruptive && decision.rule_id == NULL);
    uint8_t first = code;
    frame.opcode = TRAEFIK_ENGINE_PROTOCOL_RESPONSE_CHUNK;
    assert(traefik_engine_dispatch(&session, &frame, &decision, &code) == -1);
    assert(code == first && calls == 1);
  }
  assert(pthread_mutex_destroy(&service.runtime_lock) == 0);
}

static void run_dispatch_states(msconnector_runtime *runtime,
                                unsigned char opcode, int invalid) {
  const msconnector_error_code causes[] = {
      MSCONNECTOR_ERROR_MODSECURITY_FAILURE, MSCONNECTOR_ERROR_INTERNAL,
      MSCONNECTOR_ERROR_PROTOCOL, MSCONNECTOR_ERROR_TIMEOUT,
      MSCONNECTOR_ERROR_RUNTIME_UNAVAILABLE};
  for (int committed = 0; committed < 3; committed++)
    for (size_t cause = 0; cause < sizeof(causes) / sizeof(causes[0]); cause++)
      run_dispatch_case(runtime, opcode, invalid, committed, causes[cause]);
}

static void run_framed_failure(msconnector_runtime *runtime) {
  /* The actual framed caller must return stop after emitting its error result.
   */
  {
    int sockets[2];
    traefik_engine_service service = {0};
    traefik_engine_session session = {0};
    traefik_engine_frame frame = {0};
    traefik_engine_frame result = {0};
    unsigned char payload[64] = {0};
    size_t offset = 0;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(pthread_mutex_init(&service.runtime_lock, NULL) == 0);
    service.runtime = runtime;
    session.service = &service;
    session.begun = 1;
    session.request_eos = 1;
    typed_decision = 0;
    native_result = 0;
    test_error_code = MSCONNECTOR_ERROR_MODSECURITY_FAILURE;
    assert(traefik_engine_self_test_append_u16(payload, sizeof(payload),
                                               &offset, 200));
    assert(traefik_engine_self_test_append_text(payload, sizeof(payload),
                                                &offset, "HTTP/1.1"));
    assert(traefik_engine_self_test_append_u16(payload, sizeof(payload),
                                               &offset, 0));
    assert(traefik_engine_send_frame(sockets[0],
                                     TRAEFIK_ENGINE_PROTOCOL_RESPONSE_HEADERS,
                                     payload, offset) == 1);
    assert(traefik_engine_process_frame(&session, sockets[1], &frame) == 0);
    assert(traefik_engine_receive_frame(sockets[0], &result) == 1);
    assert(result.opcode == TRAEFIK_ENGINE_PROTOCOL_RESULT &&
           result.payload_size >= 14);
    assert(result.payload[1] == TRAEFIK_ENGINE_PROTOCOL_RESULT_RUNTIME);
    assert(traefik_engine_read_u16(result.payload + 10) ==
           0); /* no stale rule */
    traefik_engine_frame_reset(&frame);
    traefik_engine_frame_reset(&result);
    assert(close(sockets[0]) == 0);
    assert(close(sockets[1]) == 0);
    assert(pthread_mutex_destroy(&service.runtime_lock) == 0);
  }
}

/* Exercise the actual framed caller before the generic wire result loses the
 * native body-limit bit, plus the legitimate rule/late-outcome control. */
static void verify_native_response_runtime_error(
    const traefik_engine_session *session, const traefik_engine_frame *result) {
  assert(result->payload[1] == TRAEFIK_ENGINE_PROTOCOL_RESULT_RUNTIME);
  assert(session->failed && session->terminal &&
         !session->pending_result.pending_disruptive);
  assert(calls == 1 && !session->response_eos);
}

static void acknowledge_native_response_rule(traefik_engine_session *session) {
  unsigned char outcome[4] = {MSCONNECTOR_DECISION_KIND_LOG_ONLY, 0, 0, 200};
  msconnector_decision decision;
  uint8_t code;
  traefik_engine_frame acknowledged = {
      .opcode = TRAEFIK_ENGINE_PROTOCOL_OUTCOME,
      .payload = outcome,
      .payload_size = sizeof(outcome)};
  session->transaction = (msconnector_runtime_transaction *)session;
  assert(traefik_engine_dispatch(session, &acknowledged, &decision, &code) == 1);
  assert(code == TRAEFIK_ENGINE_PROTOCOL_RESULT_OK && decision.late_intervention);
  assert(decision.kind == MSCONNECTOR_DECISION_KIND_LOG_ONLY && calls == 2);
  session->transaction = NULL;
}

static void verify_native_response_deny(traefik_engine_session *session,
                                       const traefik_engine_frame *result,
                                       int kind, int committed) {
  assert(result->payload[1] == TRAEFIK_ENGINE_PROTOCOL_RESULT_OK);
  assert(result->payload[2] == MSCONNECTOR_DECISION_KIND_DENY);
  assert(traefik_engine_read_u16(result->payload + 4U) == 403);
  assert(!session->failed && session->pending_result.pending_disruptive);
  assert(session->response_eos);
  assert(session->pending_decision.body_limit == (kind == 1));
  assert(session->pending_decision.http_status == 403);
  if (committed)
    acknowledge_native_response_rule(session);
}

static void run_native_response_case(msconnector_runtime *runtime,
                                     int committed, int kind) {
  int sockets[2];
  traefik_engine_service service = {0};
  traefik_engine_session session = {0};
  traefik_engine_frame frame = {0};
  traefik_engine_frame result = {0};
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  assert(pthread_mutex_init(&service.runtime_lock, NULL) == 0);
  service.runtime = runtime;
  session.service = &service;
  session.begun = 1;
  session.request_eos = 1;
  session.response_headers = 1;
  session.response_status = 200;
  session.response_headers_sent = committed > 0;
  session.response_body_started = committed > 1;
  native_response_kind = kind;
  native_result = 1;
  typed_decision = 0;
  test_error_code = MSCONNECTOR_ERROR_NONE;
  calls = 0;
  assert(traefik_engine_send_frame(sockets[0], TRAEFIK_ENGINE_PROTOCOL_RESPONSE_EOS,
                                   NULL, 0U) == 1);
  assert(traefik_engine_process_frame(&session, sockets[1], &frame) ==
         (kind == 2 || !committed));
  assert(traefik_engine_receive_frame(sockets[0], &result) == 1);
  assert(result.opcode == TRAEFIK_ENGINE_PROTOCOL_RESULT &&
         result.payload_size >= 14);
  if (kind == 1 && committed)
    verify_native_response_runtime_error(&session, &result);
  else
    verify_native_response_deny(&session, &result, kind, committed);
  traefik_engine_frame_reset(&frame);
  traefik_engine_frame_reset(&result);
  assert(close(sockets[0]) == 0 && close(sockets[1]) == 0);
  assert(pthread_mutex_destroy(&service.runtime_lock) == 0);
}

static void run_native_response_results(msconnector_runtime *runtime) {
  for (int committed = 0; committed < 3; ++committed)
    for (int kind = 1; kind <= 2; ++kind)
      run_native_response_case(runtime, committed, kind);
  native_response_kind = 0;
}

static void run_matrix(msconnector_runtime *runtime) {
  const unsigned char opcodes[] = {1, 2, 3, 4, 5, 6, 7, 8, 10};
  for (size_t i = 0; i < sizeof(opcodes); i++)
    for (int invalid = 0; invalid < 4; invalid++) {
      if (invalid == 2 && opcodes[i] != 1 && opcodes[i] != 3 &&
          opcodes[i] != 4 && opcodes[i] != 6)
        continue;
      run_dispatch_states(runtime, opcodes[i], invalid);
    }
  run_dispatch_states(runtime, 7, 4);
  run_framed_failure(runtime);
  run_native_response_results(runtime);
  puts("traefik_i10_dispatcher=pass failures=345 reentries=345 "
       "positive_controls=135");
}

int main(int argc, char **argv) {
  assert(argc == 4);
  for (int mode = 0; mode < 3; ++mode) {
    traefik_engine_service configured = {0};
    char error[256] = {0};
    const char *failure_stage = NULL;
    int configured_ok = traefik_engine_configure_service_runtime(
        &configured, argv[mode + 1], error, sizeof(error), &failure_stage);
    if (mode == 2) {
      assert(configured_ok == 0); /* Strict remains unsupported. */
    } else {
      assert(configured_ok == 1);
      assert(msconnector_runtime_phase4_mode(configured.runtime) ==
             (mode == 0 ? MSCONNECTOR_PHASE4_MODE_OFF
                        : MSCONNECTOR_PHASE4_MODE_SAFE));
      run_matrix(configured.runtime);
    }
    msconnector_runtime_destroy(&configured.runtime);
  }
  return 0;
}
