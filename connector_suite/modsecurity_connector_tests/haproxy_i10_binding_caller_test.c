#include "PRODUCT_BINDING"
#include <assert.h>
#include <stdio.h>
extern const char *native_failure;
extern int native_failure_result;
extern unsigned int native_calls;
extern unsigned int native_cleanups;
extern int native_intervention;
static haproxy_modsecurity_engine engine;
static haproxy_modsecurity_header headers[] = {{"Host", "example.test"}};
static haproxy_modsecurity_header response_headers[] = {
    {"Content-Type", "text/plain"}};
static haproxy_modsecurity_request request;
static haproxy_modsecurity_response response;
static haproxy_modsecurity_transaction *start(int companion, int mode) {
  haproxy_modsecurity_transaction *t = NULL;
  haproxy_modsecurity_decision d;
  memset(&engine, 0, sizeof(engine));
  msconnector_config_init(&engine.common_config);
  msconnector_config_apply_defaults(&engine.common_config);
  engine.common_config.phase4_mode = mode;
  engine.modsec = (ModSecurity *)&engine;
  engine.rules = (RulesSet *)&engine;
  memset(&request, 0, sizeof(request));
  request.method = "GET";
  request.http_version = "1.1";
  request.uri = "/";
  request.client_ip = "192.0.2.1";
  request.client_port = 1234;
  request.server_ip = "198.51.100.1";
  request.server_port = 443;
  request.request_id = "i10-binding";
  request.headers = headers;
  request.header_count = 1;
  memset(&response, 0, sizeof(response));
  response.status = 200;
  response.protocol = "HTTP/1.1";
  response.headers = response_headers;
  response.header_count = 1;
  native_failure = NULL;
  native_failure_result = 0;
  native_intervention = 0;
  assert(haproxy_modsecurity_transaction_begin_request_with_profile(
             &engine, &request, companion ? "haproxy-spoe-spop" : "haproxy-htx",
             &d, &t) == 0);
  assert(t && haproxy_modsecurity_transaction_finish_request_body(t, &d) == 0);
  if (companion) {
    assert(haproxy_modsecurity_transaction_handoff_response_companion(t) == 0);
    assert(haproxy_modsecurity_transaction_claim_response_companion(t) == 0);
  }
  return t;
}
static void check_header_failure(int mode, int companion) {
  haproxy_modsecurity_decision d;
  haproxy_modsecurity_transaction *t = start(companion, mode);
  native_failure = "msc_add_response_header";
  native_failure_result = -1;
  assert(haproxy_modsecurity_transaction_process_response_headers(t, &response,
                                                                  &d) != 0);
  assert(msconnector_transaction_contract_is_terminal(&t->contract));
  assert(t->contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE);
  unsigned int before = native_calls;
  assert(haproxy_modsecurity_transaction_process_response_headers(t, &response,
                                                                  &d) != 0);
  assert(native_calls == before);
  haproxy_modsecurity_transaction_abort(t);
}
static void check_terminal(int mode, int companion, int commitment,
                           msconnector_transaction_error_class error) {
  haproxy_modsecurity_decision d;
  haproxy_modsecurity_transaction *t = start(companion, mode);
  assert(haproxy_modsecurity_transaction_process_response_headers(t, &response,
                                                                  &d) == 0);
  assert(haproxy_modsecurity_transaction_set_response_commit_state(
             t, commitment != 0, commitment == 2) == 0);
  assert(t->contract.response_committed == (commitment != 0));
  assert(msconnector_transaction_contract_fail(&t->contract, error, 0) ==
         MSCONNECTOR_TRANSACTION_TRANSITION_OK);
  unsigned int before = native_calls;
  assert(haproxy_modsecurity_transaction_append_response_body_chunk(
             t, (const unsigned char *)"x", 1, &d) != 0);
  assert(haproxy_modsecurity_transaction_finish_response_body(t, &d) != 0);
  assert(haproxy_modsecurity_transaction_append_request_body_chunk(
             t, (const unsigned char *)"x", 1, &d) != 0);
  assert(native_calls == before);
  assert(t->contract.error_class == error);
  assert(haproxy_modsecurity_transaction_error_class(t) == error);
  if (companion) {
    assert(haproxy_modsecurity_transaction_record_response_companion_outcome(
               t, MSCONNECTOR_DECISION_ACTION_ALLOW, "complete", 200, 0) != 0);
    assert(t->response_companion.response_companion_transport_result[0] == '\0');
    assert(t->contract.error_class == error);
  }
  assert(msconnector_transaction_contract_fail(
             &t->contract, MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR, 0) != 123);
  assert(t->contract.error_class == error);
  assert(haproxy_modsecurity_transaction_error_class(t) == error);
  unsigned int cleanups = native_cleanups;
  haproxy_modsecurity_transaction_abort(t);
  assert(native_cleanups == cleanups + 1);
}
static void check_eos_failure(int mode, int companion) {
  haproxy_modsecurity_decision d;
  haproxy_modsecurity_transaction *t = start(companion, mode);
  assert(haproxy_modsecurity_transaction_process_response_headers(t, &response,
                                                                  &d) == 0);
  assert(haproxy_modsecurity_transaction_set_response_commit_state(t, 1, 0) ==
         0);
  native_failure = "msc_process_response_body";
  native_failure_result = 0;
  assert(haproxy_modsecurity_transaction_finish_response_body(t, &d) != 0);
  assert(t->contract.error_class ==
         MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE);
  unsigned int before = native_calls;
  assert(haproxy_modsecurity_transaction_finish_response_body(t, &d) != 0);
  assert(native_calls == before);
  haproxy_modsecurity_transaction_abort(t);
}
static void check_route(int mode, int companion) {
  const msconnector_transaction_error_class errors[] = {
      MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE,
      MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR,
      MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL,
      MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT,
      MSCONNECTOR_TRANSACTION_ERROR_ENGINE_UNAVAILABLE,
      MSCONNECTOR_TRANSACTION_ERROR_CLIENT_CANCEL,
      MSCONNECTOR_TRANSACTION_ERROR_UPSTREAM_DISCONNECT};
  check_header_failure(mode, companion);
  for (int commitment = 0; commitment < 3; commitment++) {
    for (size_t error = 0; error < 7; error++)
      check_terminal(mode, companion, commitment, errors[error]);
  }
  check_eos_failure(mode, companion);
}
static void check_companion_native_outcome(int phase, int body_limit, int logging_failure) {
  haproxy_modsecurity_decision d;
  haproxy_modsecurity_transaction *t = start(1, MSCONNECTOR_PHASE4_MODE_SAFE);
  if (phase == 4) {
    assert(haproxy_modsecurity_transaction_process_response_headers(t, &response, &d) == 0);
    assert(haproxy_modsecurity_transaction_set_response_commit_state(t, 1, 1) == 0);
    assert(haproxy_modsecurity_transaction_append_response_body_chunk(
               t, (const unsigned char *)"x", 1, &d) == 0);
  }
  native_intervention = body_limit ? 2 : 1;
  assert((phase == 3 ?
      haproxy_modsecurity_transaction_process_response_headers(t, &response, &d) :
      haproxy_modsecurity_transaction_finish_response_body(t, &d)) == 0);
  assert(d.disruptive && d.rule_id == (body_limit ? 0 : 123));
  assert(d.body_limit == body_limit);
  assert(t->contract.status == MSCONNECTOR_TRANSACTION_STATUS_TERMINAL);
  const msconnector_transaction_error_class expected_error = body_limit ?
      MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT : MSCONNECTOR_TRANSACTION_ERROR_NONE;
  assert(t->contract.error_class == expected_error);
  const msconnector_decision_action actual = phase == 3 ?
      MSCONNECTOR_DECISION_ACTION_DENY : MSCONNECTOR_DECISION_ACTION_LOG_ONLY;
  const msconnector_decision_action engine_action = t->contract.action;
  const unsigned int before = native_calls;
  assert(haproxy_modsecurity_transaction_record_response_companion_outcome(
             t, actual, NULL, 200, 0) != 0);
  assert(haproxy_modsecurity_transaction_record_response_companion_outcome(
             t, actual, "complete", 1000, 0) != 0);
  assert(t->response_companion.response_companion_transport_result[0] == '\0');
  assert(haproxy_modsecurity_transaction_record_response_companion_outcome(
             t, actual, "complete", phase == 3 ? 403 : 200, 0) == 0);
  assert(native_calls == before);
  assert(t->contract.error_class == expected_error);
  assert(t->contract.action == engine_action);
  assert(t->response_companion.response_companion_action == actual);
  assert(t->response_companion.response_companion_visible_status == (phase == 3 ? 403 : 200));
  assert(strcmp(t->response_companion.response_companion_transport_result, "complete") == 0);
  native_intervention = 0;
  if (logging_failure) {
    native_failure = "msc_process_logging";
    native_failure_result = 0;
  }
  const unsigned int cleanups = native_cleanups;
  assert(haproxy_modsecurity_transaction_finish_with_decision(t, &d) == logging_failure);
  if (logging_failure) {
    assert(d.error_class == MSCONNECTOR_TRANSACTION_ERROR_BODY_LIMIT);
  }
  assert(native_cleanups == cleanups + 1);
}
int main(int argc, char **argv) {
  if (argc == 2) {
    const int logging_failure = strcmp(argv[1], "body-limit-logging-failure") == 0;
    const int body_limit = logging_failure || strcmp(argv[1], "body-limit") == 0;
    assert(body_limit || strcmp(argv[1], "3") == 0 || strcmp(argv[1], "4") == 0);
    check_companion_native_outcome(body_limit ? 4 : atoi(argv[1]), body_limit, logging_failure);
    return 0;
  }
  check_companion_native_outcome(3, 0, 0);
  check_companion_native_outcome(4, 0, 0);
  check_companion_native_outcome(4, 1, 0);
  check_companion_native_outcome(4, 1, 1);
  const int modes[] = {MSCONNECTOR_PHASE4_MODE_OFF,
                       MSCONNECTOR_PHASE4_MODE_SAFE,
                       MSCONNECTOR_PHASE4_MODE_STRICT};
  for (size_t mode = 0; mode < 3; mode++) {
    for (int companion = 0; companion < 2; companion++)
      check_route(modes[mode], companion);
  }
  puts("real HAProxy binding/Common: 7 causes x 2 routes x 3 config modes x 3 "
       "commitment states + terminal phases and cleanup");
  return 0;
}
