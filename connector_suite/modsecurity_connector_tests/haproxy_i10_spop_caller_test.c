#define _GNU_SOURCE
#define main haproxy_spop_program_main
#include "PRODUCT_RUNTIME"
#undef main
#include <assert.h>
extern const char *native_failure;
extern int native_failure_result;
extern unsigned int native_calls;
extern unsigned int native_cleanups;
extern int native_intervention;
/* Semantic regression: this production caller must finish a finite request
 * authorization without inventing response phases. The HTTP version check
 * observes the native API boundary independently of the ACK decision. */
extern char native_http_version[16];
static void check_request_authorization(agent_state *state, int version_only) {
  notify_request request = {0};
  runtime_header headers[] = {{"Host", "example.test"}, {"Content-Length", "0"}};
  copy_cstring(request.client_ip, sizeof(request.client_ip), "192.0.2.1");
  copy_cstring(request.server_ip, sizeof(request.server_ip), "198.51.100.1");
  copy_cstring(request.method, sizeof(request.method), "GET");
  copy_cstring(request.uri, sizeof(request.uri), "/");
  copy_cstring(request.request_id, sizeof(request.request_id), "request-authorization");
  request.client_port = 1234; request.server_port = 443;
  request.has_client_ip = 1;
  request.has_server_ip = 1;
  request.has_client_port = 1;
  request.has_server_port = 1;
  request.headers = headers; request.header_count = 2;
  request.has_body = 1;
  request.has_body_len_arg = 1;
  request.has_headers_text = 1;
  request.http_metadata.has_http_version = 1;
  copy_cstring(request.http_metadata.http_version,
      sizeof(request.http_metadata.http_version), version_only ? "2.0" : "1.1");
  haproxy_modsecurity_decision decision;
  int processed = 0;
  spop_ack_decision_origin origin = SPOP_ACK_FAILURE_DECISION;
  const char *text = "pass";
  char handle[HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_STORAGE] = {0};
  unsigned int before = native_cleanups;
  native_failure = NULL;
  process_production_request_notify(state, &request, &decision, &processed,
      &origin, &text, handle);
  if (version_only) {
    assert(strcmp(native_http_version, "2.0") == 0);
  } else {
    assert(processed == 1 && origin == SPOP_ACK_ENGINE_DECISION);
    assert(!decision.disruptive && decision.status == 200);
    assert(native_cleanups == before + 1);
    assert(handle[0] == '\0');
  }
}
static void check_version_admission(agent_state *state) {
  runtime_header headers[] = {{"Host", "example.test"}, {"Content-Length", "0"}};
  const char *versions[] = {NULL, "0.9", "3.0", "9.9"};
  for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); ++i) {
    notify_request r = {0};
    r.has_client_ip = 1;
    r.has_server_ip = 1;
    r.has_client_port = 1;
    r.has_server_port = 1;
    r.client_port = 1234; r.server_port = 443;
    strcpy(r.client_ip, "192.0.2.1"); strcpy(r.server_ip, "198.51.100.1");
    strcpy(r.method, "GET"); strcpy(r.uri, "/"); strcpy(r.request_id, "version-reject");
    r.headers = headers; r.header_count = 2;
    r.has_body = 1;
    r.has_body_len_arg = 1;
    r.has_headers_text = 1;
    if (versions[i]) { r.http_metadata.has_http_version = 1; strcpy(r.http_metadata.http_version, versions[i]); }
    haproxy_modsecurity_decision d;
    int processed = 0;
    spop_ack_decision_origin origin = SPOP_ACK_FAILURE_DECISION;
    const char *text = "pass";
    char handle[HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_STORAGE] = {0};
    unsigned int calls = native_calls;
    unsigned int cleanups = native_cleanups;
    process_production_request_notify(state, &r, &d, &processed, &origin, &text, handle);
    assert(d.disruptive && d.status == 503 && processed == 0);
    assert(origin == SPOP_ACK_FAILURE_DECISION);
    assert(native_calls == calls && native_cleanups == cleanups);
    haproxy_modsecurity_request mapped;
    haproxy_modsecurity_transaction *tx = NULL;
    build_modsecurity_request_from_notify(&r, NULL, &mapped);
    assert(haproxy_modsecurity_transaction_begin_request_authorization(
        state->engine, &mapped, &d, &tx) != 0);
    assert(tx == NULL && native_calls == calls && native_cleanups == cleanups);
  }
  /* Two declared versions are contradictory even when one is otherwise valid.
   * Reject identical duplicates too; no last-value-wins normalization. */
  for (int conflict = 0; conflict < 2; ++conflict) {
    spop_buffer frame = {0};
    notify_request r = {0};
    size_t pos = 0;
    assert(append_string(&frame, "http_version") == 0);
    assert(append_typed_string(&frame, "1.1") == 0);
    assert(append_string(&frame, "http_version") == 0);
    assert(append_typed_string(&frame, conflict ? "2.0" : "1.1") == 0);
    assert(parse_notify_arguments(frame.data, frame.len, &pos, &r, 2U) != 0);
    free_notify_request(&r);
  }
}
static void check_request_failure(agent_state *state, size_t failure,
                                  const char *failure_name) {
  haproxy_modsecurity_decision d;
  notify_request request;
  memset(&request, 0, sizeof(request));
  copy_cstring(request.client_ip, sizeof(request.client_ip), "192.0.2.1");
  copy_cstring(request.server_ip, sizeof(request.server_ip), "198.51.100.1");
  copy_cstring(request.method, sizeof(request.method), "POST");
  copy_cstring(request.uri, sizeof(request.uri), "/");
  copy_cstring(request.request_id, sizeof(request.request_id),
               "i10-spop-request");
  request.client_port = 1234;
  request.server_port = 443;
  request.has_client_ip = 1;
  request.has_server_ip = 1;
  request.has_client_port = 1;
  request.has_server_port = 1;
  runtime_header headers[] = {{"Host", "example.test"}, {"Content-Length", "1"}};
  request.headers = headers;
  request.header_count = 2;
  request.has_body = 1;
  request.has_body_len_arg = 1;
  request.has_headers_text = 1;
  request.http_metadata.advertised_body_len = 1;
  request.http_metadata.has_http_version = 1;
  strcpy(request.http_metadata.http_version, "1.1");
  unsigned char body[] = "x";
  request.body = body;
  request.body_len = 1;
  int processed = 0;
  spop_ack_decision_origin origin = SPOP_ACK_FAILURE_DECISION;
  const char *text = "pass";
  char handle[HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_STORAGE] = {0};
  native_failure = failure_name;
  native_failure_result = failure == 2 ? -1 : 0;
  unsigned int cleanup_before = native_cleanups;
  process_production_request_notify(state, &request, &d, &processed, &origin,
                                    &text, handle);
  assert(d.disruptive && d.status == 503 && strcmp(d.action, "deny") == 0);
  assert(d.rule_id == 0 && d.redirect_url[0] == '\0' &&
         d.log_message[0] != '\0');
  assert(origin == SPOP_ACK_FAILURE_DECISION &&
         strcmp(text, "fail-closed") == 0);
  assert(native_cleanups == cleanup_before + 1);
  spop_buffer payload = {0};
  assert(build_decision_ack_payload(
             &payload, &d, safe_decision_reason_code(&d, processed, text),
             production_ack_enforces(&state->config, origin), NULL) == 0);
  assert(payload_has_set_var_blocked_true(&payload));
}
static void check_missing_companion(agent_state *state) {
  haproxy_modsecurity_decision d;
  native_failure = NULL;
  /* Missing companion completion is a real rejected Common finish,
   * never a successful request-only terminal acknowledgement. */
  haproxy_modsecurity_request terminal_request = {0};
  haproxy_modsecurity_header terminal_headers[] = {{"Host", "example.test"}};
  terminal_request.method = "GET";
  terminal_request.http_version = "1.1";
  terminal_request.uri = "/";
  terminal_request.client_ip = "192.0.2.1";
  terminal_request.server_ip = "198.51.100.1";
  terminal_request.client_port = 1234;
  terminal_request.server_port = 443;
  terminal_request.request_id = "i10-missing-companion";
  terminal_request.headers = terminal_headers;
  terminal_request.header_count = 1;
  haproxy_modsecurity_transaction *unfinished = NULL;
  assert(haproxy_modsecurity_transaction_begin(state->engine, &terminal_request,
                                               &d, &unfinished) == 0);
  spop_ack_decision_origin terminal_origin = SPOP_ACK_ENGINE_DECISION;
  const char *terminal_text = "pass";
  notify_request unused_request = {0};
  finish_or_store_request_transaction(state, &unused_request, unfinished, &d,
                                      &terminal_origin, &terminal_text);
  assert(terminal_origin == SPOP_ACK_FAILURE_DECISION && d.disruptive &&
         d.status == 503);
}
static void check_owner_failure(agent_state *state, int operation) {
  haproxy_modsecurity_decision d;
  haproxy_modsecurity_request r = {0};
  haproxy_modsecurity_header h[] = {{"Host", "example.test"}};
  r.method = "GET";
  r.http_version = "1.1";
  r.uri = "/";
  r.client_ip = "192.0.2.1";
  r.server_ip = "198.51.100.1";
  r.client_port = 1234;
  r.server_port = 443;
  r.request_id = "i10-spop-companion";
  r.headers = h;
  r.header_count = 1;
  haproxy_modsecurity_transaction *t = NULL;
  native_failure = NULL;
  assert(haproxy_modsecurity_transaction_begin(state->engine, &r, &d, &t) == 0);
  assert(haproxy_modsecurity_transaction_handoff_response_companion(t) == 0);
  assert(haproxy_modsecurity_transaction_claim_response_companion(t) == 0);
  spop_bridge_task_context context = {0};
  context.state = state;
  context.transaction = t;
  context.command.decision_storage = &context.decision_storage;
  msconnector_response response = {0};
  response.status = 200;
  msconnector_header bridge_headers[] = {{.name = "Content-Type",
                                          .name_size = 12,
                                          .value = "text/plain",
                                          .value_size = 10}};
  response.http_version = "HTTP/1.1";
  context.command.response = &response;
  if (operation == 0 || operation == 5) {
    context.command.operation =
        HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_HEADERS;
    response.headers = bridge_headers;
    response.header_count = 1;
    native_failure = operation == 5 ? "msc_add_response_header"
                                    : "msc_process_response_headers";
    native_failure_result = operation == 5 ? -1 : 0;
    assert(prepare_spop_bridge_headers(&context, &context.command,
                                       &context.error) == 0);
  } else {
    haproxy_modsecurity_response native_response = {0};
    native_response.status = 200;
    native_response.protocol = "HTTP/1.1";
    assert(haproxy_modsecurity_transaction_process_response_headers(
               t, &native_response, &d) == 0);
    switch (operation) {
    case 1:
      context.command.operation = HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_BODY;
      context.command.body = (const unsigned char *)"x";
      context.command.body_size = 1;
      native_failure = "msc_append_response_body";
      native_failure_result = 2;
      break;
    case 2:
      context.command.operation = HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_EOS;
      native_failure = "msc_process_response_body";
      native_failure_result = 0;
      break;
    case 3:
      context.command.operation = HAPROXY_SPOP_RESPONSE_COMPANION_COMMIT;
      context.command.headers_sent = 0;
      context.command.body_started = 1;
      break;
    default:
      context.command.operation = HAPROXY_SPOP_RESPONSE_COMPANION_RELEASE;
    }
  }
  run_spop_bridge_task(&context);
  assert(context.success == 0 && context.error.code != MSCONNECTOR_ERROR_NONE);
  if (operation < 3)
    assert(context.error.code == MSCONNECTOR_ERROR_MODSECURITY_FAILURE);
  if (operation == 5)
    assert(context.error.code == MSCONNECTOR_ERROR_MODSECURITY_FAILURE);
  if (operation == 4)
    assert(context.transaction_consumed == 1);
  else
    haproxy_modsecurity_transaction_abort(t);
}
static ssize_t fail_outcome_event(void *opaque, const char *data, size_t size) {
  (void)opaque; (void)data; (void)size; errno = EIO; return -1;
}
static void set_owner_outcome_action(spop_bridge_task_context *context,
                                     int phase, int fault, int strict) {
  if (fault >= 2) {
    context->command.action = MSCONNECTOR_DECISION_ACTION_ALLOW;
    context->command.visible_http_status = 200;
    context->command.transport_result = "allowed";
  } else if (phase == 3) {
    context->command.action = MSCONNECTOR_DECISION_ACTION_DENY;
    context->command.visible_http_status = 403;
    context->command.transport_result = "denied";
  } else {
    context->command.action = MSCONNECTOR_DECISION_ACTION_LOG_ONLY;
    context->command.visible_http_status = 200;
    context->command.transport_result = "log_only";
  }
  if (strict && phase == 4 && fault < 2) {
    context->command.action = MSCONNECTOR_DECISION_ACTION_ABORT_CONNECTION;
    context->command.transport_result = "connection_aborted";
    context->command.connection_aborted = 1;
  }
}
static void check_owner_outcome_replay_guards(haproxy_modsecurity_transaction *tx,
                                            const msconnector_decision *requested,
                                            const spop_bridge_task_context *context,
                                            int phase) {
  msconnector_error error;
  msconnector_event event;
  msconnector_error_init(&error);
  assert(haproxy_modsecurity_transaction_response_event(tx, requested, &event, &error) == 1);
  assert(event.flags.late_intervention_mode == NULL);
  msconnector_decision forged_allow;
  msconnector_decision_set_allow(&forged_allow);
  forged_allow.phase = requested->phase;
  msconnector_error_init(&error);
  assert(!haproxy_modsecurity_transaction_response_event(tx, &forged_allow, &event, &error));
  assert(haproxy_modsecurity_transaction_record_response_companion_outcome(tx,
      context->command.action, "stale-replay", 200, 0) != 0);
  msconnector_decision wrong = *requested;
  wrong.disruptive = 0;
  wrong.intervention.disruptive = 0;
  msconnector_error_init(&error);
  assert(!haproxy_modsecurity_transaction_response_event(tx, &wrong, &event, &error));
  wrong = *requested;
  wrong.http_status = 401;
  msconnector_error_init(&error);
  assert(!haproxy_modsecurity_transaction_response_event(tx, &wrong, &event, &error));
  wrong = *requested; wrong.kind = MSCONNECTOR_DECISION_KIND_REDIRECT;
  msconnector_error_init(&error);
  assert(!haproxy_modsecurity_transaction_response_event(tx, &wrong, &event, &error));
  wrong = *requested; wrong.rule_id = "999999";
  msconnector_error_init(&error);
  assert(!haproxy_modsecurity_transaction_response_event(tx, &wrong, &event, &error));
  wrong = *requested; wrong.phase = phase == 3 ? MSCONNECTOR_PHASE_RESPONSE_BODY : MSCONNECTOR_PHASE_RESPONSE_HEADERS;
  msconnector_error_init(&error);
  assert(!haproxy_modsecurity_transaction_response_event(tx, &wrong, &event, &error));
}
static void check_owner_outcome_line(agent_state *state, int phase, int strict) {
  const char *expected_action = "\"actual_action\":\"log_only\"";
  if (phase == 3) {
    expected_action = "\"actual_action\":\"deny\"";
  } else if (strict) {
    expected_action = "\"actual_action\":\"abort_connection\"";
  }
  assert(ftell(state->decision_log) > 0);
  rewind(state->decision_log); char line[8192];
  assert(fgets(line, sizeof(line), state->decision_log) != NULL);
  assert(strstr(line, "native-owner-event") != NULL);
  assert(strstr(line, "\"rule_id\":\"123\"") != NULL);
  assert(strstr(line, "SECRET-INPUT-NATIVE-LOG") == NULL);
  assert(strstr(line, "\"http_status\":403") != NULL);
  assert(strstr(line, phase == 3 ? "\"visible_http_status\":403" : "\"visible_http_status\":200") != NULL);
  assert(strstr(line, strict && phase == 4 ? "\"connection_aborted\":true" : "\"connection_aborted\":false") != NULL);
  assert(strstr(line, expected_action) != NULL);
}
static void finish_owner_outcome(agent_state *state,
                                 haproxy_modsecurity_transaction *tx,
                                 spop_bridge_task_context *context,
                                 int phase, int fault, int strict) {
  if (fault == 1 || fault == 3) {
    assert(!context->success && context->error.code == MSCONNECTOR_ERROR_IO);
    assert(state->decision_log_error.code == MSCONNECTOR_ERROR_IO);
    haproxy_modsecurity_transaction_abort(tx);
  } else {
    if (!context->success) fprintf(stderr, "OUTCOME failed phase=%d fixture=%d error=%d %s\n",
        phase, fault, context->error.code, context->error.message ? context->error.message : "");
    assert(context->success);
    assert(fflush(state->decision_log) == 0);
    if (fault >= 2) {
      assert(ftell(state->decision_log) == 0);
    } else {
      check_owner_outcome_line(state, phase, strict);
    }
    if (fault >= 2 && phase == 3) {
      /* P3 Allow has no P4/EOS: do not fabricate a successful full finish. */
      haproxy_modsecurity_transaction_abort(tx);
    } else {
      context->command.operation = HAPROXY_SPOP_RESPONSE_COMPANION_RELEASE;
      run_spop_bridge_task(context);
      assert(context->success && context->transaction_consumed);
    }
  }
}
static void check_owner_outcome_event(agent_state *state, int phase, int fault, int strict) {
  haproxy_modsecurity_request r = {0};
  haproxy_modsecurity_header h[] = {{"Host", "example.test"}};
  r.method = "GET"; r.uri = "/"; r.http_version = "1.1";
  r.client_ip = "192.0.2.1"; r.server_ip = "198.51.100.1";
  r.client_port = 1234; r.server_port = 443;
  r.headers = h; r.header_count = 1; r.request_id = "native-owner-event";
  haproxy_modsecurity_transaction *tx = NULL;
  haproxy_modsecurity_decision d;
  native_failure = NULL; native_intervention = 0;
  assert(haproxy_modsecurity_transaction_begin(state->engine, &r, &d, &tx) == 0);
  assert(haproxy_modsecurity_transaction_handoff_response_companion(tx) == 0);
  assert(haproxy_modsecurity_transaction_claim_response_companion(tx) == 0);
  haproxy_modsecurity_response response = {0};
  response.status = 200; response.protocol = "HTTP/1.1";
  native_intervention = phase == 3 && fault < 2;
  assert(haproxy_modsecurity_transaction_process_response_headers(tx, &response, &d) == 0);
  if (phase == 4) {
    assert(haproxy_modsecurity_transaction_set_response_commit_state(tx, 1, 0) == 0);
    native_intervention = fault < 2;
    assert(haproxy_modsecurity_transaction_finish_response_body(tx, &d) == 0);
  }
  assert(fault >= 2 ? !d.disruptive : (d.disruptive && d.rule_id == 123));
  native_intervention = 0;
  msconnector_decision requested;
  char borrowed_reason[] = "SECRET-INPUT-NATIVE-LOG";
  msconnector_decision_set_deny(&requested, 403, NULL, borrowed_reason);
  /* Common retains equal fields in distinct owned buffers. */
  char borrowed_intervention_log[] = "SECRET-INPUT-NATIVE-LOG";
  requested.intervention.log_message = borrowed_intervention_log;
  if (fault >= 2) msconnector_decision_set_allow(&requested);
  requested.phase = phase == 3 ? MSCONNECTOR_PHASE_RESPONSE_HEADERS : MSCONNECTOR_PHASE_RESPONSE_BODY;
  msconnector_event event;
  msconnector_error error;
  msconnector_error_init(&error);
  assert(!haproxy_modsecurity_transaction_response_event(tx, &requested, &event, &error));
  assert(error.code == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
  msconnector_error_init(&state->decision_log_error);
  copy_cstring(state->config.decision_log, sizeof(state->config.decision_log), "configured");
  if (fault == 1) {
    cookie_io_functions_t ops = {.write = fail_outcome_event};
    state->decision_log = fopencookie(NULL, "w", ops);
    assert(state->decision_log != NULL);
    assert(setvbuf(state->decision_log, NULL, _IONBF, 0) == 0);
  } else {
    state->decision_log = fopen("native-owner-event.jsonl", "w+");
    assert(state->decision_log != NULL && ftell(state->decision_log) == 0);
  }
  spop_bridge_task_context context = {0};
  context.state = state; context.transaction = tx;
  context.command.operation = HAPROXY_SPOP_RESPONSE_COMPANION_OUTCOME;
  context.command.decision = &requested;
  set_owner_outcome_action(&context, phase, fault, strict);
  haproxy_spop_response_companion_owner_command borrowed = context.command;
  borrowed.lease = 1U;
  msconnector_error_init(&error);
  assert(prepare_spop_bridge_context(&context, &borrowed, &error) == 0);
  assert(context.command.decision == &context.outcome_decision);
  memset(borrowed_reason, 'X', sizeof(borrowed_reason) - 1U);
  memset(borrowed_intervention_log, 'X', sizeof(borrowed_intervention_log) - 1U);
  if (fault < 2) {
    assert(context.command.decision->reason != NULL);
    assert(strcmp(context.command.decision->reason, "SECRET-INPUT-NATIVE-LOG") == 0);
  }
  if (fault == 3) msconnector_error_set(&state->decision_log_error,
      MSCONNECTOR_ERROR_IO, "earlier sink failure", "test");
  unsigned int before = native_cleanups;
  run_spop_bridge_task(&context);
  if (!fault) { check_owner_outcome_replay_guards(tx, &requested, &context, phase); }
  finish_owner_outcome(state, tx, &context, phase, fault, strict);
  assert(native_cleanups == before + 1);
  (void)fclose(state->decision_log); state->decision_log = NULL;
  state->config.decision_log[0] = '\0';
  msconnector_error_init(&state->decision_log_error);
}
static void check_owner_outcome_modes(agent_state *state) {
  for (int phase = 3; phase <= 4; ++phase) {
    for (int fault = 0; fault <= 3; ++fault) {
      check_owner_outcome_event(state, phase, fault, 0);
      if (phase == 4) { check_owner_outcome_event(state, phase, fault, 1); }
    }
  }
}
static void check_mode(const char *mode, const char *fail_mode, int enforces, const char *only) {
  agent_state state;
  memset(&state, 0, sizeof(state));
  copy_cstring(state.config.mode, sizeof(state.config.mode), mode);
  copy_cstring(state.config.fail_mode, sizeof(state.config.fail_mode),
               fail_mode);
  assert(pthread_mutex_init(&state.decision_log_lock, NULL) == 0);
  state.decision_log_lock_initialized = 1;
  haproxy_modsecurity_engine_config cfg;
  memset(&cfg, 0, sizeof(cfg));
  msconnector_config_init(&cfg.common_config);
  msconnector_config_apply_defaults(&cfg.common_config);
  cfg.rules_file = "PRODUCT_RULES";
  if (only && strcmp(only, "owner-events") == 0)
    cfg.common_config.phase4_mode = MSCONNECTOR_PHASE4_MODE_STRICT;
  haproxy_modsecurity_decision d;
  assert(haproxy_modsecurity_engine_create(&cfg, &state.engine, &d) == 0);
  if (only != NULL) {
    if (strcmp(only, "owner-events") == 0) {
      check_owner_outcome_modes(&state);
    } else if (strcmp(only, "invalid-version") == 0) check_version_admission(&state);
    else check_request_authorization(&state, strcmp(only, "http-version") == 0);
    haproxy_modsecurity_engine_destroy(state.engine);
    return;
  }
  const char *failures[] = {
      "msc_process_connection", "msc_process_request_headers",
      "msc_append_request_body", "msc_process_request_body", "msc_process_logging"};
  for (size_t failure = 0; failure < 5; failure++)
    check_request_failure(&state, failure, failures[failure]);
  check_missing_companion(&state);
  for (int operation = 0; operation < 6; operation++)
    check_owner_failure(&state, operation);
  native_failure = NULL;
  /* Engine rule observer mode still differs; failure origin always enforces. */
  assert(production_ack_enforces(&state.config, SPOP_ACK_FAILURE_DECISION));
  assert(production_ack_enforces(&state.config, SPOP_ACK_ENGINE_DECISION) ==
         enforces);
  haproxy_modsecurity_engine_destroy(state.engine);
}
static void check_bridge_native_decisions(void) {
  const int phases[] = {3, 4};
  const enum msconnector_phase expected_phases[] = {
      MSCONNECTOR_PHASE_RESPONSE_HEADERS, MSCONNECTOR_PHASE_RESPONSE_BODY};
  const char *actions[] = {"pass", "deny", "redirect"};
  const int expected_statuses[] = {200, 403, 302};
  const msconnector_decision_action expected_actions[] = {
      MSCONNECTOR_DECISION_ACTION_ALLOW, MSCONNECTOR_DECISION_ACTION_DENY,
      MSCONNECTOR_DECISION_ACTION_REDIRECT};
  for (size_t phase = 0; phase < 2; phase++) {
    for (size_t action = 0; action < 3; action++) {
      spop_bridge_task_context context = {0};
      haproxy_modsecurity_decision native = {0};
      context.command.decision_storage = &context.decision_storage;
      native.phase = phases[phase];
      native.disruptive = action != 0;
      native.status = expected_statuses[action];
      copy_cstring(native.action, sizeof(native.action), actions[action]);
      copy_cstring(native.redirect_url, sizeof(native.redirect_url),
                   "https://example.test/redirect");
      copy_cstring(native.log_message, sizeof(native.log_message), "native rule");
      assert(set_bridge_native_decision(&context, &native));
      assert(context.decision.phase == expected_phases[phase]);
      assert(msconnector_decision_action_from_decision(&context.decision) ==
             expected_actions[action]);
      assert(context.error.code == MSCONNECTOR_ERROR_NONE);
      if (action != 0) {
        assert(context.decision.http_status == native.status);
        assert(context.decision.reason != NULL);
        assert(strcmp(context.decision.reason, "native rule") == 0);
      }
      if (action == 2)
        assert(strcmp(context.decision.redirect_url,
                      "https://example.test/redirect") == 0);
    }
  }
}
int main(int argc, char **argv) {
  check_bridge_native_decisions();
  if (argc == 2 && strcmp(argv[1], "native-decisions") == 0)
    return 0;
  const char *modes[] = {"detect-only", "enforce"};
  const char *fail_modes[] = {"closed", "open"};
  for (size_t mode = 0; mode < 2; mode++) {
    for (size_t fail_mode = 0; fail_mode < 2; fail_mode++)
      check_mode(modes[mode], fail_modes[fail_mode], mode != 0, argc == 2 ? argv[1] : NULL);
  }
  puts("full SPOP request TU: P1/P2 native failure -> disruptive503 -> "
       "serialized blocked ACK; detect/enforce x open/closed; cleanup and "
       "stale fields");
  return 0;
}
