#include <assert.h>
#include <pthread.h>
#include <string.h>

#include "haproxy_spop_response_companion_backend.h"

static unsigned int abort_calls;

typedef struct fake_owner_blocking_control {
  int timeout_body;
  int fail_release;
  int block_a_claim;
  int a_started;
  int release_a;
  int block_a_body;
  int body_started;
  int release_body;
} fake_owner_blocking_control;

typedef struct fake_owner_claim_reuse_control {
  int simulate_claim_finalizer_reuse;
  int simulated_reuse_done;
  char simulated_reuse_handle[HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_STORAGE];
} fake_owner_claim_reuse_control;

typedef struct fake_owner_expiry_control {
  int simulate_expire_finalizer_before_return;
  int expire_finalizer_simulated;
} fake_owner_expiry_control;

typedef struct fake_owner_terminal_control {
  int simulate_terminal_finalizer_before_return;
  int terminal_finalizer_simulated;
  uint64_t terminal_expire_at_ms;
  int timeout_release;
  int simulate_terminal_timeout_finalizer_before_return;
  int terminal_timeout_finalizer_simulated;
  int terminal_timeout_finalizer_consumed;
  int defer_response_headers_finalizer;
  int simulate_stale_response_headers_finalizer_before_release_timeout;
  int stale_response_headers_finalizer_simulated;
  uint64_t stale_response_headers_lease;
} fake_owner_terminal_control;

typedef struct fake_owner_fail_reuse_control {
  int simulate_fail_finalizer_reuse;
  int fail_reuse_done;
  uint64_t fail_expire_at_ms;
  char fail_reuse_handle[HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_STORAGE];
} fake_owner_fail_reuse_control;

typedef struct fake_owner_control {
  fake_owner_blocking_control blocking;
  fake_owner_claim_reuse_control claim_reuse;
  fake_owner_expiry_control expiry;
  fake_owner_terminal_control terminal;
  fake_owner_fail_reuse_control fail_reuse;
} fake_owner_control;

void haproxy_modsecurity_transaction_abort(
    haproxy_modsecurity_transaction *const) {
  abort_calls++;
}

typedef struct fake_owner {
  unsigned int calls[HAPROXY_SPOP_RESPONSE_COMPANION_FAIL + 1];
  const unsigned char *expected_body;
  size_t expected_body_size;
  const msconnector_decision *expected_decision;
  haproxy_modsecurity_transaction *transaction_a;
  haproxy_modsecurity_transaction *transaction_b;
  pthread_mutex_t lock;
  pthread_cond_t changed;
  haproxy_spop_response_companion_backend *backend;
  fake_owner_control control;
} fake_owner;

static int dispatch_expire_finalizer(fake_owner *const owner,
                                     haproxy_modsecurity_transaction *const transaction,
                                     const haproxy_spop_response_companion_owner_command *const command,
                                     msconnector_error *const error) {
  if (!owner->control.expiry.simulate_expire_finalizer_before_return ||
      owner->control.expiry.expire_finalizer_simulated ||
      command->operation != HAPROXY_SPOP_RESPONSE_COMPANION_EXPIRE ||
      transaction != owner->transaction_a) {
    return 0;
  }
  owner->control.expiry.expire_finalizer_simulated = 1;
  assert(haproxy_spop_response_companion_backend_dispatch_finished(
             owner->backend, transaction, command->lease, command->operation,
             0) == 1);
  msconnector_error_set(error, MSCONNECTOR_ERROR_TIMEOUT,
                        "expiry owner timeout", "test");
  return 1;
}

static int dispatch_terminal_finalizer(
    fake_owner *const owner, haproxy_modsecurity_transaction *const transaction,
    const haproxy_spop_response_companion_owner_command *const command,
    int *const transaction_consumed) {
  int terminal_operation =
      command->operation == HAPROXY_SPOP_RESPONSE_COMPANION_RELEASE ||
      command->operation == HAPROXY_SPOP_RESPONSE_COMPANION_CANCEL ||
      command->operation == HAPROXY_SPOP_RESPONSE_COMPANION_FAIL;
  if (!owner->control.terminal.simulate_terminal_finalizer_before_return ||
      owner->control.terminal.terminal_finalizer_simulated || !terminal_operation ||
      transaction != owner->transaction_a) {
    return 0;
  }
  owner->control.terminal.terminal_finalizer_simulated = 1;
  assert(haproxy_spop_response_companion_backend_dispatch_finished(
             owner->backend, transaction, command->lease, command->operation,
             1) == 0);
  haproxy_spop_response_companion_backend_expire(
      owner->backend, owner->control.terminal.terminal_expire_at_ms);
  *transaction_consumed = 1;
  return 1;
}

static int dispatch_terminal_timeout(
    fake_owner *const owner, haproxy_modsecurity_transaction *const transaction,
    const haproxy_spop_response_companion_owner_command *const command,
    msconnector_error *const error) {
  if (!owner->control.terminal.simulate_terminal_timeout_finalizer_before_return ||
      owner->control.terminal.terminal_timeout_finalizer_simulated ||
      command->operation != HAPROXY_SPOP_RESPONSE_COMPANION_RELEASE ||
      transaction != owner->transaction_a) {
    return 0;
  }
  owner->control.terminal.terminal_timeout_finalizer_simulated = 1;
  assert(haproxy_spop_response_companion_backend_dispatch_finished(
             owner->backend, transaction, command->lease, command->operation,
             owner->control.terminal.terminal_timeout_finalizer_consumed) == 0);
  msconnector_error_set(error, MSCONNECTOR_ERROR_TIMEOUT,
                        "terminal owner timeout after finalizer", "test");
  return 1;
}

static int dispatch_stale_headers(
    fake_owner *const owner, haproxy_modsecurity_transaction *const transaction,
    const haproxy_spop_response_companion_owner_command *const command,
    msconnector_error *const error) {
  if (!owner->control.terminal.simulate_stale_response_headers_finalizer_before_release_timeout ||
      owner->control.terminal.stale_response_headers_finalizer_simulated ||
      command->operation != HAPROXY_SPOP_RESPONSE_COMPANION_RELEASE ||
      transaction != owner->transaction_a) {
    return 0;
  }
  owner->control.terminal.stale_response_headers_finalizer_simulated = 1;
  assert(owner->control.terminal.stale_response_headers_lease == command->lease);
  assert(haproxy_spop_response_companion_backend_dispatch_finished(
             owner->backend, transaction, owner->control.terminal.stale_response_headers_lease,
             HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_HEADERS, 0) == 0);
  msconnector_error_set(error, MSCONNECTOR_ERROR_TIMEOUT,
                        "terminal owner timeout after stale response finalizer",
                        "test");
  return 1;
}

static int dispatch_fail_reuse(
    fake_owner *const owner, haproxy_modsecurity_transaction *const transaction,
    const haproxy_spop_response_companion_owner_command *const command,
    msconnector_error *const error) {
  msconnector_error ignored;
  if (!owner->control.fail_reuse.simulate_fail_finalizer_reuse ||
      owner->control.fail_reuse.fail_reuse_done ||
      command->operation != HAPROXY_SPOP_RESPONSE_COMPANION_FAIL ||
      transaction != owner->transaction_a) {
    return 0;
  }
  owner->control.fail_reuse.fail_reuse_done = 1;
  msconnector_error_init(&ignored);
  haproxy_spop_response_companion_backend_expire(
      owner->backend, owner->control.fail_reuse.fail_expire_at_ms);
  assert(haproxy_spop_response_companion_backend_dispatch_finished(
             owner->backend, transaction, command->lease, command->operation,
             0) == 1);
  assert(haproxy_spop_response_companion_handoff(
      owner->backend, owner->transaction_a,
      owner->control.fail_reuse.fail_expire_at_ms + 1U,
      owner->control.fail_reuse.fail_reuse_handle, &ignored));
  msconnector_error_set(error, MSCONNECTOR_ERROR_PHASE_SEQUENCE,
                        "old fail returned after finalizer", "test");
  return 1;
}

static void dispatch_claim_reuse(fake_owner *const owner,
                                 haproxy_modsecurity_transaction *const transaction,
                                 const haproxy_spop_response_companion_owner_command *const command) {
  msconnector_error ignored;
  haproxy_modsecurity_transaction *replacement = owner->transaction_b;
  if (!owner->control.claim_reuse.simulate_claim_finalizer_reuse ||
      owner->control.claim_reuse.simulated_reuse_done ||
      command->operation != HAPROXY_SPOP_RESPONSE_COMPANION_CLAIM ||
      transaction != owner->transaction_a) {
    return;
  }
  owner->control.claim_reuse.simulated_reuse_done = 1;
  msconnector_error_init(&ignored);
  haproxy_spop_response_companion_backend_expire(owner->backend, 6101U);
  assert(haproxy_spop_response_companion_backend_dispatch_finished(
             owner->backend, transaction, command->lease, command->operation,
             0) == 1);
  assert(haproxy_spop_response_companion_handoff(
      owner->backend, replacement, 6200U,
      owner->control.claim_reuse.simulated_reuse_handle, &ignored));
  pthread_mutex_lock(&owner->backend->lock);
  owner->backend->slots[0].in_flight = 1;
  pthread_mutex_unlock(&owner->backend->lock);
}

static int is_response_operation(
    const haproxy_spop_response_companion_owner_operation operation) {
  return operation == HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_HEADERS ||
         operation == HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_BODY ||
         operation == HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_EOS;
}

static void assert_response_command(
    const haproxy_spop_response_companion_owner_command *const command) {
  if (is_response_operation(command->operation)) {
    assert(command->decision_storage != NULL);
  }
}

static void set_response_decision(
    const haproxy_spop_response_companion_owner_command *const command,
    msconnector_decision *const decision) {
  if (command->operation == HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_HEADERS) {
    memcpy(command->decision_storage->redirect_url, "/owner-redirect",
           sizeof("/owner-redirect"));
    memcpy(command->decision_storage->log_message, "owner-p3-decision",
           sizeof("owner-p3-decision"));
    msconnector_decision_set_redirect(
        decision, 302, command->decision_storage->redirect_url, NULL,
        command->decision_storage->log_message);
  }
  if (command->operation == HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_EOS) {
    memcpy(command->decision_storage->log_message, "owner-p4-decision",
           sizeof("owner-p4-decision"));
    msconnector_decision_set_deny(decision, 451, NULL,
                                  command->decision_storage->log_message);
  }
}

static void wait_for_blocking_callback(
    fake_owner *const owner,
    const haproxy_modsecurity_transaction *const transaction,
    const haproxy_spop_response_companion_owner_command *const command) {
  if (owner->control.blocking.block_a_claim && transaction == owner->transaction_a &&
      command->operation == HAPROXY_SPOP_RESPONSE_COMPANION_CLAIM) {
    pthread_mutex_lock(&owner->lock);
    owner->control.blocking.a_started = 1;
    pthread_cond_broadcast(&owner->changed);
    while (!owner->control.blocking.release_a) {
      pthread_cond_wait(&owner->changed, &owner->lock);
    }
    pthread_mutex_unlock(&owner->lock);
  }
  if (owner->control.blocking.block_a_body && transaction == owner->transaction_a &&
      command->operation == HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_BODY) {
    pthread_mutex_lock(&owner->lock);
    owner->control.blocking.body_started = 1;
    pthread_cond_broadcast(&owner->changed);
    while (!owner->control.blocking.release_body) {
      pthread_cond_wait(&owner->changed, &owner->lock);
    }
    pthread_mutex_unlock(&owner->lock);
  }
}

static int handle_callback_error(
    const fake_owner *const owner,
    const haproxy_spop_response_companion_owner_command *const command,
    msconnector_error *const error, int *const transaction_consumed) {
  if (command->operation == HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_BODY &&
      owner->control.blocking.timeout_body) {
    msconnector_error_set(error, MSCONNECTOR_ERROR_TIMEOUT,
                          "owner callback timeout", "test");
    return 1;
  }
  if (command->operation == HAPROXY_SPOP_RESPONSE_COMPANION_RELEASE &&
      owner->control.terminal.timeout_release) {
    msconnector_error_set(error, MSCONNECTOR_ERROR_TIMEOUT,
                          "terminal owner timeout", "test");
    return 1;
  }
  if (command->operation == HAPROXY_SPOP_RESPONSE_COMPANION_RELEASE &&
      owner->control.blocking.fail_release) {
    *transaction_consumed = 1;
    msconnector_error_set(error, MSCONNECTOR_ERROR_PHASE_SEQUENCE,
                          "finish failed after consuming transaction", "test");
    return 1;
  }
  return 0;
}

static void assert_operation_contract(
    const fake_owner *const owner,
    const haproxy_spop_response_companion_owner_command *const command) {
  if (command->operation == HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_BODY) {
    assert(command->body == owner->expected_body);
    assert(command->body_size == owner->expected_body_size);
  }
  if (command->operation == HAPROXY_SPOP_RESPONSE_COMPANION_COMMIT) {
    assert(command->headers_sent == 1);
    assert(command->body_started == 0);
  }
  if (command->operation == HAPROXY_SPOP_RESPONSE_COMPANION_OUTCOME) {
    assert(command->decision == owner->expected_decision);
    assert(strcmp(command->transport_result, "sent") == 0);
    assert(command->visible_http_status == 200);
    assert(command->connection_aborted == 0);
  }
}

static int
dispatch(void *const context, haproxy_modsecurity_transaction *const transaction,
         const haproxy_spop_response_companion_owner_command *const command,
         msconnector_decision *const decision, msconnector_error *const error,
         int *const transaction_consumed) {
  fake_owner *owner = context;
  assert(transaction != NULL);
  assert(command->operation <= HAPROXY_SPOP_RESPONSE_COMPANION_FAIL);
  assert(command->lease != 0U);
  owner->calls[command->operation]++;
  assert_response_command(command);
  set_response_decision(command, decision);
  if (owner->control.terminal.defer_response_headers_finalizer &&
      command->operation == HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_HEADERS &&
      transaction == owner->transaction_a) {
    owner->control.terminal.stale_response_headers_lease = command->lease;
    return 1;
  }
  if (dispatch_expire_finalizer(owner, transaction, command, error)) {
    return 0;
  }
  if (dispatch_terminal_finalizer(owner, transaction, command,
                                  transaction_consumed)) {
    return 1;
  }
  if (dispatch_terminal_timeout(owner, transaction, command, error)) {
    return 0;
  }
  if (dispatch_stale_headers(owner, transaction, command, error)) {
    return 0;
  }
  if (dispatch_fail_reuse(owner, transaction, command, error)) {
    return 0;
  }
  dispatch_claim_reuse(owner, transaction, command);
  wait_for_blocking_callback(owner, transaction, command);
  if (handle_callback_error(owner, command, error, transaction_consumed)) {
    return 0;
  }
  assert_operation_contract(owner, command);
  return 1;
}

static void init_error(msconnector_error *const error) {
  msconnector_error_init(error);
}

static void reset_backend_session(
    msconnector_response_companion_backend_session *const session,
    msconnector_response_companion_decision_storage *const decision_storage) {
  assert(session != NULL);
  assert(decision_storage != NULL);
  memset(session, 0, sizeof(*session));
  memset(decision_storage, 0, sizeof(*decision_storage));
  session->decision_storage = decision_storage;
}

typedef struct claim_thread_context {
  msconnector_response_companion_backend *vtable;
  const char *handle;
  msconnector_response_companion_backend_session session;
  msconnector_error error;
  int result;
} claim_thread_context;

static void *run_claim_thread(void *opaque) {
  claim_thread_context *context = opaque;
  memset(&context->session, 0, sizeof(context->session));
  msconnector_error_init(&context->error);
  context->result =
      context->vtable->claim(context->vtable->context, context->handle,
                             &context->session, &context->error);
  return NULL;
}

typedef struct body_thread_context {
  msconnector_response_companion_backend *vtable;
  const msconnector_response_companion_backend_session *session;
  const unsigned char *body;
  size_t body_size;
  msconnector_error error;
  int result;
} body_thread_context;

static void *run_body_thread(void *opaque) {
  body_thread_context *context = opaque;

  msconnector_error_init(&context->error);
  context->result = context->vtable->append_response_body_chunk(
      context->vtable->context, context->session, context->body,
      context->body_size, &context->error);
  return NULL;
}

int main(void) {
  haproxy_spop_response_companion_backend backend;
  haproxy_spop_response_companion_slot slots[2];
  msconnector_response_companion_backend vtable;
  msconnector_response_companion_backend_session session;
  msconnector_response_companion_decision_storage session_decision_storage;
  msconnector_error error;
  msconnector_decision decision;
  fake_owner owner;
  char handle[HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_STORAGE];
  char second[HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_STORAGE];
  const unsigned char body[] = "bounded";

  memset(&owner, 0, sizeof(owner));
  reset_backend_session(&session, &session_decision_storage);
  owner.expected_body = body;
  owner.expected_body_size = sizeof(body) - 1U;
  init_error(&error);
  assert(haproxy_spop_response_companion_backend_init(
      &backend, slots, 2U, 100U, &owner, dispatch, &error));
  owner.backend = &backend;
  haproxy_spop_response_companion_backend_vtable(&backend, &vtable);
  assert(vtable.allow_parallel_callbacks == 1);
  assert(pthread_mutex_init(&owner.lock, NULL) == 0);
  assert(pthread_cond_init(&owner.changed, NULL) == 0);
  owner.transaction_a = (haproxy_modsecurity_transaction *)(uintptr_t)0x1234U;
  owner.transaction_b = (haproxy_modsecurity_transaction *)(uintptr_t)0x5678U;
  assert(haproxy_spop_response_companion_handoff(&backend, owner.transaction_a,
                                                 1000U, handle, &error));
  assert(strlen(handle) == HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_SIZE);
  assert(haproxy_spop_response_companion_handoff(&backend, owner.transaction_a,
                                                 1000U, second, &error));
  assert(strcmp(handle, second) != 0);
  assert(!haproxy_spop_response_companion_backend_destroy(&backend, &error));
  assert(error.code == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
  assert(!haproxy_spop_response_companion_handoff(&backend, owner.transaction_a,
                                                  1000U, handle, &error));
  assert(error.code == MSCONNECTOR_ERROR_RUNTIME_UNAVAILABLE);

  /* Invalid syntax and a second claim are rejected before owner dispatch. */
  assert(!vtable.claim(
      vtable.context,
      "00000000000000000000000000000000000000000000000000000000000000G",
      &session, &error));
  assert(error.code == MSCONNECTOR_ERROR_PROTOCOL);

  msconnector_decision_init(&decision);
  owner.expected_decision = &decision;
  assert(vtable.claim(vtable.context, handle, &session, &error));
  assert(session.opaque != NULL);
  {
    msconnector_response_companion_backend_session missing_storage = session;
    missing_storage.decision_storage = NULL;
    assert(!vtable.process_response_headers(vtable.context, &missing_storage,
                                            NULL, &decision, &error));
    assert(error.code == MSCONNECTOR_ERROR_CORRELATION_MISSING);
  }
  {
    msconnector_response_companion_backend_session forged = {
        .opaque = (void *)(uintptr_t)1U};
    assert(!vtable.release(vtable.context, &forged, &error));
    assert(error.code == MSCONNECTOR_ERROR_CORRELATION_MISSING);
  }
  {
    msconnector_response_companion_backend_session duplicate = {.opaque = NULL};
    assert(!vtable.claim(vtable.context, handle, &duplicate, &error));
    assert(error.code == MSCONNECTOR_ERROR_CORRELATION_MISMATCH);
  }
  assert(vtable.process_response_headers(vtable.context, &session, NULL,
                                         &decision, &error));
  assert(decision.redirect_url == session.decision_storage->redirect_url);
  assert(decision.reason == session.decision_storage->log_message);
  assert(
      vtable.set_response_commit_state(vtable.context, &session, 1, 0, &error));
  assert(vtable.append_response_body_chunk(vtable.context, &session, body,
                                           sizeof(body) - 1U, &error));
  assert(
      vtable.finish_response_body(vtable.context, &session, &decision, &error));
  assert(decision.reason == session.decision_storage->log_message);
  assert(strcmp(decision.reason, "owner-p4-decision") == 0);
  {
    const msconnector_response_companion_host_action action = {
        .decision = &decision,
        .actual_action = MSCONNECTOR_DECISION_ACTION_ALLOW,
        .visible_http_status = 200,
        .transport_result = "sent",
        .connection_aborted = 0};
    assert(vtable.record_host_action(vtable.context, &session, &action,
                                     &error));
  }
  assert(vtable.release(vtable.context, &session, &error));
  assert(session.opaque == NULL);
  assert(owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_CLAIM] == 1U);
  assert(owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_HEADERS] == 1U);
  assert(owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_BODY] == 1U);
  assert(owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_EOS] == 1U);
  assert(owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_RELEASE] == 1U);

  /* A finalizer may expire the old claim and reuse the slot before the
   * original claim callback returns.  Its post-dispatch path must reject
   * the old generation and must not clear the replacement's in-flight bit. */
  {
    uint64_t replacement_lease;
    assert(haproxy_spop_response_companion_handoff(
        &backend, owner.transaction_a, 6000U, handle, &error));
    owner.control.claim_reuse.simulate_claim_finalizer_reuse = 1;
    owner.control.claim_reuse.simulated_reuse_done = 0;
    reset_backend_session(&session, &session_decision_storage);
    assert(!vtable.claim(vtable.context, handle, &session, &error));
    assert(error.code == MSCONNECTOR_ERROR_CORRELATION_MISMATCH);
    assert(session.opaque == NULL);
    assert(slots[0].in_use);
    replacement_lease = slots[0].lease;
    assert(replacement_lease != 0U);
    assert(slots[0].in_flight == 1);
    slots[0].in_flight = 0;
    owner.control.claim_reuse.simulate_claim_finalizer_reuse = 0;
    reset_backend_session(&session, &session_decision_storage);
    assert(vtable.claim(vtable.context, owner.control.claim_reuse.simulated_reuse_handle, &session,
                        &error));
    assert(vtable.release(vtable.context, &session, &error));
  }

  /* A timed-out owner callback quarantines the native slot.  No terminal
   * callback may race it until the owner reports that the callback really
   * returned; afterwards normal release remains available. */
  assert(haproxy_spop_response_companion_handoff(&backend, owner.transaction_a,
                                                 1500U, handle, &error));
  reset_backend_session(&session, &session_decision_storage);
  assert(vtable.claim(vtable.context, handle, &session, &error));
  owner.control.blocking.timeout_body = 1;
  assert(!vtable.append_response_body_chunk(vtable.context, &session, body,
                                            sizeof(body) - 1U, &error));
  assert(error.code == MSCONNECTOR_ERROR_TIMEOUT);
  assert(!vtable.release(vtable.context, &session, &error));
  assert(error.code == MSCONNECTOR_ERROR_PHASE_SEQUENCE);
  vtable.fail(vtable.context, &session,
              MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT);
  assert(session.opaque != NULL);
  haproxy_spop_response_companion_backend_dispatch_finished(
      &backend, owner.transaction_a, slots[0].lease,
      HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_BODY, 0);
  /* One abort belongs to the earlier simulated finalizer; this timeout
   * contributes exactly one additional abort. */
  assert(abort_calls == 2U);
  owner.control.blocking.timeout_body = 0;
  session.opaque = NULL;

  /* A released handle is single-use; the other slot expires through the
   * owner dispatch and cannot be claimed afterwards. */
  init_error(&error);
  reset_backend_session(&session, &session_decision_storage);
  haproxy_spop_response_companion_backend_expire(&backend, 1101U);
  assert(owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_EXPIRE] == 1U);
  assert(!vtable.claim(vtable.context, second, &session, &error));
  assert(error.code == MSCONNECTOR_ERROR_CORRELATION_MISMATCH);

  /* Expiry marks its generation before owner dispatch.  If a timed-out
   * owner finalizer runs before expire() can reacquire the lock, it still
   * performs exactly one abort and no later expiry retries that pointer. */
  {
    unsigned int expires_before;
    unsigned int aborts_before;

    assert(haproxy_spop_response_companion_handoff(
        &backend, owner.transaction_a, 7000U, handle, &error));
    owner.control.expiry.simulate_expire_finalizer_before_return = 1;
    owner.control.expiry.expire_finalizer_simulated = 0;
    expires_before = owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_EXPIRE];
    aborts_before = abort_calls;
    haproxy_spop_response_companion_backend_expire(&backend, 7101U);
    assert(owner.control.expiry.expire_finalizer_simulated);
    assert(owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_EXPIRE] ==
           expires_before + 1U);
    assert(abort_calls == aborts_before + 1U);
    assert(!slots[0].in_use);
    haproxy_spop_response_companion_backend_expire(&backend, 7201U);
    assert(owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_EXPIRE] ==
           expires_before + 1U);
    owner.control.expiry.simulate_expire_finalizer_before_return = 0;
  }

  /* Owner task destruction may happen before terminal() returns from its
   * dispatch.  Preserve the callback guard through that post-dispatch
   * window, so expiry quarantines rather than dispatching EXPIRE against a
   * transaction already consumed by RELEASE. */
  {
    unsigned int expires_before;
    unsigned int aborts_before;

    assert(haproxy_spop_response_companion_handoff(
        &backend, owner.transaction_a, 7300U, handle, &error));
    reset_backend_session(&session, &session_decision_storage);
    assert(vtable.claim(vtable.context, handle, &session, &error));
    owner.control.terminal.simulate_terminal_finalizer_before_return = 1;
    owner.control.terminal.terminal_finalizer_simulated = 0;
    owner.control.terminal.terminal_expire_at_ms = 7401U;
    expires_before = owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_EXPIRE];
    aborts_before = abort_calls;
    assert(!vtable.release(vtable.context, &session, &error));
    assert(error.code == MSCONNECTOR_ERROR_CORRELATION_EXPIRED);
    assert(owner.control.terminal.terminal_finalizer_simulated);
    assert(owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_EXPIRE] ==
           expires_before);
    assert(abort_calls == aborts_before);
    assert(session.opaque == NULL);
    assert(!slots[0].in_use);
    owner.control.terminal.simulate_terminal_finalizer_before_return = 0;
  }

  /* A terminal timeout leaves cleanup to the owner finalizer.  Its exact
   * generation is deleted once, without aborting an already-consumed
   * transaction. */
  {
    uint64_t lease;
    unsigned int aborts_before;

    assert(haproxy_spop_response_companion_handoff(
        &backend, owner.transaction_a, 7450U, handle, &error));
    reset_backend_session(&session, &session_decision_storage);
    assert(vtable.claim(vtable.context, handle, &session, &error));
    lease = slots[0].lease;
    owner.control.terminal.timeout_release = 1;
    aborts_before = abort_calls;
    assert(!vtable.release(vtable.context, &session, &error));
    assert(error.code == MSCONNECTOR_ERROR_TIMEOUT);
    assert(session.opaque == NULL);
    assert(slots[0].in_use && slots[0].in_flight && slots[0].terminal_pending &&
           slots[0].terminal_timed_out && !slots[0].terminal_finished);
    assert(haproxy_spop_response_companion_backend_dispatch_finished(
               &backend, owner.transaction_a, lease,
               HAPROXY_SPOP_RESPONSE_COMPANION_RELEASE, 1) == 0);
    assert(abort_calls == aborts_before);
    assert(!slots[0].in_use);
    owner.control.terminal.timeout_release = 0;
  }

  /* If a timed-out terminal owner reports that it did not consume the
   * native transaction, its finalizer owns exactly one abort. */
  {
    uint64_t lease;
    unsigned int aborts_before;

    assert(haproxy_spop_response_companion_handoff(
        &backend, owner.transaction_a, 7500U, handle, &error));
    reset_backend_session(&session, &session_decision_storage);
    assert(vtable.claim(vtable.context, handle, &session, &error));
    lease = slots[0].lease;
    owner.control.terminal.timeout_release = 1;
    aborts_before = abort_calls;
    assert(!vtable.release(vtable.context, &session, &error));
    assert(error.code == MSCONNECTOR_ERROR_TIMEOUT);
    assert(haproxy_spop_response_companion_backend_dispatch_finished(
               &backend, owner.transaction_a, lease,
               HAPROXY_SPOP_RESPONSE_COMPANION_RELEASE, 0) == 0);
    assert(abort_calls == aborts_before + 1U);
    assert(!slots[0].in_use);
    owner.control.terminal.timeout_release = 0;
  }

  /* The owner finalizer can win before the synchronous timeout result is
   * observed.  The caller must use its recorded completion state and never
   * leave an occupied bounded slot behind. */
  {
    unsigned int aborts_before;

    assert(haproxy_spop_response_companion_handoff(
        &backend, owner.transaction_a, 7550U, handle, &error));
    reset_backend_session(&session, &session_decision_storage);
    assert(vtable.claim(vtable.context, handle, &session, &error));
    owner.control.terminal.simulate_terminal_timeout_finalizer_before_return = 1;
    owner.control.terminal.terminal_timeout_finalizer_simulated = 0;
    owner.control.terminal.terminal_timeout_finalizer_consumed = 1;
    aborts_before = abort_calls;
    assert(!vtable.release(vtable.context, &session, &error));
    assert(error.code == MSCONNECTOR_ERROR_TIMEOUT);
    assert(owner.control.terminal.terminal_timeout_finalizer_simulated);
    assert(abort_calls == aborts_before);
    assert(session.opaque == NULL);
    assert(!slots[0].in_use);
    owner.control.terminal.simulate_terminal_timeout_finalizer_before_return = 0;
  }

  /* The same early-finalizer ordering with an unconsumed transaction must
   * be closed by the timeout caller with exactly one abort. */
  {
    unsigned int aborts_before;

    assert(haproxy_spop_response_companion_handoff(
        &backend, owner.transaction_a, 7600U, handle, &error));
    reset_backend_session(&session, &session_decision_storage);
    assert(vtable.claim(vtable.context, handle, &session, &error));
    owner.control.terminal.simulate_terminal_timeout_finalizer_before_return = 1;
    owner.control.terminal.terminal_timeout_finalizer_simulated = 0;
    owner.control.terminal.terminal_timeout_finalizer_consumed = 0;
    aborts_before = abort_calls;
    assert(!vtable.release(vtable.context, &session, &error));
    assert(error.code == MSCONNECTOR_ERROR_TIMEOUT);
    assert(owner.control.terminal.terminal_timeout_finalizer_simulated);
    assert(abort_calls == aborts_before + 1U);
    assert(session.opaque == NULL);
    assert(!slots[0].in_use);
    owner.control.terminal.simulate_terminal_timeout_finalizer_before_return = 0;
  }

  /* A delayed response-header finalizer must not become the completion of a
   * later RELEASE.  The real RELEASE finalizer remains the only authority
   * to resolve a terminal timeout for this transaction/lease. */
  {
    uint64_t lease;
    unsigned int aborts_before;

    assert(haproxy_spop_response_companion_handoff(
        &backend, owner.transaction_a, 7650U, handle, &error));
    reset_backend_session(&session, &session_decision_storage);
    assert(vtable.claim(vtable.context, handle, &session, &error));
    owner.control.terminal.defer_response_headers_finalizer = 1;
    assert(vtable.process_response_headers(vtable.context, &session, NULL,
                                           &decision, &error));
    lease = slots[0].lease;
    owner.control.terminal.simulate_stale_response_headers_finalizer_before_release_timeout = 1;
    owner.control.terminal.stale_response_headers_finalizer_simulated = 0;
    aborts_before = abort_calls;
    assert(!vtable.release(vtable.context, &session, &error));
    assert(error.code == MSCONNECTOR_ERROR_TIMEOUT);
    assert(owner.control.terminal.stale_response_headers_finalizer_simulated);
    assert(abort_calls == aborts_before);
    assert(session.opaque == NULL);
    assert(slots[0].in_use && slots[0].in_flight && slots[0].terminal_pending &&
           slots[0].terminal_timed_out && !slots[0].terminal_finished);
    assert(haproxy_spop_response_companion_backend_dispatch_finished(
               &backend, owner.transaction_a, lease,
               HAPROXY_SPOP_RESPONSE_COMPANION_RELEASE, 1) == 0);
    assert(abort_calls == aborts_before);
    assert(!slots[0].in_use);
    owner.control.terminal.defer_response_headers_finalizer = 0;
    owner.control.terminal.simulate_stale_response_headers_finalizer_before_release_timeout = 0;
  }

  /* A delayed old FAIL cannot set expiry on a replacement generation, even
   * when the native transaction pointer is reused.  The lease and opaque
   * token are both part of the exact slot-generation comparison. */
  {
    uint64_t replacement_lease;

    assert(haproxy_spop_response_companion_handoff(
        &backend, owner.transaction_a, 7500U, handle, &error));
    reset_backend_session(&session, &session_decision_storage);
    assert(vtable.claim(vtable.context, handle, &session, &error));
    owner.control.fail_reuse.simulate_fail_finalizer_reuse = 1;
    owner.control.fail_reuse.fail_reuse_done = 0;
    owner.control.fail_reuse.fail_expire_at_ms = 7601U;
    vtable.fail(vtable.context, &session,
                MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL);
    assert(owner.control.fail_reuse.fail_reuse_done);
    assert(session.opaque == NULL);
    assert(slots[0].in_use);
    replacement_lease = slots[0].lease;
    assert(replacement_lease != 0U);
    assert(!slots[0].expire_pending);
    assert(!slots[0].in_flight);
    owner.control.fail_reuse.simulate_fail_finalizer_reuse = 0;
    reset_backend_session(&session, &session_decision_storage);
    assert(vtable.claim(vtable.context, owner.control.fail_reuse.fail_reuse_handle, &session,
                        &error));
    assert(vtable.release(vtable.context, &session, &error));
  }

  /* The backend opts into parallel transport callbacks because its own
   * slot lock serializes each session independently.  A blocked owner
   * callback for slot A must not prevent slot B from entering dispatch.
   * Once A expires, its callback result is not usable and only the owner
   * finalizer may abort and release that exact generation. */
  {
    pthread_t thread;
    claim_thread_context first_claim;
    msconnector_response_companion_backend_session second_session;
    char parallel_a[HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_STORAGE];
    char parallel_b[HAPROXY_SPOP_RESPONSE_COMPANION_HANDLE_STORAGE];
    unsigned int expire_calls;
    unsigned int aborts_before;
    uint64_t parallel_a_lease;
    memset(&first_claim, 0, sizeof(first_claim));
    owner.control.blocking.block_a_claim = 1;
    assert(haproxy_spop_response_companion_handoff(
        &backend, owner.transaction_a, 4000U, parallel_a, &error));
    assert(haproxy_spop_response_companion_handoff(
        &backend, owner.transaction_b, 4050U, parallel_b, &error));
    parallel_a_lease = slots[0].lease;
    first_claim.vtable = &vtable;
    first_claim.handle = parallel_a;
    assert(pthread_create(&thread, NULL, run_claim_thread, &first_claim) == 0);
    pthread_mutex_lock(&owner.lock);
    while (!owner.control.blocking.a_started) {
      pthread_cond_wait(&owner.changed, &owner.lock);
    }
    pthread_mutex_unlock(&owner.lock);
    memset(&second_session, 0, sizeof(second_session));
    assert(vtable.claim(vtable.context, parallel_b, &second_session, &error));
    assert(second_session.opaque != NULL);
    expire_calls = owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_EXPIRE];
    haproxy_spop_response_companion_backend_expire(&backend, 4101U);
    assert(owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_EXPIRE] == expire_calls);
    assert(vtable.release(vtable.context, &second_session, &error));
    pthread_mutex_lock(&owner.lock);
    owner.control.blocking.release_a = 1;
    pthread_cond_broadcast(&owner.changed);
    pthread_mutex_unlock(&owner.lock);
    assert(pthread_join(thread, NULL) == 0);
    assert(!first_claim.result);
    assert(first_claim.error.code == MSCONNECTOR_ERROR_CORRELATION_EXPIRED);
    assert(first_claim.session.opaque == NULL);
    assert(slots[0].in_use && slots[0].in_flight && slots[0].expire_pending);
    aborts_before = abort_calls;
    assert(haproxy_spop_response_companion_backend_dispatch_finished(
               &backend, owner.transaction_a, parallel_a_lease,
               HAPROXY_SPOP_RESPONSE_COMPANION_CLAIM, 0) == 1);
    assert(abort_calls == aborts_before + 1U);
    assert(!slots[0].in_use);
    owner.control.blocking.block_a_claim = 0;
  }

  /* Expiry observed during a response callback must suppress that callback's
   * successful result as well.  The opaque transport capability becomes
   * unusable immediately, while the finalizer retains sole abort/cleanup
   * ownership. */
  {
    pthread_t thread;
    body_thread_context body_context;
    uint64_t body_lease;
    unsigned int expire_calls;
    unsigned int aborts_before;

    assert(haproxy_spop_response_companion_handoff(
        &backend, owner.transaction_a, 4500U, handle, &error));
    reset_backend_session(&session, &session_decision_storage);
    assert(vtable.claim(vtable.context, handle, &session, &error));
    assert(vtable.process_response_headers(vtable.context, &session, NULL,
                                           &decision, &error));
    assert(vtable.set_response_commit_state(vtable.context, &session, 1, 0,
                                            &error));
    body_lease = slots[0].lease;
    memset(&body_context, 0, sizeof(body_context));
    body_context.vtable = &vtable;
    body_context.session = &session;
    body_context.body = body;
    body_context.body_size = sizeof(body) - 1U;
    owner.control.blocking.block_a_body = 1;
    assert(pthread_create(&thread, NULL, run_body_thread, &body_context) == 0);
    pthread_mutex_lock(&owner.lock);
    while (!owner.control.blocking.body_started) {
      pthread_cond_wait(&owner.changed, &owner.lock);
    }
    pthread_mutex_unlock(&owner.lock);
    expire_calls = owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_EXPIRE];
    haproxy_spop_response_companion_backend_expire(&backend, 4601U);
    assert(owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_EXPIRE] == expire_calls);
    pthread_mutex_lock(&owner.lock);
    owner.control.blocking.release_body = 1;
    pthread_cond_broadcast(&owner.changed);
    pthread_mutex_unlock(&owner.lock);
    assert(pthread_join(thread, NULL) == 0);
    assert(!body_context.result);
    assert(body_context.error.code == MSCONNECTOR_ERROR_CORRELATION_EXPIRED);
    /* Read-only response callbacks cannot rewrite the caller capability;
     * the expired generation still rejects every subsequent operation. */
    assert(session.opaque != NULL);
    assert(slots[0].in_use && slots[0].in_flight && slots[0].expire_pending);
    aborts_before = abort_calls;
    assert(haproxy_spop_response_companion_backend_dispatch_finished(
               &backend, owner.transaction_a, body_lease,
               HAPROXY_SPOP_RESPONSE_COMPANION_RESPONSE_BODY, 0) == 1);
    assert(abort_calls == aborts_before + 1U);
    assert(!slots[0].in_use);
    init_error(&error);
    assert(!vtable.append_response_body_chunk(vtable.context, &session, body,
                                              sizeof(body) - 1U, &error));
    assert(error.code == MSCONNECTOR_ERROR_CORRELATION_MISSING ||
           error.code == MSCONNECTOR_ERROR_CORRELATION_EXPIRED);
    owner.control.blocking.block_a_body = 0;
    owner.control.blocking.body_started = 0;
    owner.control.blocking.release_body = 0;
  }

  /* A delayed finalizer from the old lease cannot clear a reused slot,
   * even when the native transaction pointer is reused verbatim. */
  {
    uint64_t old_lease;
    uint64_t new_lease;
    void *stale_opaque;
    msconnector_response_companion_backend_session stale_session;
    assert(haproxy_spop_response_companion_handoff(
        &backend, owner.transaction_a, 5000U, handle, &error));
    old_lease = slots[0].lease;
    reset_backend_session(&session, &session_decision_storage);
    assert(vtable.claim(vtable.context, handle, &session, &error));
    stale_opaque = session.opaque;
    assert(vtable.release(vtable.context, &session, &error));
    assert(haproxy_spop_response_companion_handoff(
        &backend, owner.transaction_a, 5100U, handle, &error));
    new_lease = slots[0].lease;
    assert(new_lease != old_lease);
    assert(haproxy_spop_response_companion_backend_dispatch_finished(
               &backend, owner.transaction_a, old_lease,
               HAPROXY_SPOP_RESPONSE_COMPANION_RELEASE, 0) == 0);
    assert(slots[0].in_use && slots[0].lease == new_lease);
    stale_session.opaque = stale_opaque;
    assert(!vtable.release(vtable.context, &stale_session, &error));
    assert(slots[0].in_use && slots[0].lease == new_lease);
    reset_backend_session(&session, &session_decision_storage);
    assert(vtable.claim(vtable.context, handle, &session, &error));
    assert(vtable.release(vtable.context, &session, &error));
  }

  /* A transport failure invokes FAIL and invalidates the opaque session. */
  assert(haproxy_spop_response_companion_handoff(&backend, owner.transaction_a,
                                                 2000U, handle, &error));
  assert(vtable.claim(vtable.context, handle, &session, &error));
  vtable.fail(vtable.context, &session, MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL);
  assert(session.opaque == NULL);
  /* The stale-generation regression above issued the first FAIL.  This
   * ordinary transport failure must still reach its own owner operation. */
  assert(owner.calls[HAPROXY_SPOP_RESPONSE_COMPANION_FAIL] == 2U);

  /* A failed RELEASE still consumes the native transaction.  The explicit
   * owner signal clears the backend slot without a second abort. */
  assert(haproxy_spop_response_companion_handoff(&backend, owner.transaction_a,
                                                 3000U, handle, &error));
  reset_backend_session(&session, &session_decision_storage);
  assert(vtable.claim(vtable.context, handle, &session, &error));
  owner.control.blocking.fail_release = 1;
  assert(!vtable.release(vtable.context, &session, &error));
  assert(session.opaque == NULL);
  assert(abort_calls == 8U);
  assert(haproxy_spop_response_companion_backend_destroy(&backend, &error));
  pthread_cond_destroy(&owner.changed);
  pthread_mutex_destroy(&owner.lock);
  return 0;
}
