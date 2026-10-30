
#define _POSIX_C_SOURCE 200809L
#include "common/runtime/msconnector_runtime.h"
#include "connectors/profile_registry.h"
#include "msconnector/late_intervention.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
/* Controlled fixture seams preserve real headers above. Read-only mocks
 * accept const arguments; separate native builds verify the actual ABI. */
#define msconnector_runtime_transaction_append_response_body_chunk             \
  fixture_msconnector_runtime_transaction_append_response_body_chunk
#define msconnector_runtime_transaction_finalize_and_snapshot                  \
  fixture_msconnector_runtime_transaction_finalize_and_snapshot
#define msconnector_runtime_transaction_finish                                 \
  fixture_msconnector_runtime_transaction_finish
#define msconnector_runtime_transaction_finish_response_body                   \
  fixture_msconnector_runtime_transaction_finish_response_body
#define msconnector_runtime_transaction_process_response_headers               \
  fixture_msconnector_runtime_transaction_process_response_headers
#define msconnector_runtime_transaction_record_failure_host_action             \
  fixture_msconnector_runtime_transaction_record_failure_host_action
#define msconnector_runtime_transaction_record_host_action                     \
  fixture_msconnector_runtime_transaction_record_host_action
#define msconnector_runtime_transaction_set_response_commit_state_checked      \
  fixture_msconnector_runtime_transaction_set_response_commit_state_checked
#define SIDECAR_IO_CHUNK 2048U
/* TYPES */
struct msconnector_runtime {
  int mode;
};
struct msconnector_runtime_transaction {
  int failed;
  msconnector_transaction_contract contract;
};
static msconnector_runtime_transaction tx;
static int fault;
static int native_calls;
static int cleanup_calls;
static int receipt_calls;
static int host_calls;
static int exchange_allowed;
static int fixture_spool_fd = -1;
static int timeout_calls;
static int visible_status;
size_t msconnector_runtime_total_header_limit(const msconnector_runtime *r) {
  (void)r;
  return 8192;
}
size_t msconnector_runtime_header_count_limit(const msconnector_runtime *r) {
  (void)r;
  return 64;
}
size_t msconnector_runtime_request_body_limit(const msconnector_runtime *r) {
  (void)r;
  return 8192;
}
size_t msconnector_runtime_response_body_limit(const msconnector_runtime *r) {
  (void)r;
  return 8192;
}
int msconnector_runtime_error_http_status(const msconnector_runtime *r,
                                          msconnector_error_code c) {
  (void)r;
  (void)c;
  return 500;
}
int msconnector_runtime_transaction_fail(msconnector_runtime_transaction *t,
                                         msconnector_transaction_error_class c,
                                         msconnector_error *e) {
  msconnector_error_init(e);
  (void)msconnector_transaction_contract_fail(&t->contract, c, 0U);
  t->failed = 1;
  return 1;
}
int msconnector_runtime_transaction_timeout(msconnector_runtime_transaction *t,
                                            msconnector_error *e) {
  msconnector_error_init(e);
  ++timeout_calls;
  (void)msconnector_transaction_contract_timeout(&t->contract, 0U);
  t->failed = 1;
  return 1;
}
int fixture_msconnector_runtime_transaction_finish(
    const msconnector_runtime_transaction *t, const msconnector_error *e) {
  (void)t;
  (void)e;
  return 1;
}
int fixture_msconnector_runtime_transaction_record_failure_host_action(
    const msconnector_runtime_transaction *t, int status, int aborted,
    const msconnector_error *e) {
  (void)t;
  visible_status = status;
  (void)aborted;
  (void)e;
  ++host_calls;
  return 1;
}
int fixture_msconnector_runtime_transaction_set_response_commit_state_checked(
    const msconnector_runtime_transaction *t, int h, int b,
    const msconnector_error *e) {
  (void)t;
  (void)h;
  (void)b;
  (void)e;
  return fault == 4 ? 0 : 1;
}
int fixture_msconnector_runtime_transaction_append_response_body_chunk(
    const msconnector_runtime_transaction *t, const unsigned char *d, size_t n,
    msconnector_error *e) {
  (void)t;
  (void)d;
  (void)n;
  ++native_calls;
  if (fault == 1 || fault == 2) {
    msconnector_error_set(e, MSCONNECTOR_ERROR_HOST_API_FAILURE,
                          "native failure", "fixture");
    return fault == 2 ? -1 : 0;
  }
  return 1;
}
int fixture_msconnector_runtime_transaction_finalize_and_snapshot(
    msconnector_runtime_transaction **t,
    msconnector_runtime_transaction_snapshot *s, const msconnector_error *e) {
  (void)e;
  memset(s, 0, sizeof(*s));
  s->contract.engine_decision = exchange_allowed
                                    ? MSCONNECTOR_TRANSACTION_DECISION_ALLOW
                                    : MSCONNECTOR_TRANSACTION_DECISION_ENFORCE;
  s->contract.action = exchange_allowed ? MSCONNECTOR_DECISION_ACTION_ALLOW
                                        : MSCONNECTOR_DECISION_ACTION_DENY;
  s->contract.error_class = exchange_allowed
                                ? MSCONNECTOR_TRANSACTION_ERROR_NONE
                                : MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR;
  ++cleanup_calls;
  *t = NULL;
  return 1;
}
void msconnector_runtime_transaction_destroy(
    msconnector_runtime_transaction **t) {
  if (*t) {
    ++cleanup_calls;
    *t = NULL;
  }
}
static int
sidecar_write_allow_receipt(const msconnector_runtime_transaction_snapshot *s,
                            int status) {
  (void)s;
  (void)status;
  ++receipt_calls;
  return 1;
}
static int sidecar_write_non_allow_receipt(
    const msconnector_runtime_transaction_snapshot *s) {
  (void)s;
  ++receipt_calls;
  return 1;
}
static int sidecar_exchange_request(sidecar_exchange_state *s) {
  s->transaction = &tx;
  /* Keep the actual cleanup helper exercised even when the native request
   * seam supplies no body: one real descriptor owns one budget reservation. */
  s->payload.request_spool_fd = fixture_spool_fd;
  s->payload.spool_reservation = 4096U;
  return exchange_allowed;
}

static int phase_upstream;
static int sidecar_connect(const char *s, const sidecar_deadline *d) {
  (void)s;
  (void)d;
  return dup(phase_upstream);
}
static int sidecar_write_upstream_request(int fd, const char *l,
                                          const sidecar_headers *h,
                                          const unsigned char *b, size_t n,
                                          const sidecar_deadline *d) {
  (void)fd;
  (void)l;
  (void)h;
  (void)b;
  (void)n;
  (void)d;
  return 1;
}
static int sidecar_read_final_response_headers(sidecar_exchange_state *s) {
  s->payload.response_headers.status_code = 200;
  s->payload.response_headers.content_length = 1;
  return 1;
}
static int sidecar_forward_response(sidecar_exchange_state *s) {
  s->client_response_started = 1;
  return 1;
}
static int sidecar_replay_request_body(const sidecar_exchange_state *s) { (void)s; return 1; }
static void sidecar_finish_decision(sidecar_exchange_state *s) {
  s->handled = 1;
}
static void sidecar_record_action(const msconnector_runtime_transaction *t,
                                  const msconnector_decision *d,
                                  const msconnector_error *e) {
  (void)t;
  (void)d;
  (void)e;
}
static void sidecar_record_decision_delivery_failure(
    int fd, const sidecar_owned_socket_stop *stop, const msconnector_runtime_transaction *t,
    const msconnector_decision *d, const msconnector_error *e) {
  (void)fd;
  (void)stop;
  (void)t;
  (void)d;
  (void)e;
}
int fixture_msconnector_runtime_transaction_record_host_action(
    const msconnector_runtime_transaction *t, const msconnector_decision *d,
    msconnector_decision_action a, int status, const char *x, int aborted,
    const msconnector_error *e) {
  (void)t;
  (void)d;
  (void)a;
  (void)status;
  (void)x;
  (void)aborted;
  (void)e;
  return 1;
}
enum msconnector_phase4_mode
msconnector_runtime_phase4_mode(const msconnector_runtime *r) {
  return (enum msconnector_phase4_mode)r->mode;
}
int fixture_msconnector_runtime_transaction_process_response_headers(
    const msconnector_runtime_transaction *t, const msconnector_response *r,
    msconnector_decision *d, msconnector_error *e) {
  (void)t;
  (void)r;
  ++native_calls;
  msconnector_decision_init(d);
  if (fault == 5) {
    msconnector_error_set(e, MSCONNECTOR_ERROR_HOST_API_FAILURE, "P3 failure",
                          "fixture");
    return 0;
  }
  return 1;
}
int fixture_msconnector_runtime_transaction_finish_response_body(
    const msconnector_runtime_transaction *t, msconnector_decision *d,
    msconnector_error *e) {
  (void)t;
  ++native_calls;
  msconnector_decision_init(d);
  if (fault == 6) {
    msconnector_error_set(e, MSCONNECTOR_ERROR_HOST_API_FAILURE,
                          "P4 EOS failure", "fixture");
    return -1;
  }
  return 1;
}
/* DEFINITIONS */

static void fixture_body(sidecar_exchange_state *state, const int *client,
                         const int *upstream, int committed) {

  assert(send(upstream[1], "x", 1, 0) == 1);
  int result = sidecar_read_response_body(state);
  if (fault) {
    assert(result == 0);
    sidecar_exchange_error(state);
    int calls = native_calls;
    int actions = host_calls;
    assert(sidecar_read_response_body(state) == 0);
    sidecar_exchange_error(state);
    assert(native_calls == calls && host_calls == actions);
    char output[256];
    ssize_t n = recv(client[1], output, sizeof(output) - 1, MSG_DONTWAIT);
    if (committed)
      assert(n == 0);
    else {
      assert(n > 0);
      output[n] = '\0';
      assert(strstr(output, "HTTP/1.1 500 Error"));
      assert(!strstr(output, "HTTP/1.1 200"));
    }
  } else {
    assert(result == 1);
    char byte = 0;
    assert(recv(client[1], &byte, 1, 0) == 1 && byte == 'x');
  }
}

static void fixture_protocol(sidecar_exchange_state *state, const int *client,
                             const int *upstream, int committed) {
  (void)upstream;

  state->failure_origin = SIDECAR_FAILURE_PROTOCOL;
  sidecar_exchange_error(state);
  char output[256];
  ssize_t n = recv(client[1], output, sizeof(output) - 1, MSG_DONTWAIT);
  assert(committed ? n == 0 : n > 0);
  assert(tx.failed);
}

static void fixture_deadline(sidecar_exchange_state *state, const int *client,
                             const int *upstream, int committed) {
  (void)client;
  (void)upstream;

  state->deadline.at_ms = 0;
  msconnector_error_code initial = MSCONNECTOR_ERROR_NONE;
  if (fault == 1)
    initial = MSCONNECTOR_ERROR_HOST_API_FAILURE;
  else if (fault != 0)
    initial = MSCONNECTOR_ERROR_MODSECURITY_FAILURE;
  msconnector_error_set(&state->error, initial, "first typed cause", "fixture");
  assert(msconnector_transaction_contract_init(
             &tx.contract, msconnector_profile_registry_find("lighttpd-stock"),
             "first-cause", "lighttpd", "fixture",
             MSCONNECTOR_TRANSACTION_MODE_SAFE,
             0U) == MSCONNECTOR_TRANSACTION_TRANSITION_OK);
  msconnector_transaction_error_class cause =
      fault == 1 ? MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR
                 : MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE;
  if (fault)
    assert(msconnector_transaction_contract_fail(&tx.contract, cause, 0U) ==
           MSCONNECTOR_TRANSACTION_TRANSITION_OK);
  sidecar_exchange_error(state);
  int expected_status = fault ? 500 : 504;
  if (committed)
    expected_status = 0;
  assert(visible_status == expected_status);
  assert(timeout_calls == (fault ? 0 : 1));
  assert(state->error.code == initial);
  if (fault)
    assert(tx.contract.error_class == cause);
  int actions = host_calls;
  sidecar_exchange_error(state);
  assert(host_calls == actions);
}

static void fixture_phases(sidecar_exchange_state *state, const int *client,
                           const int *upstream, int committed) {
  (void)committed;

  phase_upstream = upstream[0];
  assert(send(upstream[1], "x", 1, 0) == 1);
  int result = sidecar_exchange_response(state);
  assert(result == 0);
  sidecar_exchange_error(state);
  char output[256];
  ssize_t n = recv(client[1], output, sizeof(output) - 1, 0);
  assert(n > 0);
  output[n] = '\0';
  if (fault == 5) {
    assert(strstr(output, "HTTP/1.1 500 Error"));
    assert(native_calls == 1);
  } else {
    assert(fault == 6);
    assert(n == 1 && output[0] == 'x');
    assert(native_calls == 3);
    assert(recv(client[1], output, sizeof(output), 0) == 0);
  }
  close(state->upstream);
}

static void fixture_exchange(const int *client, const int *upstream,
                             const sidecar_options *options,
                             msconnector_runtime *runtime) {
  exchange_allowed = fault == 0;
  phase_upstream = upstream[0];
  if (exchange_allowed)
    assert(send(upstream[1], "x", 1, 0) == 1);
  sidecar_spool_budget budget = {
      .lock = PTHREAD_MUTEX_INITIALIZER, .reserved = 4096U,
      .capacity = 8192U, .free_reserve = 4096U};
  fixture_spool_fd = open("/dev/null", O_RDWR);
  assert(fixture_spool_fd >= 0);
  int result = sidecar_exchange(client[0], options, runtime, &budget);
  assert(budget.reserved == 0U);
  assert(fcntl(fixture_spool_fd, F_GETFD) < 0 && errno == EBADF);
  assert(pthread_mutex_destroy(&budget.lock) == 0);
  assert(result == exchange_allowed);
  assert(cleanup_calls == 1);
  assert(receipt_calls == 1);
}
int main(int argc, char **argv) {
  assert(argc == 5);
  msconnector_runtime runtime = {.mode = atoi(argv[1])};
  int committed = atoi(argv[2]);
  fault = atoi(argv[3]);
  int operation = atoi(argv[4]);
  int client[2];
  int upstream[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, client) == 0);
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, upstream) == 0);
  sidecar_options options = {.timeout_ms = 1000};
  sidecar_exchange_state state;
  sidecar_exchange_state_init(&state, client[0], &options, &runtime);
  state.transaction = &tx;
  state.upstream = upstream[0];
  state.client_response_started = committed;
  state.payload.response_headers.content_length = 1;
  switch (operation) {
  case 0:
    fixture_body(&state, client, upstream, committed);
    break;
  case 1:
    fixture_protocol(&state, client, upstream, committed);
    break;
  case 4:
    fixture_deadline(&state, client, upstream, committed);
    break;
  case 3:
    fixture_phases(&state, client, upstream, committed);
    break;
  default:
    fixture_exchange(client, upstream, &options, &runtime);
    break;
  }
  close(client[0]);
  close(client[1]);
  close(upstream[0]);
  close(upstream[1]);
  printf("sidecar caller mode=%d commit=%d operation=%d fault=%d\n",
         runtime.mode, committed, operation, fault);
  return 0;
}
