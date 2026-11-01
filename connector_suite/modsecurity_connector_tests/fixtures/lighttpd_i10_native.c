
#include "common/runtime/msconnector_runtime.h"
#include "connectors/lighttpd/src/lighttpd_modsecurity_mapper.h"
#include "connectors/profile_registry.h"
#include "msconnector/late_intervention.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
/* Controlled fixture seams preserve real headers above. Read-only mocks
 * accept const arguments; separate native builds verify the actual ABI. */
#define lighttpd_modsecurity_map_request                                       \
  fixture_lighttpd_modsecurity_map_request
#define lighttpd_modsecurity_map_response                                      \
  fixture_lighttpd_modsecurity_map_response
#define msconnector_runtime_transaction_append_request_body_chunk              \
  fixture_msconnector_runtime_transaction_append_request_body_chunk
#define msconnector_runtime_transaction_append_response_body_chunk             \
  fixture_msconnector_runtime_transaction_append_response_body_chunk
#define msconnector_runtime_transaction_begin_request_stream fixture_msconnector_runtime_transaction_begin
#define msconnector_runtime_transaction_begin                                  \
  fixture_msconnector_runtime_transaction_begin
#define msconnector_runtime_transaction_cancel fixture_msconnector_runtime_transaction_cancel
#define msconnector_runtime_transaction_fail                                   \
  fixture_msconnector_runtime_transaction_fail
#define msconnector_runtime_transaction_finish                                 \
  fixture_msconnector_runtime_transaction_finish
#define msconnector_runtime_transaction_finish_host_rejected_request_body      \
  fixture_msconnector_runtime_transaction_finish_host_rejected_request_body
#define msconnector_runtime_transaction_finish_request_body                    \
  fixture_msconnector_runtime_transaction_finish_request_body
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
#define LIGHTTPD_MSCONNECTOR_STREAM_HOOK_ABI_VERSION 2
#define HTTP_VERSION_1_1 1
#define FDEVENT_STREAM_REQUEST 1
#define FDEVENT_STREAM_REQUEST_BUFMIN 2
#define REQUEST_FUNC(n) handler_t n(request_st *r, void *p_d)
typedef enum { HANDLER_GO_ON, HANDLER_FINISHED, HANDLER_ERROR } handler_t;
typedef enum {
  PLUGIN_BODY_HOOK_CONTINUE,
  PLUGIN_BODY_HOOK_ERROR,
  PLUGIN_BODY_HOOK_ABORT
} plugin_body_hook_result;
typedef enum {
  PLUGIN_RESPONSE_ABORT_UPSTREAM_EOF = 1
} plugin_response_abort_reason;
struct chunkqueue {
  off_t bytes_in;
  off_t bytes_out;
};
struct request_st {
  void *plugin_ctx[1];
  struct {
    void *errh;
    int stream_request_body;
  } conf;
  chunkqueue write_queue;
  size_t resp_header_len;
  int http_status;
  int http_version;
  int resp_body_finished;
};
typedef struct {
  unsigned id;
  struct {
    int enabled;
    int expose_host_transaction_id;
  } defaults;
  msconnector_runtime *runtime;
  size_t header_count_limit;
  size_t total_header_limit;
  size_t request_body_limit;
  int request_body_hooks_enabled;
  int response_body_hooks_enabled;
} plugin_data;
struct msconnector_runtime {
  enum msconnector_phase4_mode mode;
};
struct msconnector_runtime_transaction {
  msconnector_transaction_contract contract;
};
typedef struct {
  msconnector_runtime_transaction *transaction;
  lighttpd_modsecurity_map_storage request_storage;
  lighttpd_modsecurity_map_storage response_storage;
  msconnector_request request;
  msconnector_response response;
  char host_request_id[96];
  int technical_failed;
  int failure_response_selected;
  int api_failed;
  int host_response_attempted;
  int response_processed;
  int request_body_finished;
  int request_intervened;
  int request_body_gate_rejected;
  int response_body_finished;
  int response_body_aborted;
  off_t request_body_next_offset;
  off_t response_body_next_offset;
} handler_ctx;
static int fault;
static int invalid_return;
static int native_calls;
static int status_calls;
static int ack_calls;
static msconnector_runtime_transaction *active_tx;
static msconnector_error_code fixture_error_code(void) {
  switch (fault) {
  case 5:
    return MSCONNECTOR_ERROR_TIMEOUT;
  case 6:
    return MSCONNECTOR_ERROR_RUNTIME_UNAVAILABLE;
  case 7:
    return MSCONNECTOR_ERROR_PROTOCOL;
  case 8:
    return MSCONNECTOR_ERROR_MODSECURITY_FAILURE;
  default:
    return MSCONNECTOR_ERROR_HOST_API_FAILURE;
  }
}
static msconnector_transaction_error_class fixture_error_cause(void) {
  switch (fault) {
  case 5:
    return MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT;
  case 6:
    return MSCONNECTOR_TRANSACTION_ERROR_ENGINE_UNAVAILABLE;
  case 7:
    return MSCONNECTOR_TRANSACTION_ERROR_PROTOCOL;
  default:
    return MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE;
  }
}
static int native_result(msconnector_error *error) {
  ++native_calls;
  if (fault) {
    msconnector_error_code code = fixture_error_code();
    msconnector_error_set(error, code, "controlled native failure", "fixture");
    if (active_tx->contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_NONE) {
      msconnector_transaction_error_class cause = fixture_error_cause();
      assert(msconnector_transaction_contract_fail(&active_tx->contract, cause,
                                                   101U) == 0);
    }
    return invalid_return ? -1 : 0;
  }
  return 1;
}
int msconnector_runtime_error_http_status(const msconnector_runtime *r,
                                          msconnector_error_code c) {
  (void)r;
  return msconnector_error_http_status(c);
}
int fixture_msconnector_runtime_transaction_fail(
    msconnector_runtime_transaction *tx, msconnector_transaction_error_class c,
    const msconnector_error *e) {
  (void)e;
  if (tx->contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_NONE)
    assert(msconnector_transaction_contract_fail(&tx->contract, c, 102U) == 0);
  return 1;
}
int fixture_msconnector_runtime_transaction_set_response_commit_state_checked(
    msconnector_runtime_transaction *tx, int h, int b,
    const msconnector_error *e) {
  (void)e;
  tx->contract.response_committed = h;
  (void)b;
  return fault == 4 ? 0 : 1;
}
int fixture_msconnector_runtime_transaction_record_failure_host_action(
    const msconnector_runtime_transaction *tx, int status, int aborted,
    const msconnector_error *e) {
  (void)tx;
  (void)status;
  (void)aborted;
  (void)e;
  ++ack_calls;
  return fault == 14 ? 0 : 1;
}
int fixture_msconnector_runtime_transaction_record_host_action(
    const msconnector_runtime_transaction *tx, const msconnector_decision *d,
    msconnector_decision_action a, int status, const char *t, int abort,
    const msconnector_error *e) {
  (void)tx;
  (void)d;
  (void)a;
  (void)status;
  (void)t;
  (void)abort;
  (void)e;
  ++ack_calls;
  return fault == 11 ? 0 : 1;
}
int fixture_msconnector_runtime_transaction_append_response_body_chunk(
    const msconnector_runtime_transaction *t, const unsigned char *d, size_t n,
    msconnector_error *e) {
  (void)t;
  (void)d;
  (void)n;
  return native_result(e);
}
int fixture_msconnector_runtime_transaction_cancel(
    msconnector_runtime_transaction *tx, int upstream, msconnector_error *error) {
  assert(upstream == 1);
  if (tx->contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_NONE)
    (void)msconnector_transaction_contract_fail(&tx->contract,
        MSCONNECTOR_TRANSACTION_ERROR_UPSTREAM_DISCONNECT, 0);
  return native_result(error);
}
int fixture_msconnector_runtime_transaction_finish_response_body(
    const msconnector_runtime_transaction *t, msconnector_decision *d,
    msconnector_error *e) {
  (void)t;
  msconnector_decision_init(d);
  return native_result(e);
}
int fixture_msconnector_runtime_transaction_finish_request_body(
    const msconnector_runtime_transaction *t, msconnector_decision *d,
    msconnector_error *e) {
  (void)t;
  msconnector_decision_init(d);
  return native_result(e);
}
enum msconnector_phase4_mode
msconnector_runtime_phase4_mode(const msconnector_runtime *r) {
  return r->mode;
}
static handler_t http_status_set_err(request_st *r, int status) {
  ++status_calls;
  if (fault == 10)
    return HANDLER_ERROR;
  r->http_status = status;
  return HANDLER_FINISHED;
}
static handler_t http_status_set_err_fin(request_st *r, int status) {
  r->resp_body_finished = 1;
  return http_status_set_err(r, status);
}
static void http_response_reset(request_st *r) {
  r->http_status = 0;
  r->resp_body_finished = 0;
  r->write_queue.bytes_in = 0;
  r->write_queue.bytes_out = 0;
  r->resp_header_len = 0;
}
/* Logging is intentionally outside the controlled host-action observations. */
static char fixture_log_buffer[4096];
#define log_error(h, f, l, ...)                                                \
  ((void)(h), (void)(f), (void)(l),                                            \
   (void)snprintf(fixture_log_buffer, sizeof(fixture_log_buffer),              \
                  __VA_ARGS__))

static handler_ctx mod_msconnector_failed_context = {.technical_failed = 1};
static handler_ctx *allocated_ctx;
static int cleanup_calls;
static handler_ctx *handler_ctx_create(const plugin_data *p) {
  (void)p;
  return fault == 9 ? NULL : allocated_ctx;
}
static void handler_ctx_destroy(handler_ctx **c) {
  if (*c) {
    ++cleanup_calls;
    *c = NULL;
  }
}
static handler_t mod_msconnector_prepare_request_body(const request_st *r,
                                                      const plugin_data *p,
                                                      const handler_ctx *c) {
  (void)r;
  (void)p;
  (void)c;
  return HANDLER_GO_ON;
}
static int mod_msconnector_emit_host_transaction_id(const request_st *r,
                                                    const plugin_data *p,
                                                    const handler_ctx *c) {
  (void)r;
  (void)p;
  (void)c;
  return 1;
}
void msconnector_runtime_request_contract(
    const msconnector_runtime *r, msconnector_request_mapper_contract *c) {
  (void)r;
  memset(c, 0, sizeof(*c));
}
void msconnector_runtime_response_contract(
    const msconnector_runtime *r, msconnector_response_mapper_contract *c) {
  (void)r;
  memset(c, 0, sizeof(*c));
}
int fixture_lighttpd_modsecurity_map_request(
    const request_st *r, const msconnector_request_mapper_contract *c, size_t l,
    const lighttpd_modsecurity_map_storage *s, const msconnector_request *out,
    const char *e, size_t n) {
  (void)r;
  (void)c;
  (void)l;
  (void)s;
  (void)out;
  (void)e;
  (void)n;
  return 1;
}
int fixture_lighttpd_modsecurity_map_response(
    const request_st *r, const msconnector_response_mapper_contract *c,
    size_t l, const lighttpd_modsecurity_map_storage *s,
    const msconnector_response *out, const char *e, size_t n) {
  (void)r;
  (void)c;
  (void)l;
  (void)s;
  (void)out;
  (void)e;
  (void)n;
  return 1;
}
int fixture_msconnector_runtime_transaction_begin(
    const msconnector_runtime *r, const msconnector_request *q, const char *h,
    msconnector_runtime_transaction **t, msconnector_decision *d,
    msconnector_error *e) {
  (void)r;
  (void)q;
  (void)h;
  *t = allocated_ctx->transaction;
  msconnector_decision_init(d);
  return native_result(e);
}
int fixture_msconnector_runtime_transaction_process_response_headers(
    const msconnector_runtime_transaction *t, const msconnector_response *r,
    msconnector_decision *d, msconnector_error *e) {
  (void)t;
  (void)r;
  msconnector_decision_init(d);
  return native_result(e);
}
int fixture_msconnector_runtime_transaction_finish(
    const msconnector_runtime_transaction *t, const msconnector_error *e) {
  (void)t;
  (void)e;
  ++native_calls;
  return fault == 12 ? 0 : 1;
}
int fixture_msconnector_runtime_transaction_finish_host_rejected_request_body(
    const msconnector_runtime_transaction *t, const msconnector_error *e) {
  (void)t;
  (void)e;
  return 1;
}
static handler_t
mod_msconnector_finish_uninspected_response_body(const request_st *r,
                                                 const handler_ctx *c) {
  (void)r;
  (void)c;
  return fault == 13 ? HANDLER_ERROR : HANDLER_GO_ON;
}
REQUEST_FUNC(mod_msconnector_handle_response_start);

typedef struct {
  handler_ctx *ctx;
  msconnector_error runtime_error;
} mod_msconnector_body_append_context;
int fixture_msconnector_runtime_transaction_append_request_body_chunk(
    const msconnector_runtime_transaction *t, const unsigned char *d, size_t n,
    msconnector_error *e) {
  (void)t;
  (void)d;
  (void)n;
  return native_result(e);
}
int lighttpd_modsecurity_visit_body_range(
    const chunkqueue *q, off_t o, off_t n,
    lighttpd_modsecurity_body_chunk_consumer c, void *u, char *e, size_t l) {
  (void)q;
  (void)o;
  (void)n;
  return c(u, (const unsigned char *)"x", 1, e, l);
}
#include "native-lighttpd-definitions.inc"
static int fixture_dispatch(int operation, request_st *r, plugin_data *p,
                            handler_ctx *ctx, const msconnector_runtime *runtime) {
  int result;
  if (operation == 0)
    result = mod_msconnector_finish_request_body(r, p, ctx);
  else if (operation == 1)
    result = mod_msconnector_handle_response_body(r, (const unsigned char *)"x",
                                                  1, 0, 0, p);
  else if (operation == 2)
    result = mod_msconnector_handle_response_body(r, NULL, 0, 0, 1, p);
  else if (operation == 3)
    result = mod_msconnector_handle_response_abort(
        r, PLUGIN_RESPONSE_ABORT_UPSTREAM_EOF, p);
  else if (operation == 10 || operation == 11) {
    ctx->request_body_finished = 1;
    ctx->response_body_finished = operation == 10;
    if (operation == 11)
      p->response_body_hooks_enabled = 0;
    result = mod_msconnector_handle_request_reset(r, p);
    assert(result == HANDLER_ERROR && cleanup_calls == 1 && status_calls == 0);
    assert(mod_msconnector_handle_request_reset(r, p) == HANDLER_GO_ON);
    assert(cleanup_calls == 1 && native_calls == (operation == 10 ? 1 : 0));
    return 0;
  } else if (operation == 8 || operation == 9) {
    msconnector_decision decision;
    msconnector_decision_set_deny(&decision, 403, "fixture-rule",
                                  "fixture deny");
    result = mod_msconnector_apply_decision(r, p, ctx, &decision);
  } else if (operation == 7) {
    chunkqueue q = {0};
    result = mod_msconnector_handle_request_body(r, &q, 0, 1, 0, 1, p);
  } else if (operation == 5) {
    r->plugin_ctx[0] = NULL;
    result = mod_msconnector_handle_uri_clean(r, p);
  } else if (operation == 6) {
    ctx->response_processed = 0;
    result = mod_msconnector_handle_response_start(r, p);
  } else
    result = mod_msconnector_fail_request(r, runtime, ctx,
                                          MSCONNECTOR_ERROR_HOST_API_FAILURE);
  return result;
}
static void fixture_reenter(int operation, request_st *r, plugin_data *p,
                            handler_ctx *ctx) {
  if (operation == 5)
    assert(mod_msconnector_handle_uri_clean(r, p) == HANDLER_ERROR);
  else if (operation == 6)
    assert(mod_msconnector_handle_response_start(r, p) ==
           (ctx->failure_response_selected ? HANDLER_GO_ON : HANDLER_ERROR));
  else if (operation == 7) {
    chunkqueue q = {0};
    assert(mod_msconnector_handle_request_body(r, &q, 0, 1, 0, 1, p) ==
           HANDLER_ERROR);
  } else if (operation == 0)
    assert(mod_msconnector_finish_request_body(r, p, ctx) == HANDLER_ERROR);
  else
    assert(mod_msconnector_handle_response_body(
               r, NULL, 0, ctx->response_body_next_offset, 1, p) ==
           PLUGIN_BODY_HOOK_ERROR);
}
/* Independent HTTP oracle: do not derive expected values from Common mapping.
 */
static int fixture_expected_status(int operation) {
  if (operation == 4)
    return 500;
  switch (fault) {
  case 5:
    return 504;
  case 6:
    return 503;
  case 7:
    return 502;
  default:
    return 500;
  }
}
typedef struct {
  int operation;
  int commit;
  int result;
  int calls;
  int statuses;
  int acks;
} fixture_verification_snapshot;

static void fixture_verify(const fixture_verification_snapshot *snapshot,
                           request_st *r, plugin_data *p, handler_ctx *ctx,
                           const msconnector_runtime_transaction *tx) {
  if (fault || snapshot->operation == 3 || snapshot->operation == 4) {
    assert(ctx->technical_failed || fault == 9);
    assert(snapshot->operation == 0 || snapshot->result == HANDLER_ERROR ||
           snapshot->result == PLUGIN_BODY_HOOK_ERROR ||
           (snapshot->operation == 4 && snapshot->result == HANDLER_FINISHED));
    assert(snapshot->commit ? snapshot->statuses == 0
                            : snapshot->statuses == 1);
    int expected = fixture_expected_status(snapshot->operation);
    if (snapshot->operation == 8) {
      /* Reset retired the uncommitted upstream200 before the injected host
       * setter failed. No replacement status was successfully selected. */
      assert(r->http_status == 0);
    }
    else if (snapshot->operation == 9)
      assert(r->http_status == 403);
    else
      assert(r->http_status == (snapshot->commit ? 200 : expected));
    assert(fault == 9 ||
           tx->contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE);
    msconnector_transaction_error_class first_cause = tx->contract.error_class;
    fixture_reenter(snapshot->operation, r, p, ctx);
    assert(tx->contract.error_class == first_cause);
    assert(native_calls == snapshot->calls);
    assert(status_calls == snapshot->statuses);
    assert(ack_calls == snapshot->acks);
    assert(mod_msconnector_handle_request_reset(r, p) == HANDLER_ERROR);
    assert(mod_msconnector_handle_request_reset(r, p) == HANDLER_GO_ON);
    assert(cleanup_calls == 1);
    assert(native_calls == snapshot->calls);
  } else {
    assert(!ctx->technical_failed);
    assert(snapshot->result == 0);
    assert(snapshot->statuses == 0);
  }
}
int main(int argc, char **argv) {
  assert(argc == 5);
  int mode = atoi(argv[1]);
  int commit = atoi(argv[2]);
  int operation = atoi(argv[3]);
  fault = atoi(argv[4]);
  msconnector_runtime runtime = {.mode = (enum msconnector_phase4_mode)mode};
  msconnector_runtime_transaction tx = {0};
  const msconnector_transaction_profile *profile =
      msconnector_profile_registry_find("lighttpd-patched");
  assert(profile != NULL && !profile->strict_post_commit_action);
  assert(msconnector_transaction_contract_init(
             &tx.contract, profile, "lighttpd-test", "lighttpd", "fixture",
             MSCONNECTOR_TRANSACTION_MODE_SAFE, 100U) == 0);
  active_tx = &tx;
  handler_ctx ctx = {.transaction = &tx, .response_processed = 1};
  request_st r = {.plugin_ctx = {&ctx},
                  .resp_header_len = 20,
                  .http_status = 200,
                  .http_version = 1};
  plugin_data p = {.defaults = {.enabled = 1},
                   .runtime = &runtime,
                   .request_body_limit = 8192,
                   .request_body_hooks_enabled = 1,
                   .response_body_hooks_enabled = 1};
  allocated_ctx = &ctx;
  if (commit)
    r.write_queue.bytes_out = commit == 1 ? 20 : 21;
  invalid_return = fault == 2;
  int result = fixture_dispatch(operation, &r, &p, &ctx, &runtime);
  if (operation == 10 || operation == 11)
    return 0;
  const fixture_verification_snapshot snapshot = {.operation = operation,
                                                  .commit = commit,
                                                  .result = result,
                                                  .calls = native_calls,
                                                  .statuses = status_calls,
                                                  .acks = ack_calls};
  fixture_verify(&snapshot, &r, &p, &ctx, &tx);
  printf("native caller mode=%d commit=%d operation=%d fault=%d calls=%d "
         "status=%d ack=%d\n",
         mode, commit, operation, fault, native_calls, status_calls, ack_calls);
  return 0;
}
