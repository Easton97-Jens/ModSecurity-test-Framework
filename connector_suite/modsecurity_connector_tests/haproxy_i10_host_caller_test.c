#include "haproxy_modsecurity_binding.h"
#include "msconnector/block_statuses.h"
#include "msconnector/config.h"
#include "msconnector/late_intervention.h"
#include "msconnector/limits.h"
#include "response_companion_client.h"
#include <assert.h>
#include <pthread.h>
#include "msconnector/event_jsonl.h"
#include "msconnector/event_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Real ABI declarations above; controlled readonly hooks below. */
#define haproxy_modsecurity_transaction_abort                                  \
  fixture_haproxy_modsecurity_transaction_abort
#define haproxy_modsecurity_transaction_finish_with_decision                   \
  fixture_haproxy_modsecurity_transaction_finish_with_decision
#define haproxy_modsecurity_transaction_set_response_commit_state              \
  fixture_haproxy_modsecurity_transaction_set_response_commit_state
#define haproxy_modsecurity_transaction_finish_request_body                    \
  fixture_haproxy_modsecurity_transaction_finish_request_body
#define haproxy_modsecurity_transaction_finish_response_body                   \
  fixture_haproxy_modsecurity_transaction_finish_response_body
#define msconnector_response_companion_client_open                             \
  fixture_msconnector_response_companion_client_open
#define msconnector_response_companion_client_claim                            \
  fixture_msconnector_response_companion_client_claim
#define msconnector_response_companion_client_response_headers                 \
  fixture_msconnector_response_companion_client_response_headers
#define msconnector_response_companion_client_body_eos                         \
  fixture_msconnector_response_companion_client_body_eos
#define msconnector_response_companion_client_body_chunk                       \
  fixture_msconnector_response_companion_client_body_chunk
#define msconnector_response_companion_client_commit                           \
  fixture_msconnector_response_companion_client_commit
#define msconnector_response_companion_client_outcome                          \
  fixture_msconnector_response_companion_client_outcome
#define msconnector_response_companion_client_release                          \
  fixture_msconnector_response_companion_client_release
#define msconnector_response_companion_client_close                            \
  fixture_msconnector_response_companion_client_close
#define msconnector_response_companion_client_cancel_with_cause                \
  fixture_msconnector_response_companion_client_cancel_with_cause
#define HAPROXY_MODSECURITY_HTX_RESPONSE_HANDLE_LENGTH 64U
#define HAPROXY_MODSECURITY_HTX_MAX_PROTOCOL_BYTES 32U
#define CF_ISRESP 1U
#define SF_ERR_KILLED 9U
#define SC_FL_NOLINGER 4U
struct channel {
  unsigned int flags;
  int buf;
  size_t output;
  unsigned int erase_order;
};
struct htx {
  int unused;
};
struct htx_sl {
  int unused;
};
struct ist {
  const char *ptr;
  size_t len;
};
struct http_msg {
  struct channel *chn;
};
struct http_txn {
  short status;
};
#define REDIRECT_TYPE_LOCATION 2
#define REDIRECT_FLAG_FROM_REQ 4U
struct redirect_rule { int type; int rdr_len; char *rdr_str; int code; unsigned int flags; };
#define CO_FL_XPRT_READY 8U
#define SE_FL_T_MUX 1U
struct stream;
struct connection;
struct xprt_ops { void (*shutw)(struct connection *, void *, int); };
struct mux_ops { const char *name; };
struct connection {
  unsigned int flags;
  const struct xprt_ops *xprt;
  void *xprt_ctx;
  const struct mux_ops *mux;
  struct stream *owner;
  unsigned int hard_calls;
  unsigned int clean_calls;
  unsigned int close_notify;
  unsigned int quiet;
  unsigned int hard_order;
  unsigned int clean_order;
  unsigned int stream_shutdowns;
};
struct sedesc { struct connection *conn; unsigned int flags; };
struct stconn { unsigned int flags; unsigned int aborts; unsigned int shutdowns; struct sedesc *sedesc; };
static int sc_ep_test(const struct stconn *sc, unsigned int flags) {
  return (sc->sedesc->flags & flags) != 0;
}
/* HAPROXY_TRANSPORT_API_BEGIN */
/* Pinned HAProxy 3.2.25 public inline bodies; controlled endpoint structs. */
static inline int conn_xprt_ready(const struct connection *conn)
{
	return (conn->flags & CO_FL_XPRT_READY);
}

static inline const char *conn_get_mux_name(const struct connection *conn)
{
	if (!conn || !conn->mux)
		return "NONE";
	return conn->mux->name;
}

static inline void conn_xprt_shutw(struct connection *c)
{
	/* clean data-layer shutdown */
	if (c->xprt && c->xprt->shutw)
		c->xprt->shutw(c, c->xprt_ctx, 1);
}

static inline void conn_xprt_shutw_hard(struct connection *c)
{
	/* unclean data-layer shutdown */
	if (c->xprt && c->xprt->shutw)
		c->xprt->shutw(c, c->xprt_ctx, 0);
}

static inline struct connection *__sc_conn(const struct stconn *sc)
{
	return sc->sedesc->conn;
}

static inline struct connection *sc_conn(const struct stconn *sc)
{
	if (sc_ep_test(sc, SE_FL_T_MUX))
		return __sc_conn(sc);
	return NULL;
}
/* HAPROXY_TRANSPORT_API_END */
struct stream {
  struct http_txn *txn;
  unsigned int replies;
  unsigned int kills;
  unsigned int stream_aborts;
  struct channel res;
  struct stconn frontend;
  struct stconn *scf;
  struct stconn backend;
  struct stconn *scb;
  struct connection client_conn;
  struct connection server_conn;
  struct sedesc client_desc;
  struct sedesc server_desc;
  unsigned int stream_abort_order;
  unsigned int async_order;
  unsigned int redirects;
  char location[1024];
  size_t delivered_bytes;
};
struct filter {
  void *ctx;
  void *conf;
};
#define FLT_CONF(f) ((f)->conf)
#define ha_warning(...)                                                        \
  do {                                                                         \
    if (0)                                                                     \
      fprintf(stderr, __VA_ARGS__);                                            \
  } while (0)
#define haproxy_modsecurity_transaction_error fixture_haproxy_modsecurity_transaction_error
#define haproxy_modsecurity_error_event_write fixture_haproxy_modsecurity_error_event_write
static msconnector_transaction_error_class fixture_haproxy_modsecurity_transaction_error(
    const haproxy_modsecurity_transaction *t) {
  (void)t;
  return MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR;
}
static int fixture_haproxy_modsecurity_error_event_write(
    const haproxy_modsecurity_decision *d, const char *id, char *line, size_t capacity) {
  assert(d->error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE);
  (void)id;
  return snprintf(line, capacity, "typed technical error\n") > 0;
}
/* PRODUCT_STRUCTS */
static int native_result;
static int native_disruptive;
static int common_result;
static int finish_result;
static int commit_result;
static int open_result;
static int claim_result;
static int claim_calls;
static int release_result;
static int result_success;
static int decision_kind;
static int append_calls;
static int finish_calls;
static int abort_calls;
static int eos_calls;
static int close_result;
static int close_calls;
static int outcome_calls;
static int release_calls;
static int outcome_result;
static int cancel_result;
static int cancel_calls;
static struct stream *observed_stream;
static int register_calls;
static int unregistered;
static int redirect_api_result;
static int redirect_status;
static unsigned int redirect_api_calls;
static unsigned int last_redirect_flags;
static unsigned int redirect_order;
static unsigned int outcome_order;
static unsigned int release_order;
static const char *redirect_input;
static struct haproxy_modsecurity_htx_filter_context *observed_context;
static unsigned int call_sequence;
static const struct mux_ops fixture_h1_mux = {"H1"};
static const struct mux_ops fixture_h2_mux = {"H2"};
static const struct mux_ops fixture_unknown_mux = {"OTHER"};
/* Model the independently traced ssl_sock_shutw contract. This is not wire
 * evidence: only a real host/client retest can establish the TLS result. */
static void fixture_tls_shutw(struct connection *conn, void *context, int clean) {
  assert(context == conn && conn->owner != NULL);
  if (!clean) {
    conn->hard_calls++; conn->quiet = 1; conn->hard_order = ++call_sequence;
    assert(conn->owner->res.output == 0);
  } else {
    conn->clean_calls++; conn->clean_order = ++call_sequence;
    if (!conn->quiet) conn->close_notify++;
  }
}
static const struct xprt_ops fixture_tls = {fixture_tls_shutw};
static const struct xprt_ops fixture_raw = {NULL};
static void initialize_transports(struct stream *s) {
  memset(&s->frontend, 0, sizeof(s->frontend));
  memset(&s->backend, 0, sizeof(s->backend));
  s->client_conn = (struct connection){.flags=CO_FL_XPRT_READY,
    .xprt=&fixture_tls, .mux=&fixture_h1_mux, .owner=s};
  s->server_conn = s->client_conn;
  s->client_conn.xprt_ctx = &s->client_conn;
  s->server_conn.xprt_ctx = &s->server_conn;
  s->client_desc = (struct sedesc){&s->client_conn, SE_FL_T_MUX};
  s->server_desc = (struct sedesc){&s->server_conn, SE_FL_T_MUX};
  s->frontend.sedesc=&s->client_desc; s->backend.sedesc=&s->server_desc;
  s->scf=&s->frontend; s->scb=&s->backend;
}
static void http_set_term_flags(const struct stream *s) { (void)s; }
static void *http_error_message(const struct stream *s) {
  (void)s;
  return NULL;
}
static void http_reply_and_close(struct stream *s, short status, void *reply) {
  (void)reply;
  assert(status == s->txn->status);
  s->replies++;
}
/* Controlled public reply boundary; full HTX serialization is a native host obligation. */
static int http_apply_redirect_rule(struct redirect_rule *rule,struct stream *s,struct http_txn *txn) {
  assert(s && txn==s->txn && rule->type==REDIRECT_TYPE_LOCATION);
  assert(observed_context->lifecycle.disabled && observed_context->transaction==NULL);
  assert(rule->rdr_len>0 && (size_t)rule->rdr_len<sizeof(s->location));
  assert(rule->rdr_str[rule->rdr_len]==0);
  redirect_api_calls++;last_redirect_flags=rule->flags;
  if(redirect_api_result!=1)return redirect_api_result;
  memcpy(s->location,rule->rdr_str,(size_t)rule->rdr_len+1U);
  txn->status=(short)rule->code;s->replies++;s->redirects++;
  redirect_order=++call_sequence;
  return 1;
}
void channel_htx_erase(struct channel *channel, const struct htx *htx) {
  (void)htx;
  channel->output = 0;
  channel->buf = 0;
  channel->erase_order = ++call_sequence;
}
void stream_abort(struct stream *s) { s->stream_aborts++; s->stream_abort_order=++call_sequence; }
void sc_abort(struct stconn *sc) { sc->aborts++; }
void sc_shutdown(struct stconn *sc) {
  sc->shutdowns++;
  if (!sc->sedesc) return;
  struct connection *conn=sc_conn(sc);
  if (!conn || !conn_xprt_ready(conn)) return;
  const char *mux=conn_get_mux_name(conn);
  if (mux && strcmp(mux,"H1")==0) conn_xprt_shutw(conn);
  else if (mux && strcmp(mux,"H2")==0) conn->stream_shutdowns++;
}
static void stream_shutdown(struct stream *s, unsigned int reason) {
  assert(reason == SF_ERR_KILLED);
  s->kills++;
  s->async_order = ++call_sequence;
}
static void unregister_data_filter(const struct stream *s,
                                   const struct channel *c,
                                   const struct filter *f) {
  (void)s;
  (void)c;
  (void)f;
  unregistered++;
}
static void register_data_filter(const struct stream *s,
                                 const struct channel *c,
                                 const struct filter *f) {
  (void)s;
  (void)c;
  (void)f;
  register_calls++;
}
static void haproxy_modsecurity_htx_request_snapshot_free(
    const struct haproxy_modsecurity_htx_filter_context *c) {
  (void)c;
}

static void fixture_haproxy_modsecurity_transaction_abort(
    const haproxy_modsecurity_transaction *t) {
  (void)t;
  abort_calls++;
}
static int fixture_haproxy_modsecurity_transaction_finish_with_decision(
    const haproxy_modsecurity_transaction *t, haproxy_modsecurity_decision *d) {
  if (finish_result != 0) d->error_class = MSCONNECTOR_TRANSACTION_ERROR_CLEANUP_INCOMPLETE;
  (void)t;
  finish_calls++;
  return finish_result;
}
static int fixture_haproxy_modsecurity_transaction_set_response_commit_state(
    const haproxy_modsecurity_transaction *t, int headers, int body) {
  (void)t;
  assert(headers == 1 && body == 0);
  return commit_result;
}
static int fixture_haproxy_modsecurity_transaction_finish_request_body(
    const haproxy_modsecurity_transaction *t, haproxy_modsecurity_decision *d) {
  (void)t;
  memset(d, 0, sizeof(*d));
  finish_calls++;
  return native_result;
}
static int fixture_haproxy_modsecurity_transaction_finish_response_body(
    const haproxy_modsecurity_transaction *t, haproxy_modsecurity_decision *d) {
  (void)t;
  memset(d, 0, sizeof(*d));
  d->disruptive = native_disruptive;
  d->status = native_disruptive ? 403 : 200;
  finish_calls++;
  return native_result;
}
static int
haproxy_modsecurity_htx_append_request_payload(const struct filter *f,
                                               const struct http_msg *m,
                                               unsigned int o, unsigned int n) {
  (void)f;
  (void)m;
  (void)o;
  (void)n;
  append_calls++;
  return native_result;
}
static int haproxy_modsecurity_htx_append_response_payload(
    const struct filter *f, const struct http_msg *m, unsigned int o,
    unsigned int n) {
  return haproxy_modsecurity_htx_append_request_payload(f, m, o, n);
}
static int haproxy_modsecurity_htx_append_companion_response_payload(
    const struct filter *f, const struct http_msg *m, unsigned int o,
    unsigned int n) {
  return haproxy_modsecurity_htx_append_request_payload(f, m, o, n);
}
static int haproxy_modsecurity_htx_process_response_headers(
    const struct stream *s, struct filter *f, const struct http_msg *m) {
  (void)s;
  (void)m;
  ((struct haproxy_modsecurity_htx_filter_context *)f->ctx)
      ->response.headers_seen = 1;
  return native_result;
}
static int haproxy_modsecurity_htx_companion_enabled(
    const struct haproxy_modsecurity_htx_filter_config *cfg) {
  (void)cfg;
  return 1;
}
static int haproxy_modsecurity_htx_copy_response_handle(
    const struct stream *s, struct haproxy_modsecurity_htx_filter_context *c) {
  (void)s;
  c->response.handle_present = 1;
  return 0;
}
static int fixture_msconnector_response_companion_client_open(
    msconnector_response_companion_client *c, const char *path,
    uint64_t timeout, uid_t uid, gid_t gid, const msconnector_error *e) {
  (void)path;
  (void)timeout;
  (void)uid;
  (void)gid;
  (void)e;
  c->opened = 1;
  return open_result;
}
static int fixture_msconnector_response_companion_client_claim(
    msconnector_response_companion_client *c, const char *handle,
    msconnector_response_companion_result *r, const msconnector_error *e) {
  (void)handle;
  (void)e;
  c->claimed = 1;
  claim_calls++;
  memset(r, 0, sizeof(*r));
  return claim_result;
}
static struct htx *htxbuf(const int *b) {
  static struct htx h;
  (void)b;
  return &h;
}
static struct htx_sl *http_get_stline(const struct htx *h) {
  static struct htx_sl s;
  (void)h;
  return &s;
}
static struct ist htx_sl_res_vsn(const struct htx_sl *s) {
  (void)s;
  return (struct ist){"HTTP/1.1", 8};
}
static int haproxy_modsecurity_htx_copy_headers(
    const struct htx *h, struct haproxy_modsecurity_htx_owned_headers *out) {
  (void)h;
  memset(out, 0, sizeof(*out));
  return 0;
}
static int haproxy_modsecurity_htx_copy_common_headers(
    const struct haproxy_modsecurity_htx_owned_headers *h,
    msconnector_header **out) {
  (void)h;
  *out = NULL;
  return 0;
}
static void haproxy_modsecurity_htx_owned_headers_free(
    const struct haproxy_modsecurity_htx_owned_headers *h) {
  (void)h;
}
static char *haproxy_modsecurity_htx_dup_ist(struct ist p, size_t max) {
  assert(p.len <= max);
  char *out = malloc(p.len + 1);
  assert(out);
  memcpy(out, p.ptr, p.len);
  out[p.len] = '\0';
  return out;
}
static int haproxy_modsecurity_htx_handle_request_headers(
    const struct stream *s, const struct filter *f, const struct http_msg *m) {
  (void)s;
  (void)f;
  (void)m;
  assert(0 && "terminal request was restarted");
  return 1;
}
static void haproxy_modsecurity_htx_report_decision(
    const char *p, const struct haproxy_modsecurity_htx_filter_context *c,
    const haproxy_modsecurity_decision *d) {
  (void)p;
  (void)c;
  (void)d;
}
static void haproxy_modsecurity_htx_report_late_decision(
    const struct haproxy_modsecurity_htx_filter_config *cfg,
    const struct haproxy_modsecurity_htx_filter_context *c,
    const haproxy_modsecurity_decision *d) {
  (void)cfg;
  (void)c;
  (void)d;
}
static void haproxy_modsecurity_htx_companion_result_reset(
    msconnector_response_companion_result *r) {
  free(r->redirect_url);
  memset(r, 0, sizeof(*r));
}
static int result(msconnector_response_companion_result *r) {
  r->success = result_success;
  r->decision = decision_kind;
  r->status = 200;
  if (decision_kind == MSCONNECTOR_DECISION_KIND_REDIRECT) {
    r->status = (uint16_t)redirect_status;
  } else if (decision_kind == MSCONNECTOR_DECISION_KIND_DENY) {
    r->status = 403;
  }
  if(decision_kind==MSCONNECTOR_DECISION_KIND_REDIRECT && redirect_input) {
    size_t length=strlen(redirect_input);r->redirect_url=malloc(length+1U);assert(r->redirect_url);
    memcpy(r->redirect_url,redirect_input,length+1U);
  }
  return common_result;
}
static int fixture_msconnector_response_companion_client_response_headers(
    const msconnector_response_companion_client *c,
    const msconnector_response *response,
    msconnector_response_companion_result *r, const msconnector_error *e) {
  (void)c;
  (void)response;
  (void)e;
  return result(r);
}
static int fixture_msconnector_response_companion_client_body_eos(
    msconnector_response_companion_client *c,
    msconnector_response_companion_result *r, const msconnector_error *e) {
  (void)e;
  eos_calls++;
  c->response_eos = 1;
  return result(r);
}
static int fixture_msconnector_response_companion_client_body_chunk(
    const msconnector_response_companion_client *c, const unsigned char *d,
    size_t n, msconnector_response_companion_result *r,
    const msconnector_error *e) {
  (void)c;
  (void)d;
  (void)n;
  (void)e;
  append_calls++;
  return result(r);
}
static int fixture_msconnector_response_companion_client_commit(
    const msconnector_response_companion_client *c, int h, int b,
    msconnector_response_companion_result *r, const msconnector_error *e) {
  (void)c;
  (void)h;
  (void)b;
  (void)e;
  return result(r);
}
static int fixture_msconnector_response_companion_client_outcome(
    const msconnector_response_companion_client *c,
    msconnector_decision_action a, int s, int aborted,
    msconnector_response_companion_result *r, const msconnector_error *e) {
  (void)c;
  (void)s;
  (void)e;
  outcome_calls++;
  assert(!aborted && "requested kill is not observed abort");
  if (a == MSCONNECTOR_DECISION_ACTION_DENY)
    assert(observed_stream->replies == 1);
  if(decision_kind==MSCONNECTOR_DECISION_KIND_REDIRECT)assert(a==MSCONNECTOR_DECISION_ACTION_REDIRECT);
  if (a == MSCONNECTOR_DECISION_ACTION_REDIRECT) {
    assert(observed_stream->replies==1 && observed_stream->redirects==1);
    assert(observed_stream->txn->status==s && s==redirect_status);
    assert(strcmp(observed_stream->location,redirect_input)==0);
    outcome_order=++call_sequence;assert(outcome_order>redirect_order);
  }
  (void)result(r);
  return outcome_result;
}
static int fixture_msconnector_response_companion_client_release(
    const msconnector_response_companion_client *c,
    msconnector_response_companion_result *r, const msconnector_error *e) {
  (void)c;
  (void)e;
  release_calls++;
  if(decision_kind==MSCONNECTOR_DECISION_KIND_REDIRECT) {
    assert(outcome_calls==1 && outcome_result==1);
    release_order=++call_sequence;assert(release_order>outcome_order);
  }
  (void)result(r);
  return release_result;
}
static int fixture_msconnector_response_companion_client_close(
    msconnector_response_companion_client *c, const msconnector_error *e) {
  (void)e;
  close_calls++;
  c->opened = 0;
  c->claimed = 0;
  c->closed = 1;
  return close_result;
}
static int fixture_msconnector_response_companion_client_cancel_with_cause(
    const msconnector_response_companion_client *c,
    msconnector_response_companion_cancel_cause cause,
    msconnector_response_companion_result *r, const msconnector_error *e) {
  (void)c;
  (void)cause;
  (void)e;
  cancel_calls++;
  (void)result(r);
  return cancel_result;
}
/* PRODUCT_FUNCTIONS */
static void reset(struct haproxy_modsecurity_htx_filter_context *c,
                  struct stream *s) {
  memset(c, 0, sizeof(*c));
  c->transaction = (haproxy_modsecurity_transaction *)c;
  c->request.headers_seen = 1;
  c->response.headers_seen = 1;
  c->request.finished = 1;
  c->companion.client.claimed = 1;
  c->companion.client.opened = 1;
  s->txn->status = 200;
  s->replies = 0;
  s->kills = 0;
  s->stream_aborts = 0;
  s->res.output = 0;
  s->delivered_bytes = 0;
  s->redirects=0;s->location[0]=0;
  redirect_api_result=1;redirect_status=302;
  redirect_input="https://no-crs.invalid/phase3-redirect";
  redirect_api_calls=0;
  last_redirect_flags=0;
  redirect_order=0;
  outcome_order=0;
  release_order=0;
  observed_context=c;
  initialize_transports(s);
  call_sequence = 0;
  s->res.erase_order = 0;
  s->stream_abort_order = 0;
  s->async_order = 0;
  native_disruptive = 0;
  native_result = 1;
  common_result = 1;
  finish_result = 0;
  commit_result = 0;
  open_result = 1;
  claim_result = 1;
  release_result = 1;
  result_success = 1;
  claim_calls = 0;
  observed_stream = s;
  outcome_result = 1;
  cancel_result = 1;
  cancel_calls = 0;
  close_result = 1;
  decision_kind = MSCONNECTOR_DECISION_KIND_ALLOW;
  append_calls = 0;
  finish_calls = 0;
  abort_calls = 0;
  eos_calls = 0;
  close_calls = 0;
  outcome_calls = 0;
  release_calls = 0;
  register_calls = 0;
  unregistered = 0;
}
struct fixture_environment {
  struct haproxy_modsecurity_htx_filter_context c;
  struct haproxy_modsecurity_htx_filter_config config;
  struct filter f;
  struct http_txn txn;
  struct stream s;
  struct stream neighbour;
  struct channel request_channel;
  struct channel response_channel;
  struct http_msg req;
  struct http_msg res;
};
static void initialize_environment(struct fixture_environment *e) {
  memset(e, 0, sizeof(*e));
  e->f = (struct filter){&e->c, &e->config};
  e->s.txn = &e->txn;
  e->neighbour.txn = &e->txn;
  initialize_transports(&e->neighbour);
  e->response_channel.flags = CF_ISRESP;
  e->req.chn = &e->request_channel;
  e->res.chn = &e->response_channel;
}
static void check_forwardable(void) {
  const int invalid[] = {0, -1, 2};
  msconnector_response_companion_result forwardable = {0};
  forwardable.decision = MSCONNECTOR_DECISION_KIND_ALLOW;
  for (size_t bad = 0; bad < 3; bad++) {
    forwardable.success = invalid[bad];
    assert(
        !haproxy_modsecurity_htx_companion_result_is_forwardable(&forwardable));
  }
  forwardable.success = 1;
  assert(haproxy_modsecurity_htx_companion_result_is_forwardable(&forwardable));
}
static void check_terminal(struct fixture_environment *e, int companion,
                           int commitment) {
  reset(&e->c, &e->s);
  e->c.companion.mode = companion;
  e->c.response.headers_committed = commitment != 0;
  e->c.response.body_started = commitment == 2;
  haproxy_modsecurity_htx_fail_closed_request_phase(&e->s, &e->c,
                                                    "technical failure");
  assert(e->c.lifecycle.fail_closed && e->c.lifecycle.disabled);
  assert(e->s.replies == (unsigned int)(commitment == 0));
  assert(e->s.kills == (unsigned int)(commitment != 0));
  assert(commitment == 0 ? e->txn.status == 503 : e->txn.status == 200);
  haproxy_modsecurity_htx_fail_closed_request_phase(&e->s, &e->c,
                                                    "second failure");
  assert(e->s.replies + e->s.kills == 1 && abort_calls == 1);
  assert(haproxy_modsecurity_htx_filter_http_headers(&e->s, &e->f, &e->req) ==
         -1);
  assert(haproxy_modsecurity_htx_filter_request_payload(&e->s, &e->f, &e->req,
                                                        0, 4) == -1);
  assert(haproxy_modsecurity_htx_filter_http_payload(&e->s, &e->f, &e->res, 0,
                                                     4) == -1);
  assert(haproxy_modsecurity_htx_filter_http_end(&e->s, &e->f, &e->res) == -1);
  assert(append_calls == 0 && eos_calls == 0 && finish_calls == 0);
  assert(e->neighbour.replies == 0 && e->neighbour.kills == 0);
}
static void check_direct(struct fixture_environment *e) {
  reset(&e->c, &e->s);
  e->c.response.headers_committed = 1;
  haproxy_modsecurity_htx_handle_response_headers(&e->s, &e->f, &e->res);
  assert(e->s.kills == 1 && e->s.replies == 0 && e->txn.status == 200);
  /* Binding failures reach the actual direct payload/EOS host caller. */
  reset(&e->c, &e->s);
  e->c.request.finished = 0;
  assert(haproxy_modsecurity_htx_filter_http_payload(&e->s, &e->f, &e->req, 0,
                                                     4) == -1);
  assert(e->s.replies == 1 && append_calls == 1 && abort_calls == 1);
  reset(&e->c, &e->s);
  e->c.response.headers_committed = 1;
  assert(haproxy_modsecurity_htx_filter_http_payload(&e->s, &e->f, &e->res, 0,
                                                     4) == -1);
  assert(e->s.kills == 1 && e->s.replies == 0 && append_calls == 1);
  reset(&e->c, &e->s);
  e->c.response.headers_committed = 1;
  haproxy_modsecurity_htx_filter_http_end(&e->s, &e->f, &e->res);
  assert(e->s.kills == 1 && e->s.replies == 0 && finish_calls == 1);
  /* Failed terminal Common completion may never turn into success. */
  reset(&e->c, &e->s);
  native_result = 0;
  finish_result = 1;
  haproxy_modsecurity_htx_filter_http_end(&e->s, &e->f, &e->res);
  assert(e->s.kills == 1 && e->s.replies == 0 && finish_calls == 2);
  /* Header commit ack failure remains precommit. */
  reset(&e->c, &e->s);
  native_result = 0;
  commit_result = 1;
  haproxy_modsecurity_htx_handle_response_headers(&e->s, &e->f, &e->res);
  assert(e->s.replies == 1 && e->s.kills == 0 &&
         !e->c.response.headers_committed && register_calls == 0);
}
static void check_invalid(struct fixture_environment *e, int invalid_result) {
  reset(&e->c, &e->s);
  e->c.companion.mode = 1;
  e->c.transaction = NULL;
  result_success = invalid_result;
  assert(haproxy_modsecurity_htx_process_companion_response_headers(
             &e->s, &e->f, &e->res) == -1);
  assert(e->s.replies == 1 && e->txn.status == 503 && outcome_calls == 0);
  reset(&e->c, &e->s);
  e->c.companion.mode = 1;
  e->c.transaction = NULL;
  result_success = invalid_result;
  haproxy_modsecurity_htx_filter_http_end(&e->s, &e->f, &e->res);
  assert(e->s.kills == 1 && release_calls == 0 && outcome_calls == 0);
  reset(&e->c, &e->s);
  open_result = invalid_result;
  assert(!haproxy_modsecurity_htx_companion_open_and_claim(&e->s, &e->config,
                                                           &e->c));
  assert(claim_calls == 0 && close_calls == 1);
  reset(&e->c, &e->s);
  claim_result = invalid_result;
  assert(!haproxy_modsecurity_htx_companion_open_and_claim(&e->s, &e->config,
                                                           &e->c));
  assert(claim_calls == 1 && close_calls == 1);
  reset(&e->c, &e->s);
  e->c.companion.mode = 1;
  e->c.transaction = NULL;
  release_result = invalid_result;
  assert(haproxy_modsecurity_htx_filter_http_end(&e->s, &e->f, &e->res) == -1);
  assert(e->s.kills == 1 && e->s.replies == 0 && release_calls == 1 &&
         close_calls == 1 && outcome_calls == 0);
  assert(haproxy_modsecurity_htx_filter_http_end(&e->s, &e->f, &e->res) == -1);
  assert(release_calls == 1 && close_calls == 1);
  reset(&e->c, &e->s);
  e->c.companion.mode = 1;
  e->c.transaction = NULL;
  common_result = invalid_result;
  assert(!haproxy_modsecurity_htx_companion_commit(&e->c));
  reset(&e->c, &e->s);
  e->c.companion.mode = 1;
  e->c.transaction = NULL;
  common_result = invalid_result;
  assert(haproxy_modsecurity_htx_send_companion_response_chunk(&e->c, "x", 1) ==
         -1);
  reset(&e->c, &e->s);
  e->c.companion.mode = 1;
  e->c.transaction = NULL;
  common_result = invalid_result;
  e->c.response.headers_committed = 1;
  haproxy_modsecurity_htx_filter_http_end(&e->s, &e->f, &e->res);
  assert(e->s.kills == 1 && e->s.replies == 0 && eos_calls == 1);
  assert(haproxy_modsecurity_htx_filter_http_end(&e->s, &e->f, &e->res) == -1);
  assert(eos_calls == 1 && close_calls == 1 && outcome_calls == 0 &&
         release_calls == 0);
}
static void check_precommit_cleanup_failure(struct fixture_environment *e,
                                           int bad_close) {
  reset(&e->c, &e->s);
  e->c.companion.mode = 1;
  e->c.transaction = NULL;
  decision_kind = MSCONNECTOR_DECISION_KIND_DENY;
  if (bad_close)
    close_result = -1;
  else
    release_result = -1;
  assert(haproxy_modsecurity_htx_process_companion_response_headers(
             &e->s, &e->f, &e->res) == -1);
  assert(e->s.replies == 1 && e->s.kills == 1 && outcome_calls == 1);
  assert(cancel_calls == (bad_close ? 0 : 1) && release_calls == 1 &&
         close_calls == 1 && e->c.lifecycle.fail_closed);
  assert(haproxy_modsecurity_htx_filter_http_end(&e->s, &e->f, &e->res) == -1);
  assert(cancel_calls == (bad_close ? 0 : 1) && close_calls == 1);
}
static void check_direct_precommit_redirect(struct fixture_environment *e, int phase) {
  reset(&e->c,&e->s);
  e->c.response.headers_committed=0;
  e->c.response.headers_seen=phase==3;
  haproxy_modsecurity_decision d={0};
  d.phase=phase;d.disruptive=1;d.status=302;d.rule_id=1100202;
  strcpy(d.action,"redirect");
  strcpy(d.redirect_url,"https://no-crs.invalid/phase3-redirect");
  haproxy_modsecurity_htx_apply_precommit_decision_or_fail_closed(&e->s,&e->c,&d,"redirect");
  assert(e->s.txn->status==302 && e->s.replies==1 && e->s.kills==0);
  assert(e->s.redirects==1 && strcmp(e->s.location,d.redirect_url)==0);
  assert(last_redirect_flags==(phase<=2?REDIRECT_FLAG_FROM_REQ:0U));
  assert(finish_calls==1 && e->c.transaction==NULL && !e->c.lifecycle.fail_closed);
  haproxy_modsecurity_htx_apply_precommit_decision_or_fail_closed(&e->s,&e->c,&d,"reentry");
  assert(e->s.redirects==1 && finish_calls==1);
}
static void check_literal_precommit_redirect(struct fixture_environment *e, int code) {
  reset(&e->c,&e->s);e->c.response.headers_committed=0;
  haproxy_modsecurity_decision d={0};d.phase=3;d.disruptive=1;d.status=code;
  strcpy(d.action,"redirect");strcpy(d.redirect_url,"/literal/%[path]?value=%0d%0a");
  assert(haproxy_modsecurity_htx_apply_precommit_decision_or_fail_closed(&e->s,&e->c,&d,"literal redirect"));
  assert(e->s.txn->status==code && strcmp(e->s.location,d.redirect_url)==0);
}
static void check_precommit_redirect(struct fixture_environment *e) {
  for (int phase = 1; phase <= 3; ++phase) {
    check_direct_precommit_redirect(e, phase);
  }
  const int codes[] = {301, 302, 303, 307, 308};
  for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
    check_literal_precommit_redirect(e, codes[i]);
  }
  reset(&e->c,&e->s);e->c.companion.mode=1;e->c.transaction=NULL;
  decision_kind=MSCONNECTOR_DECISION_KIND_REDIRECT;
  assert(haproxy_modsecurity_htx_process_companion_response_headers(&e->s,&e->f,&e->res)==1);
  assert(e->s.txn->status==302 && e->s.redirects==1 && e->s.kills==0);
  assert(outcome_calls==1 && release_calls==1 && close_calls==1 && cancel_calls==0);
  assert(e->c.response.headers_committed && last_redirect_flags==0 && finish_calls==0);
  assert(release_order>outcome_order && outcome_order>redirect_order);
  assert(e->neighbour.replies==0 && e->neighbour.kills==0);
}
static void configure_redirect_failure(struct fixture_environment *e,
                                       haproxy_modsecurity_decision *d, int failure) {
  switch(failure) {
    case 0:d->status=304;break;
    case 1:d->redirect_url[0]=0;break;
    case 2:strcpy(d->redirect_url,"/bad\r\nInjected: yes");break;
    case 3:strcpy(d->redirect_url,"/bad\tvalue");break;
    case 4:d->redirect_url[0]=127;d->redirect_url[1]=0;break;
    case 5:memset(d->redirect_url,'x',sizeof(d->redirect_url));break;
    case 6:redirect_api_result=0;break;
    case 7:redirect_api_result=2;break;
    case 8:finish_result=1;break;
    case 9:
      e->c.lifecycle.fail_closed=1;
      e->c.lifecycle.error.error_class=MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT;
      e->c.lifecycle.error.phase=2;e->c.lifecycle.error.status=504;break;
    case 10:e->c.response.headers_committed=1;break;
    case 11:e->c.lifecycle.fail_closed=1;break;
    default: assert(0 && "unknown redirect failure variant"); break;
  }
}
static void check_direct_redirect_failure(struct fixture_environment *e, int failure) {
  reset(&e->c,&e->s);e->c.response.headers_committed=0;
  haproxy_modsecurity_decision d={0};d.phase=3;d.disruptive=1;d.status=302;
  strcpy(d.action,"redirect");strcpy(d.redirect_url,"https://no-crs.invalid/phase3-redirect");
  configure_redirect_failure(e, &d, failure);
  assert(!haproxy_modsecurity_htx_apply_precommit_decision_or_fail_closed(&e->s,&e->c,&d,"invalid redirect"));
  assert(e->s.redirects==0 && e->s.location[0]==0);
  if(failure==10)assert(e->s.replies==0 && e->s.kills==1 && e->s.txn->status==200);
  else assert(e->s.replies==1 && e->s.txn->status==503 && e->s.kills==0);
  assert(redirect_api_calls==(unsigned int)(failure==6 || failure==7));
  if(failure==9) {
    assert(e->c.lifecycle.error.error_class==MSCONNECTOR_TRANSACTION_ERROR_ENGINE_TIMEOUT);
    assert(e->c.lifecycle.error.phase==2 && e->c.lifecycle.error.status==504);
  } else if(failure!=8)assert(e->c.lifecycle.error.phase==3);
  unsigned int replies=e->s.replies;
  unsigned int kills=e->s.kills;
  assert(!haproxy_modsecurity_htx_apply_precommit_decision_or_fail_closed(&e->s,&e->c,&d,"reentry"));
  assert(e->s.replies==replies && e->s.kills==kills);
}
static void check_redirect_fail_closed(struct fixture_environment *e) {
  for (int failure = 0; failure < 12; ++failure) {
    check_direct_redirect_failure(e, failure);
  }
  char overlong[1025];memset(overlong,'x',sizeof(overlong));overlong[1024]=0;
  const char *invalid[]={NULL,"/bad\r\nInjected: yes","",overlong};
  for(size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i) {
    reset(&e->c,&e->s);e->c.companion.mode=1;e->c.transaction=NULL;
    decision_kind=MSCONNECTOR_DECISION_KIND_REDIRECT;redirect_input=invalid[i];
    assert(haproxy_modsecurity_htx_process_companion_response_headers(&e->s,&e->f,&e->res)==-1);
    assert(e->s.txn->status==503 && e->s.redirects==0 && redirect_api_calls==0);
    assert(outcome_calls==0 && release_calls==0 && cancel_calls==1);
  }
  reset(&e->c,&e->s);e->c.companion.mode=1;e->c.transaction=NULL;
  decision_kind=MSCONNECTOR_DECISION_KIND_REDIRECT;outcome_result=-1;
  assert(haproxy_modsecurity_htx_process_companion_response_headers(&e->s,&e->f,&e->res)==-1);
  assert(e->s.txn->status==302 && e->s.redirects==1 && e->s.replies==1 && e->s.kills==1);
  assert(outcome_calls==1 && release_calls==0 && cancel_calls==1);
}
static void check_precommit(struct fixture_environment *e) {
  /* A real precommit deny is normal terminal policy cleanup after its
   * acknowledged host outcome, never a typed technical cancellation. */
  reset(&e->c, &e->s);
  e->c.companion.mode = 1;
  e->c.transaction = NULL;
  decision_kind = MSCONNECTOR_DECISION_KIND_DENY;
  assert(haproxy_modsecurity_htx_process_companion_response_headers(
             &e->s, &e->f, &e->res) == 1);
  assert(e->s.replies == 1 && e->txn.status == 403 && e->s.kills == 0);
  assert(outcome_calls == 1 && release_calls == 1 && cancel_calls == 0 && close_calls == 1);
  /* Actual P3 caller: error results are technical, failed host outcome
   * acknowledgement occurs after its single reply and kills the stream. */
  reset(&e->c, &e->s);
  e->c.companion.mode = 1;
  e->c.transaction = NULL;
  decision_kind = MSCONNECTOR_DECISION_KIND_ERROR;
  assert(haproxy_modsecurity_htx_process_companion_response_headers(
             &e->s, &e->f, &e->res) == -1);
  assert(e->s.replies == 1 && e->txn.status == 503 && outcome_calls == 0);
  reset(&e->c, &e->s);
  e->c.companion.mode = 1;
  e->c.transaction = NULL;
  decision_kind = MSCONNECTOR_DECISION_KIND_DENY;
  outcome_result = -1;
  assert(haproxy_modsecurity_htx_process_companion_response_headers(
             &e->s, &e->f, &e->res) == -1);
  assert(e->s.replies == 1 && e->txn.status == 403 && e->s.kills == 1 &&
         outcome_calls == 1);
  assert(cancel_calls == 1 && release_calls == 0);
  assert(e->c.lifecycle.fail_closed);
  for (int bad_cleanup = 0; bad_cleanup < 2; bad_cleanup++) {
    check_precommit_cleanup_failure(e, bad_cleanup);
  }
}
static void check_eos(struct fixture_environment *e) {
  /* Successful EOS containing a technical error is still terminal,
   * independently of Off/Safe rule downgrade. No fabricated observation. */
  reset(&e->c, &e->s);
  e->c.companion.mode = 1;
  e->c.transaction = NULL;
  decision_kind = MSCONNECTOR_DECISION_KIND_ERROR;
  haproxy_modsecurity_htx_filter_http_end(&e->s, &e->f, &e->res);
  assert(e->s.kills == 1 && e->s.replies == 0 && outcome_calls == 0);
  reset(&e->c, &e->s);
  e->c.companion.mode = 1;
  e->c.transaction = NULL;
  close_result = -1;
  haproxy_modsecurity_htx_filter_http_end(&e->s, &e->f, &e->res);
  assert(e->s.kills == 1 && e->s.replies == 0);
  /* Legitimate allow completes, with no host kill or synthetic reply. */
  reset(&e->c, &e->s);
  e->c.companion.mode = 1;
  e->c.transaction = NULL;
  haproxy_modsecurity_htx_filter_http_end(&e->s, &e->f, &e->res);
  assert(e->s.kills == 0 && e->s.replies == 0 && eos_calls == 1 &&
         release_calls == 1);
}
static void check_strict_queued_case(struct fixture_environment *e,
                                     int companion, size_t queued,
                                     int committed, int strict) {
  reset(&e->c, &e->s);
  e->config.common_config.phase4_mode = strict ? MSCONNECTOR_PHASE4_MODE_STRICT : MSCONNECTOR_PHASE4_MODE_SAFE;
  e->c.companion.mode = companion;
  if (companion) e->c.transaction = NULL;
  e->c.response.headers_committed = 1;
  e->s.res.output = queued;
  e->s.delivered_bytes = committed ? 177 : 0;
  native_result = 0;
  native_disruptive = 1;
  decision_kind = MSCONNECTOR_DECISION_KIND_DENY;
  int result = haproxy_modsecurity_htx_filter_http_end(&e->s, &e->f, &e->res);
  assert(e->s.delivered_bytes == (committed ? 177U : 0U));
  if (strict) {
    /* Positive http_end lets HAProxy advance/forward queued output. */
    assert(result == -1);
    assert(e->s.res.output == 0 && e->s.stream_aborts == 1);
    assert(e->s.frontend.aborts == 1 && e->s.frontend.shutdowns == 1);
    assert(e->s.frontend.flags & SC_FL_NOLINGER);
    assert(e->s.client_conn.hard_calls==1 && e->s.client_conn.clean_calls==1);
    assert(e->s.client_conn.close_notify==0);
    assert(e->s.res.erase_order < e->s.client_conn.hard_order);
    assert(e->s.client_conn.hard_order < e->s.stream_abort_order);
    assert(e->s.client_conn.hard_order < e->s.client_conn.clean_order);
    assert(e->s.client_conn.clean_order < e->s.async_order);
    assert(outcome_calls == 0); /* shutdown is not invented wire observation */
    int terminal_calls = abort_calls + release_calls;
    assert(haproxy_modsecurity_htx_filter_http_end(&e->s, &e->f, &e->res) == -1);
    assert(abort_calls + release_calls == terminal_calls);
  } else {
    assert(result == 1 && e->s.res.output == queued);
    assert(e->s.stream_aborts == 0);
    assert(e->s.frontend.aborts == 0 && e->s.frontend.shutdowns == 0);
    assert(e->s.client_conn.hard_calls==0 && e->s.client_conn.clean_calls==0);
  }
  assert(e->neighbour.kills == 0 && e->neighbour.replies == 0);
  assert(e->neighbour.client_conn.hard_calls==0 && e->neighbour.client_conn.clean_calls==0);
  assert(e->s.server_conn.hard_calls==0 && e->s.server_conn.clean_calls==0);
}
static void check_strict_queued_route(struct fixture_environment *e, int companion) {
  const size_t queued[] = {0, 33, 65537};
  for (size_t n = 0; n < sizeof(queued) / sizeof(queued[0]); ++n) {
    for (int committed = 0; committed < 2; ++committed) {
      for (int strict = 0; strict < 2; ++strict) {
        check_strict_queued_case(e, companion, queued[n], committed, strict);
      }
    }
  }
}
static void check_strict_queued_response(struct fixture_environment *e) {
  for (int companion = 0; companion < 2; ++companion) {
    check_strict_queued_route(e, companion);
  }
}
static void check_strict_transport_endpoints(struct fixture_environment *e) {
  haproxy_modsecurity_htx_abort_response_stream(NULL);
  for (int endpoint=0; endpoint<11; ++endpoint) {
    reset(&e->c,&e->s);
    e->s.res.output=33;
    struct mux_ops nameless={NULL};
    switch(endpoint) {
      case 0: e->s.scf=NULL; break;
      case 1: e->s.frontend.sedesc=NULL; break;
      case 2: e->s.client_desc.flags=0; break;
      case 3: e->s.client_desc.conn=NULL; break;
      case 4: e->s.client_conn.flags=0; e->s.client_conn.xprt_ctx=NULL; break;
      case 5: e->s.client_conn.xprt=&fixture_raw; e->s.client_conn.xprt_ctx=NULL; break;
      case 6: e->s.client_conn.xprt=NULL; break;
      case 7: e->s.client_conn.mux=&fixture_unknown_mux; break;
      case 8:
        e->s.client_conn.mux=&fixture_h2_mux;
        e->neighbour.client_desc.conn=&e->s.client_conn;
        break;
      case 9: e->s.client_conn.mux=NULL; break;
      case 10: e->s.client_conn.mux=&nameless; break;
      default: assert(0 && "unknown transport endpoint variant"); break;
    }
    haproxy_modsecurity_htx_abort_response_stream(&e->s);
    assert(e->s.res.output==0 && e->s.kills==1);
    assert(e->s.client_conn.hard_calls==0);
    assert(e->s.server_conn.hard_calls==0 && e->s.server_conn.clean_calls==0);
    if(endpoint==8) {
      /* Existing H2 stream-shutdown path stays intact; no shared TLS close. */
      assert(e->s.client_conn.stream_shutdowns==1);
      assert(e->s.client_conn.clean_calls==0 && e->s.client_conn.quiet==0);
      assert(e->neighbour.frontend.sedesc->conn==&e->s.client_conn);
      assert(e->neighbour.frontend.sedesc->conn->hard_calls==0);
      e->neighbour.client_desc.conn=&e->neighbour.client_conn;
    }
    assert(e->neighbour.frontend.aborts==0 && e->neighbour.frontend.shutdowns==0);
    assert(e->neighbour.client_conn.hard_calls==0 && e->neighbour.client_conn.clean_calls==0);
  }
}
static void check_strict_allow_keeps_transport(struct fixture_environment *e) {
  for (int companion=0;companion<2;++companion) {
    reset(&e->c,&e->s);
    e->config.common_config.phase4_mode=MSCONNECTOR_PHASE4_MODE_STRICT;
    e->c.companion.mode=companion;
    if(companion)e->c.transaction=NULL;
    e->c.response.headers_committed=1;
    e->s.res.output=33;
    native_result=0;native_disruptive=0;decision_kind=MSCONNECTOR_DECISION_KIND_ALLOW;
    assert(haproxy_modsecurity_htx_filter_http_end(&e->s,&e->f,&e->res)==1);
    assert(e->s.res.output==33 && e->s.kills==0);
    assert(e->s.client_conn.hard_calls==0 && e->s.client_conn.clean_calls==0);
  }
}
static void check_request_version(void) {
  char version[4];
  const char *valid[] = {"HTTP/1.0", "HTTP/1.1", "HTTP/2.0"};
  const char *invalid[] = {"", "HTTP/2", "HTTP/3.0", "HTTP/1.9", "http/1.1", "HTTP/1.1x"};
  for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
    assert(haproxy_modsecurity_htx_request_version((struct ist){(char *)valid[i], strlen(valid[i])}, version) == 0);
    assert(strcmp(version, valid[i] + 5) == 0);
  }
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
    assert(haproxy_modsecurity_htx_request_version((struct ist){(char *)invalid[i], strlen(invalid[i])}, version) == -1);
    assert(version[0] == 0);
  }
  assert(haproxy_modsecurity_htx_request_version((struct ist){NULL, 8}, version) == -1);
}

int main(void) {
  check_request_version();
  struct fixture_environment e;
  const int modes[] = {MSCONNECTOR_PHASE4_MODE_OFF,
                       MSCONNECTOR_PHASE4_MODE_SAFE,
                       MSCONNECTOR_PHASE4_MODE_STRICT};
  const int invalid[] = {0, -1, 2};
  initialize_environment(&e);
  check_forwardable();
  check_precommit_redirect(&e);
  check_redirect_fail_closed(&e);
  for (size_t mode = 0; mode < 3; mode++) {
    e.config.common_config.phase4_mode = modes[mode];
    for (int companion = 0; companion < 2; companion++) {
      for (int commitment = 0; commitment < 3; commitment++)
        check_terminal(&e, companion, commitment);
    }
    check_direct(&e);
    for (size_t bad = 0; bad < 3; bad++)
      check_invalid(&e, invalid[bad]);
    check_precommit(&e);
    check_eos(&e);
  }
  check_strict_queued_response(&e);
  check_strict_transport_endpoints(&e);
  check_strict_allow_keeps_transport(&e);
  puts("HAProxy HTX direct/companion: Off/Safe/Strict config x pre/header/body "
       "x terminal reentry; native, commit, EOS, close, checked "
       "OPEN/CLAIM/RELEASE and nested success");
  return 0;
}
