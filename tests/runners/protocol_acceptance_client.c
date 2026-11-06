/* Real libcurl multi acceptance probe. JSONL contains metadata, never bodies. */
#define _POSIX_C_SOURCE 200809L
#include <curl/curl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct request {
  CURL *easy;
  const char *name;
  const char *path;
  char *url;
  size_t bytes;
  int first_data;
  int active;
  int done;
  long stream_id;
  char error[CURL_ERROR_SIZE];
  char failure[512];
};
static int output_failed;

static double monotonic(void) {
  struct timespec t;
  if(clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
  return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
static void quoted(const char *s) {
  putchar('"');
  for(; *s; ++s) {
    unsigned char c = (unsigned char)*s;
    if(c == '"' || c == '\\') { putchar('\\'); putchar(c); }
    else if(c >= 32 && c < 127) putchar(c);
    else printf("\\u%04x", c);
  }
  putchar('"');
}
static void begin(const char *event, const struct request *r) {
  printf("{\"event\":"); quoted(event);
  printf(",\"name\":"); quoted(r->name);
  printf(",\"monotonic_ns\":%.0f", monotonic() * 1e9);
}
static void finish(void) {
  puts("}");
  if(fflush(stdout) || ferror(stdout)) output_failed = 1;
}
/* libcurl requires this exact mutable-buffer callback ABI; data is not modified. */
static size_t receive(char *data, size_t size, size_t count, void *userdata) {
  struct request *r = userdata;
  size_t n;
  (void)data;
  if(size && count > (size_t)-1 / size) return CURL_WRITEFUNC_ERROR;
  n = size * count;
  if(n > (size_t)-1 - r->bytes) return CURL_WRITEFUNC_ERROR;
  r->bytes += n;
  if(n && !r->first_data) {
    r->first_data = 1;
    begin("first_data", r);
    printf(",\"bytes\":%zu,\"monotonic\":%.9f", r->bytes, monotonic());
    finish();
  }
  return output_failed ? CURL_WRITEFUNC_ERROR : n;
}
static int debug_text(CURL *easy, curl_infotype type, const char *data, size_t size, void *userdata) {
  struct request *r = userdata;
  char line[512];
  const char *p;
  long stream;
  curl_off_t conn = -1;
  (void)easy;
  if(type != CURLINFO_TEXT || size >= sizeof(line)) return 0;
  memcpy(line, data, size); line[size] = 0;
  while(size && (line[size-1] == '\n' || line[size-1] == '\r')) line[--size] = 0;
  p = strstr(line, "] [");
  if(p && (strstr(line, "[HTTP/2]") || strstr(line, "[HTTP/3]")) &&
     strstr(line, "OPENED stream") && sscanf(p + 3, "%ld]", &stream) == 1) {
    r->stream_id = stream;
    begin("debug_observation", r);
    printf(",\"stream_id\":%ld", stream);
    if(curl_easy_getinfo(r->easy, CURLINFO_CONN_ID, &conn) == CURLE_OK && conn >= 0)
      printf(",\"conn_id\":%" CURL_FORMAT_CURL_OFF_T, conn);
    printf(",\"observation\":"); quoted(line); finish();
  }
  if(strstr(line, "ALPN: server accepted ")) {
    begin("debug_observation", r);
    printf(",\"alpn\":"); quoted(strstr(line, "ALPN: server accepted ") + 22);
    printf(",\"observation\":"); quoted(line); finish();
  }
  if((!strncmp(line, "HTTP/2 stream ", 14) ||
      !strncmp(line, "HTTP/3 stream ", 14)) &&
     (strstr(line + 14, "reset") || strstr(line + 14, "not closed cleanly") ||
      strstr(line + 14, "error"))) {
    memcpy(r->failure, line, size + 1);
    begin("debug_observation", r);
    printf(",\"debug_failure\":"); quoted(line); finish();
  }
  return 0;
}
/* libcurl owns the buffer and requires char * in its callback ABI. */
static int debug(CURL *easy, curl_infotype type, char *data, size_t size, void *userdata) {
  return debug_text(easy, type, data, size, userdata);
}
static int completed(struct request *r, CURLcode result, int cancelled) {
  long status = 0;
  long version = 0;
  long connects = 0;
  curl_off_t conn = -1;
  curl_off_t xfer = -1;
  if(curl_easy_getinfo(r->easy, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK ||
     curl_easy_getinfo(r->easy, CURLINFO_HTTP_VERSION, &version) != CURLE_OK ||
     curl_easy_getinfo(r->easy, CURLINFO_NUM_CONNECTS, &connects) != CURLE_OK ||
     curl_easy_getinfo(r->easy, CURLINFO_CONN_ID, &conn) != CURLE_OK ||
     curl_easy_getinfo(r->easy, CURLINFO_XFER_ID, &xfer) != CURLE_OK) return 1;
  begin("completed", r);
  printf(",\"status\":%ld,\"curl_code\":", status);
  if(cancelled) printf("null"); else printf("%d", (int)result);
  printf(",\"http_version\":%ld,"
         "\"conn_id\":%" CURL_FORMAT_CURL_OFF_T ",\"xfer_id\":%" CURL_FORMAT_CURL_OFF_T
         ",\"bytes\":%zu,\"cancelled\":%s,\"num_connects\":%ld", version,
         conn, xfer, r->bytes, cancelled ? "true" : "false", connects);
  if(r->stream_id >= 0) printf(",\"stream_id\":%ld", r->stream_id);
  printf(",\"error\":"); quoted(r->error);
  if(r->failure[0]) { printf(",\"debug_failure\":"); quoted(r->failure); }
  finish(); r->done = 1;
  return output_failed;
}
static int start(CURLM *multi, struct request *r, const char *base, const char *ca, long version) {
  size_t n = strlen(base) + strlen(r->path) + 1;
  r->url = malloc(n);
  r->easy = curl_easy_init();
  if(!r->url || !r->easy) return 1;
  if(curl_easy_setopt(r->easy, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3) != CURLE_OK ||
     curl_easy_setopt(r->easy, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK ||
     curl_easy_setopt(r->easy, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK ||
     curl_easy_setopt(r->easy, CURLOPT_CAINFO, ca) != CURLE_OK) return 1;
  snprintf(r->url, n, "%s%s", base, r->path);
#define OPT(key, value) do { if(curl_easy_setopt(r->easy, key, value) != CURLE_OK) return 1; } while(0)
  OPT(CURLOPT_URL, r->url);
  OPT(CURLOPT_HTTP_VERSION, version);
  OPT(CURLOPT_PROXY, "");
  OPT(CURLOPT_NOSIGNAL, 1L);
  OPT(CURLOPT_TIMEOUT_MS, 14000L);
  OPT(CURLOPT_CONNECTTIMEOUT_MS, 5000L);
  OPT(CURLOPT_PIPEWAIT, 1L);
  OPT(CURLOPT_VERBOSE, 1L);
  OPT(CURLOPT_DEBUGFUNCTION, debug);
  OPT(CURLOPT_DEBUGDATA, r);
  OPT(CURLOPT_WRITEFUNCTION, receive);
  OPT(CURLOPT_WRITEDATA, r);
  OPT(CURLOPT_ERRORBUFFER, r->error);
  OPT(CURLOPT_PRIVATE, r);
#undef OPT
  if(curl_multi_add_handle(multi, r->easy) != CURLM_OK) return 1;
  r->active = 1;
  begin("request_started", r); printf(",\"path\":"); quoted(r->path); finish();
  return output_failed;
}
static int allowed(const char *s, const char *const *choices) {
  for(; *choices; ++choices) if(!strcmp(s, *choices)) return 1;
  return 0;
}
struct options {
  const char *protocol;
  const char *base;
  const char *ca;
  const char *scenario;
  long version;
};
struct option_binding {
  const char *name;
  const char **destination;
};
struct session {
  CURLM *multi;
  struct request req[3];
  int results;
  int followup;
  double deadline;
};
static int set_argument(const char *name, const char *value,
                        const struct option_binding *bindings, size_t count) {
  for(size_t i = 0; i < count; ++i) {
    if(!strcmp(name, bindings[i].name)) {
      *bindings[i].destination = value;
      return 0;
    }
  }
  return 1;
}
static int parse_arguments(int argc, char **argv, struct options *options,
                           struct request *req) {
  const struct option_binding bindings[] = {
    {"--protocol", &options->protocol}, {"--base-url", &options->base},
    {"--ca", &options->ca}, {"--scenario", &options->scenario},
    {"--target-path", &req[0].path}, {"--peer-path", &req[1].path},
    {"--followup-path", &req[2].path}
  };
  if(argc % 2 != 1) return 1;
  for(int i = 1; i < argc; i += 2) {
    if(set_argument(argv[i], argv[i+1], bindings,
                    sizeof(bindings) / sizeof(bindings[0]))) return 1;
  }
  return 0;
}
static int valid_protocol(struct options *options) {
  if(!strcmp(options->protocol, "h3")) {
    options->version = CURL_HTTP_VERSION_3ONLY;
    return 1;
  }
  if(!strcmp(options->protocol, "h2") || !strcmp(options->protocol, "h2c")) {
    options->version = CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE;
    return 1;
  }
  return 0;
}
static int valid_paths(const struct request *req) {
  for(size_t i = 0; i < 3; ++i) {
    if(req[i].path[0] != '/' || strchr(req[i].path, '\r') ||
       strchr(req[i].path, '\n')) return 0;
  }
  return 1;
}
static int valid_loopback_origin(const char *base, const char *scheme) {
  const char *port;
  unsigned int number = 0;
  size_t scheme_length = strlen(scheme);
  const char authority[] = "127.0.0.1:";
  if(strncmp(base, scheme, scheme_length)) return 0;
  port = base + scheme_length;
  if(strncmp(port, authority, sizeof(authority) - 1)) return 0;
  port += sizeof(authority) - 1;
  if(!*port) return 0;
  for(; *port; ++port) {
    unsigned int digit;
    if(*port < '0' || *port > '9') return 0;
    digit = (unsigned int)(*port - '0');
    if(number > (65535U - digit) / 10U) return 0;
    number = number * 10U + digit;
  }
  return number != 0;
}
static int valid_options(struct options *options, const struct request *req) {
  const char *const scenarios[] = {"multiplex", "client-cancel", "server-reset",
                                  "streaming", "phase3", "safe", "h2c", NULL};
  const char *scheme = "https://";
  if(!options->protocol || !options->base || !options->ca || !options->scenario)
    return 0;
  if(!allowed(options->scenario, scenarios) || !valid_protocol(options)) return 0;
  /* h2c is deliberately cleartext HTTP/2 prior knowledge, never a TLS fallback. */
  if(!strcmp(options->protocol, "h2c")) scheme = "http://";
  /* Only the task driver's explicit IPv4 loopback origin is admissible. */
  if(!valid_loopback_origin(options->base, scheme)) return 0;
  return valid_paths(req);
}
static int collect_completion(struct session *session, const CURLMsg *message) {
  struct request *r = NULL;
  if(message->msg != CURLMSG_DONE) return 0;
  if(curl_easy_getinfo(message->easy_handle, CURLINFO_PRIVATE, &r) != CURLE_OK || !r)
    return 1;
  if(completed(r, message->data.result, 0)) return 1;
  ++session->results;
  if(curl_multi_remove_handle(session->multi, r->easy) != CURLM_OK) return 1;
  r->active = 0;
  return 0;
}
static int collect_completions(struct session *session) {
  const CURLMsg *message;
  int remaining;
  while((message = curl_multi_info_read(session->multi, &remaining))) {
    if(collect_completion(session, message)) return 1;
  }
  return 0;
}
static int cancel_target(struct session *session, const struct options *options) {
  struct request *target = &session->req[0];
  if(strcmp(options->scenario, "client-cancel") || !target->active ||
     !target->first_data) return 0;
  if(!session->req[1].active) return 1;
  if(curl_multi_remove_handle(session->multi, target->easy) != CURLM_OK) return 1;
  target->active = 0;
  begin("cancelled", target);
  printf(",\"method\":\"curl_multi_remove_handle\",\"peer_active\":true");
  finish();
  if(completed(target, CURLE_OK, 1)) return 1;
  ++session->results;
  return 0;
}
static int start_followup(struct session *session, const struct options *options) {
  if(!session->req[0].done || !session->req[1].done || session->followup) return 0;
  if(start(session->multi, &session->req[2], options->base, options->ca,
           options->version)) return 1;
  session->followup = 1;
  return 0;
}
static int run_requests(struct session *session, const struct options *options) {
  int running = 0;
  session->deadline = monotonic() + 14.5;
  /* Admit the held allowed peer first, so early target denials overlap an
     actual host transaction rather than just a queued client easy handle. */
  if(start(session->multi, &session->req[1], options->base, options->ca, options->version) ||
     start(session->multi, &session->req[0], options->base, options->ca, options->version))
    return 1;
  while(!session->req[2].done) {
    if(curl_multi_perform(session->multi, &running) != CURLM_OK || output_failed)
      return 1;
    if(collect_completions(session) || cancel_target(session, options) ||
       start_followup(session, options)) return 1;
    if(!session->req[2].done &&
       (monotonic() > session->deadline ||
        curl_multi_poll(session->multi, NULL, 0, 50, NULL) != CURLM_OK)) return 1;
  }
  return session->results == 3 && !output_failed ? 0 : 1;
}
static int cleanup_session(struct session *session, int result) {
  for(size_t i = 0; i < 3; ++i) {
    struct request *r = &session->req[i];
    if(r->active && session->multi &&
       curl_multi_remove_handle(session->multi, r->easy) != CURLM_OK) result = 1;
    if(r->easy) curl_easy_cleanup(r->easy);
    free(r->url);
  }
  if(session->multi && curl_multi_cleanup(session->multi) != CURLM_OK) result = 1;
  curl_global_cleanup();
  return result;
}
int main(int argc, char **argv) {
  struct options options = {0};
  struct session session = {.req = {
    {.name="target", .path="/acceptance/target", .stream_id=-1},
    {.name="peer", .path="/acceptance/peer", .stream_id=-1},
    {.name="followup", .path="/acceptance/followup", .stream_id=-1}}};
  int result = 1;
  if(parse_arguments(argc, argv, &options, session.req) ||
     !valid_options(&options, session.req)) {
    fputs("usage: protocol-client --protocol h2|h3|h2c --base-url URL --ca FILE --scenario SCENARIO [--target-path PATH] [--peer-path PATH] [--followup-path PATH]\n", stderr);
    return 2;
  }
  if(curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return 1;
  session.multi = curl_multi_init();
  if(session.multi &&
     curl_multi_setopt(session.multi, CURLMOPT_PIPELINING, (long)CURLPIPE_MULTIPLEX) == CURLM_OK &&
     curl_multi_setopt(session.multi, CURLMOPT_MAX_HOST_CONNECTIONS, 1L) == CURLM_OK)
    result = run_requests(&session, &options);
  return cleanup_session(&session, result);
}
