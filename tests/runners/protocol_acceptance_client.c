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
static int debug(CURL *easy, curl_infotype type, char *data, size_t size, void *userdata) {
  struct request *r = userdata;
  char line[512];
  char *p;
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
static int completed(struct request *r, CURLcode result, int cancelled) {
  long status = 0, version = 0, connects = 0;
  curl_off_t conn = -1, xfer = -1;
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
  snprintf(r->url, n, "%s%s", base, r->path);
#define OPT(key, value) do { if(curl_easy_setopt(r->easy, key, value) != CURLE_OK) return 1; } while(0)
  OPT(CURLOPT_URL, r->url);
  OPT(CURLOPT_HTTP_VERSION, version);
  OPT(CURLOPT_CAINFO, ca);
  OPT(CURLOPT_SSL_VERIFYPEER, 1L);
  OPT(CURLOPT_SSL_VERIFYHOST, 2L);
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
int main(int argc, char **argv) {
  const char *protocol = NULL, *base = NULL, *ca = NULL, *scenario = NULL;
  const char *const scenarios[] = {"multiplex", "client-cancel", "server-reset", "streaming", "phase3", "safe", "h2c", NULL};
  struct request req[3] = {{.name="target", .path="/acceptance/target", .stream_id=-1},
                           {.name="peer", .path="/acceptance/peer", .stream_id=-1},
                           {.name="followup", .path="/acceptance/followup", .stream_id=-1}};
  CURLM *multi = NULL;
  long version;
  int i, running = 0, rc = 1, results = 0, followup = 0;
  double deadline;
  for(i = 1; i < argc; i += 2) {
    if(i+1 >= argc) goto usage;
    if(!strcmp(argv[i], "--protocol")) protocol = argv[i+1];
    else if(!strcmp(argv[i], "--base-url")) base = argv[i+1];
    else if(!strcmp(argv[i], "--ca")) ca = argv[i+1];
    else if(!strcmp(argv[i], "--scenario")) scenario = argv[i+1];
    else if(!strcmp(argv[i], "--target-path")) req[0].path = argv[i+1];
    else if(!strcmp(argv[i], "--peer-path")) req[1].path = argv[i+1];
    else if(!strcmp(argv[i], "--followup-path")) req[2].path = argv[i+1];
    else goto usage;
  }
  if(!protocol || !base || !ca || !scenario || !allowed(scenario, scenarios)) goto usage;
  if(!strcmp(protocol, "h2")) version = CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE;
  else if(!strcmp(protocol, "h3")) version = CURL_HTTP_VERSION_3ONLY;
  else if(!strcmp(protocol, "h2c")) version = CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE;
  else goto usage;
  if(strncmp(base, !strcmp(protocol, "h2c") ? "http://" : "https://",
             !strcmp(protocol, "h2c") ? 7 : 8) || strchr(base, '?') || strchr(base, '#')) goto usage;
  for(i = 0; i < 3; ++i) if(req[i].path[0] != '/' || strchr(req[i].path, '\r') || strchr(req[i].path, '\n')) goto usage;
  if(curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return 1;
  multi = curl_multi_init();
  if(!multi) goto cleanup;
  if(curl_multi_setopt(multi, CURLMOPT_PIPELINING, (long)CURLPIPE_MULTIPLEX) != CURLM_OK ||
     curl_multi_setopt(multi, CURLMOPT_MAX_HOST_CONNECTIONS, 1L) != CURLM_OK) goto cleanup;
  deadline = monotonic() + 14.5;
  /* Admit the held allowed peer first, so early target denials can overlap an
     actual host transaction rather than just a queued client easy handle. */
  if(start(multi, &req[1], base, ca, version) || start(multi, &req[0], base, ca, version)) goto cleanup;
  do {
    CURLMsg *msg;
    int remaining;
    if(curl_multi_perform(multi, &running) != CURLM_OK || output_failed) goto cleanup;
    while((msg = curl_multi_info_read(multi, &remaining))) {
      struct request *r = NULL;
      if(msg->msg != CURLMSG_DONE) continue;
      if(curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &r) != CURLE_OK || !r) goto cleanup;
      if(completed(r, msg->data.result, 0)) goto cleanup;
      ++results;
      if(curl_multi_remove_handle(multi, r->easy) != CURLM_OK) goto cleanup;
      r->active = 0;
    }
    if(!strcmp(scenario, "client-cancel") && req[0].active && req[0].first_data) {
      if(!req[1].active) goto cleanup;
      if(curl_multi_remove_handle(multi, req[0].easy) != CURLM_OK) goto cleanup;
      req[0].active = 0;
      begin("cancelled", &req[0]);
      printf(",\"method\":\"curl_multi_remove_handle\",\"peer_active\":true"); finish();
      if(completed(&req[0], CURLE_OK, 1)) goto cleanup;
      ++results;
    }
    if(req[0].done && req[1].done && !followup) {
      if(start(multi, &req[2], base, ca, version)) goto cleanup;
      followup = 1;
    }
    if(req[2].done) break;
    if(monotonic() > deadline || curl_multi_poll(multi, NULL, 0, 50, NULL) != CURLM_OK) goto cleanup;
  } while(1);
  rc = results == 3 && !output_failed ? 0 : 1;
cleanup:
  for(i = 0; i < 3; ++i) {
    if(req[i].active && multi && curl_multi_remove_handle(multi, req[i].easy) != CURLM_OK) rc = 1;
    if(req[i].easy) curl_easy_cleanup(req[i].easy);
    free(req[i].url);
  }
  if(multi && curl_multi_cleanup(multi) != CURLM_OK) rc = 1;
  curl_global_cleanup();
  return rc;
usage:
  fputs("usage: protocol-client --protocol h2|h3|h2c --base-url URL --ca FILE --scenario SCENARIO [--target-path PATH] [--peer-path PATH] [--followup-path PATH]\n", stderr);
  return 2;
}
