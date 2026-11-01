#include "msconnector/event.h"
#include "msconnector/event_jsonl.h"
#include "msconnector/integrity_event.h"
#include "msconnector/limits.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

const char *msconnector_phase_name(enum msconnector_phase phase) {
    (void)phase;
    return "connection";
}

static void check_uri(const char *input, const char *expected, int redacted) {
    msconnector_event event;
    char json[4096];
    char jsonl[4096];
    char safe[256];
    int helper_truncated;
    uint64_t hash;

    msconnector_event_init(&event);
    event.request.method = strcmp(input, "*") == 0 ? "OPTIONS" : "GET";
    event.request.uri = input;
    assert(msconnector_event_uri_query_redacted(input) == redacted);
    assert(msconnector_event_uri_redact_query_ex(input, safe, sizeof(safe),
        &helper_truncated) == redacted);
    assert(helper_truncated == 0);
    assert(strcmp(safe, expected) == 0);
    hash = msconnector_integrity_event_hash(&event, 0U);
    event.integrity.event_hash = hash;
    assert(msconnector_integrity_event_chain_verify(0U, hash, &event));
    assert(msconnector_event_write_json(&event, json, sizeof(json)));
    assert(strstr(json, "\"uri\":\"") != NULL);
    assert(strstr(json, expected) != NULL);
    assert(strstr(json, "CANARY") == NULL);
    assert(strstr(json, redacted ? "\"redacted\":true" : "\"redacted\":false") != NULL);
    assert(msconnector_event_write_jsonl_line(&event, jsonl, sizeof(jsonl), NULL));
    assert(strstr(jsonl, "CANARY") == NULL);
    assert(strcmp(event.request.uri, input) == 0);
}

static void check_long_uri_serialization(void) {
    char long_path[384];
    char long_query[384];
    char safe[256];
    char json[4096];
    char jsonl[4096];
    msconnector_event event;
    uint64_t hash;
    int truncated;

    memset(long_path, 'p', sizeof(long_path) - 1U);
    long_path[0] = '/';
    long_path[sizeof(long_path) - 1U] = '\0';
    truncated = 0;
    assert(msconnector_event_uri_redact_query_ex(long_path, safe, sizeof(safe),
        &truncated) == 0);
    assert(truncated == 1);
    assert(strlen(safe) == sizeof(safe) - 1U);

    msconnector_event_init(&event);
    event.request.method = "GET";
    event.request.uri = long_path;
    truncated = 0;
    assert(msconnector_event_write_json_ex(&event, json, sizeof(json),
        &truncated) == 0);
    assert(truncated == 1);
    assert(strstr(json, "\"redacted\":false") != NULL);
    assert(strstr(json, "\"truncated\":true") != NULL);
    assert(strcmp(event.request.uri, long_path) == 0);
    hash = msconnector_integrity_event_hash(&event, 0U);
    event.request.uri = safe;
    event.flags.truncated = 1;
    assert(msconnector_integrity_event_hash(&event, 0U) == hash);
    event.flags.truncated = 0;
    event.request.uri = long_path;

    memset(long_query, 'q', sizeof(long_query));
    long_query[0] = '/';
    memset(long_query + 1U, 'a', 248U);
    long_query[249] = '?';
    memcpy(long_query + 250U, "id=CANARY", sizeof("id=CANARY"));
    truncated = 0;
    assert(msconnector_event_uri_redact_query_ex(long_query, safe, sizeof(safe),
        &truncated) == 1);
    assert(truncated == 1);
    assert(strstr(safe, "CANARY") == NULL);
    assert(strstr(safe, "<redacted>") == NULL);
    assert(strstr(safe, "<reda") != NULL);

    event.request.uri = long_query;
    hash = msconnector_integrity_event_hash(&event, 0U);
    event.integrity.event_hash = hash;
    assert(msconnector_integrity_event_chain_verify(0U, hash, &event));
    event.request.uri = safe;
    assert(msconnector_integrity_event_hash(&event, 0U) == hash);
    event.request.uri = long_query;
    truncated = 0;
    assert(msconnector_event_write_json_ex(&event, json, sizeof(json),
        &truncated) == 0);
    assert(truncated == 1);
    assert(strstr(json, "\"redacted\":true") != NULL);
    assert(strstr(json, "\"truncated\":true") != NULL);
    assert(strstr(json, "CANARY") == NULL);
    assert(strcmp(event.request.uri, long_query) == 0);
    truncated = 0;
    assert(msconnector_event_write_jsonl_line(&event, jsonl, sizeof(jsonl),
        &truncated) == 0);
    assert(truncated == 1);
    assert(strstr(jsonl, "\"redacted\":true") != NULL);
    assert(strstr(jsonl, "\"truncated\":true") != NULL);
    assert(strstr(jsonl, "CANARY") == NULL);
    assert(jsonl[strlen(jsonl) - 1U] == '\n');

    memcpy(long_query + 250U, "id=OTHER", sizeof("id=OTHER"));
    assert(msconnector_integrity_event_hash(&event, 0U) == hash);
}

static void check_unterminated_uri_is_bounded(void) {
    char input[MSCONNECTOR_MAX_JSON_FIELD_LENGTH];
    char safe[MSCONNECTOR_EVENT_URI_SAFE_BUFFER_SIZE];
    char json[4096];
    msconnector_event event;
    int truncated = 0;

    memset(input, 'u', sizeof(input));
    input[0] = '/';
    input[sizeof(input) - 1U] = '?';
    assert(msconnector_event_uri_redact_query_ex(input, safe, sizeof(safe),
        &truncated) == 1);
    assert(truncated == 1);

    msconnector_event_init(&event);
    event.request.method = "GET";
    event.request.uri = input;
    assert(msconnector_event_write_json_ex(&event, json, sizeof(json),
        &truncated) == 0);
    assert(strstr(json, "\"redacted\":true") != NULL);
    assert(strstr(json, "\"truncated\":true") != NULL);
    assert(msconnector_integrity_event_chain_verify(0U,
        msconnector_integrity_event_hash(&event, 0U), &event));
}

static void check_bounded_redacted_query_is_not_truncated(void) {
    char input[MSCONNECTOR_MAX_JSON_FIELD_LENGTH];
    char safe[MSCONNECTOR_EVENT_URI_SAFE_BUFFER_SIZE];
    char json[4096];
    msconnector_event event;
    int truncated = 0;

    memset(input, 'u', sizeof(input));
    input[0] = '?';
    assert(msconnector_event_uri_redact_query_ex(input, safe, sizeof(safe),
        &truncated) == 1);
    assert(truncated == 0);
    assert(strcmp(safe, "?<redacted>") == 0);

    msconnector_event_init(&event);
    event.request.method = "GET";
    event.request.uri = input;
    assert(msconnector_event_write_json_ex(&event, json, sizeof(json),
        &truncated) == 1);
    assert(truncated == 0);
    assert(strstr(json, "\"redacted\":true") != NULL);
    assert(strstr(json, "\"truncated\":false") != NULL);
    assert(strstr(json, "uuuu") == NULL);
}

int main(void) {
    msconnector_event event;
    uint64_t safe_hash;
    char exact[sizeof("/path?<redacted>")];
    int truncated;

    check_uri("/path?x=CANARY", "/path?<redacted>", 1);
    check_uri("/path", "/path", 0);
    check_uri("/path?", "/path?", 0);
    check_uri("https://example.test/path?x=CANARY", "https://example.test/path?<redacted>", 1);
    check_uri("*", "*", 0);
    check_uri("example.test:443", "example.test:443", 0);

    truncated = 0;
    assert(msconnector_event_uri_redact_query_ex("/path?x=CANARY", exact,
        sizeof(exact), &truncated) == 1);
    assert(truncated == 0);
    assert(strcmp(exact, "/path?<redacted>") == 0);
    check_long_uri_serialization();
    check_unterminated_uri_is_bounded();
    check_bounded_redacted_query_is_not_truncated();

    msconnector_event_init(&event);
    event.request.uri = "/path?x=CANARY";
    safe_hash = msconnector_integrity_event_hash(&event, 0U);
    event.request.uri = "/path?<redacted>";
    assert(msconnector_integrity_event_hash(&event, 0U) == safe_hash);
    event.request.uri = "/path?x=OTHER";
    assert(msconnector_integrity_event_hash(&event, 0U) == safe_hash);
    return 0;
}
