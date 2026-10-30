/*
 * Focused Common-event regression smoke.
 *
 * Manual run (from the repository root):
 *   cc -std=c17 -Wall -Wextra -Werror -Icommon/include \
 *     tests/event_json_utf8_smoke.c <all Common C sources> -o /tmp/event-json-smoke \
 *     && /tmp/event-json-smoke | python3 -c 'import json,sys; assert json.load(sys.stdin)["requested_protocol"] == "h2\"\\test"'
 */

#include "msconnector/event.h"
#include "msconnector/event_jsonl.h"
#include "msconnector/integrity_event.h"
#include "msconnector/json_escape.h"

#include <stdio.h>
#include <string.h>

static int expect_string(const char *actual, const char *expected) {
    return actual != NULL && expected != NULL && strcmp(actual, expected) == 0;
}

static int test_transport_provenance_integrity_projection(void) {
    char excessive_token[65];
    char projected_json[16384];
    msconnector_event event;
    msconnector_event sanitized;
    uint64_t event_hash;
    int truncated = 0;

    memset(excessive_token, 'a', sizeof(excessive_token) - 1U);
    excessive_token[sizeof(excessive_token) - 1U] = '\0';
    msconnector_event_init(&event);
    event.meta.timestamp = "2026-09-03T00:00:00Z";
    event.meta.level = "error";
    event.meta.message_id = "MSCONN_EVENT_INTERNAL_ERROR";
    event.meta.event = event.meta.message_id;
    event.meta.connector = "event-integrity-smoke";
    event.protocol.stream_reset_code = "peer_reset";
    event.protocol.reset_by = "upstream";
    event.protocol.reset_code = "peer_closed";
    event.flags.timeout_stage = "engine";
    event.flags.write_result = "ok";
    event.flags.cleanup_reason = "normal";
    if (!msconnector_event_transport_provenance_is_valid(&event) ||
        !msconnector_event_write_jsonl_line(&event, projected_json,
            sizeof(projected_json), &truncated) || truncated != 0 ||
        strstr(projected_json, "\"cleanup_reason\":\"normal\"") == NULL) {
        (void)fprintf(stderr, "valid transport provenance control failed\n");
        return 1;
    }

    event.flags.truncated = 1;
    if (!msconnector_event_write_jsonl_line(&event, projected_json,
            sizeof(projected_json), &truncated) || truncated != 1 ||
        strstr(projected_json, "\"truncated\":true") == NULL) {
        (void)fprintf(stderr, "authenticated source truncation control failed\n");
        return 1;
    }
    event.flags.truncated = 0;

    event.flags.cleanup_reason = excessive_token;
    if (msconnector_event_transport_provenance_is_valid(&event)) {
        (void)fprintf(stderr, "oversized transport provenance was accepted\n");
        return 1;
    }
    event_hash = msconnector_integrity_event_hash(&event, 0U);
    sanitized = event;
    sanitized.protocol.stream_reset_code = NULL;
    sanitized.protocol.reset_by = NULL;
    sanitized.protocol.reset_code = NULL;
    sanitized.flags.timeout_stage = NULL;
    sanitized.flags.write_result = NULL;
    sanitized.flags.cleanup_reason = NULL;
    sanitized.flags.truncated = 1;
    if (event_hash != msconnector_integrity_event_hash(&sanitized, 0U)) {
        (void)fprintf(stderr, "transport provenance hash projection failed\n");
        return 1;
    }
    event.integrity.event_hash = event_hash;
    if (msconnector_event_write_jsonl_line(&event, projected_json,
            sizeof(projected_json), &truncated) != 0 || truncated != 1 ||
        projected_json[0] != '\0') {
        (void)fprintf(stderr, "transport provenance truncation control failed\n");
        return 1;
    }
    return 0;
}

int main(void) {
    static const char invalid_utf8[] = {
        'o', 'k', (char)0x80, (char)0xc0, (char)0xaf, '\0'
    };
    static const char valid_utf8[] = {
        'o', 'k', (char)0xc3, (char)0xa4, '\0'
    };
    static const char embedded_nul[] = {'a', '\0', 'b'};
    char escaped[128];
    char json[16384];
    char bounded_json[16384];
    char unterminated[1024];
    msconnector_event event;
    int truncated = 0;

    if (msconnector_json_utf8_is_valid_n(invalid_utf8,
            sizeof(invalid_utf8) - 1U) ||
        !msconnector_json_utf8_is_valid_n(valid_utf8,
            sizeof(valid_utf8) - 1U) ||
        !expect_string(
            (msconnector_json_escape(invalid_utf8, escaped, sizeof(escaped)), escaped),
            "ok\\u0080\\u00c0\\u00af") ||
        !expect_string(
            (msconnector_json_escape(valid_utf8, escaped, sizeof(escaped)), escaped),
            valid_utf8) ||
        !expect_string(
            (msconnector_json_escape_n(embedded_nul, sizeof(embedded_nul),
                escaped, sizeof(escaped)), escaped),
            "a\\u0000b")) {
        (void)fprintf(stderr, "event JSON UTF-8 escaping control failed\n");
        return 1;
    }

    if (test_transport_provenance_integrity_projection() != 0) {
        return 1;
    }

    msconnector_event_init(&event);
    event.meta.timestamp = "2026-08-24T00:00:00Z";
    event.meta.level = "error";
    event.meta.message_id = "MSCONN_EVENT_INTERNAL_ERROR";
    event.meta.event = event.meta.message_id;
    event.meta.connector = "event-json-smoke";
    event.meta.run_id = "run\"id";
    event.request.uri = invalid_utf8;
    event.protocol.requested_protocol = invalid_utf8;
    if (!msconnector_event_write_jsonl_line(&event, json, sizeof(json),
            &truncated) || truncated != 0 ||
        strstr(json, "\\u0080\\u00c0\\u00af") == NULL ||
        strstr(json, "\"run_id\":\"run\\\"id\"") == NULL ||
        strstr(json, "\"uri\":\"ok\\u0080\\u00c0\\u00af\"") == NULL ||
        strstr(json,
            "\"requested_protocol\":\"ok\\u0080\\u00c0\\u00af\"") == NULL) {
        (void)fprintf(stderr, "event JSONL UTF-8 serialization control failed\n");
        return 1;
    }

    event.protocol.requested_protocol = "h2\"\\test";
    if (!msconnector_event_write_jsonl_line(&event, json, sizeof(json),
            &truncated) || truncated != 0 ||
        strstr(json, "\"requested_protocol\":\"h2\\\"\\\\test\"") == NULL) {
        (void)fprintf(stderr, "event JSONL decoded-value control failed\n");
        return 1;
    }

    event.request.uri = invalid_utf8;
    event.protocol.requested_protocol = "h2";
    if (!msconnector_event_write_jsonl_line(&event, json, sizeof(json),
            &truncated) || truncated != 0 ||
        strstr(json, "\"uri\":\"ok\\u0080\\u00c0\\u00af\"") == NULL) {
        (void)fprintf(stderr, "event JSONL invalid URI escaping failed\n");
        return 1;
    }

    event.request.uri = "/event-json-smoke";
    event.protocol.requested_protocol = invalid_utf8;
    if (!msconnector_event_write_jsonl_line(&event, json, sizeof(json),
            &truncated) || truncated != 0 ||
        strstr(json,
            "\"requested_protocol\":\"ok\\u0080\\u00c0\\u00af\"") == NULL) {
        (void)fprintf(stderr, "event JSONL invalid protocol escaping failed\n");
        return 1;
    }

    event.protocol.requested_protocol = "h2\"\\test";
    if (!msconnector_event_write_jsonl_line(&event, json, sizeof(json),
            &truncated) || truncated != 0) {
        (void)fprintf(stderr, "event JSONL decoded-value control failed\n");
        return 1;
    }

    /* The event writer reads no more than its declared metadata input cap. */
    memset(unterminated, 'x', sizeof(unterminated));
    event.request.uri = unterminated;
    truncated = 0;
    if (msconnector_event_write_json_ex(&event, bounded_json, sizeof(bounded_json),
            &truncated) != 0 || truncated == 0) {
        (void)fprintf(stderr, "event metadata bound control failed\n");
        return 1;
    }

    (void)fputs(json, stdout);
    return 0;
}
