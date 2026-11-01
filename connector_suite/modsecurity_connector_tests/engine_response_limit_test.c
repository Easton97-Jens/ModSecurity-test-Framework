#define _POSIX_C_SOURCE 200809L
/* Real Common runtime + libModSecurity response policy test. Arguments are
 * required; this executable never supplies engine policy defaults. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "common/runtime/msconnector_runtime.h"
#include "tests/transaction_phase_test_support.h"
#include "connectors/profile_registry.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"
#include "modsecurity/transaction.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s (%s)\n", __LINE__, #x, error.message); goto cleanup; } } while (0)
/* Configuration loading only: no response inspection and no fixture defaults. */
static int config_omission_test(const char *directory) {
    char rules[4096];
    char config[4096];
    char diagnostic[1024];
    FILE *file;
    msconnector_runtime *runtime = NULL;
    if (snprintf(rules, sizeof(rules), "%s/omitted-rules", directory) < 0 ||
        snprintf(config, sizeof(config), "%s/omitted-config", directory) < 0) return 1;
    file = fopen(rules, "w");
    if (file == NULL) return 1;
    int written = fputs("SecRuleEngine On\n", file) != EOF;
    int closed = fclose(file) == 0;
    if (!written || !closed) return 1;
    file = fopen(config, "w");
    if (file == NULL) return 1;
    written = fprintf(file, "enabled=on\nrules_file=%s\nrequest_body_mode=none\n"
            "response_body_mode=none\nphase4_mode=safe\n", rules) >= 0;
    closed = fclose(file) == 0;
    if (!written || !closed) return 1;
    if (!msconnector_runtime_create("lighttpd", config, &runtime,
            diagnostic, sizeof(diagnostic))) {
        fprintf(stderr, "config-only omission failed: %s\n", diagnostic);
        return 1;
    }
    msconnector_runtime_destroy(&runtime);
    puts("config-only omission PASS; no response inspection executed");
    return 0;
}

static int close_test_file(FILE **file) {
    FILE *owned = *file;
    *file = NULL;
    return fclose(owned) == 0;
}

static int append_test_body(msconnector_runtime_transaction *tx, size_t length,
    size_t chunk_size, size_t marker_offset, size_t *offset,
    msconnector_error *error) {
    unsigned char chunk[65536];
    while (*offset < length) {
        size_t count = length - *offset < chunk_size ? length - *offset : chunk_size;
        memset(chunk, 'x', count);
        for (size_t i = 0; i < count; ++i) {
            size_t position = *offset + i;
            if (position >= marker_offset && position - marker_offset < 6U)
                chunk[i] = (unsigned char)"MARKER"[position - marker_offset];
        }
        if (!msconnector_runtime_transaction_append_response_body_chunk(tx, chunk, count, error)) { return 0; }
        *offset += count;
    }
    return 1;
}

static int check_reject_evidence(const char *events) {
    char evidence[16384];
    FILE *file = fopen(events, "r");
    if (file == NULL) return 0;
    size_t count = fread(evidence, 1U, sizeof(evidence) - 1U, file);
    int readable = !ferror(file);
    int closed = fclose(file) == 0;
    if (!readable || !closed) return 0;
    evidence[count] = '\0';
    return strstr(evidence, "MSCONN_EVENT_BODY_LIMIT") != NULL &&
        strstr(evidence, "\"body_limit_outcome\":\"reject\"") != NULL &&
        strstr(evidence, "MSCONN_EVENT_INVALID_ENGINE_RESPONSE") == NULL;
}


static void fill_request_chunk(unsigned char *chunk, size_t count,
    size_t offset, size_t marker, size_t length, int multipart) {
    memset(chunk, 'x', count);
    for (size_t i = 0; i < count; ++i)
        if (offset + i >= marker && offset + i - marker < 6U)
            chunk[i] = (unsigned char)"MARKER"[offset + i - marker];
    if (multipart) {
        const char *prefix = "--X\r\nContent-Disposition: form-data; name=\"p\"\r\n\r\n";
        const char *suffix = "\r\n--X--\r\n";
        size_t prefix_size = strlen(prefix);
        size_t suffix_size = strlen(suffix);
        for (size_t i = 0U; i < count; ++i) {
            size_t position = offset + i;
            if (position < prefix_size) chunk[i] = (unsigned char)prefix[position];
            if (position >= length - suffix_size) chunk[i] = (unsigned char)suffix[position - (length - suffix_size)];
        }
    }
}

typedef struct request_payload {
    size_t length;
    size_t chunk_size;
    size_t marker;
    const char *input_kind;
} request_payload;

/* Consume every intervention allocation, including invalid return values. */
static int take_native_intervention(Transaction *transaction, int *status) {
    ModSecurityIntervention intervention = {0};
    intervention.status = 200;
    int native_result = msc_intervention(transaction, &intervention);
    int valid = native_result == 0 || native_result == 1;
    *status = 0;
    if (valid && (native_result || intervention.disruptive)) *status = intervention.status;
    msc_intervention_cleanup(&intervention);
    return valid;
}

static int append_native_reference(Transaction *transaction, const request_payload *payload,
    const char *content_type, int *pending_status) {
    unsigned char scratch[65536];
    for (size_t offset = 0U; offset < payload->length;) {
        size_t count = payload->length - offset < payload->chunk_size
            ? payload->length - offset : payload->chunk_size;
        fill_request_chunk(scratch, count, offset, payload->marker, payload->length,
            strncmp(content_type, "multipart/", 10U) == 0);
        int native_result = msc_append_request_body(transaction, scratch, count);
        if (native_result != 0 && native_result != 1) return 0;
        int status;
        if (!take_native_intervention(transaction, &status)) return 0;
        if (*pending_status == 0) *pending_status = status;
        offset += count;
    }
    return 1;
}

/* Independent genuine engine execution records its native prefix and result.
 * Common's offered-byte counters are deliberately not used to infer either. */
static int native_request_reference(const char *rules_path, const request_payload *payload,
    const char *content_type, size_t *prefix, int *status) {
    ModSecurity *engine = msc_init();
    RulesSet *rules = msc_create_rules_set();
    Transaction *transaction = NULL;
    const char *diagnostic = NULL;
    int result = 0;
    int pending_status = 0;
    if (engine == NULL || rules == NULL ||
        msc_rules_add_file(rules, rules_path, &diagnostic) < 0) goto cleanup;
    transaction = msc_new_transaction(engine, rules, NULL);
    if (transaction == NULL ||
        msc_process_connection(transaction, "127.0.0.1", 1, "127.0.0.1", 2) != 1 ||
        msc_process_uri(transaction, "/engine-request-limit", "POST", "1.1") != 1 ||
        msc_add_request_header(transaction, (const unsigned char *)"Content-Type",
            (const unsigned char *)content_type) != 1 ||
        msc_process_request_headers(transaction) != 1) goto cleanup;
    if (!append_native_reference(transaction, payload, content_type, &pending_status)) goto cleanup;
    *prefix = msc_get_request_body_length(transaction);
    if (msc_process_request_body(transaction) != 1) goto cleanup;
    if (!take_native_intervention(transaction, status)) goto cleanup;
    if (pending_status != 0) *status = pending_status;
    result = 1;
cleanup:
    if (transaction != NULL) msc_transaction_cleanup(transaction);
    if (rules != NULL) (void)msc_rules_cleanup(rules);
    if (engine != NULL) msc_cleanup(engine);
    return result;
}

static int write_request_input(FILE *input, const request_payload *payload) {
    unsigned char scratch[65536];
    for (size_t offset = 0U; offset < payload->length;) {
        size_t count = payload->length - offset < payload->chunk_size
            ? payload->length - offset : payload->chunk_size;
        fill_request_chunk(scratch, count, offset, payload->marker, payload->length,
            strcmp(payload->input_kind, "multipart") == 0);
        if (fwrite(scratch, 1U, count, input) != count) return 0;
        offset += count;
    }
    return fseek(input, 0L, SEEK_SET) == 0;
}

static int append_request_chunks(msconnector_runtime_transaction *transaction, FILE *input,
    const request_payload *payload, msconnector_error *error) {
    unsigned char scratch[65536];
    for (size_t offset = 0U; offset < payload->length;) {
        size_t count = payload->length - offset < payload->chunk_size
            ? payload->length - offset : payload->chunk_size;
        if (input != NULL) {
            if (fread(scratch, 1U, count, input) != count) {
                msconnector_error_set(error, MSCONNECTOR_ERROR_HOST_API_FAILURE,
                    "test input read failed", "fixture");
                return 0;
            }
        } else {
            fill_request_chunk(scratch, count, offset, payload->marker, payload->length,
                strcmp(payload->input_kind, "multipart") == 0);
        }
        if (!msconnector_runtime_transaction_append_request_body_chunk(transaction, scratch, count, error)) return 0;
        offset += count;
    }
    return 1;
}

static int request_limit_test(int argc, char **argv) {
    msconnector_error error;
    msconnector_runtime *runtime = NULL;
    msconnector_runtime_transaction *transaction = NULL;
    msconnector_runtime_transaction_snapshot snapshot;
    msconnector_request request = {0};
    msconnector_decision decision;
    msconnector_header headers[] = {{"Content-Type", 12U, "text/plain", 10U}};
    const unsigned char accounting_probe = 'x';
    char rules[4096];
    char config[4096];
    char events[4096];
    char input_path[4096];
    char diagnostic[1024];
    FILE *file = NULL;
    FILE *input = NULL;
    int result = 1;
    size_t native_prefix = 0;
    int native_status = 0;
    msconnector_error_init(&error);
    if (argc != 12) {
        fprintf(stderr, "request required: directory request_limit no_files_limit Reject|ProcessPartial On|DetectionOnly buffered|streaming length chunk marker memory|file\n");
        return 2;
    }
    const size_t limit = (size_t)strtoull(argv[3], NULL, 10);
    const size_t no_files_limit = (size_t)strtoull(argv[4], NULL, 10);
    const size_t length = (size_t)strtoull(argv[8], NULL, 10);
    const size_t chunk_size = (size_t)strtoull(argv[9], NULL, 10);
    const size_t marker = (size_t)strtoull(argv[10], NULL, 10);
    CHECK(limit > 0 && no_files_limit > 0 && chunk_size > 0 && chunk_size <= 65536U);
    CHECK(marker <= length && length - marker >= 6U);
    CHECK(snprintf(rules, sizeof(rules), "%s/request-rules", argv[2]) > 0);
    CHECK(snprintf(config, sizeof(config), "%s/request-config", argv[2]) > 0);
    CHECK(snprintf(events, sizeof(events), "%s/request-events", argv[2]) > 0);
    CHECK(snprintf(input_path, sizeof(input_path), "%s/request-input", argv[2]) > 0);
    file = fopen(rules, "w"); CHECK(file != NULL);
    CHECK(fprintf(file, "SecRuleEngine %s\nSecRequestBodyAccess On\n"
        "SecRequestBodyLimit %zu\nSecRequestBodyNoFilesLimit %zu\nSecRequestBodyLimitAction %s\n"
        "SecAction \"id:720001,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On\"\n"
        "SecAction \"id:720002,phase:2,pass,nolog\"\n"
        "SecRule REQUEST_BODY \"@contains MARKER\" \"id:720003,phase:2,deny,status:451,log\"\n",
        argv[6], limit, no_files_limit, argv[5]) > 0);
    CHECK(close_test_file(&file));
    if (strcmp(argv[11], "urlencoded") == 0) {
        headers[0].value = "application/x-www-form-urlencoded";
        headers[0].value_size = strlen(headers[0].value);
    }
    if (strcmp(argv[11], "multipart") == 0) {
        headers[0].value = "multipart/form-data; boundary=X";
        headers[0].value_size = strlen(headers[0].value);
    }
    const request_payload payload = {length, chunk_size, marker, argv[11]};
    CHECK(native_request_reference(rules, &payload, headers[0].value, &native_prefix, &native_status));
    file = fopen(config, "w"); CHECK(file != NULL);
    CHECK(fprintf(file, "enabled=on\nrules_file=%s\nrequest_body_mode=%s\n"
        "response_body_mode=none\nphase4_mode=safe\nevent_path=%s\n", rules, argv[7], events) > 0);
    CHECK(close_test_file(&file));
    CHECK(msconnector_runtime_create("lighttpd", config, &runtime, diagnostic, sizeof(diagnostic)) ||
        (fprintf(stderr, "%s\n", diagnostic), 0));
    CHECK(msconnector_runtime_set_event_integration_mode(runtime, "stock-lighttpd-sidecar"));
    CHECK(msconnector_runtime_set_transaction_profile(runtime, msconnector_profile_registry_find("lighttpd-stock")));
    request.method = "POST"; request.uri = "/engine-request-limit"; request.http_version = "HTTP/1.1";
    request.client.address = "127.0.0.1"; request.client.port = 1;
    request.server.address = "127.0.0.1"; request.server.port = 2;
    request.headers = headers; request.header_count = 1U;
    CHECK(msconnector_runtime_transaction_begin_request_stream(runtime, &request,
        "real-request-limit", &transaction, &decision, &error));
    CHECK(msconnector_runtime_transaction_snapshot_get(transaction, &snapshot));
    CHECK(!snapshot.request_body.finished);
    if (strcmp(argv[11], "file") == 0) {
        input = fopen(input_path, "w+b"); CHECK(input != NULL);
        CHECK(write_request_input(input, &payload));
    } else CHECK(strcmp(argv[11], "memory") == 0 || strcmp(argv[11], "urlencoded") == 0 || strcmp(argv[11], "multipart") == 0);
    CHECK(append_request_chunks(transaction, input, &payload, &error));
    CHECK(msconnector_runtime_transaction_finish_request_body(transaction, &decision, &error));
    CHECK(decision.disruptive ? decision.intervention.status == native_status : native_status == 0);
    CHECK(msconnector_runtime_transaction_snapshot_get(transaction, &snapshot));
    CHECK(snapshot.request_body.bytes_seen == length);
    CHECK(snapshot.request_body.bytes_retained == native_prefix);
    CHECK(snapshot.request_body.bytes_inspected == 0U);
    CHECK(snapshot.request_body.truncated == (native_prefix < length));
    CHECK(snapshot.contract.last_completed_phase == MSCONNECTOR_PHASE_REQUEST_BODY);
    CHECK(!msconnector_runtime_transaction_finish_request_body(transaction, &decision, &error));
    CHECK(error.code != MSCONNECTOR_ERROR_NONE);
    printf("request-limit PASS limit=%zu no_files=%zu action=%s engine=%s body_mode=%s length=%zu chunk=%zu input=%s native_prefix=%zu native_status=%d\n",
        limit, no_files_limit, argv[5], argv[6], argv[7], length, chunk_size, argv[11], native_prefix, native_status);
    msconnector_runtime_transaction_destroy(&transaction);
    CHECK(msconnector_runtime_transaction_begin_request_stream(runtime, &request,
        "request-overflow", &transaction, &decision, &error));
    CHECK(msconnector_runtime_transaction_append_request_body_chunk(transaction, &accounting_probe, 1U, &error));
    CHECK(!msconnector_runtime_transaction_append_request_body_chunk(transaction, &accounting_probe, SIZE_MAX, &error));
    CHECK(error.code == MSCONNECTOR_ERROR_HOST_API_FAILURE);
    CHECK(msconnector_runtime_transaction_snapshot_get(transaction, &snapshot));
    CHECK(snapshot.contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR);
    CHECK(snapshot.request_body.bytes_seen == 1U);
    CHECK(snapshot.request_body.bytes_inspected == 0U);
    msconnector_runtime_transaction_destroy(&transaction);
    CHECK(msconnector_runtime_transaction_begin_request_stream(runtime, &request,
        "request-missing-eos", &transaction, &decision, &error));
    CHECK(!msconnector_runtime_transaction_finish(transaction, &error));
    CHECK(msconnector_runtime_transaction_snapshot_get(transaction, &snapshot));
    CHECK(!snapshot.request_body.finished);
    CHECK(snapshot.contract.error_class == MSCONNECTOR_TRANSACTION_ERROR_PHASE_SEQUENCE);
    CHECK(msconnector_runtime_transaction_finish_host_rejected_request_body(transaction, &error));
    CHECK(msconnector_runtime_transaction_snapshot_get(transaction, &snapshot));
    CHECK(!snapshot.request_body.finished);
    CHECK(msconnector_runtime_transaction_finish_host_rejected_request_body(transaction, &error));
    msconnector_runtime_transaction_destroy(&transaction);
    msconnector_runtime_destroy(&runtime);
    if (native_status == 403 || native_status == 413) CHECK(check_reject_evidence(events));
    for (int option = 0; option < 2; ++option) {
        file = fopen(config, "w"); CHECK(file != NULL);
        CHECK(fprintf(file, "enabled=on\nrules_file=%s\nrequest_body_mode=%s\nresponse_body_mode=none\nphase4_mode=safe\n", rules, argv[7]) > 0);
        CHECK(fputs(option ? "body_limit_action=reject\n" : "request_body_limit=128\n", file) != EOF);
        CHECK(close_test_file(&file));
        CHECK(!msconnector_runtime_config_check("lighttpd", config, diagnostic, sizeof(diagnostic)));
        CHECK(strstr(diagnostic, "unknown") != NULL);
        CHECK(strstr(diagnostic, "was removed") != NULL);
        CHECK(strstr(diagnostic, "SecRequestBodyLimit/SecRequestBodyLimitAction") != NULL);
    }
    result = 0;
cleanup:
    if (input != NULL && fclose(input) != 0) result = 1;
    if (file != NULL && fclose(file) != 0) result = 1;
    msconnector_runtime_transaction_destroy(&transaction);
    msconnector_runtime_destroy(&runtime);
    return result;
}

int main(int argc, char **argv) {
    msconnector_error error;
    msconnector_runtime *runtime = NULL;
    msconnector_runtime_transaction *tx = NULL;
    msconnector_decision decision;
    msconnector_runtime_transaction_snapshot snapshot;
    msconnector_response response = {0};
    msconnector_header headers[] = {{"Content-Type", 12U, "text/plain", 10U}};
    char config[4096];
    char rules[4096];
    char events[4096];
    char message[1024];
    size_t limit;
    size_t length;
    size_t chunk_size;
    size_t offset = 0;
    int partial;
    int expect_marker;
    int appended;
    int finished;
    int result = 1;
    FILE *file = NULL;
    msconnector_error_init(&error);
    if (argc >= 2 && strcmp(argv[1], "--request") == 0) return request_limit_test(argc, argv);
    if (argc == 3 && strcmp(argv[1], "--config-only") == 0) {
        return config_omission_test(argv[2]);
    }
    if (argc != 8) {
        fprintf(stderr, "required: directory limit Reject|ProcessPartial off|safe|strict length chunk_size marker_offset\n");
        return 2;
    }
    limit = (size_t)strtoull(argv[2], NULL, 10);
    length = (size_t)strtoull(argv[5], NULL, 10);
    chunk_size = (size_t)strtoull(argv[6], NULL, 10);
    const size_t marker_offset = (size_t)strtoull(argv[7], NULL, 10);
    partial = strcmp(argv[3], "ProcessPartial") == 0;
    CHECK(limit > 0U && chunk_size > 0U && chunk_size <= 65536U);
    CHECK(partial || strcmp(argv[3], "Reject") == 0);
    CHECK(marker_offset <= length && length - marker_offset >= 6U);
    CHECK(snprintf(config, sizeof(config), "%s/config", argv[1]) > 0);
    CHECK(snprintf(rules, sizeof(rules), "%s/rules", argv[1]) > 0);
    CHECK(snprintf(events, sizeof(events), "%s/events", argv[1]) > 0);
    file = fopen(rules, "w"); CHECK(file != NULL);
    CHECK(fprintf(file,
        "SecRuleEngine On\nSecRequestBodyAccess Off\nSecResponseBodyAccess On\n"
        "SecResponseBodyMimeType text/plain\nSecResponseBodyLimit %zu\n"
        "SecResponseBodyLimitAction %s\n"
        /* Matching P4 pass can clear an earlier native Reject at EOS. */
        "SecAction \"id:710002,phase:4,pass,nolog\"\n"
        "SecRule RESPONSE_BODY \"@contains MARKER\" \"id:710001,phase:4,deny,status:451,log\"\n",
        limit, argv[3]) > 0);
    CHECK(close_test_file(&file));
    file = fopen(config, "w"); CHECK(file != NULL);
    CHECK(fprintf(file, "enabled=on\nrules_file=%s\nrequest_body_mode=none\n"
        "response_body_mode=streaming\nphase4_mode=%s\nevent_path=%s\n", rules, argv[4], events) > 0);
    CHECK(close_test_file(&file));
    CHECK(msconnector_runtime_create("lighttpd", config, &runtime, message, sizeof(message)) ||
          (fprintf(stderr, "%s\n", message), 0));
    CHECK(msconnector_runtime_set_event_integration_mode(runtime, "stock-lighttpd-sidecar"));
    CHECK(msconnector_runtime_set_transaction_profile(runtime, msconnector_profile_registry_find("lighttpd-stock")));
    CHECK(msconnector_test_begin_transaction(runtime, "/engine-response-limit", "real-limit-test", &tx, &decision, &error));
    response.status = 200; response.http_version = "HTTP/1.1";
    response.headers = headers; response.header_count = 1U;
    CHECK(msconnector_runtime_transaction_process_response_headers(tx, &response, &decision, &error));
    appended = append_test_body(tx, length, chunk_size, marker_offset, &offset, &error);
    expect_marker = marker_offset + 6U <= (length < limit ? length : limit);
    if (length <= limit || partial) {
        CHECK(appended && offset == length);
        finished = msconnector_runtime_transaction_finish_response_body(tx, &decision, &error);
        CHECK(finished);
        CHECK(expect_marker ? decision.intervention.status == 451 : !decision.disruptive);
        CHECK(msconnector_runtime_transaction_snapshot_get(tx, &snapshot));
        CHECK(snapshot.response_body.bytes_seen == length);
        CHECK(snapshot.response_body.bytes_inspected == length);
        CHECK(!snapshot.response_body.truncated);
        CHECK(snapshot.contract.last_completed_phase == MSCONNECTOR_PHASE_RESPONSE_BODY);
    } else {
        if (appended) {
            CHECK(msconnector_runtime_transaction_finish_response_body(tx, &decision, &error));
            CHECK(decision.disruptive && decision.intervention.status == 403);
        } else {
            /* A native negative append result remains a technical failure. */
            CHECK(error.code == MSCONNECTOR_ERROR_MODSECURITY_FAILURE);
        }
    }
    printf("engine-limit PASS limit=%zu action=%s mode=%s length=%zu chunk=%zu marker=%zu appended=%d native_status=%d\n",
        limit, argv[3], argv[4], length, chunk_size, marker_offset, appended, decision.intervention.status);
    msconnector_runtime_transaction_destroy(&tx);
    msconnector_runtime_destroy(&runtime);
    if (length > limit && !partial && appended) {
        CHECK(check_reject_evidence(events));
    }
    file = fopen(config, "a"); CHECK(file != NULL);
    CHECK(fputs("response_body_limit=128\n", file) != EOF); CHECK(close_test_file(&file));
    CHECK(!msconnector_runtime_config_check("lighttpd", config, message, sizeof(message)));
    CHECK(strstr(message, "unknown") != NULL);
    result = 0;
cleanup:
    if (file != NULL && fclose(file) != 0) result = 1;
    msconnector_runtime_transaction_destroy(&tx);
    msconnector_runtime_destroy(&runtime);
    return result;
}
