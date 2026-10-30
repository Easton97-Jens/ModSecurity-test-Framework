#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <modsecurity/transaction.h>
#include "common/runtime/msconnector_runtime.h"
#include "connectors/profile_registry.h"

static int fault;
size_t __real_msc_get_request_body_length(Transaction *transaction);
size_t __wrap_msc_get_request_body_length(Transaction *transaction) {
    return fault == 1 ? SIZE_MAX : __real_msc_get_request_body_length(transaction);
}
int __real_msc_process_request_body(Transaction *transaction);
int __wrap_msc_process_request_body(Transaction *transaction) {
    return fault == 2 ? -1 : __real_msc_process_request_body(transaction);
}
int __real_fflush(FILE *stream);
int __wrap_fflush(FILE *stream) {
    if (fault == 3) { errno = EIO; return EOF; }
    return __real_fflush(stream);
}

typedef struct {
    const char *scenario;
    int reject;
    int partial;
    int disabled;
    int sink_error;
    char rules[4096];
    char config[4096];
    char events[4096];
} telemetry_fixture;

static void write_fixture(telemetry_fixture *fixture, const char *directory) {
    assert(snprintf(fixture->rules, sizeof(fixture->rules), "%s/rules", directory) > 0);
    assert(snprintf(fixture->config, sizeof(fixture->config), "%s/config", directory) > 0);
    assert(snprintf(fixture->events, sizeof(fixture->events), "%s/events", directory) > 0);
    FILE *file = fopen(fixture->rules, "w");
    assert(file);
    assert(fprintf(file, "SecRuleEngine On\nSecRequestBodyAccess %s\n"
        "SecRequestBodyLimit %d\nSecRequestBodyNoFilesLimit %d\n"
        "SecRequestBodyLimitAction %s\n"
        "SecAction \"id:77301,phase:2,pass,nolog\"\n",
        fixture->disabled ? "Off" : "On", fixture->reject || fixture->partial ? 16 : 64,
        fixture->reject || fixture->partial ? 16 : 64, fixture->reject ? "Reject" : "ProcessPartial") > 0);
    assert(fclose(file) == 0);
    file = fopen(fixture->config, "w");
    assert(file);
    assert(fprintf(file, "enabled=on\nrules_file=%s\nrequest_body_mode=streaming\n"
        "response_body_mode=none\nevent_path=%s\n", fixture->rules, fixture->events) > 0);
    assert(fclose(file) == 0);
}

static void verify_finish(msconnector_runtime_transaction *transaction,
    const telemetry_fixture *fixture, msconnector_decision *decision, msconnector_error *error) {
    msconnector_runtime_body_progress progress;
    if (strcmp(fixture->scenario, "phase-error") == 0) fault = 2;
    if (fixture->sink_error) fault = 3;
    int finished = msconnector_runtime_transaction_finish_request_body(transaction, decision, error);
    msconnector_runtime_transaction_request_body_progress(transaction, &progress);
    if (fault == 3) {
        assert(!finished && error->code == MSCONNECTOR_ERROR_IO);
        assert(progress.finished && progress.bytes_inspected == 0U);
    } else if (fault == 2) {
        assert(!finished && error->code == MSCONNECTOR_ERROR_MODSECURITY_FAILURE);
        assert(!progress.finished && progress.bytes_inspected == 0U);
    } else {
        size_t retained = 17U;
        msconnector_body_limit_outcome outcome = MSCONNECTOR_BODY_LIMIT_OUTCOME_NONE;
        if (fixture->reject) {
            retained = 8U;
            outcome = MSCONNECTOR_BODY_LIMIT_OUTCOME_REJECT;
        } else if (fixture->partial) {
            retained = 16U;
            outcome = MSCONNECTOR_BODY_LIMIT_OUTCOME_PROCESS_PARTIAL;
        }
        assert(finished && progress.finished);
        assert(progress.bytes_retained == retained);
        assert(progress.bytes_inspected == 0U);
        assert(progress.limit_outcome == outcome);
        assert((decision->disruptive != 0) == fixture->reject);
    }
}

static void verify_append(msconnector_runtime_transaction *transaction,
    const telemetry_fixture *fixture, msconnector_decision *decision, msconnector_error *error) {
    msconnector_runtime_body_progress progress;
    if (strcmp(fixture->scenario, "accessor-error") == 0) fault = 1;
    int appended = msconnector_runtime_transaction_append_request_body_chunk(transaction,
        (const unsigned char *)"abcdefgh", 8U, error);
    if (fault == 1) {
        assert(!appended && error->code == MSCONNECTOR_ERROR_MODSECURITY_FAILURE);
        msconnector_runtime_transaction_request_body_progress(transaction, &progress);
        assert(progress.bytes_inspected == 0U && progress.bytes_retained == 0U);
    } else {
        assert(appended);
        assert(msconnector_runtime_transaction_append_request_body_chunk(transaction,
            (const unsigned char *)"ijklmnopq", 9U, error));
        msconnector_runtime_transaction_request_body_progress(transaction, &progress);
        assert(progress.bytes_seen == 17U && progress.bytes_inspected == 0U);
        verify_finish(transaction, fixture, decision, error);
    }
}

static void verify_events(const telemetry_fixture *fixture) {
    FILE *file = fopen(fixture->events, "r");
    assert(file);
    char evidence[16384];
    size_t count = fread(evidence, 1U, sizeof(evidence)-1U, file);
    assert(!ferror(file));
    assert(fclose(file) == 0);
    evidence[count] = '\0';
    if (fixture->reject || fixture->partial) {
        const char *limit_event = strstr(evidence, "MSCONN_EVENT_BODY_LIMIT");
        assert(limit_event);
        assert(!strstr(limit_event + strlen("MSCONN_EVENT_BODY_LIMIT"), "MSCONN_EVENT_BODY_LIMIT"));
        assert(strstr(evidence, "\"body_bytes_inspected\":0"));
        assert(strstr(evidence, "\"body_bytes_seen\":17"));
        assert(strstr(evidence, "\"body_truncated\":true"));
        assert(strstr(evidence, fixture->reject ? "\"body_limit_outcome\":\"reject\"" :
            "\"body_limit_outcome\":\"process_partial\""));
    } else assert(!strstr(evidence, "MSCONN_EVENT_BODY_LIMIT"));
}

int main(int argc, char **argv) {
    assert(argc == 3);
    telemetry_fixture fixture = {.scenario = argv[2]};
    fixture.reject = strcmp(fixture.scenario, "reject") == 0;
    fixture.sink_error = strcmp(fixture.scenario, "sink-error") == 0;
    fixture.partial = strcmp(fixture.scenario, "partial") == 0 || fixture.sink_error;
    fixture.disabled = strcmp(fixture.scenario, "disabled") == 0;
    write_fixture(&fixture, argv[1]);
    msconnector_runtime *runtime = NULL;
    char diagnostic[1024];
    assert(msconnector_runtime_create("traefik", fixture.config, &runtime, diagnostic, sizeof(diagnostic)));
    assert(msconnector_runtime_set_transaction_profile(runtime,
        msconnector_profile_registry_find("traefik-forwardauth")));
    msconnector_request request = {0};
    request.method = "POST";
    request.uri = "/telemetry";
    request.http_version = "HTTP/1.1";
    request.client.address = "127.0.0.1";
    request.server.address = "127.0.0.1";
    msconnector_runtime_transaction *transaction = NULL;
    msconnector_decision decision;
    msconnector_error error;
    assert(msconnector_runtime_transaction_begin_request_stream(runtime, &request,
        "telemetry", &transaction, &decision, &error));
    verify_append(transaction, &fixture, &decision, &error);
    fault = 0;
    msconnector_runtime_transaction_destroy(&transaction);
    msconnector_runtime_destroy(&runtime);
    verify_events(&fixture);
    puts("native request telemetry PASS");
    return 0;
}
