#define _GNU_SOURCE
#include "msconnector/event_jsonl.h"
#include "msconnector/event_protocol.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct fault_sink { int writes; int closes; int write_fault; int close_fault; };
static ssize_t write_cookie(void *opaque, const char *data, size_t size) {
    struct fault_sink *sink = opaque;
    (void)data;
    sink->writes++;
    if (sink->write_fault) { errno = EIO; return -1; }
    return (ssize_t)size;
}
static int close_cookie(void *opaque) {
    struct fault_sink *sink = opaque;
    sink->closes++;
    if (sink->close_fault) { errno = EIO; return -1; }
    return 0;
}
static FILE *stream(struct fault_sink *sink, int buffered) {
    cookie_io_functions_t functions = {.write = write_cookie, .close = close_cookie};
    FILE *file = fopencookie(sink, "w", functions);
    assert(file != NULL);
    if (!buffered) assert(setvbuf(file, NULL, _IONBF, 0) == 0);
    return file;
}
int main(void) {
    msconnector_error error;
    msconnector_event event;
    msconnector_event_init(&event);
    event.meta.connector = "haproxy";
    event.meta.transaction_id = "physical-event-sink";
    event.meta.message_id = MSCONN_EVENT_REQUEST_BLOCKED;
    event.decision.phase = MSCONNECTOR_PHASE_REQUEST_HEADERS;
    event.decision.status = MSCONNECTOR_STATUS_BLOCKED;
    event.decision.requested_action = "deny";
    event.decision.action = "deny";
    event.decision.rule_id = "1250921";
    event.http.http_status = 403;
    event.http.transport_result = "not_observable";
    char json[8192];
    struct fault_sink sink = {0};
    FILE *file = stream(&sink, 0);
    msconnector_error_init(&error);
    assert(msconnector_event_write_jsonl_stream(&event, file, json, sizeof(json), &error));
    assert(sink.writes == 1 && error.code == MSCONNECTOR_ERROR_NONE);
    assert(msconnector_event_file_close(&file, &error) && file == NULL && sink.closes == 1);

    for (int buffered = 0; buffered < 2; ++buffered) {
        sink = (struct fault_sink){.write_fault = 1}; file = stream(&sink, buffered);
        msconnector_error_init(&error);
        assert(!msconnector_event_write_jsonl_stream(&event, file, json, sizeof(json), &error));
        assert(error.code == MSCONNECTOR_ERROR_IO && sink.writes >= 1);
        int calls = sink.writes;
        assert(!msconnector_event_file_write(file, "{}\n", &error));
        assert(sink.writes == calls); /* Sticky first error prevents retries. */
        assert(!msconnector_event_file_close(&file, &error));
        assert(file == NULL && sink.closes == 1 && error.code == MSCONNECTOR_ERROR_IO);
    }
    /* A successful fputs does not clear an existing stream error. */
    sink = (struct fault_sink){.write_fault = 1}; file = stream(&sink, 0);
    assert(fputs("prior-error", file) == EOF && ferror(file));
    sink.write_fault = 0;
    msconnector_error_init(&error);
    assert(!msconnector_event_file_write(file, "{}\n", &error));
    assert(error.code == MSCONNECTOR_ERROR_IO);
    assert(!msconnector_event_file_close(&file, &error) && file == NULL);

    sink = (struct fault_sink){.close_fault = 1}; file = stream(&sink, 0);
    msconnector_error_init(&error);
    assert(!msconnector_event_file_close(&file, &error));
    assert(file == NULL && sink.closes == 1 && error.code == MSCONNECTOR_ERROR_IO);
    assert(msconnector_event_file_close(&file, NULL));

    sink = (struct fault_sink){0}; file = stream(&sink, 0);
    msconnector_error_init(&error);
    assert(!msconnector_event_write_jsonl_stream(&event, file, json, 4, &error));
    assert(sink.writes == 0 && error.code != MSCONNECTOR_ERROR_NONE);
    msconnector_error_code first = error.code;
    assert(!msconnector_event_file_close(&file, &error));
    assert(file == NULL && sink.closes == 1 && error.code == first);
    return 0;
}
