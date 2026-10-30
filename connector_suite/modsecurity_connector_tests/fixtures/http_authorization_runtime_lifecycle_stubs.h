#ifndef MSCONNECTOR_TEST_HTTP_AUTHORIZATION_RUNTIME_LIFECYCLE_STUBS_H
#define MSCONNECTOR_TEST_HTTP_AUTHORIZATION_RUNTIME_LIFECYCLE_STUBS_H

#include <stdlib.h>
#include <string.h>

#include "http_authorization_request_stream_stubs.h"

/* The trusted-binding fixture renames these callbacks before including the
 * legacy model. Declare its selected names before the shared callers. */
int msconnector_runtime_transaction_begin_request_stream(
    msconnector_runtime *runtime, const msconnector_request *request,
    const char *host_request_id, msconnector_runtime_transaction **out,
    msconnector_decision *decision, msconnector_error *error);
int msconnector_runtime_transaction_finish(
    msconnector_runtime_transaction *transaction, msconnector_error *error);

/* Shared lifecycle model for the legacy timeout and detached-worker fixtures.
 * Their runtime accounting/finish implementations remain fixture-specific. */
void msconnector_runtime_transaction_destroy(
    msconnector_runtime_transaction **transaction) {
    if (transaction != NULL) {
        free(*transaction);
        *transaction = NULL;
    }
}

/* These fixtures exercise the old NULL-binding entry point. Refuse non-NULL
 * metadata rather than claiming a provenance copy or native P1 observation. */
int msconnector_runtime_transaction_begin_request_stream_with_trusted_provenance(
    msconnector_runtime *runtime, const msconnector_request *request,
    const char *host_request_id,
    const msconnector_runtime_trusted_provenance *provenance,
    msconnector_runtime_transaction **out, msconnector_decision *decision,
    msconnector_error *error) {
    if (provenance != NULL) {
        if (out != NULL) *out = NULL;
        msconnector_error_set(error, MSCONNECTOR_ERROR_UNSUPPORTED_PHASE,
            "trusted provenance is outside this legacy fixture", "fixture");
        return 0;
    }
    return msconnector_runtime_transaction_begin_request_stream(runtime, request,
        host_request_id, out, decision, error);
}

int msconnector_runtime_transaction_finalize_and_snapshot(
    msconnector_runtime_transaction **transaction,
    msconnector_runtime_transaction_snapshot *snapshot,
    msconnector_error *error) {
    if (transaction == NULL || *transaction == NULL || snapshot == NULL ||
        !msconnector_runtime_transaction_finish(*transaction, error)) return 0;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->finished = (*transaction)->finished;
    snapshot->request_body.bytes_seen = (*transaction)->request_body_bytes;
    snapshot->request_body.finished = (*transaction)->request_body_finished;
    snapshot->contract.cleanup_started = 1;
    snapshot->contract.cleanup_complete = 1;
    snapshot->contract.status = MSCONNECTOR_TRANSACTION_STATUS_CLEANED;
    msconnector_runtime_transaction_destroy(transaction);
    return 1;
}

int msconnector_runtime_error_http_status(
    const msconnector_runtime *runtime,
    msconnector_error_code code) {
    (void)runtime;
    (void)code;
    return 500;
}

#endif
