#ifndef MSCONNECTOR_TRANSACTION_PHASE_TEST_SUPPORT_H
#define MSCONNECTOR_TRANSACTION_PHASE_TEST_SUPPORT_H

#include <assert.h>
#include <string.h>

#include "common/runtime/msconnector_runtime.h"

/* Build the canonical request context used by response-companion tests.  The
 * caller supplies the scenario URI so protocol-specific assertions remain
 * visible at the call site while the shared transaction metadata stays in one
 * place. */
static inline int msconnector_test_begin_transaction(
    msconnector_runtime *runtime,
    const char *uri,
    const char *transaction_id,
    msconnector_runtime_transaction **transaction,
    msconnector_decision *decision,
    msconnector_error *error)
{
    msconnector_request request;

    assert(runtime != NULL);
    assert(uri != NULL);
    assert(transaction_id != NULL);
    assert(transaction != NULL);
    assert(decision != NULL);
    assert(error != NULL);
    memset(&request, 0, sizeof(request));
    request.method = "GET";
    request.uri = uri;
    request.http_version = "HTTP/1.1";
    request.client.address = "127.0.0.1";
    request.client.port = 12345;
    request.server.address = "127.0.0.1";
    request.server.port = 9191;
    msconnector_error_init(error);
    msconnector_decision_init(decision);
    return msconnector_runtime_transaction_begin(runtime, &request,
        transaction_id, transaction, decision, error);
}

#endif
