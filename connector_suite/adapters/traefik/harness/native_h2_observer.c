/* Opt-in test link wrapper: enable Common native cleanup/decision records.
 * Provenance labels are literal observer scope, never HTTP-derived authority.
 * Physical connection/reuse is proved independently by the H2 wire client. */
#include "common/runtime/msconnector_runtime.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
int __wrap_msconnector_runtime_transaction_begin_request_stream(
    msconnector_runtime *runtime, const msconnector_request *request,
    const char *host_request_id, msconnector_runtime_transaction **out,
    msconnector_decision *decision, msconnector_error *error)
{
    const char *run_id = getenv("TRAEFIK_NATIVE_H2_OBSERVER_RUN_ID");
    if (run_id == NULL || strlen(run_id) != 32U ||
        strspn(run_id, "0123456789abcdef") != 32U) return 0;
    const msconnector_runtime_trusted_provenance provenance = {
        run_id, "native-h2-opt-in", "engine-observer-scope", 0
    };
    return msconnector_runtime_transaction_begin_request_stream_with_trusted_provenance(
        runtime, request, host_request_id, &provenance, out, decision, error);
}

/* Explicit negative control on this test-linked executable only. */
int __real_fputs(const char *text, FILE *stream);
int __wrap_fputs(const char *text, FILE *stream)
{
    const char *fault = getenv("TRAEFIK_NATIVE_H2_FAULT_EVENT_WRITER");
    if (fault != NULL && strcmp(fault, "1") == 0 &&
        stream != stdout && stream != stderr) {
        errno = ENOSPC;
        return EOF;
    }
    return __real_fputs(text, stream);
}
