/* HAProxy current request-authorization scope, using the existing I12 collector.
 * Compile this translation unit instead of native-lifecycle-observer.c; never
 * link both. All recorded state comes from the actual Common enter/return.
 */
#include "modsecurity_connector_ci/runtime/lifecycle/native-lifecycle-observer.c"

#ifndef COMMON_TIME_WRAPPER
#error "The selected I12 observer lacks its Common time-wrapper contract"
#endif

COMMON_TIME_WRAPPER(finish_request_authorization,
    "common_finish_request_authorization", 0)
