#ifndef MSCONNECTOR_TEST_RESULT_H
#define MSCONNECTOR_TEST_RESULT_H
#include "msconnector/status.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Common smoke/runtime result metadata model; it does not replace existing framework formats. */
typedef struct msconnector_test_result { const char *connector; const char *case_name; enum msconnector_status status; int expected_http_status; int actual_http_status; const char *reason; } msconnector_test_result;
void msconnector_test_result_init(msconnector_test_result *result);
int msconnector_test_result_passed(const msconnector_test_result *result);
#ifdef __cplusplus
}
#endif
#endif
