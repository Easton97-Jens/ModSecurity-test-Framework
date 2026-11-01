#ifndef MSCONNECTOR_TEST_RESULT_JSON_H
#define MSCONNECTOR_TEST_RESULT_JSON_H
#include "msconnector/test_result.h"
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
int msconnector_test_result_write_json(const msconnector_test_result *result, char *dst, size_t dst_size, int *truncated);
#ifdef __cplusplus
}
#endif
#endif
