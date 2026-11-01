#include "msconnector/test_result.h"
void msconnector_test_result_init(msconnector_test_result *r) { if (r) { r->connector = 0; r->case_name = 0; r->status = MSCONNECTOR_STATUS_UNSUPPORTED; r->expected_http_status = 0; r->actual_http_status = 0; r->reason = 0; } }
int msconnector_test_result_passed(const msconnector_test_result *r) { return r && r->status == MSCONNECTOR_STATUS_OK && r->expected_http_status == r->actual_http_status; }
