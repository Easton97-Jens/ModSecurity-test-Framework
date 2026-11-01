#!/usr/bin/env python3
"""Run the Apache/Common adoption suite plus review-hardened scoped guards."""
import re
import sys

import modsecurity_connector_ci.checks.connectors.apache.apache_common_adoption_base as base


DOWNSTREAM_PASS = "rc = ap_pass_brigade(f->next, brigade);"
NORMALIZE_ASSIGNMENT = (
    "*eos_bucket = apache_phase4_normalize_response_brigade(*brigade);"
)
RC_NOT_SUCCESS = "if (rc != APR_SUCCESS)"
RETURN_APR_SUCCESS = "return APR_SUCCESS;"
RETURN_APR_EGENERAL = "return APR_EGENERAL;"
RETURN_VOID = "return;"
INTERVENTION_SENTINEL = "N_INTERVENTION_STATUS"
TERMINAL_EMITTING = "MSC_PHASE4_TERMINAL_OUTPUT_EMITTING"
TERMINAL_SEALED = "MSC_PHASE4_TERMINAL_OUTPUT_SEALED"
RESET_HTTP_STATUS = "r->status = HTTP_OK;"
RESET_STATUS_LINE = "r->status_line = NULL;"
AP_DIE_STATUS = "ap_die(status, r);"
FILTER_ATTACH_FAILURE = "r->connection) == NULL"
CONNECTION_ABORT = "r->connection->aborted = 1;"
CONNECTION_CLOSE = "r->connection->keepalive = AP_CONN_CLOSE;"
PHASE4_GATE_FAILED = "msr->response_phase4_gate_failed = 1;"
RECORD_INTERVENTION = "!msc_apache_contract_record_intervention_decision(msr)"
REQUEST_BODY_PHASE = "MSCONNECTOR_PHASE_REQUEST_BODY"
RESPONSE_HEADERS_PHASE = "MSCONNECTOR_PHASE_RESPONSE_HEADERS"
RESPONSE_BODY_PHASE = "MSCONNECTOR_PHASE_RESPONSE_BODY"
P2_PROCESS = "if (!msconnector_native_phase_succeeded(msc_process_request_body(msr->t)))"
P3_PROCESS = ('if (!msconnector_native_phase_succeeded(\n'
              '            msc_process_response_headers(msr->t, original_status, "HTTP 1.1")))')
P4_PROCESS = "if (!msconnector_native_phase_succeeded(msc_process_response_body(msr->t)))"
P2_APPEND_GUARD = (
    r"!\s*msconnector_native_body_append_can_continue\s*\(\s*"
    r"msc_append_request_body\s*\(\s*msr->t\s*,\s*"
    r"\(\s*const\s+unsigned\s+char\s*\*\s*\)\s*data\s*,\s*"
    r"len\s*\)\s*\)"
)
REMOVE_OUTPUT_FILTER = "ap_remove_output_filter(f);"
BUCKET_NEXT_LOOP = "bucket = APR_BUCKET_NEXT(bucket))"
RETURN_APR_SUCCESS_PATTERN = r"\breturn\s+APR_SUCCESS\s*;"
RETURN_INPUT_TERMINAL_ERROR_PATTERN = (
    r"\breturn\s+apache_input_filter_terminal_error\s*\("
)

def patterns_in_order(text: str, *patterns: str) -> bool:
    """Return whether regular-expression patterns occur in order."""
    position = 0
    for pattern in patterns:
        match = re.search(pattern, text[position:], re.DOTALL)
        if match is None:
            return False
        position += match.end()
    return True


def direct_body_ends_with(text: str, pattern: str) -> bool:
    """Require a direct helper-body terminal sequence through its final brace."""
    direct_body = base.function_direct_body(text)
    return re.search(pattern + r"\s*\Z", direct_body, re.DOTALL) is not None


def native_intervention_flow_is_checked(text: str) -> bool:
    """Follow real storage and require cleanup on every post-native outcome."""
    collector = base.function_section(text, "process_intervention")
    native_call = "native_result = msc_intervention(t, &intervention);"
    native_tail = collector.partition(native_call)[2]
    return (
        base.native_redirect_storage_is_checked(text)
        and base.tokens_in_order(collector,
            "msr->intervention.collecting = 1;", native_call,
            "if (native_result != 0 && native_result != 1)",
            "result = apache_record_failure(msr, r,",
            "MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE",
            "else if (msr->contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE)",
            "else if (native_result == 0 && !intervention.disruptive)",
            "result = N_INTERVENTION_STATUS;",
            "result = apache_store_native_intervention(msr, r, &intervention);",
            "msc_release_intervention_buffers(&intervention);",
            "msr->intervention.collecting = 0;", "return result;")
        and len(re.findall(r"\breturn\b", native_tail)) == 1
        and direct_body_ends_with(collector,
            r"msc_release_intervention_buffers\s*\(\s*&intervention\s*\)\s*;\s*"
            r"msr->intervention\.collecting\s*=\s*0\s*;\s*return\s+result\s*;")
    )


request_body_finalizer = base.function_section(
    base.filters_c, "msc_finalize_request_body"
)
phase4_normalize_helper = base.source_section(
    base.filters_c,
    "static apr_bucket *apache_phase4_normalize_response_brigade",
    "static int apache_phase4_error_bucket_status",
)
error_bucket_classifier = base.source_section(
    base.filters_c,
    "static int apache_phase4_error_bucket_status",
    "static int apache_phase3_snapshot_table_value",
)
response_start_classifier = base.source_section(
    base.filters_c,
    "static int apache_phase4_brigade_starts_response",
    "static apr_status_t apache_phase4_release_response_brigade",
)
phase4_terminal_guard = base.source_section(
    base.filters_c,
    "apr_status_t phase4_terminal_guard_filter",
    "static int apache_phase4_response_committed",
)
precommit_terminal_helper = base.source_section(
    base.filters_c,
    "static apr_status_t apache_send_precommit_terminal_error",
    "static apr_status_t apache_phase4_fail_closed",
)
phase4_fail_closed_helper = base.source_section(
    base.filters_c,
    "static apr_status_t apache_phase4_fail_closed(msc_t *msr, ap_filter_t *f,\n"
    "    apr_bucket_brigade *bb_in, const char *reason)\n{",
    "static apr_status_t apache_finish_unread_request_body",
)
finish_unread_request_body = base.source_section(
    base.filters_c,
    "static apr_status_t apache_finish_unread_request_body",
    "static apr_status_t apache_output_filter_terminal_result",
)
input_eos_handler = base.function_section(
    base.filters_c, "apache_input_filter_handle_eos"
)
input_bucket_processor = base.function_section(
    base.filters_c, "apache_input_filter_process_bucket"
)
input_filter_handler = base.function_section(base.filters_c, "input_filter")
input_bucket_processor_direct = base.function_direct_body(input_bucket_processor)
prepare_response_brigade = base.source_section(
    base.filters_c,
    "static apr_status_t apache_output_filter_prepare_response_brigade",
    "static apr_status_t apache_phase4_finish_response_body",
)
phase4_finish_helper = base.source_section(
    base.filters_c,
    "static apr_status_t apache_phase4_finish_response_body",
    "static apr_status_t apache_phase4_handle_intervention",
)
phase3_headers_handler = base.source_section(
    base.filters_c,
    "static apr_status_t apache_output_filter_process_headers",
    "static apr_status_t apache_output_filter_prepare_response_brigade",
)
phase4_intervention_handler = base.source_section(
    base.filters_c,
    "static apr_status_t apache_phase4_handle_intervention",
    "static apr_status_t apache_output_filter_finish_response",
)
finish_response_handler = base.source_section(
    base.filters_c,
    "static apr_status_t apache_output_filter_finish_response",
    "apr_status_t output_filter",
)
redirect_terminal_emission = base.source_section(
    base.module_c,
    "static int apache_phase4_redirect_is_terminal_error_emission",
    "static void apache_phase4_fail_normal_redirect",
)
hook_insert_filter = base.source_section(
    base.module_c,
    "static void hook_insert_filter(request_rec *r)\n{",
    "static int apache_emit_phase1_intervention_event",
)
register_hooks = base.source_section(
    base.module_c,
    "static void msc_register_hooks",
    "module AP_MODULE_DECLARE_DATA security3_module",
)
release_after_pass = base.phase4_release_helper.partition(DOWNSTREAM_PASS)[2]
terminal_success_seal = (
    "if (terminal)\n"
    "    {\n"
    "        msr->response_phase4_terminal_output =\n"
    f"            {TERMINAL_SEALED};\n"
    "        apr_brigade_cleanup(brigade);\n"
    "    }"
)

review_guards: list[tuple[bool, str]] = [
    (
        base.tokens_in_order(input_bucket_processor,
            "ret = process_intervention(msr->t, r);",
            "if (ret != N_INTERVENTION_STATUS && !msr->request_intervention_pending)",
            "msr->pending_request_intervention = msr->intervention;",
            "msr->request_intervention_pending = 1;")
        and base.tokens_in_order(request_body_finalizer,
            "intervention = process_intervention(msr->t, r);",
            "msr->request_intervention_pending)",
            "msr->intervention = msr->pending_request_intervention;",
            "intervention = msr->last_intervention_status;"),
        "Apache retains a native request append intervention through matching-rule EOS completion",
    ),
    (
        base.tokens_in_order(
            request_body_finalizer,
            "if (msr->intervention.mandatory_event_failed ||",
            "msr->contract.error_class != MSCONNECTOR_TRANSACTION_ERROR_NONE)",
            "return HTTP_INTERNAL_SERVER_ERROR;",
            "if (msr->request_body_processed)",
            f"return {INTERVENTION_SENTINEL};",
            P2_PROCESS,
            f"msc_apache_contract_complete(msr,\n            {REQUEST_BODY_PHASE})",
            "msr->request_body_processed = 1;",
            "intervention = process_intervention(msr->t, r);",
            "return msr->intervention.mandatory_event_failed\n"
            "        ? HTTP_INTERNAL_SERVER_ERROR : intervention;",
        )
        # This helper is part of the P2 call graph. A known-unreachable
        # lexical decoy must not satisfy its completion/intervention contract.
        and not base.has_forbidden_contract_control_flow(request_body_finalizer),
        "Apache Phase2 one-shot gate precedes processing, completion, intervention collection, and the collected result return",
    ),
    (
        base.tokens_in_order(
            phase4_normalize_helper,
            "for (apr_bucket *bucket = APR_BRIGADE_FIRST(bb_in);",
            "bucket != APR_BRIGADE_SENTINEL(bb_in); bucket = next)",
            "next = APR_BUCKET_NEXT(bucket);",
            "if (eos != NULL)",
            "APR_BUCKET_REMOVE(bucket);",
            "apr_bucket_destroy(bucket);",
            "continue;",
            "if (APR_BUCKET_IS_EOS(bucket))",
            "eos = bucket;",
            "return eos;",
        )
        and base.tokens_in_order(
            prepare_response_brigade,
            NORMALIZE_ASSIGNMENT,
            "for (apr_bucket *bucket = APR_BRIGADE_FIRST(*brigade);",
        ),
        "Apache Phase4 advances through normalization, destroys every suffix bucket after the first EOS, returns that EOS, and binds the prepare call site",
    ),
    (
        base.tokens_in_order(
            error_bucket_classifier,
            "first = APR_BRIGADE_FIRST(bb_in);",
            "for (apr_bucket *bucket = first; bucket != APR_BRIGADE_SENTINEL(bb_in);",
            BUCKET_NEXT_LOOP,
            "if (!AP_BUCKET_IS_ERROR(bucket))",
            "if (bucket != first)",
            "return -1;",
            "error = (ap_bucket_error *)bucket->data;",
            "if (error == NULL || !ap_is_HTTP_ERROR(error->status))",
            "return -1;",
            "return error->status;",
        ),
        "Apache Phase4 error-bucket classifier scans the complete brigade, validates type, placement, and HTTP status, and returns the validated status",
    ),
    (
        base.tokens_in_order(
            response_start_classifier,
            "for (apr_bucket *bucket = APR_BRIGADE_FIRST(brigade);",
            "bucket != APR_BRIGADE_SENTINEL(brigade);",
            BUCKET_NEXT_LOOP,
            "if (APR_BUCKET_IS_FLUSH(bucket) ||",
            "(!APR_BUCKET_IS_METADATA(bucket) && !APR_BUCKET_IS_EOS(bucket)))",
            "return 1;",
            "return 0;",
        ),
        "Apache response-start classifier detects every FLUSH or non-metadata body bucket before release",
    ),
    (
        base.tokens_in_order(
            prepare_response_brigade,
            "error_status = apache_phase4_error_bucket_status(*brigade);",
            "if (error_status < 0)",
            '"malformed response error bucket before Phase 4 decision"',
            "if (error_status > 0)",
            "ap_remove_output_filter(filter);",
            "return apache_send_precommit_terminal_error(msr, filter, *brigade,",
            "error_status);",
            NORMALIZE_ASSIGNMENT,
        ),
        "Apache Phase4 validates malformed and terminal error buckets before normalization",
    ),
    (
        base.tokens_in_order(
            prepare_response_brigade,
            NORMALIZE_ASSIGNMENT,
            "for (apr_bucket *bucket = APR_BRIGADE_FIRST(*brigade);",
            "bucket != APR_BRIGADE_SENTINEL(*brigade);",
            BUCKET_NEXT_LOOP,
            "rc = apache_phase4_append_bucket(msr, conf, bucket);",
            RC_NOT_SUCCESS,
            "return apache_phase4_fail_closed(msr, filter, *brigade,",
            '"failed to append response body to libmodsecurity"',
        ),
        "Apache Phase4 walks every normalized bucket and fails closed on append errors",
    ),
    (
        base.tokens_in_order(
            phase4_finish_helper,
            P4_PROCESS,
            "return apache_phase4_fail_closed(msr, f, bb_in,",
            '"failed to finish response body in libmodsecurity"',
            f"msc_apache_contract_complete(msr, {RESPONSE_BODY_PHASE})",
            "msr->response_body_processed = 1;",
            "*intervention = process_intervention(msr->t, f->r);",
            f"if (*intervention != {INTERVENTION_SENTINEL} &&",
            RECORD_INTERVENTION,
            "MSCONNECTOR_TRANSACTION_ERROR_INVALID_ENGINE_RESPONSE",
            '"could not record canonical P4 intervention decision"',
        ),
        "Apache Phase4 fails closed on engine finalization errors and completes before collecting intervention",
    ),
    (
        base.tokens_in_order(
            finish_response_handler,
            "if (!msr->response_body_processed)",
            "rc = apache_phase4_finish_response_body(msr, f, bb_in,",
            "&intervention);",
            RC_NOT_SUCCESS,
            f"if (intervention != {INTERVENTION_SENTINEL})",
            "rc = apache_phase4_handle_intervention(msr, conf, f, bb_in,",
            "intervention);",
            RC_NOT_SUCCESS,
            "return apache_phase4_release_response_brigade(msr, f, terminal_brigade,",
        ),
        "Apache Phase4 first-EOS gate finalizes before intervention dispatch and terminal release",
    ),
    (
        patterns_in_order(
            input_eos_handler,
            r"\bif\s*\(\s*msr->request_body_eos_released\s*\)",
            RETURN_INPUT_TERMINAL_ERROR_PATTERN,
            r"\bif\s*\(\s*!\s*msr->request_body_processed\s*\)",
            r"\bintervention\s*=\s*msc_finalize_request_body\s*\(\s*msr\s*,\s*r\s*\)",
            r"\bif\s*\(\s*intervention\s*!=\s*N_INTERVENTION_STATUS\s*\)",
            r"\bap_remove_input_filter\s*\(\s*filter\s*\)",
            rf"{RETURN_INPUT_TERMINAL_ERROR_PATTERN}\s*msr\s*,\s*r\s*,\s*intervention\s*\)",
            r"\bmsr->request_body_eos_released\s*=\s*1\s*;",
            r"\bAPR_BUCKET_REMOVE\s*\(\s*bucket\s*\)",
            r"\bAPR_BRIGADE_INSERT_TAIL\s*\(\s*output\s*,\s*bucket\s*\)",
            r"\bap_remove_input_filter\s*\(\s*filter\s*\)",
            RETURN_APR_SUCCESS_PATTERN,
        )
        and base.function_call_count(
            input_eos_handler, "msc_finalize_request_body"
        ) == 1
        and base.function_call_count(
            input_eos_handler, "apache_input_filter_terminal_error"
        ) >= 2,
        "Apache Phase2 EOS helper rejects duplicate EOS, finalizes once, bridges intervention before forwarding, and detaches after canonical release",
    ),
    (
        not base.has_forbidden_contract_control_flow(input_eos_handler)
        and len(re.findall(RETURN_APR_SUCCESS_PATTERN, input_eos_handler)) == 1
        and re.search(r"\breturn\s+0\s*;", input_eos_handler) is None
        and direct_body_ends_with(
            input_eos_handler,
            r"\bmsr->request_body_eos_released\s*=\s*1\s*;\s*"
            r"\bAPR_BUCKET_REMOVE\s*\(\s*bucket\s*\)\s*;\s*"
            r"\bAPR_BRIGADE_INSERT_TAIL\s*\(\s*output\s*,\s*bucket\s*\)\s*;\s*"
            r"\bap_remove_input_filter\s*\(\s*filter\s*\)\s*;\s*"
            + RETURN_APR_SUCCESS_PATTERN,
        ),
        "Apache Phase2 EOS helper has one direct canonical success tail and no dead-code control transfer",
    ),
    (
        patterns_in_order(
            input_bucket_processor,
            r"\bret\s*=\s*apr_bucket_read\s*\(\s*bucket\s*,\s*&data\s*,\s*&len\s*,\s*block\s*\)",
            r"\bif\s*\(\s*ret\s*!=\s*APR_SUCCESS\s*\)\s*return\s+ret\s*;",
            r"\bmsr->request_body_bytes_seen\s*>\s*SIZE_MAX\s*-\s*len",
            r"\bmsc_apache_contract_record_body\s*\(\s*msr\s*,\s*0\s*,\s*len\s*\)",
            P2_APPEND_GUARD,
            r"\bmsr->request_body_bytes_seen\s*\+=\s*len\s*;",
            r"\bmsr->request_body_bytes_inspected\s*\+=\s*len\s*;",
            r"\bAPR_BUCKET_REMOVE\s*\(\s*bucket\s*\)",
            r"\bAPR_BRIGADE_INSERT_TAIL\s*\(\s*output\s*,\s*bucket\s*\)",
            RETURN_APR_SUCCESS_PATTERN,
        )
        and base.function_call_count(input_bucket_processor, "APR_BUCKET_REMOVE") == 1
        and base.function_call_count(
            input_bucket_processor, "APR_BRIGADE_INSERT_TAIL"
        ) == 1
        and re.search(
            r"\bmsc_append_request_body\s*\(\s*msr->t\s*,\s*"
            r"\(\s*const\s+unsigned\s+char\s*\*\s*\)\s*data\s*,\s*len\s*\)",
            input_bucket_processor,
            re.DOTALL,
        ) is not None
        and "msconnector_body_limit_plan_chunk" not in input_bucket_processor
        and "(len > 0 && data == NULL)" in input_bucket_processor
        and "msr->request_body_bytes_inspected > SIZE_MAX - len" in input_bucket_processor,
        "Apache Phase2 bucket helper validates pointers and arithmetic, records and appends complete chunks, captures intervention, and forwards after native success",
    ),
    (
        patterns_in_order(
            input_bucket_processor_direct,
            r"\bret\s*=\s*apr_bucket_read\s*\(\s*bucket\s*,\s*&data\s*,\s*&len\s*,\s*block\s*\)",
            r"\bif\s*\(\s*ret\s*!=\s*APR_SUCCESS\s*\)\s*return\s+ret\s*;",
            r"\bmsr->request_body_bytes_seen\s*>\s*SIZE_MAX\s*-\s*len",
            r"\bmsc_apache_contract_record_body\s*\(\s*msr\s*,\s*0\s*,\s*len\s*\)",
            P2_APPEND_GUARD,
            r"\bmsr->request_body_bytes_seen\s*\+=\s*len\s*;",
            r"\bmsr->request_body_bytes_inspected\s*\+=\s*len\s*;",
        )
        and not base.has_forbidden_contract_control_flow(input_bucket_processor)
        and all(
            base.function_call_count(input_bucket_processor_direct, name) == 1
            for name in (
                "apr_bucket_read",
                "process_intervention",
                "msc_apache_contract_record_body",
                "msc_append_request_body",
                "APR_BUCKET_REMOVE",
                "APR_BRIGADE_INSERT_TAIL",
            )
        )
        and len(re.findall(RETURN_APR_SUCCESS_PATTERN, input_bucket_processor)) == 1
        and re.search(r"\breturn\s+0\s*;", input_bucket_processor) is None
        and direct_body_ends_with(
            input_bucket_processor,
            r"\bmsr->request_body_bytes_seen\s*\+=\s*len\s*;\s*"
            r"\bmsr->request_body_bytes_inspected\s*\+=\s*len\s*;\s*"
            r"\bAPR_BUCKET_REMOVE\s*\(\s*bucket\s*\)\s*;\s*"
            r"\bAPR_BRIGADE_INSERT_TAIL\s*\(\s*output\s*,\s*bucket\s*\)\s*;\s*"
            + RETURN_APR_SUCCESS_PATTERN,
        ),
        "Apache Phase2 direct bucket pipeline cannot satisfy its bounded-forwarding contract from a dead-code decoy",
    ),
    (
        patterns_in_order(
            input_filter_handler,
            r"\bif\s*\(\s*msr\s*==\s*NULL\s*\)",
            RETURN_INPUT_TERMINAL_ERROR_PATTERN,
            r"\bif\s*\(\s*conf\s*==\s*NULL\s*\)",
            RETURN_INPUT_TERMINAL_ERROR_PATTERN,
            r"\bif\s*\(\s*APR_BUCKET_IS_EOS\s*\(\s*pbktIn\s*\)\s*\)",
            r"\breturn\s+apache_input_filter_handle_eos\s*\(",
            r"\bret\s*=\s*apache_input_filter_process_bucket\s*\(",
            r"\bif\s*\(\s*ret\s*!=\s*APR_SUCCESS\s*\)",
            r"\breturn\s+ret\s*;",
        )
        and base.function_call_count(
            input_filter_handler, "apache_input_filter_handle_eos"
        ) == 1
        and base.function_call_count(
            input_filter_handler, "apache_input_filter_process_bucket"
        ) == 1
        and base.function_call_count(
            input_filter_handler, "apache_input_filter_terminal_error"
        ) >= 2
        and not base.has_forbidden_contract_control_flow(input_filter_handler)
        and re.search(
            r"\bif\s*\(\s*APR_BUCKET_IS_EOS\s*\(\s*pbktIn\s*\)\s*\)\s*"
            r"\{\s*\breturn\s+apache_input_filter_handle_eos\s*\(\s*"
            r"msr\s*,\s*r\s*,\s*f\s*,\s*pbbOut\s*,\s*pbktIn\s*\)\s*;\s*\}\s*"
            r"\bret\s*=\s*apache_input_filter_process_bucket\s*\(",
            input_filter_handler,
            re.DOTALL,
        ) is not None
        and not any(
            token in input_filter_handler
            for token in (
                "apr_bucket_read(",
                "msconnector_body_limit_plan_chunk(",
                "msc_apache_contract_record_body(",
                "msc_append_request_body(",
                "msc_finalize_request_body(",
            )
        ),
        "Apache input filter delegates EOS and bounded non-EOS processing without a competing body path",
    ),
    (
        base.function_call_count(
            input_bucket_processor, "apache_input_filter_terminal_error"
        ) >= 4
        and base.function_call_count(
            input_bucket_processor, "ap_remove_input_filter"
        ) >= 4
        and all(
            token in input_bucket_processor
            for token in (
                "MSCONNECTOR_TRANSACTION_ERROR_PHASE_SEQUENCE",
                "MSCONNECTOR_TRANSACTION_ERROR_CONNECTOR",
                "msc_apache_contract_record_body",
                "msc_append_request_body",
            )
        )
        and base.function_call_count(
            input_eos_handler, "apache_input_filter_terminal_error"
        ) >= 2
        and "if (msr->request_body_eos_released)" in input_eos_handler
        and base.function_call_count(
            input_filter_handler, "apache_input_filter_terminal_error"
        ) >= 2
        and "if (msr == NULL)" in input_filter_handler
        and "if (conf == NULL)" in input_filter_handler,
        "Apache input helper errors remove the filter and enter the shared terminal bridge for sequence, pointer/overflow, contract, append/intervention, context, and EOS failures",
    ),
    (
        patterns_in_order(
            phase3_headers_handler,
            r"\berror_headers_added\s*=\s*apache_add_response_headers\s*\(\s*msr\s*,\s*r->err_headers_out\s*\)\s*;",
            r"\bresponse_headers_added\s*=\s*apache_add_response_headers\s*\(\s*msr\s*,\s*r->headers_out\s*\)\s*;",
            r"\bif\s*\(\s*!\s*error_headers_added\s*\|\|\s*!\s*response_headers_added\s*\|\|",
            r"\bcontent_type\s*!=\s*NULL\s*&&\s*content_type\s*\[\s*0\s*\]\s*!=\s*'\\0'\s*&&",
            r"\bmsc_add_response_header\s*\(\s*msr->t\s*,\s*\(\s*const\s+unsigned\s+char\s*\*\s*\)\s*\"Content-Type\"\s*,\s*\(\s*const\s+unsigned\s+char\s*\*\s*\)\s*content_type\s*\)\s*!=\s*1",
            r"\bap_remove_output_filter\s*\(\s*filter\s*\)",
            r"\breturn\s+apache_send_precommit_terminal_error\s*\(\s*msr\s*,\s*filter\s*,\s*brigade\s*,\s*HTTP_INTERNAL_SERVER_ERROR\s*\)",
            re.escape(P3_PROCESS),
            r"\bap_remove_output_filter\s*\(\s*filter\s*\)",
            r"\breturn\s+apache_send_precommit_terminal_error\s*\(\s*msr\s*,\s*filter\s*,\s*brigade\s*,\s*HTTP_INTERNAL_SERVER_ERROR\s*\)",
            r"\bmsc_apache_contract_complete\s*\(\s*msr\s*,\s*MSCONNECTOR_PHASE_RESPONSE_HEADERS\s*\)",
            r"\bmsr->response_headers_processed\s*=\s*1\s*;",
            r"\bintervention\s*=\s*process_intervention\s*\(\s*msr->t\s*,\s*r\s*\)",
            r"\bif\s*\(\s*intervention\s*==\s*N_INTERVENTION_STATUS\s*\)",
            RETURN_APR_SUCCESS_PATTERN,
            r"\bif\s*\(\s*!\s*msc_apache_contract_record_intervention_decision\s*\(\s*msr\s*\)\s*\)",
            r"\bwanted\s*=\s*msc_apache_contract_intervention_action\s*\(\s*msr\s*\)",
            r"\bapache_phase3_log_event\s*\(\s*msr\s*,\s*r\s*,\s*wanted\s*,\s*wanted\s*,\s*original_status\s*\)",
            r"\breturn\s+apache_send_precommit_terminal_error\s*\(\s*msr\s*,\s*filter\s*,\s*brigade\s*,\s*intervention\s*\)",
        )
        and base.function_call_count(
            phase3_headers_handler, "apache_add_response_headers"
        ) == 2
        and base.function_call_count(
            phase3_headers_handler, "msc_add_response_header"
        ) == 1
        and not base.has_forbidden_contract_control_flow(phase3_headers_handler),
        "Apache Phase3 checks both response-header tables, fails closed on helper or engine error, completes, and then collects and enforces intervention",
    ),
    (
        base.tokens_in_order(
            phase4_intervention_handler,
            "msr->response.committed = apache_phase4_response_committed(msr, r);",
            "wanted = msc_apache_contract_intervention_action(msr);",
            "msconnector_late_intervention_policy_init(&policy);",
            "action = msconnector_late_intervention_resolve(&policy,",
            "msr->response.committed, msr->response.committed,",
            "conf->common_config.phase4_mode == MSCONNECTOR_PHASE4_MODE_STRICT);",
            "actual = apache_phase4_actual_action(action, wanted);",
            "if (action == MSCONNECTOR_LATE_INTERVENTION_LOG_ONLY)",
            RETURN_APR_SUCCESS,
            "if (action == MSCONNECTOR_LATE_INTERVENTION_ABORT_CONNECTION)",
            "return apache_phase4_abort_response_connection(f);",
            '"response_not_committed"',
            "return apache_send_precommit_terminal_error(msr, f, NULL, intervention);",
        ),
        "Apache Phase4 derives commitment before policy resolution, bypasses only log-only, aborts strict committed responses, and denies before commit",
    ),
    (
        base.tokens_in_order(
            phase4_fail_closed_helper,
            "if (apache_phase4_response_committed(msr, r))",
            "rc = apache_phase4_abort_response_connection(f);",
            "apache_emit_contract_failure_event_with_action(msr, r,",
            "return rc;",
            '"ModSecurity: Phase 4 response gate failed before response commit: %s"',
            REMOVE_OUTPUT_FILTER,
            "return apache_send_precommit_terminal_error(msr, f, NULL,",
            "HTTP_INTERNAL_SERVER_ERROR);",
        ),
        "Apache Phase4 fail-closed helper removes the resource filter and emits a terminal error before commit",
    ),
    (
        base.tokens_in_order(
            finish_unread_request_body,
            "if (msr->request_body_processed)",
            RETURN_APR_SUCCESS,
            "if (ap_request_has_body(r))",
            "discard_status = ap_discard_request_body(r);",
            "if (discard_status != OK)",
            REMOVE_OUTPUT_FILTER,
            "if (msr->request_body_intervention_sent)",
            "return AP_FILTER_ERROR;",
            "return apache_send_precommit_terminal_error(msr, f, NULL,",
            "if (!msr->request_body_processed)",
            REMOVE_OUTPUT_FILTER,
            "return APR_ECONNABORTED;",
            RETURN_APR_SUCCESS,
            "it = msc_finalize_request_body(msr, r);",
        ),
        "Apache drains every advertised unread request body and fails closed unless Phase2 reached its processed state before response inspection",
    ),
    (
        base.tokens_in_order(
            base.phase4_release_helper,
            "starts_response = apache_phase4_brigade_starts_response(brigade);",
            "if ((starts_response || terminal) && !msr->response.committed &&",
            "!apache_phase3_restore_response_state(msr, f->r))",
            "return apache_phase4_fail_closed(msr, f, brigade,",
            '"missing Phase 3 response-state snapshot"',
            "if ((starts_response || terminal) && !msr->response.committed)",
            "msc_apache_contract_mark_response_committed(msr)",
            "msr->response.committed = 1;",
            DOWNSTREAM_PASS,
        )
        and base.tokens_in_order(
            release_after_pass,
            RC_NOT_SUCCESS,
            terminal_success_seal,
            "return rc;",
        ),
        "Apache progressive release restores the Phase3 snapshot, commits before output, and seals the successful terminal path afterward",
    ),
    (
        base.tokens_in_order(
            phase4_terminal_guard,
            "msc_t *msr = f != NULL ? (msc_t *)f->ctx : NULL;",
            "msr->response_phase4_terminal_output ==",
            TERMINAL_SEALED,
            "apr_brigade_cleanup(bb_in);",
            RETURN_APR_EGENERAL,
        ),
        "Apache protocol terminal guard reads its transaction context and rejects every brigade after output is sealed",
    ),
    (
        base.tokens_in_order(
            redirect_terminal_emission,
            "if (!apache_phase4_redirect_has_local_error_document_proof(msr, r))",
            "return 0;",
            "msr->response_phase4_terminal_error_redirect_seen = 1;",
            "apr_table_setn(r->notes, apache_phase4_terminal_error_redirect_note,",
            "return 1;",
        ),
        "Apache terminal-error redirect exception requires the local ErrorDocument proof before permitting the bounded redirect",
    ),
    (
        base.tokens_in_order(
            hook_insert_filter,
            "if (r->main != NULL)",
            RETURN_VOID,
            "if (r->prev != NULL)",
            "if (!apache_phase4_redirect_is_terminal_error_emission(msr, r))",
            "apache_phase4_fail_normal_redirect(msr, r,",
            '"request transaction cannot be safely rebound to the target URI");',
            RETURN_VOID,
            'ap_add_input_filter("MODSECURITY_IN", msr, r, r->connection);',
        ),
        "Apache excludes subrequests and rejects normal internal redirects before attaching request or response filters",
    ),
    (
        base.tokens_in_order(
            hook_insert_filter,
            'ap_add_output_filter("MODSECURITY_PHASE4_GUARD", msr, r,',
            FILTER_ATTACH_FAILURE,
            '"ModSecurity: unable to install the mandatory Phase 4 terminal guard; aborting request"',
            CONNECTION_ABORT,
            RETURN_VOID,
            'ap_add_output_filter("MODSECURITY_OUT", msr, r,',
            FILTER_ATTACH_FAILURE,
            PHASE4_GATE_FAILED,
            TERMINAL_SEALED,
            '"ModSecurity: unable to install the mandatory Phase 4 content filter; aborting request"',
            CONNECTION_CLOSE,
            CONNECTION_ABORT,
            RETURN_VOID,
        ),
        "Apache fails closed when either mandatory output filter cannot be attached",
    ),
    (
        base.tokens_in_order(
            register_hooks,
            'ap_register_output_filter("MODSECURITY_PHASE4_GUARD",',
            "phase4_terminal_guard_filter, NULL, AP_FTYPE_PROTOCOL);",
        ),
        "Apache registers the terminal guard as a protocol output filter",
    ),
    (
        native_intervention_flow_is_checked(base.module_c),
        "Apache validates the native intervention result and preserves both redirect and non-redirect enforcement sinks",
    ),
    (
        base.tokens_in_order(
            base.input_filter_terminal_error,
            TERMINAL_EMITTING,
            RESET_HTTP_STATUS,
            RESET_STATUS_LINE,
            AP_DIE_STATUS,
            TERMINAL_SEALED,
            "return AP_FILTER_ERROR;",
        ),
        "Apache input terminal errors neutralize status, emit, and seal the protocol output guard in order",
    ),
    (
        base.tokens_in_order(
            precommit_terminal_helper,
            TERMINAL_EMITTING,
            RESET_HTTP_STATUS,
            RESET_STATUS_LINE,
            AP_DIE_STATUS,
            TERMINAL_SEALED,
            RETURN_APR_EGENERAL,
        ),
        "Apache pre-commit terminal errors neutralize status, emit, and seal the protocol output guard in order",
    ),
]

ok = True
for passed, message in review_guards:
    if passed:
        print(f"PASS: {message}")
    else:
        print(f"FAIL: {message}")
        ok = False

if not ok:
    sys.exit(1)
print("apache-common-adoption: scoped review guards passed")
