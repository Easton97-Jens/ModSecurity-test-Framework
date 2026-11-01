#!/usr/bin/env python3
"""Enforce Apache/Common SDK structure-level adoption without runtime claims."""
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import re
import sys

ROOT = connector_root()
APACHE = source_path('connectors/apache', root=ROOT)
SRC = APACHE / "src"

checks: list[tuple[bool, str]] = []

def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")

config_h = read(SRC / "mod_security3.h")
config_c = read(SRC / "msc_config.c")
filters_c = read(SRC / "msc_filters.c")
module_c = read(SRC / "mod_security3.c")
utils_c = read(SRC / "msc_utils.c")
mapper_h = read(SRC / "msc_apache_mapper.h") if (SRC / "msc_apache_mapper.h").exists() else ""
mapper_c = read(SRC / "msc_apache_mapper.c") if (SRC / "msc_apache_mapper.c").exists() else ""
apache_text = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in SRC.glob("*.c")) + "\n" + "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in SRC.glob("*.h"))
docs_text = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in [APACHE / "README.md", APACHE / "README.de.md", source_path('docs/connectors/apache.md', root=ROOT), source_path('reports/audits/architecture-and-evidence.md', root=ROOT)] if p.exists())
DISCARD_RESPONSE_BRIGADE_CALL = "msc_discard_response_brigade(msr);"
RC_NOT_SUCCESS = "if (rc != APR_SUCCESS)"


def source_section(text: str, start: str, end: str) -> str:
    """Return one intentional C source region, or an empty string if absent.

    The Apache event writer is shared by the phase-3 and phase-4 wrappers.
    Keeping these checks scoped to their respective functions prevents a
    similarly named token elsewhere in the file from satisfying the adoption
    contract accidentally.
    """
    begin = text.find(start)
    if begin < 0:
        return ""
    finish = text.find(end, begin + len(start))
    if finish < 0:
        return ""
    return text[begin:finish]


def _mask_non_newline(
    text: str, masked: list[str], start: int, end: int
) -> None:
    """Replace a source span with spaces while retaining its line layout."""
    for offset in range(start, end):
        if text[offset] != "\n":
            masked[offset] = " "


def _mask_line_comment(text: str, masked: list[str], index: int) -> int:
    """Mask a C++-style comment and return the first byte after it."""
    end = text.find("\n", index)
    end = len(text) if end < 0 else end
    _mask_non_newline(text, masked, index, end)
    return end


def _mask_block_comment(text: str, masked: list[str], index: int) -> int:
    """Mask a C-style comment, including an unterminated one, without moving LF."""
    end = text.find("*/", index + 2)
    end = len(text) if end < 0 else end + 2
    _mask_non_newline(text, masked, index, end)
    return end


def _mask_c_literal(text: str, masked: list[str], index: int) -> int:
    """Mask one C string or character literal and return the next source index."""
    quote = text[index]
    _mask_non_newline(text, masked, index, index + 1)
    index += 1
    while index < len(text):
        character = text[index]
        _mask_non_newline(text, masked, index, index + 1)
        if character == "\\" and index + 1 < len(text):
            index += 1
            _mask_non_newline(text, masked, index, index + 1)
        elif character == quote:
            return index + 1
        index += 1
    return index


def _mask_c_comments_and_literals(text: str) -> str:
    """Mask C comments and literals while retaining source offsets and lines."""
    masked = list(text)
    index = 0
    while index < len(text):
        marker = text[index:index + 2]
        if marker == "//":
            index = _mask_line_comment(text, masked, index)
        elif marker == "/*":
            index = _mask_block_comment(text, masked, index)
        elif text[index] in {'"', "'"}:
            index = _mask_c_literal(text, masked, index)
        else:
            index += 1
    return "".join(masked)


def _matching_delimiter(text: str, opening: int, start: str, end: str) -> int:
    """Return the matching delimiter index, or -1 for incomplete source."""
    depth = 0
    for offset in range(opening, len(text)):
        if text[offset] == start:
            depth += 1
        elif text[offset] == end:
            depth -= 1
            if depth == 0:
                return offset
    return -1


def function_section(text: str, name: str) -> str:
    """Return one top-level C function definition with non-code masked.

    This is deliberately narrower than a C parser: it locates a named,
    top-level definition and balances its braces after comments and literals
    have been masked. Returning an empty section for a missing, duplicate, or
    incomplete definition keeps the static contract fail-closed and prevents
    comments or unrelated functions from satisfying a helper-specific check.
    """
    masked = _mask_c_comments_and_literals(text)
    definitions: list[tuple[int, int]] = []
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", masked):
        if masked[:match.start()].count("{") != masked[:match.start()].count("}"):
            continue
        opening_parenthesis = match.end() - 1
        closing_parenthesis = _matching_delimiter(
            masked, opening_parenthesis, "(", ")"
        )
        if closing_parenthesis < 0:
            continue
        cursor = closing_parenthesis + 1
        while cursor < len(masked) and masked[cursor] not in "{;":
            cursor += 1
        if cursor >= len(masked) or masked[cursor] != "{":
            continue
        closing_brace = _matching_delimiter(masked, cursor, "{", "}")
        if closing_brace >= 0:
            definitions.append((match.start(), closing_brace + 1))
    if len(definitions) != 1:
        return ""
    start, end = definitions[0]
    return masked[start:end]


def function_call_count(text: str, name: str) -> int:
    """Count calls to a named helper inside a previously scoped section."""
    return len(re.findall(rf"\b{re.escape(name)}\s*\(", text))


def function_direct_body(text: str) -> str:
    """Return direct function-body code, masking nested compound blocks.

    Apache's P2 pipeline deliberately keeps its read, planning, Common record,
    bounded append, accounting, and forwarding tail in the direct function
    body. Keeping only brace-depth-one code distinguishes that live pipeline
    from a similarly shaped nested decoy without claiming to be a general C
    control-flow parser.
    """
    masked = _mask_c_comments_and_literals(text)
    opening = masked.find("{")
    if opening < 0:
        return ""
    closing = _matching_delimiter(masked, opening, "{", "}")
    if closing < 0 or masked[closing + 1:].strip():
        return ""

    direct = ["\n" if character == "\n" else " " for character in masked]
    depth = 0
    for offset, character in enumerate(masked):
        if character == "{":
            depth += 1
            continue
        if character == "}":
            depth -= 1
            if depth < 0:
                return ""
            continue
        if depth == 1:
            direct[offset] = character
    return "".join(direct)


def has_forbidden_contract_control_flow(text: str) -> bool:
    """Reject controls that make a helper-only contract ambiguous.

    The guard is deliberately narrow and fail-closed for critical Apache P2
    helpers: it catches preprocessor branches, labels/goto, and obvious
    constant-false controls. Arbitrary C reachability is outside this
    lightweight source-contract checker's stated scope.
    """
    masked = _mask_c_comments_and_literals(text)
    forbidden_patterns = (
        r"(?m)^\s*#\s*(?:if|ifdef|ifndef|elif|else|endif)\b",
        r"\bgoto\s+[A-Za-z_]\w*\s*;",
        r"(?m)^\s*(?!case\b|default\b)[A-Za-z_]\w*\s*:",
        r"\b(?:if|while)\s*\(\s*(?:\(\s*)*(?:0|false|NULL|"
        + r"0\s*==\s*1|1\s*==\s*0|!\s*(?:1|true))(?:\s*\))*\s*\)",
        r"\bfor\s*\(\s*[^;]*;\s*(?:\(\s*)*(?:0|false|NULL)"
        + r"(?:\s*\))*\s*;",
    )
    return any(re.search(pattern, masked) is not None for pattern in forbidden_patterns)


def tokens_in_order(text: str, *tokens: str) -> bool:
    """Return whether the required source tokens occur in this order."""
    position = -1
    for token in tokens:
        position = text.find(token, position + 1)
        if position < 0:
            return False
    return True


def typed_event_status_assignment(text: str) -> bool:
    """Check one executable status assignment with bounded linear string scans."""
    compact = "".join(function_section(text, "apache_log_intervention_event").split())
    compact = compact.replace("event.decision.status==", "event.decision.status_EQ_")
    marker = "event.decision.status="
    if compact.count(marker) != 1:
        return False
    assignment = compact.partition(marker)[2].partition(";")[0]
    return assignment.endswith("?MSCONNECTOR_STATUS_ERROR:MSCONNECTOR_STATUS_BLOCKED")


def native_redirect_storage_is_checked(text: str) -> bool:
    """Follow the actual native collector and its one request-owned sink.

    Comments and unrelated functions cannot provide the executable checks.
    The string-bearing Location assignment is checked in its scoped source
    as well as the masked code path. Compiled APR tests prove runtime behavior.
    """
    collector = function_section(text, "process_intervention")
    storage = function_section(text, "apache_store_native_intervention")
    raw_storage = source_section(text,
        "static int apache_store_native_intervention(", "int process_intervention (")
    return (
        not has_forbidden_contract_control_flow(collector)
        and not has_forbidden_contract_control_flow(storage)
        and tokens_in_order(collector,
            "native_result = msc_intervention(t, &intervention);",
            "native_result != 0 && native_result != 1",
            "result = apache_store_native_intervention(msr, r, &intervention);",
            "msc_release_intervention_buffers(&intervention);", "return result;")
        and function_call_count(collector, "apache_store_native_intervention") == 1
        and function_call_count(collector, "msc_release_intervention_buffers") == 1
        and tokens_in_order(storage,
            "msconnector_intervention_normalize_status(intervention->url,",
            "msconnector_intervention_has_redirect_url(intervention->url)",
            "status >= HTTP_MULTIPLE_CHOICES && status < HTTP_BAD_REQUEST",
            "if (redirect && !msr->response.committed && r->bytes_sent == 0)",
            "location = apr_pstrdup(r->pool, intervention->url);",
            "if (location == NULL || r->headers_out == NULL)",
            "return apache_record_failure(msr, r,",
            "msr->last_intervention_status = status;",
            "if (location != NULL)", "apr_table_setn(r->headers_out,",
            "return status;")
        and 'apr_table_setn(r->headers_out, "Location", location);' in raw_storage
    )


intervention_event_helper = source_section(
    filters_c,
    "static msconnector_error_code apache_log_intervention_event",
    "static msconnector_error_code apache_phase4_log_event",
)
intervention_http_helper = source_section(
    filters_c,
    "static void apache_intervention_set_http",
    "static msconnector_error_code apache_intervention_write_event",
)
intervention_writer = source_section(
    filters_c,
    "static msconnector_error_code apache_intervention_write_event",
    "static msconnector_error_code apache_log_intervention_event",
)
intervention_writer_code = function_section(filters_c, "apache_intervention_write_event")
phase4_event_wrapper = source_section(
    filters_c,
    "static msconnector_error_code apache_phase4_log_event",
    "static msconnector_error_code apache_phase3_log_event",
)
phase3_event_wrapper = source_section(
    filters_c,
    "static msconnector_error_code apache_phase3_log_event",
    "static apr_status_t apache_phase4_append_bucket",
)
request_body_finalizer = function_section(filters_c, "msc_finalize_request_body")
input_filter_terminal_error = function_section(
    filters_c, "apache_input_filter_terminal_error"
)
input_filter_eos_handler = function_section(
    filters_c, "apache_input_filter_handle_eos"
)
input_filter_process_bucket = function_section(
    filters_c, "apache_input_filter_process_bucket"
)
input_filter_handler = function_section(filters_c, "input_filter")
phase4_append_helper = function_section(filters_c, "apache_phase4_append_bucket")
phase4_finish_code = function_section(filters_c, "apache_phase4_finish_response_body")
phase4_release_helper = source_section(
    filters_c,
    "static apr_status_t apache_phase4_release_response_brigade",
    "apr_status_t phase4_terminal_guard_filter",
)
output_filter_c = filters_c.split("apr_status_t output_filter", 1)[1]
intervention_action_mapper = source_section(
    module_c,
    "static msconnector_transaction_decision_kind apache_intervention_decision_kind",
    "int msc_apache_contract_record_intervention_decision",
)
intervention_action_helper = source_section(
    module_c,
    "const char *msc_apache_contract_intervention_action",
    "int msc_apache_contract_fail",
)
process_intervention_helper = source_section(
    module_c,
    "int process_intervention (Transaction *t, request_rec *r)",
    "int msc_apache_init",
)

checks.extend([
    ("msconnector_config common_config" in config_h, "Apache config embeds msconnector_config common_config"),
    ("msconnector_config_init(&cnf->common_config)" in config_c, "Apache config init uses msconnector_config_init"),
    ("msconnector_config_merge(&destination->common_config" in config_c, "Apache config merge uses msconnector_config_merge"),
    ("msconnector_config_validate(&destination->common_config" in config_c, "Apache config validation path uses msconnector_config_validate"),
    ("msconnector_parse_bool" in config_c, "Apache bool parsing uses Common parser"),
    ("msconnector_parse_phase4_mode" in config_c, "Apache phase4 parsing uses Common parser"),
    ("MSCONNECTOR_DIRECTIVE_PHASE4_BODY_LIMIT" not in config_c and "msc_config_phase4_body_limit" not in config_c, "Apache no longer registers or parses the removed Phase-4 body-limit API"),
    ("MSCONNECTOR_DIRECTIVE_" in config_c and "msconnector_directive_adapter_find" in config_c, "Apache directives reference Common directive names and adapter lookup"),
    ("int msc_apache_map_request" in mapper_h + mapper_c and "request_rec *r" in mapper_h + mapper_c, "Apache request_rec mapper is present"),
    ("msconnector_request_mapper_contract" in mapper_h + mapper_c and "msconnector_request_mapper_validate_output" in mapper_c, "Request mapper uses Common contract validation"),
    ("int msc_apache_map_response" in mapper_h + mapper_c and "msconnector_response_mapper_contract" in mapper_h + mapper_c, "Apache response mapper is present"),
    ("msconnector_response_mapper_validate_output" in mapper_c, "Response mapper uses Common contract validation"),
    ("copy_apr_response_headers" in mapper_c and "err_headers_out" in mapper_c and "r->content_type" in mapper_c, "Response mapper includes err_headers_out and synthesized Content-Type"),
    ("msconnector_headers_find" in mapper_c, "Apache mapper uses Common header helper"),
    ("msconnector_event_write_jsonl_line" in filters_c and "msconnector_event_init" in filters_c, "Apache event JSONL uses Common event primitives"),
    (
        typed_event_status_assignment(filters_c)
        and all(f'"{name}"' in intervention_event_helper for name in
                ("invalid_engine_response", "protocol_error", "connector_error")),
        "Apache P3/P4 intervention events distinguish technical errors from rule blocks",
    ),
    (
        "event.meta.event = input->event_name" in intervention_event_helper
        and "\"phase4_intervention\"" in phase4_event_wrapper
        and "MSCONNECTOR_PHASE_RESPONSE_BODY" in phase4_event_wrapper
        and "\"phase3_intervention\"" in phase3_event_wrapper
        and "MSCONNECTOR_PHASE_RESPONSE_HEADERS" in phase3_event_wrapper
        and "\"response_headers_before_commit\"" in phase3_event_wrapper
        and "input.original_status = original_status" in phase3_event_wrapper
        and "input.response_already_committed = 0" in phase3_event_wrapper,
        "Apache P3 and P4 wrappers retain distinct event names, phases, and pre-commit P3 status context",
    ),
    (
        "input->phase == MSCONNECTOR_PHASE_RESPONSE_BODY" in intervention_event_helper
        and "MSCONN_EVENT_PHASE4_HARD_ABORT_AFTER_200" in intervention_event_helper
        and "MSCONN_EVENT_PHASE4_LATE_INTERVENTION" in intervention_event_helper
        and "MSCONN_EVENT_RESPONSE_BLOCKED" in intervention_event_helper
        and "msconnector_event_default_level(event.meta.message_id)" in intervention_event_helper
        and "msconnector_event_default_message(event.meta.message_id)" in intervention_event_helper,
        "Apache P3/P4 events select canonical message IDs and safe default messages by phase and action",
    ),
    (
        "char line[4096];" in intervention_writer_code
        and function_call_count(intervention_writer_code, "msconnector_event_write_jsonl_line") == 1
        and function_call_count(intervention_writer_code, "apr_file_write_full") == 1
        and tokens_in_order(intervention_writer_code,
            "msconnector_event_write_jsonl_line", "apache_open_event_file",
            "rc = apr_file_write_full", "rc != APR_SUCCESS || written != length",
            "code = MSCONNECTOR_ERROR_IO;", "apr_file_close",
            "close_rc != APR_SUCCESS", "code = MSCONNECTOR_ERROR_IO;",
            "return apache_event_sink_result(msr, r, code, mandatory);")
        and "apr_psprintf" not in intervention_writer_code
        and re.search(
            r"if\s*\(\s*!msconnector_event_write_jsonl_line\([^;]+?\)\s*\)\s*\{\s*"
            r"ap_log_rerror\([^;]+?\);\s*return\s+apache_event_sink_result\([^;]+?\);\s*\}\s*"
            r"rc\s*=\s*apache_open_event_file\(",
            intervention_writer_code, re.DOTALL) is not None,
        "Apache P3/P4 events reject serialization failure before the single canonical JSONL write",
    ),
    ("body_truncated" in filters_c and "json_truncated" in filters_c and "event.flags.truncated = msr->body_truncated" not in filters_c, "Response body truncation is separate from JSON serialization truncation"),
    (
        "event->http.original_http_status = input->original_status" in filters_c
        and "event->http.visible_http_status = msr->last_intervention_status" in filters_c
        and "event.flags.late_intervention = input->response_already_committed" in filters_c
        and "event.flags.headers_sent = input->response_already_committed" in filters_c
        and "event.flags.body_started = input->phase == MSCONNECTOR_PHASE_RESPONSE_BODY" in filters_c
        and "input.response_already_committed = msr != NULL ? msr->response.committed : 0" in phase4_event_wrapper
        and "input.original_status = original_status" in phase3_event_wrapper,
        "Apache P3/P4 events preserve original and visible status while deriving commit flags from the actual phase",
    ),
    ("msconnector_late_intervention_policy_init" in filters_c and "msconnector_late_intervention_resolve" in filters_c and "msconnector_late_intervention_action_name" in filters_c, "Apache Phase4 handling uses the Common late-intervention policy"),
    ("strcmp(input->actual, \"deny\")" in filters_c and "event->http.visible_http_status = msr->last_intervention_status" in filters_c and "response_not_committed" in filters_c, "Pre-commit deny events report the deny status as visible"),
    (
        "apr_bucket_brigade *brigade;" in config_h
        and "response_body_scope_decided" not in config_h
        and "apache_output_filter_prepare_response_brigade(msr, conf, f, &bb_in," in filters_c
        and "apache_phase4_release_response_brigade" in filters_c
        and "apache_phase4_normalize_response_brigade" in filters_c
        and "APR_BUCKET_IS_FLUSH(bucket)" in filters_c
        and "if (eos_bucket == NULL)\n    {\n        return apache_phase4_release_response_brigade(msr, f, bb_in, 0);\n    }" in output_filter_c
        and "apr_brigade_split_ex(bb_in, eos_bucket, NULL)" in output_filter_c
        and "APR_BRIGADE_FIRST(bb_in) != APR_BRIGADE_SENTINEL(bb_in)" in output_filter_c
        and "apache_output_filter_finish_response(msr, conf, f," in output_filter_c
        and "ap_save_brigade(" not in filters_c
        and DISCARD_RESPONSE_BRIGADE_CALL in filters_c
        and DISCARD_RESPONSE_BRIGADE_CALL in utils_c
        and "msconnector_body_limit_plan_chunk" not in phase4_append_helper
        and "SIZE_MAX - msr->response_body_bytes_seen" in phase4_append_helper
        and "apache_phase4_in_scope" not in filters_c
        and "SecResponseBodyMimeType selection" in filters_c
        and re.search(r"!msconnector_native_body_append_can_continue\(msc_append_response_body\(msr->t,\s*"
                      r"\(const unsigned char \*\)data, len\)\)", phase4_append_helper) is not None
        and "!msconnector_native_phase_succeeded(msc_process_response_body(msr->t))" in phase4_finish_code
        and "r->bytes_sent > 0" in filters_c
        and "response_phase4_eos_released" in filters_c
        and "missing progressive response brigade" in filters_c
        and "response_phase4_gate_failed" in filters_c
        and "r->connection->aborted = 1" in filters_c
        and "phase4_terminal_guard_filter" in filters_c
        and "apache_send_precommit_terminal_error" in filters_c
        and "msc_apache_contract_mark_response_committed(msr)" in phase4_release_helper
        and "rc = ap_pass_brigade(f->next, brigade);" in phase4_release_helper
        and RC_NOT_SUCCESS in phase4_release_helper
        and "apache_phase4_abort_response_connection(f)" in phase4_release_helper
        and tokens_in_order(
            phase4_release_helper,
            "msc_apache_contract_mark_response_committed(msr)",
            "rc = ap_pass_brigade(f->next, brigade);",
            RC_NOT_SUCCESS,
            "MSC_PHASE4_TERMINAL_OUTPUT_SEALED",
        )
        and DISCARD_RESPONSE_BRIGADE_CALL in filters_c
        and "MSC_PHASE4_TERMINAL_OUTPUT_EMITTING" in filters_c
        and "MSC_PHASE4_TERMINAL_OUTPUT_SEALED" in filters_c
        and 'ap_register_output_filter("MODSECURITY_PHASE4_GUARD"' in module_c
        and 'ap_add_output_filter("MODSECURITY_PHASE4_GUARD"' in module_c
        and 'ap_add_output_filter("MODSECURITY_OUT", msr, r,' in module_c
        and "mandatory Phase 4 content filter; aborting request" in module_c
        and "ap_bucket_eoc_create" not in filters_c
        and "ap_flush_conn(r->connection)" not in filters_c,
        "Apache Phase4 splits at EOS, releases pre-EOS buckets progressively, fails closed at the native boundary, and seals terminal output",
    ),
    (
        "if (msr->request_body_processed)" in request_body_finalizer
        and function_call_count(input_filter_eos_handler, "msc_finalize_request_body") == 1
        and "msc_finalize_request_body" not in input_filter_process_bucket
        and "msc_finalize_request_body" not in input_filter_handler
        and "APR_BUCKET_REMOVE(bucket);" in input_filter_process_bucket
        and tokens_in_order(
            input_filter_eos_handler,
            "if (msr->request_body_eos_released)",
            "return apache_input_filter_terminal_error(msr, r,",
            "if (!msr->request_body_processed)",
            "intervention = msc_finalize_request_body(msr, r);",
            "if (intervention != N_INTERVENTION_STATUS)",
            "msr->request_body_eos_released = 1;",
            "APR_BUCKET_REMOVE(bucket);",
            "APR_BRIGADE_INSERT_TAIL(output, bucket);",
            "ap_remove_input_filter(filter);",
            "return APR_SUCCESS;",
        ),
        "Apache request chunks are borrowed and phase 2 finalizes once at EOS",
    ),
    (
        function_call_count(input_filter_handler, "apache_input_filter_terminal_error") >= 2
        and function_call_count(input_filter_process_bucket, "apache_input_filter_terminal_error") >= 4
        and function_call_count(input_filter_eos_handler, "apache_input_filter_terminal_error") >= 2
        and "msc_apache_contract_begin" in input_filter_process_bucket
        and "msc_apache_contract_record_body" in input_filter_process_bucket
        and "HTTP_INTERNAL_SERVER_ERROR" in input_filter_process_bucket
        and "msr->request_body_bytes_seen > SIZE_MAX - len" in input_filter_process_bucket
        and "(len > 0 && data == NULL)" in input_filter_process_bucket
        and "request_intervention_pending" in input_filter_process_bucket
        and "apache_input_filter_handle_eos" in input_filter_handler
        and "apache_input_filter_process_bucket" in input_filter_handler
        and "if (msr == NULL)" in input_filter_handler
        and "if (conf == NULL)" in input_filter_handler
        and "ap_remove_input_filter(f);" in input_filter_handler
        and "ap_die(status, r);" in input_filter_terminal_error
        and "return AP_FILTER_ERROR;" in input_filter_terminal_error
        and "r->status = HTTP_OK;" in input_filter_terminal_error
        and "send_input_error_bucket" not in filters_c
        and "send_error_bucket(msr, f" not in input_filter_handler
        and "pass_error_bucket(" not in input_filter_handler
        and "pass_error_bucket(" not in input_filter_eos_handler,
        "Apache input-filter errors enter Apache core through the input-side terminal bridge",
    ),
    ("msc_process_request_body(msr->t)" not in module_c, "Apache does not finalize Phase 2 before the input filter reaches EOS"),
    ("ap_request_has_body(r)" in module_c and "msc_finalize_request_body(msr, r)" in module_c, "Apache completes Phase 2 for a known empty request body"),
    ("ap_discard_request_body(r)" in filters_c and "apache_finish_unread_request_body" in filters_c and "return APR_ECONNABORTED" in filters_c, "Apache drains an unread request body through the streaming input filter or aborts before Phase 3 when EOS is unavailable"),
    (
        "wanted = msc_apache_contract_intervention_action(msr);" in filters_c
        and "status >= HTTP_MULTIPLE_CHOICES" in intervention_action_mapper
        and "status < HTTP_BAD_REQUEST" in intervention_action_mapper
        and tokens_in_order(
            intervention_action_helper,
            "switch (apache_intervention_decision_kind(msr->last_intervention_status))",
            "MSCONNECTOR_TRANSACTION_DECISION_REDIRECT",
            'return "redirect";',
        )
        and native_redirect_storage_is_checked(module_c),
        "Apache preserves redirect through the canonical decision mapper and native Location sink",
    ),
    (
        "failed to open intervention log" in intervention_writer
        and "failed to write intervention log" in intervention_writer
        and "common intervention event serialization %s" in intervention_writer
        and "failed to close intervention log" in intervention_writer
        and RC_NOT_SUCCESS in intervention_writer_code
        and "apr_file_close" in intervention_writer,
        "Apache reports open, canonical write, serialization, and close failures for shared P3/P4 event logging",
    ),
    ("msconnector_rule_id_extract_from_message" in filters_c, "Apache rule-id extraction uses Common helper"),
    ("apache_json_escape" not in apache_text, "Duplicate Apache JSON escape helper is removed"),
    ("apache_phase4_rule_id" not in apache_text, "Duplicate Apache rule-id helper is removed"),
    ("char *end = NULL" not in config_c and "strtoul" not in config_c, "Duplicate Apache size parser is removed"),
    ("else if (destination->common_config.transaction_id != NULL)" in config_c and "destination->transaction_id_expr = NULL" in config_c, "Child static transaction IDs override parent expressions"),
])
apxs_wrapper = read(source_path('connectors/apache/build/apxs-wrapper.in', root=ROOT))
checks.append((
    "MSCONNECTOR_COMMON_SOURCES" in apxs_wrapper
    and "common/src" in apxs_wrapper
    and "header_validation_internal.h" in apxs_wrapper
    and "MSCONNECTOR_PROFILE_REGISTRY_SRC" in apxs_wrapper
    and "profile_registry.c" in apxs_wrapper,
    "Apache APXS wrapper materializes Common SDK sources and the connector-owned profile registry",
))
for field in ["msc_state", "use_error_log;", "int phase4_mode;", "const char *phase4_log_path;", "apr_size_t phase4_body_limit;"]:
    checks.append((field not in config_h, f"Duplicate config field removed: {field}"))
checks.append((config_h.count("const char *transaction_id;") == 1, "Transaction ID state has one lifecycle-owned field"))

for forbidden in ["production-ready", "production ready", "runtime-verified", "full-matrix ready", "CRS PASS"]:
    checks.append((forbidden.lower() not in docs_text.lower(), f"No new forbidden claim: {forbidden}"))

ok = True
for passed, message in checks:
    if passed:
        print(f"PASS: {message}")
    else:
        print(f"FAIL: {message}")
        ok = False

if not ok:
    sys.exit(1)
print("apache-common-adoption: structure-level Common SDK adoption checks passed")
