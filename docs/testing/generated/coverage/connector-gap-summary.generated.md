> Generated file - do not edit manually.
>
> Generated at: `2026-07-12T19:40:11Z`
> Verified run id: `2026-06-16T19-12-00Z-614c8049`
> Data source policy: `verified-inputs-only`
> Generator: `framework:ci/reporting/generate-case-matrix.py`
> Make target: `generate-test-matrix`
> Owner: `runtime`
> Severity: `informational`
> Connector SHA: `91f51277e96ff9b58e6d6a3a3c737eb103b00331`
> Framework SHA: `91f51277e96ff9b58e6d6a3a3c737eb103b00331`
> Input status: `missing`

# Generated Connector Gap Summary

**Language:** English | [Deutsch](connector-gap-summary.generated.de.md)

| case_id | path | status | classification | tags | variables | source/provenance | notes |
|---|---|---|---|---|---|---|---|
| audit_log_message_presence_connector_gap | `tests/cases/audit-log/audit_log_message_presence_connector_gap.yaml` | imported | active | connector-gap | ARGS:a | unknown | - |
| audit_log_rule_id_presence_runtime_difference | `tests/cases/audit-log/audit_log_rule_id_presence_runtime_difference.yaml` | imported | active | runtime-difference | ARGS:a | unknown | - |
| duplicate_cookie_name_runtime_difference | `tests/cases/audit-log/duplicate_cookie_name_runtime_difference.yaml` | imported | active | runtime-difference | REQUEST_COOKIES_NAMES | unknown | - |
| parser_json_partial_body_connector_gap | `tests/cases/audit-log/parser_json_partial_body_connector_gap.yaml` | imported | active | connector-gap | REQUEST_BODY | unknown | - |
| json_duplicate_keys_runtime_difference | `tests/cases/body/json/json_duplicate_keys_runtime_difference.yaml` | imported | active | runtime-difference | REQUEST_BODY | unknown | - |
| request_body_json_invalid_runtime_difference | `tests/cases/body/json/request_body_json_invalid_runtime_difference.yaml` | imported | active | runtime-difference | REQUEST_BODY | unknown | - |
| multipart_empty_filename_connector_gap | `tests/cases/body/multipart/multipart_empty_filename_connector_gap.yaml` | imported | active | connector-gap | MULTIPART_FILENAME | unknown | - |
| multipart_encoded_filename_runtime_difference | `tests/cases/body/multipart/multipart_encoded_filename_runtime_difference.yaml` | imported | active | runtime-difference | MULTIPART_FILENAME | unknown | - |
| xml_namespace_edge_connector_gap | `tests/cases/body/xml/xml_namespace_edge_connector_gap.yaml` | imported | active | connector-gap | REQUEST_HEADERS:Content-Type, XML:/* | unknown | - |
| xml_request_body_malformed_connector_gap | `tests/cases/body/xml/xml_request_body_malformed_connector_gap.yaml` | imported | active | connector-gap | REQUEST_HEADERS:Content-Type, XML | unknown | - |
| v3_args_names_duplicate_query_connector_gap | `tests/cases/future-gap/v3_args_names_duplicate_query_connector_gap.yaml` | imported | active | connector-gap | ARGS_NAMES | unknown | - |
| v3_request_cookies_names_case_runtime_difference | `tests/cases/request/cookies/v3_request_cookies_names_case_runtime_difference.yaml` | imported | active | runtime-difference | REQUEST_COOKIES_NAMES | unknown | - |
| v3_request_headers_names_duplicate_connector_gap | `tests/cases/request/headers/v3_request_headers_names_duplicate_connector_gap.yaml` | imported | active | connector-gap | REQUEST_HEADERS_NAMES | unknown | - |
| v3_request_headers_names_lowercase_runtime_difference | `tests/cases/request/headers/v3_request_headers_names_lowercase_runtime_difference.yaml` | imported | active | runtime-difference | REQUEST_HEADERS_NAMES | unknown | - |
| edge_plus_vs_space_runtime_difference | `tests/cases/request/uri/edge_plus_vs_space_runtime_difference.yaml` | imported | active | runtime-difference | REQUEST_URI | unknown | - |
| unicode_double_encoded_uri_runtime_difference | `tests/cases/request/uri/unicode_double_encoded_uri_runtime_difference.yaml` | imported | active | runtime-difference | REQUEST_URI | unknown | - |
| phase4_auditlog_outbound_message_connector_gap | `tests/cases/response/body/phase4_auditlog_outbound_message_connector_gap.yaml` | imported | active | connector-gap | RESPONSE_BODY | unknown | - |
| phase4_auditlog_outbound_rule_id_runtime_difference | `tests/cases/response/body/phase4_auditlog_outbound_rule_id_runtime_difference.yaml` | imported | active | runtime-difference | RESPONSE_BODY | unknown | - |
| phase4_response_body_chunk_assumption_connector_gap | `tests/cases/response/body/phase4_response_body_chunk_assumption_connector_gap.yaml` | imported | active | connector-gap | RESPONSE_BODY | unknown | - |
| phase4_response_body_unicode_runtime_difference | `tests/cases/response/body/phase4_response_body_unicode_runtime_difference.yaml` | imported | active | runtime-difference | RESPONSE_BODY | unknown | - |
| phase3_response_headers_duplicate_value_runtime_difference | `tests/cases/response/headers/phase3_response_headers_duplicate_value_runtime_difference.yaml` | imported | active | runtime-difference | RESPONSE_HEADERS:Set-Cookie | unknown | - |
| phase3_response_headers_mixed_case_connector_gap | `tests/cases/response/headers/phase3_response_headers_mixed_case_connector_gap.yaml` | imported | active | connector-gap | RESPONSE_HEADERS:content-type | unknown | - |
| phase3_response_headers_multi_value_connector_gap | `tests/cases/response/headers/phase3_response_headers_multi_value_connector_gap.yaml` | imported | active | connector-gap | RESPONSE_HEADERS:Set-Cookie | unknown | - |
| sqli_like_quote_encoding_runtime_difference | `tests/cases/security/sql/sqli_like_quote_encoding_runtime_difference.yaml` | imported | active | runtime-difference | ARGS:q | unknown | - |
| request_body_limit_exceeded | `tests/cases/security-data-flow/body-limits/request_body_limit_exceeded.yaml` | connector-gap | active | connector-gap | - | unknown | - |
| response_body_truncation_event | `tests/cases/security-data-flow/body-limits/response_body_truncation_event.yaml` | connector-gap | active | connector-gap | - | unknown | - |
| decision_jsonl_no_body_payload | `tests/cases/security-data-flow/events/decision_jsonl_no_body_payload.yaml` | connector-gap | active | connector-gap | - | unknown | - |
| event_jsonl_no_body_payload | `tests/cases/security-data-flow/events/event_jsonl_no_body_payload.yaml` | connector-gap | active | connector-gap | - | unknown | - |
| integrity_event_hash_chain_tamper_detected | `tests/cases/security-data-flow/events/integrity_event_hash_chain_tamper_detected.yaml` | connector-gap | active | connector-gap | - | unknown | - |
| integrity_event_hash_chain_valid | `tests/cases/security-data-flow/events/integrity_event_hash_chain_valid.yaml` | connector-gap | active | connector-gap | - | unknown | - |
| conflicting_content_length_rejected | `tests/cases/security-data-flow/headers/conflicting_content_length_rejected.yaml` | connector-gap | active | connector-gap | - | unknown | - |
| header_count_limit_exceeded | `tests/cases/security-data-flow/headers/header_count_limit_exceeded.yaml` | connector-gap | active | connector-gap | - | unknown | - |
| header_value_limit_exceeded | `tests/cases/security-data-flow/headers/header_value_limit_exceeded.yaml` | connector-gap | active | connector-gap | - | unknown | - |
| log_control_chars_sanitized | `tests/cases/security-data-flow/log-safety/log_control_chars_sanitized.yaml` | connector-gap | active | connector-gap | - | unknown | - |
| log_secret_like_payload_redacted | `tests/cases/security-data-flow/log-safety/log_secret_like_payload_redacted.yaml` | connector-gap | active | connector-gap | - | unknown | - |
| duplicate_mutating_phase_rejected | `tests/cases/security-data-flow/phase-order/duplicate_mutating_phase_rejected.yaml` | connector-gap | active | connector-gap | - | unknown | - |
| phase_skip_rejected | `tests/cases/security-data-flow/phase-order/phase_skip_rejected.yaml` | connector-gap | active | connector-gap | - | unknown | - |
| transaction_id_control_char_rejected | `tests/cases/security-data-flow/transaction-id/transaction_id_control_char_rejected.yaml` | connector-gap | active | connector-gap | - | unknown | - |
| transaction_id_too_long_rejected | `tests/cases/security-data-flow/transaction-id/transaction_id_too_long_rejected.yaml` | connector-gap | active | connector-gap | - | unknown | - |

## Data Sources

| Value | Source | Source Hash | Verified Run ID | Status |
|---|---|---|---|---|
| Declared input | `config/testing/import-status.json` | `missing` | `unknown` | missing |
| Declared input | `docs/testing/runtime-validation-snapshot.json` | `f5594b18041c8146c6ca3adc51414b56777df742eb35ae883f3e1956e7161cbe` | `2026-06-16T19-12-00Z-614c8049` | present |

## Data Availability / Missing Information

| Input | Status | Notes |
|---|---|---|
| `config/testing/import-status.json` | missing | input file is missing |
| `docs/testing/runtime-validation-snapshot.json` | present | input file available |
