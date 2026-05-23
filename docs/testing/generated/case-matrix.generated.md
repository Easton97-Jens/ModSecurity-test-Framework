Generated file — do not edit manually.

# Generated Case Matrix

| case_id | path | scope | phase | variables | operators | transformations | status | runtime_verified | RESPONSE_BODY non-verified | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| audit_log_empty_sections_future_target | `tests/cases/audit-log/audit_log_empty_sections_future_target.yaml` | common | 1 | ARGS:a | @streq | - | xfail | false | no | - |
| audit_log_matched_var_encoded_value | `tests/cases/audit-log/audit_log_matched_var_encoded_value.yaml` | common | 2 | ARGS:q | @contains | urlDecode | xfail | false | no | - |
| audit_log_message_presence_connector_gap | `tests/cases/audit-log/audit_log_message_presence_connector_gap.yaml` | common | 1 | ARGS:a | @streq | - | xfail | false | no | - |
| audit_log_multiline_message_normalization | `tests/cases/audit-log/audit_log_multiline_message_normalization.yaml` | common | 1 | ARGS:a | @streq | - | xfail | false | no | - |
| audit_log_phase1_block | `tests/cases/audit-log/audit_log_phase1_block.yaml` | common | 1 | ARGS:audit | @streq | - | active | false | no | - |
| audit_log_rule_id_presence_runtime_difference | `tests/cases/audit-log/audit_log_rule_id_presence_runtime_difference.yaml` | common | 1 | ARGS:a | @streq | - | xfail | false | no | - |
| duplicate_args_encoded_separator_edge | `tests/cases/audit-log/duplicate_args_encoded_separator_edge.yaml` | common | 2 | ARGS_NAMES | @contains | - | xfail | false | no | - |
| duplicate_cookie_name_runtime_difference | `tests/cases/audit-log/duplicate_cookie_name_runtime_difference.yaml` | common | 1 | REQUEST_COOKIES_NAMES | @contains | - | xfail | false | no | - |
| duplicate_header_case_normalization_gap | `tests/cases/audit-log/duplicate_header_case_normalization_gap.yaml` | common | 1 | REQUEST_HEADERS_NAMES | @contains | - | xfail | false | no | - |
| parser_json_partial_body_connector_gap | `tests/cases/audit-log/parser_json_partial_body_connector_gap.yaml` | common | 2 | REQUEST_BODY | @contains | - | xfail | false | no | - |
| parser_xml_partial_body_future_target | `tests/cases/audit-log/parser_xml_partial_body_future_target.yaml` | common | 2 | XML | @contains | - | xfail | false | no | - |
| pr70_phase1_audit_request_header | `tests/cases/audit-log/pr70-phases/pr70_phase1_audit_request_header.yaml` | common | 1 | REQUEST_HEADERS:X-PR70-Phase | @streq | - | imported | unknown | no | PR70 source-derived phase 1 audit smoke; asserts stable audit substrings only. |
| pr70_phase2_audit_urlencoded_body | `tests/cases/audit-log/pr70-phases/pr70_phase2_audit_urlencoded_body.yaml` | common | 2 | ARGS_POST:arg1 | @streq | - | imported | unknown | no | PR70 source-derived phase 2 audit smoke using URL-encoded request-body support. |
| pr70_phase3_audit_response_header | `tests/cases/audit-log/pr70-phases/pr70_phase3_audit_response_header.yaml` | common | 3 | RESPONSE_HEADERS:Last-Modified | @rx | - | imported | unknown | no | PR70 source-derived phase 3 audit smoke against the stable static-file Last-Modified response header. |
| pr70_phase4_response_body_audit_xfail | `tests/cases/audit-log/pr70-phases/pr70_phase4_response_body_audit_xfail.yaml` | common | 4 | RESPONSE_BODY | @contains | - | xfail | false | yes | PR70 phase 4 RESPONSE_BODY audit probe; future/non-promoted evidence only. |
| tfn_chain_lowercase_trim_pass_through | `tests/cases/audit-log/tfn_chain_lowercase_trim_pass_through.yaml` | common | 2 | ARGS:q | @streq | lowercase, trim | xfail | false | no | - |
| tfn_chain_urldecode_compress_whitespace_gap | `tests/cases/audit-log/tfn_chain_urldecode_compress_whitespace_gap.yaml` | common | 2 | ARGS:q | @streq | compressWhitespace, urlDecode | xfail | false | no | - |
| v3_action_nolog_pass_no_audit | `tests/cases/audit-log/v3_action_nolog_pass_no_audit.yaml` | common | 1 | ARGS:foo | @rx | - | xfail | false | no | - |
| v3_auditlog_serial_fields_block | `tests/cases/audit-log/v3_auditlog_serial_fields_block.yaml` | common | 1 | ARGS:param1 | @contains | - | imported | unknown | no | - |
| json_duplicate_keys_runtime_difference | `tests/cases/body/json/json_duplicate_keys_runtime_difference.yaml` | common | 2 | REQUEST_BODY | @contains | - | xfail | false | no | - |
| json_empty_body_future_compatibility | `tests/cases/body/json/json_empty_body_future_compatibility.yaml` | common | 2 | REQUEST_BODY | @streq | - | xfail | false | no | - |
| json_nested_object_future_compatibility | `tests/cases/body/json/json_nested_object_future_compatibility.yaml` | common | 2 | REQUEST_BODY | @contains | - | xfail | false | no | - |
| json_request_body_block | `tests/cases/body/json/json_request_body_block.yaml` | common | 2 | REQUEST_BODY | @contains | - | imported | unknown | no | - |
| request_body_json_block | `tests/cases/body/json/request_body_json_block.yaml` | common | 2 | REQUEST_BODY | @contains | - | active | false | no | - |
| request_body_json_invalid_runtime_difference | `tests/cases/body/json/request_body_json_invalid_runtime_difference.yaml` | common | 2 | REQUEST_BODY | @contains | - | xfail | false | no | - |
| files_empty_part_future_compatibility | `tests/cases/body/multipart/files_empty_part_future_compatibility.yaml` | common | 2 | FILES | @contains | - | xfail | false | no | - |
| files_names_mixed_case_filename_gap | `tests/cases/body/multipart/files_names_mixed_case_filename_gap.yaml` | common | 2 | FILES_NAMES | @contains | - | xfail | false | no | - |
| multipart_basic_block | `tests/cases/body/multipart/multipart_basic_block.yaml` | common | 2 | ARGS:name | @streq | - | imported | unknown | no | - |
| multipart_duplicate_field_names_gap | `tests/cases/body/multipart/multipart_duplicate_field_names_gap.yaml` | common | 2 | ARGS_NAMES | @contains | - | xfail | false | no | - |
| multipart_empty_filename_connector_gap | `tests/cases/body/multipart/multipart_empty_filename_connector_gap.yaml` | common | 2 | MULTIPART_FILENAME | @streq | - | xfail | false | no | - |
| multipart_encoded_filename_runtime_difference | `tests/cases/body/multipart/multipart_encoded_filename_runtime_difference.yaml` | common | 2 | MULTIPART_FILENAME | @contains | - | xfail | false | no | - |
| multipart_filename_block | `tests/cases/body/multipart/multipart_filename_block.yaml` | common | 2 | MULTIPART_FILENAME | @contains | - | imported | unknown | no | - |
| multipart_files_combined_size | `tests/cases/body/multipart/multipart_files_combined_size.yaml` | common | 2 | FILES_COMBINED_SIZE | @gt | - | imported | unknown | no | - |
| multipart_files_names_block | `tests/cases/body/multipart/multipart_files_names_block.yaml` | common | 2 | FILES_NAMES | @contains | - | imported | unknown | no | - |
| multipart_files_value_block | `tests/cases/body/multipart/multipart_files_value_block.yaml` | common | 2 | FILES:filedata1 | @contains | - | imported | unknown | no | - |
| multipart_invalid_boundary_future_target | `tests/cases/body/multipart/multipart_invalid_boundary_future_target.yaml` | common | 2 | REQUEST_BODY | @contains | - | xfail | false | no | - |
| xml_deep_nesting_future_target | `tests/cases/body/xml/xml_deep_nesting_future_target.yaml` | common | 2 | XML | @contains | - | xfail | false | no | - |
| xml_namespace_edge_connector_gap | `tests/cases/body/xml/xml_namespace_edge_connector_gap.yaml` | common | 2 | XML | @contains | - | xfail | false | no | - |
| xml_request_body_block | `tests/cases/body/xml/xml_request_body_block.yaml` | common | 1,2 | XML:/* | @contains | lowercase, none | imported | unknown | no | - |
| xml_request_body_malformed_connector_gap | `tests/cases/body/xml/xml_request_body_malformed_connector_gap.yaml` | common | 2 | XML | @contains | - | xfail | false | no | - |
| nginx_phase4_content_type_out_of_scope | `tests/cases/connector-specific/nginx/nginx_phase4_content_type_out_of_scope.yaml` | nginx | 4 | RESPONSE_BODY | @contains | - | imported | unknown | yes | - |
| nginx_phase4_minimal_log_only | `tests/cases/connector-specific/nginx/nginx_phase4_minimal_log_only.yaml` | nginx | 4 | RESPONSE_BODY | @contains | - | imported | unknown | yes | - |
| nginx_phase4_safe_log_only | `tests/cases/connector-specific/nginx/nginx_phase4_safe_log_only.yaml` | nginx | 4 | RESPONSE_BODY | @contains | - | imported | unknown | yes | - |
| nginx_phase4_strict_connection_abort | `tests/cases/connector-specific/nginx/nginx_phase4_strict_connection_abort.yaml` | nginx | 4 | RESPONSE_BODY | @contains | - | xfail | false | yes | - |
| nginx_redirect_phase1_302 | `tests/cases/connector-specific/nginx/nginx_redirect_phase1_302.yaml` | nginx | 1 | ARGS | @streq | http | imported | unknown | no | - |
| nginx_tx_scoring_absolute_block | `tests/cases/connector-specific/nginx/nginx_tx_scoring_absolute_block.yaml` | nginx | 2 | ARGS, TX:SCORE | @ge, @streq | - | imported | unknown | no | - |
| nginx_tx_scoring_iterative_block | `tests/cases/connector-specific/nginx/nginx_tx_scoring_iterative_block.yaml` | nginx | 2 | ARGS, TX:SCORE | @ge, @streq | - | imported | unknown | no | - |
| v3_args_names_duplicate_query_connector_gap | `tests/cases/future-gap/v3_args_names_duplicate_query_connector_gap.yaml` | common | 2 | ARGS_NAMES | @contains | - | xfail | false | no | - |
| edge_missing_header_pass_through | `tests/cases/negative-pass-through/edge_missing_header_pass_through.yaml` | common | 1 | REQUEST_HEADERS:X-Missing | @streq | - | xfail | false | no | - |
| operator_beginswith_pass_no_match_phase2 | `tests/cases/negative-pass-through/operator_beginswith_pass_no_match_phase2.yaml` | common | 2 | ARGS:q | @beginsWith | - | xfail | false | no | - |
| operator_contains_pass_no_match_phase2 | `tests/cases/negative-pass-through/operator_contains_pass_no_match_phase2.yaml` | common | 2 | ARGS:q | @contains | - | xfail | false | no | - |
| operator_endswith_pass_no_match_phase2 | `tests/cases/negative-pass-through/operator_endswith_pass_no_match_phase2.yaml` | common | 2 | ARGS:q | @endsWith | - | xfail | false | no | - |
| operator_rx_pass_no_match_phase2 | `tests/cases/negative-pass-through/operator_rx_pass_no_match_phase2.yaml` | common | 2 | ARGS:q | @rx | - | xfail | false | no | - |
| operator_streq_pass_no_match_phase2 | `tests/cases/negative-pass-through/operator_streq_pass_no_match_phase2.yaml` | common | 2 | ARGS:q | @streq | - | xfail | false | no | - |
| phase2_header_only_pass_through | `tests/cases/negative-pass-through/phase2_header_only_pass_through.yaml` | common | 2 | REQUEST_HEADERS:X-Phase | @streq | - | xfail | false | no | - |
| tfn_lowercase_pass_no_match_phase2 | `tests/cases/negative-pass-through/tfn_lowercase_pass_no_match_phase2.yaml` | common | 2 | ARGS:q | @streq | lowercase | xfail | false | no | - |
| tfn_trim_pass_no_match_phase2 | `tests/cases/negative-pass-through/tfn_trim_pass_no_match_phase2.yaml` | common | 2 | ARGS:q | @streq | trim | xfail | false | no | - |
| v2_transformation_url_decode_pass_no_match | `tests/cases/negative-pass-through/v2_transformation_url_decode_pass_no_match.yaml` | common | 1 | REQUEST_URI | @contains | urlDecode | imported | unknown | no | - |
| v3_args_names_get_pass_no_match | `tests/cases/negative-pass-through/v3_args_names_get_pass_no_match.yaml` | common | 2 | ARGS_NAMES | @contains | - | imported | unknown | no | - |
| v3_request_cookies_names_pass_no_match | `tests/cases/negative-pass-through/v3_request_cookies_names_pass_no_match.yaml` | common | 1 | REQUEST_COOKIES_NAMES | @contains | - | imported | unknown | no | - |
| v3_request_cookies_pass_no_match | `tests/cases/negative-pass-through/v3_request_cookies_pass_no_match.yaml` | common | 1 | REQUEST_COOKIES:USER_TOKEN | @streq | - | imported | unknown | no | - |
| v3_request_headers_names_pass_no_match | `tests/cases/negative-pass-through/v3_request_headers_names_pass_no_match.yaml` | common | 1 | REQUEST_HEADERS_NAMES | @contains | - | imported | unknown | no | - |
| action_allow_phase1_pass | `tests/cases/phases/phase1/action_allow_phase1_pass.yaml` | common | 1 | - | - | - | imported | unknown | no | - |
| action_deny_phase1 | `tests/cases/phases/phase1/action_deny_phase1.yaml` | common | 1 | - | - | - | imported | unknown | no | - |
| action_status_401_phase1_block | `tests/cases/phases/phase1/action_status_401_phase1_block.yaml` | common | 1 | ARGS | @streq | - | imported | unknown | no | - |
| phase1_vs_phase2_request_body_gap | `tests/cases/phases/phase1/phase1_vs_phase2_request_body_gap.yaml` | common | 1 | REQUEST_BODY | @contains | - | xfail | false | no | - |
| action_deny_phase2 | `tests/cases/phases/phase2/action_deny_phase2.yaml` | common | 2 | - | - | - | imported | unknown | no | - |
| collection_args_combined_size_block | `tests/cases/phases/phase2/collection_args_combined_size_block.yaml` | common | 2 | ARGS_COMBINED_SIZE | @eq | - | imported | unknown | no | - |
| collection_args_get_block | `tests/cases/phases/phase2/collection_args_get_block.yaml` | common | 2 | ARGS_GET | @streq | - | imported | unknown | no | - |
| collection_args_names_block | `tests/cases/phases/phase2/collection_args_names_block.yaml` | common | 2 | ARGS_NAMES | @streq | - | imported | unknown | no | - |
| edge_semicolon_query_args_names | `tests/cases/phases/phase2/edge_semicolon_query_args_names.yaml` | common | 2 | ARGS_NAMES | @contains | - | xfail | false | no | - |
| phase2_args_block | `tests/cases/phases/phase2/phase2_args_block.yaml` | common | 2 | ARGS:test | @streq | - | active | false | no | - |
| phase2_args_pass | `tests/cases/phases/phase2/phase2_args_pass.yaml` | common | 2 | ARGS:test | @streq | - | active | false | no | - |
| request_body_args_post_names_block | `tests/cases/phases/phase2/request_body_args_post_names_block.yaml` | common | 2 | ARGS_POST_NAMES | @streq | - | imported | unknown | no | - |
| request_body_raw_text_block | `tests/cases/phases/phase2/request_body_raw_text_block.yaml` | common | 2 | REQUEST_BODY | @rx | - | imported | unknown | no | - |
| request_body_urlencoded_block | `tests/cases/phases/phase2/request_body_urlencoded_block.yaml` | common | 2 | ARGS_POST:test | @streq | - | active | false | no | - |
| v3_args_names_get_block | `tests/cases/phases/phase2/v3_args_names_get_block.yaml` | common | 2 | ARGS_NAMES | @contains | - | imported | unknown | no | - |
| v3_secaction_block | `tests/cases/phases/phase2/v3_secaction_block.yaml` | common | 2 | - | - | - | imported | unknown | no | - |
| v3_request_cookies_block | `tests/cases/request/cookies/v3_request_cookies_block.yaml` | common | 1 | REQUEST_COOKIES:USER_TOKEN | @streq | - | imported | unknown | no | - |
| v3_request_cookies_names_block | `tests/cases/request/cookies/v3_request_cookies_names_block.yaml` | common | 1 | REQUEST_COOKIES_NAMES | @contains | - | imported | unknown | no | - |
| v3_request_cookies_names_case_runtime_difference | `tests/cases/request/cookies/v3_request_cookies_names_case_runtime_difference.yaml` | common | 1 | REQUEST_COOKIES_NAMES | @contains | - | xfail | false | no | - |
| phase1_header_block | `tests/cases/request/headers/phase1_header_block.yaml` | common | 1 | REQUEST_HEADERS:User-Agent | @contains | - | active | false | no | - |
| v2_transformation_html_entity_decode_block | `tests/cases/request/headers/v2_transformation_html_entity_decode_block.yaml` | common | 1 | REQUEST_HEADERS:X-Entity-Probe | @contains | htmlEntityDecode | imported | unknown | no | - |
| v3_request_headers_names_block | `tests/cases/request/headers/v3_request_headers_names_block.yaml` | common | 1 | REQUEST_HEADERS_NAMES | @contains | - | imported | unknown | no | - |
| v3_request_headers_names_duplicate_connector_gap | `tests/cases/request/headers/v3_request_headers_names_duplicate_connector_gap.yaml` | common | 1 | REQUEST_HEADERS_NAMES | @contains | - | xfail | false | no | - |
| v3_request_headers_names_lowercase_runtime_difference | `tests/cases/request/headers/v3_request_headers_names_lowercase_runtime_difference.yaml` | common | 1 | REQUEST_HEADERS_NAMES | @contains | - | xfail | false | no | - |
| edge_plus_vs_space_runtime_difference | `tests/cases/request/uri/edge_plus_vs_space_runtime_difference.yaml` | common | 1 | REQUEST_URI | @contains | urlDecode | xfail | false | no | - |
| tfn_urldecodeuni_future_target_phase1 | `tests/cases/request/uri/tfn_urldecodeuni_future_target_phase1.yaml` | common | 1 | REQUEST_URI | @contains | urlDecodeUni | xfail | false | no | - |
| unicode_double_encoded_uri_runtime_difference | `tests/cases/request/uri/unicode_double_encoded_uri_runtime_difference.yaml` | common | 1 | REQUEST_URI | @contains | urlDecode, urlDecodeUni | xfail | false | no | - |
| v2_transformation_remove_nulls_future_target | `tests/cases/request/uri/v2_transformation_remove_nulls_future_target.yaml` | common | 1 | REQUEST_URI | @contains | removeNulls | xfail | false | no | - |
| v2_transformation_url_decode_block | `tests/cases/request/uri/v2_transformation_url_decode_block.yaml` | common | 1 | REQUEST_URI | @contains | urlDecode | imported | unknown | no | - |
| v2_transformation_url_decode_invalid_sequence_mapped_candidate | `tests/cases/request/uri/v2_transformation_url_decode_invalid_sequence_mapped_candidate.yaml` | common | 1 | REQUEST_URI | @contains | urlDecode | xfail | false | no | - |
| phase4_auditlog_outbound_escaped_value_gap | `tests/cases/response/body/phase4_auditlog_outbound_escaped_value_gap.yaml` | common | 4 | RESPONSE_BODY | @contains | - | xfail | false | yes | - |
| phase4_auditlog_outbound_matched_var_future | `tests/cases/response/body/phase4_auditlog_outbound_matched_var_future.yaml` | common | 4 | RESPONSE_BODY | @contains | - | xfail | false | yes | - |
| phase4_auditlog_outbound_message_connector_gap | `tests/cases/response/body/phase4_auditlog_outbound_message_connector_gap.yaml` | common | 4 | RESPONSE_BODY | @contains | - | xfail | false | yes | - |
| phase4_auditlog_outbound_multiline_section_gap | `tests/cases/response/body/phase4_auditlog_outbound_multiline_section_gap.yaml` | common | 4 | RESPONSE_BODY | @contains | - | xfail | false | yes | - |
| phase4_auditlog_outbound_rule_id_runtime_difference | `tests/cases/response/body/phase4_auditlog_outbound_rule_id_runtime_difference.yaml` | common | 4 | RESPONSE_BODY | @contains | - | xfail | false | yes | - |
| phase4_response_body_buffering_order_future_target | `tests/cases/response/body/phase4_response_body_buffering_order_future_target.yaml` | common | 4 | RESPONSE_BODY | @contains | - | xfail | false | yes | - |
| phase4_response_body_chunk_assumption_connector_gap | `tests/cases/response/body/phase4_response_body_chunk_assumption_connector_gap.yaml` | common | 4 | RESPONSE_BODY | @contains | - | xfail | false | yes | - |
| phase4_response_body_compressed_assumption_experimental | `tests/cases/response/body/phase4_response_body_compressed_assumption_experimental.yaml` | common | 4 | RESPONSE_BODY | @contains | - | xfail | false | yes | - |
| phase4_response_body_empty_future_target | `tests/cases/response/body/phase4_response_body_empty_future_target.yaml` | common | 4 | RESPONSE_BODY | @streq | - | xfail | false | yes | - |
| phase4_response_body_html_entity_decode_gap | `tests/cases/response/body/phase4_response_body_html_entity_decode_gap.yaml` | common | 4 | RESPONSE_BODY | @contains | htmlEntityDecode | xfail | false | yes | - |
| phase4_response_body_html_text_normalization_probe | `tests/cases/response/body/phase4_response_body_html_text_normalization_probe.yaml` | common | 4 | RESPONSE_BODY | @contains | - | xfail | false | yes | - |
| phase4_response_body_pass_no_match_experimental | `tests/cases/response/body/phase4_response_body_pass_no_match_experimental.yaml` | common | 4 | RESPONSE_BODY | @contains | - | xfail | false | yes | - |
| phase4_response_body_unicode_runtime_difference | `tests/cases/response/body/phase4_response_body_unicode_runtime_difference.yaml` | common | 4 | RESPONSE_BODY | @contains | - | xfail | false | yes | - |
| response_body_basic_block | `tests/cases/response/body/response_body_basic_block.yaml` | common | 4 | RESPONSE_BODY | @contains | - | xfail | false | yes | - |
| response_body_pass | `tests/cases/response/body/response_body_pass.yaml` | common | 4 | RESPONSE_BODY | @contains | - | imported | unknown | yes | - |
| phase3_response_headers_content_type_charset_gap | `tests/cases/response/headers/phase3_response_headers_content_type_charset_gap.yaml` | common | 3 | RESPONSE_HEADERS:Content-Type | @contains | - | xfail | false | yes | - |
| phase3_response_headers_duplicate_value_runtime_difference | `tests/cases/response/headers/phase3_response_headers_duplicate_value_runtime_difference.yaml` | common | 3 | RESPONSE_HEADERS:Set-Cookie | @contains | - | xfail | false | no | - |
| phase3_response_headers_encoded_value_future_target | `tests/cases/response/headers/phase3_response_headers_encoded_value_future_target.yaml` | common | 3 | RESPONSE_HEADERS:Location | @contains | - | xfail | false | no | - |
| phase3_response_headers_location_encoded_runtime_diff | `tests/cases/response/headers/phase3_response_headers_location_encoded_runtime_diff.yaml` | common | 3 | RESPONSE_HEADERS:Location | @contains | - | xfail | false | yes | - |
| phase3_response_headers_missing_pass_through | `tests/cases/response/headers/phase3_response_headers_missing_pass_through.yaml` | common | 3 | RESPONSE_HEADERS:X-Missing | @streq | - | xfail | false | no | - |
| phase3_response_headers_mixed_case_connector_gap | `tests/cases/response/headers/phase3_response_headers_mixed_case_connector_gap.yaml` | common | 3 | RESPONSE_HEADERS:content-type | @contains | - | xfail | false | no | - |
| phase3_response_headers_multi_value_connector_gap | `tests/cases/response/headers/phase3_response_headers_multi_value_connector_gap.yaml` | common | 3 | RESPONSE_HEADERS:Set-Cookie | @contains | - | xfail | false | no | - |
| phase3_response_headers_server_presence_pending | `tests/cases/response/headers/phase3_response_headers_server_presence_pending.yaml` | common | 3 | RESPONSE_HEADERS:Server | @contains | - | xfail | false | yes | - |
| phase3_response_headers_set_cookie_multi_gap | `tests/cases/response/headers/phase3_response_headers_set_cookie_multi_gap.yaml` | common | 3 | RESPONSE_HEADERS:Set-Cookie | @contains | - | xfail | false | yes | - |
| response_header_basic | `tests/cases/response/headers/response_header_basic.yaml` | common | 3 | - | - | - | active | false | no | - |
| response_headers_multi_value_runtime_gap | `tests/cases/response/headers/response_headers_multi_value_runtime_gap.yaml` | common | 3 | RESPONSE_HEADERS:Set-Cookie | @contains | - | xfail | false | no | - |
| sqli_like_keyword_spacing_probe | `tests/cases/security/sql/sqli_like_keyword_spacing_probe.yaml` | common | 2 | ARGS:q | @contains | compressWhitespace, lowercase | xfail | false | no | - |
| sqli_like_quote_encoding_runtime_difference | `tests/cases/security/sql/sqli_like_quote_encoding_runtime_difference.yaml` | common | 2 | ARGS:q | @contains | urlDecode | xfail | false | no | - |
| xss_like_encoded_angles_normalization_probe | `tests/cases/security/xss/xss_like_encoded_angles_normalization_probe.yaml` | common | 2 | ARGS:q | @contains | htmlEntityDecode | xfail | false | no | - |
| xss_like_mixed_case_script_token_gap | `tests/cases/security/xss/xss_like_mixed_case_script_token_gap.yaml` | common | 2 | ARGS:q | @contains | lowercase | xfail | false | no | - |
| tfn_compress_whitespace_runtime_gap | `tests/cases/transformations/tfn_compress_whitespace_runtime_gap.yaml` | common | 2 | ARGS:q | @streq | compressWhitespace | xfail | false | no | - |
| tfn_none_exact_block_phase2 | `tests/cases/transformations/tfn_none_exact_block_phase2.yaml` | common | 2 | ARGS:q | @streq | none | xfail | false | no | - |
| unicode_whitespace_normalization_gap | `tests/cases/transformations/unicode_whitespace_normalization_gap.yaml` | common | 2 | ARGS:q | @streq | compressWhitespace | xfail | false | no | - |
| v2_operator_begins_with_block | `tests/cases/transformations/v2_operator_begins_with_block.yaml` | common | 2 | ARGS:probe | @beginsWith | - | imported | unknown | no | - |
| v2_operator_contains_block | `tests/cases/transformations/v2_operator_contains_block.yaml` | common | 2 | ARGS:test | @contains | - | imported | unknown | no | - |
| v2_operator_contains_word_block | `tests/cases/transformations/v2_operator_contains_word_block.yaml` | common | 2 | ARGS:probe | @containsWord | - | imported | unknown | no | - |
| v2_operator_ends_with_block | `tests/cases/transformations/v2_operator_ends_with_block.yaml` | common | 2 | ARGS:probe | @endsWith | - | imported | unknown | no | - |
| v2_operator_pm_block | `tests/cases/transformations/v2_operator_pm_block.yaml` | common | 2 | ARGS:probe | @pm | - | imported | unknown | no | - |
| v2_operator_streq_block | `tests/cases/transformations/v2_operator_streq_block.yaml` | common | 2 | ARGS:test | @streq | - | imported | unknown | no | - |
| v2_transformation_lowercase_block | `tests/cases/transformations/v2_transformation_lowercase_block.yaml` | common | 2 | ARGS:test | @streq | lowercase | imported | unknown | no | - |
| v2_transformation_trim_block | `tests/cases/transformations/v2_transformation_trim_block.yaml` | common | 2 | ARGS:test | @streq | trim | imported | unknown | no | - |
| v2_transformation_trim_tab_future_compatibility | `tests/cases/transformations/v2_transformation_trim_tab_future_compatibility.yaml` | common | 2 | ARGS:q | @streq | trim | xfail | false | no | - |
| v3_operator_pm_digit_block | `tests/cases/transformations/v3_operator_pm_digit_block.yaml` | common | 1 | ARGS:param1 | @pm | - | imported | unknown | no | - |
| v3_operator_rx_block | `tests/cases/transformations/v3_operator_rx_block.yaml` | common | 2 | ARGS:param1 | @rx | trim | imported | unknown | no | - |
| v3_transformation_trim_block | `tests/cases/transformations/v3_transformation_trim_block.yaml` | common | 2 | ARGS:param1 | @streq | trim | imported | unknown | no | - |
