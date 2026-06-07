Generated file — do not edit manually.

# ModSecurity Connector Test Coverage Overview

## Summary
- Total cases: **141**
- Verified/pass count (`runtime_verified=true`): **0**
- Current XFAIL count: **0**
- Former XFAIL cases tracked: **80**
- Pending runtime verification count: **11**
- Connector-gap count: **11**
- Runtime-difference count: **13**
- Future/experimental count: **17**
- RESPONSE_BODY cases: **24** (still **not verified/promoted**)
- Mapped-only import inventory entries: **10**

## Coverage By Variable / Collection
| Variable | Count |
|---|---:|
| `RESPONSE_BODY` | 20 |
| `ARGS:q` | 18 |
| `REQUEST_BODY` | 10 |
| `ARGS_NAMES` | 7 |
| `REQUEST_URI` | 7 |
| `ARGS:test` | 6 |
| `REQUEST_HEADERS_NAMES` | 5 |
| `ARGS:a` | 4 |
| `REQUEST_COOKIES_NAMES` | 4 |
| `XML` | 4 |
| `ARGS:param1` | 4 |
| `ARGS` | 4 |
| `RESPONSE_HEADERS:Set-Cookie` | 4 |
| `ARGS:probe` | 4 |
| `MULTIPART_FILENAME` | 3 |
| `ARGS:chain_a` | 3 |
| `ARGS:chain_b` | 3 |
| `FILES_NAMES` | 2 |
| `TX:SCORE` | 2 |
| `REQUEST_COOKIES:USER_TOKEN` | 2 |

## Coverage By Phase
| Phase | Count |
|---|---:|
| 1 | 36 |
| 2 | 74 |
| 3 | 12 |
| 4 | 20 |

## Coverage By Status
| Status | Count |
|---|---:|
| active | 8 |
| imported | 133 |

## Coverage By Scope
| Scope | Count |
|---|---:|
| common | 134 |
| apache | 0 |
| nginx | 7 |
| unknown | 0 |

## Runtime Matrix Status
- Default runtime-executable YAML cases: **141**
- Force-all runtime-executable YAML cases: **141**
- Apache attempted YAML cases from default summary: **54**
- NGINX attempted YAML cases from default summary: **60**
- HAProxy attempted YAML cases from default summary: **134**
- Apache attempted YAML cases from force-all summary: **133**
- NGINX attempted YAML cases from force-all summary: **140**
- HAProxy attempted YAML cases from force-all summary: **133**
| Status | Apache | NGINX | HAProxy |
|---|---:|---:|---:|
| PASS | 54 | 60 | 105 |
| FAIL | 0 | 0 | 23 |
| NOT_EXECUTABLE | 87 | 81 | 13 |
| MAPPED_ONLY | 10 | 10 | 10 |
- Details: `docs/testing/generated/runtime-matrix.generated.md`
- HAProxy per-case results: `docs/testing/generated/haproxy-runtime-results.generated.md`

## Latest Local Runtime Validation Snapshot
- Snapshot: **2026-06-07** (2026-06-07 13:02:53 CEST)
- Git: branch `integrate-new-connectors-local`, commit `b5b983d`
- BUILD_ROOT: `/src/ModSecurity-conector-build`
- This is a manual local runtime snapshot rendered from tracked snapshot data and local smoke summary files.
- Runtime matrix snapshot generated from local Apache, NGINX, and HAProxy summary JSON files when present.
- Per-case PASS/FAIL/BLOCKED/NOT_EXECUTABLE values are runtime evidence for this local run only.
- Former XFAIL YAML cases are normal runtime cases; live results decide PASS/FAIL/BLOCKED/NOT_EXECUTABLE.
- RESPONSE_BODY remains non-verified/non-promoted, including pass-through response-body probes.
- Runtime-passing RESPONSE_BODY cases are marked non-promotable pass-through evidence.
- Mapped-only import inventory entries remain visible but are not executed runtime cases.
- make smoke-all is not implied by separate Apache/NGINX runtime matrix runs.

## Framework Check Status
| Command | Status | Details |
|---|---|---|
| make setup-dev | PASS | Development dependencies available in .venv |
| make lint | PASS | Repository lint checks passed |
| make generate-test-matrix | PASS | Generated coverage docs refreshed from current metadata |
| make check-test-matrix | PASS | Generated coverage docs matched generator output after staging generated docs |
| make quick-check | PASS | Lightweight framework checks passed |
| make cloud-quick-check | PASS | Framework/generator-only cloud check passed |
| .venv/bin/python -m py_compile modules/ModSecurity-test-Framework/tests/normalizers/*.py modules/ModSecurity-test-Framework/tests/runners/*.py modules/ModSecurity-test-Framework/ci/*.py | PASS | Framework Python files compiled through the connector module path |
| sh -n ci/*.sh connectors/apache/harness/*.sh connectors/nginx/harness/*.sh | PASS | POSIX shell syntax check passed for connector integration shell scripts |
| bash -n ci/*.sh connectors/apache/harness/*.sh connectors/nginx/harness/*.sh | PASS | Bash syntax check passed for connector integration shell scripts |
| git diff --check | PASS | No whitespace errors reported |
| diff -u /tmp/pre-connector.diff /tmp/post-connector.diff | PASS | Connector source diff snapshot is unchanged; no new connector source changes were introduced |
| git diff --exit-code -- connectors/apache/src connectors/nginx/src | BLOCKED | Non-zero because connectors/apache/src/mod_security3.c had a pre-existing unrelated local change before this fix; the pre/post connector diff snapshot is unchanged |
| git ls-files .venv | PASS | No tracked .venv files |

## Readiness / Fetch Status
| Command | Status | Details |
|---|---|---|
| make fetch-deps | NOT_RUN | Not rerun during the framework-module migration; runtime-matrix-all used the configured local source tree and build output location |
| optional installed readiness | BLOCKED | System Apache/APXS/NGINX/libmodsecurity readiness remains diagnostic only and is not required for source-build smokes |
| make runtime-matrix-all | PASS | Force-all matrix orchestration completed and recorded Apache/NGINX per-case evidence; expected runtime FAILs remain evidence and are not PASS promotions |

## Default Runtime Smoke Status
| Connector | Command | Status | Exit | Attempted | PASS | FAIL | BLOCKED | NOT_EXECUTABLE | Evidence |
|---|---|---|---|---|---|---|---|---|---|
| apache | make smoke-apache | PASS | 0 | 54 | 54 | 0 | 0 | 0 | /src/ModSecurity-conector-build/results/apache-summary.json |
| nginx | make smoke-nginx | PASS | 0 | 60 | 60 | 0 | 0 | 0 | /src/ModSecurity-conector-build/results/nginx-summary.json |
| haproxy | make smoke-haproxy | FAIL | 2 | 134 | 105 | 23 | 0 | 6 | /src/ModSecurity-conector-build/results/haproxy-summary.json |
| all | REFRESH=1 make smoke-all | NOT_RUN | not_run | 0 | unknown | unknown | unknown | unknown | not available |

## Force-All Runtime Smoke Status
| Connector | Command | Status | Exit | Attempted | PASS | FAIL | BLOCKED | NOT_EXECUTABLE | Evidence |
|---|---|---|---|---|---|---|---|---|---|
| apache | FORCE_ALL_CASES=1 make smoke-apache | FAIL | 1 | 133 | 100 | 27 | 0 | 6 | /src/ModSecurity-conector-build/results/force-all/apache-summary.json |
| nginx | FORCE_ALL_CASES=1 make smoke-nginx | FAIL | 1 | 140 | 95 | 39 | 0 | 6 | /src/ModSecurity-conector-build/results/force-all/nginx-summary.json |
| haproxy | FORCE_ALL_CASES=1 make smoke-haproxy | FAIL | 2 | 133 | 104 | 23 | 0 | 6 | /src/ModSecurity-conector-build/results/force-all/haproxy-summary.json |

## Connector Runtime Availability
| Connector | Status | Build | Per-case results | Attempted cases | Summary evidence | Note |
|---|---|---|---|---:|---|---|
| Apache | PASS | unknown | available | 54 | /src/ModSecurity-conector-build/results/apache-summary.json | Per-case results are copied from the local smoke summary JSON; they are runtime evidence only. |
| NGINX | PASS | unknown | available | 60 | /src/ModSecurity-conector-build/results/nginx-summary.json | Per-case results are copied from the local smoke summary JSON; they are runtime evidence only. |
| HAProxy | FAIL | unknown | available | 134 | /src/ModSecurity-conector-build/results/haproxy-summary.json | Per-case results are copied from the local smoke summary JSON; they are runtime evidence only. |

## Runtime FAIL Details

### Apache FAIL Details
No Apache runtime FAIL details were reported.

### NGINX FAIL Details
No NGINX runtime FAIL details were reported.

## HAProxy Runtime Matrix Details

### HAProxy PASS Details
| Case | Variant | Expected | Actual | Evidence |
|---|---|---:|---:|---|
| action_allow_phase1_pass | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/action_allow_phase1_pass/result.json |
| action_deny_phase1 | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/action_deny_phase1/result.json |
| action_deny_phase2 | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/action_deny_phase2/result.json |
| action_status_401_phase1_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/action_status_401_phase1_block/result.json |
| audit_log_empty_sections_future_target | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/audit_log_empty_sections_future_target/result.json |
| audit_log_matched_var_encoded_value | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/audit_log_matched_var_encoded_value/result.json |
| audit_log_message_presence_connector_gap | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/audit_log_message_presence_connector_gap/result.json |
| audit_log_multiline_message_normalization | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/audit_log_multiline_message_normalization/result.json |
| audit_log_phase1_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/audit_log_phase1_block/result.json |
| audit_log_rule_id_presence_runtime_difference | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/audit_log_rule_id_presence_runtime_difference/result.json |
| collection_args_combined_size_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/collection_args_combined_size_block/result.json |
| collection_args_get_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/collection_args_get_block/result.json |
| collection_args_names_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/collection_args_names_block/result.json |
| crs_sqli_anomaly_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/crs_sqli_anomaly_block/result.json |
| duplicate_cookie_name_runtime_difference | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/duplicate_cookie_name_runtime_difference/result.json |
| edge_missing_header_pass_through | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/edge_missing_header_pass_through/result.json |
| edge_plus_vs_space_runtime_difference | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/edge_plus_vs_space_runtime_difference/result.json |
| json_duplicate_keys_runtime_difference | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/json_duplicate_keys_runtime_difference/result.json |
| json_nested_object_future_compatibility | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/json_nested_object_future_compatibility/result.json |
| json_request_body_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/json_request_body_block/result.json |
| multipart_basic_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/multipart_basic_block/result.json |
| multipart_encoded_filename_runtime_difference | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/multipart_encoded_filename_runtime_difference/result.json |
| multipart_filename_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/multipart_filename_block/result.json |
| multipart_files_combined_size | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/multipart_files_combined_size/result.json |
| multipart_files_names_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/multipart_files_names_block/result.json |
| multipart_files_value_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/multipart_files_value_block/result.json |
| multipart_invalid_boundary_future_target | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/multipart_invalid_boundary_future_target/result.json |
| operator_beginswith_pass_no_match_phase2 | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/operator_beginswith_pass_no_match_phase2/result.json |
| operator_contains_pass_no_match_phase2 | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/operator_contains_pass_no_match_phase2/result.json |
| operator_endswith_pass_no_match_phase2 | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/operator_endswith_pass_no_match_phase2/result.json |
| operator_rx_pass_no_match_phase2 | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/operator_rx_pass_no_match_phase2/result.json |
| operator_streq_pass_no_match_phase2 | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/operator_streq_pass_no_match_phase2/result.json |
| parser_json_partial_body_connector_gap | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/parser_json_partial_body_connector_gap/result.json |
| phase1_header_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase1_header_block/result.json |
| phase1_vs_phase2_request_body_gap | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase1_vs_phase2_request_body_gap/result.json |
| phase2_args_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase2_args_block/result.json |
| phase2_args_pass | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase2_args_pass/result.json |
| phase2_header_only_pass_through | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase2_header_only_pass_through/result.json |
| phase3_response_headers_content_type_charset_gap | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase3_response_headers_content_type_charset_gap/result.json |
| phase3_response_headers_duplicate_value_runtime_difference | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase3_response_headers_duplicate_value_runtime_difference/result.json |
| phase3_response_headers_encoded_value_future_target | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase3_response_headers_encoded_value_future_target/result.json |
| phase3_response_headers_location_encoded_runtime_diff | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase3_response_headers_location_encoded_runtime_diff/result.json |
| phase3_response_headers_missing_pass_through | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase3_response_headers_missing_pass_through/result.json |
| phase3_response_headers_mixed_case_connector_gap | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase3_response_headers_mixed_case_connector_gap/result.json |
| phase4_auditlog_outbound_escaped_value_gap | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_auditlog_outbound_escaped_value_gap/result.json |
| phase4_auditlog_outbound_matched_var_future | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_auditlog_outbound_matched_var_future/result.json |
| phase4_auditlog_outbound_message_connector_gap | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_auditlog_outbound_message_connector_gap/result.json |
| phase4_auditlog_outbound_rule_id_runtime_difference | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_auditlog_outbound_rule_id_runtime_difference/result.json |
| phase4_response_body_buffering_order_future_target | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_response_body_buffering_order_future_target/result.json |
| phase4_response_body_chunk_assumption_connector_gap | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_response_body_chunk_assumption_connector_gap/result.json |
| phase4_response_body_compressed_assumption_experimental | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_response_body_compressed_assumption_experimental/result.json |
| phase4_response_body_html_entity_decode_gap | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_response_body_html_entity_decode_gap/result.json |
| phase4_response_body_html_text_normalization_probe | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_response_body_html_text_normalization_probe/result.json |
| phase4_response_body_pass_no_match_experimental | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_response_body_pass_no_match_experimental/result.json |
| phase4_response_body_unicode_runtime_difference | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_response_body_unicode_runtime_difference/result.json |
| pr70_phase1_audit_request_header | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/pr70_phase1_audit_request_header/result.json |
| pr70_phase2_audit_urlencoded_body | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/pr70_phase2_audit_urlencoded_body/result.json |
| pr70_phase3_audit_response_header | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/pr70_phase3_audit_response_header/result.json |
| pr70_phase4_response_body_audit_xfail | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/pr70_phase4_response_body_audit_xfail/result.json |
| request_body_args_post_names_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/request_body_args_post_names_block/result.json |
| request_body_json_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/request_body_json_block/result.json |
| request_body_json_invalid_runtime_difference | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/request_body_json_invalid_runtime_difference/result.json |
| request_body_raw_text_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/request_body_raw_text_block/result.json |
| request_body_urlencoded_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/request_body_urlencoded_block/result.json |
| response_body_basic_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/response_body_basic_block/result.json |
| response_body_pass | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/response_body_pass/result.json |
| response_header_basic | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/response_header_basic/result.json |
| rule_chain_both_match_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/rule_chain_both_match_block/result.json |
| rule_chain_first_only_pass | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/rule_chain_first_only_pass/result.json |
| rule_chain_second_only_pass | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/rule_chain_second_only_pass/result.json |
| tfn_chain_urldecode_compress_whitespace_gap | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/tfn_chain_urldecode_compress_whitespace_gap/result.json |
| tfn_compress_whitespace_runtime_gap | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/tfn_compress_whitespace_runtime_gap/result.json |
| tfn_lowercase_pass_no_match_phase2 | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/tfn_lowercase_pass_no_match_phase2/result.json |
| tfn_none_exact_block_phase2 | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/tfn_none_exact_block_phase2/result.json |
| tfn_trim_pass_no_match_phase2 | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/tfn_trim_pass_no_match_phase2/result.json |
| tfn_urldecodeuni_future_target_phase1 | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/tfn_urldecodeuni_future_target_phase1/result.json |
| v2_operator_begins_with_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_operator_begins_with_block/result.json |
| v2_operator_contains_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_operator_contains_block/result.json |
| v2_operator_contains_word_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_operator_contains_word_block/result.json |
| v2_operator_ends_with_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_operator_ends_with_block/result.json |
| v2_operator_pm_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_operator_pm_block/result.json |
| v2_operator_streq_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_operator_streq_block/result.json |
| v2_transformation_html_entity_decode_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_transformation_html_entity_decode_block/result.json |
| v2_transformation_lowercase_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_transformation_lowercase_block/result.json |
| v2_transformation_remove_nulls_future_target | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_transformation_remove_nulls_future_target/result.json |
| v2_transformation_trim_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_transformation_trim_block/result.json |
| v2_transformation_trim_tab_future_compatibility | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_transformation_trim_tab_future_compatibility/result.json |
| v2_transformation_url_decode_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_transformation_url_decode_block/result.json |
| v2_transformation_url_decode_pass_no_match | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_transformation_url_decode_pass_no_match/result.json |
| v3_args_names_duplicate_query_connector_gap | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_args_names_duplicate_query_connector_gap/result.json |
| v3_args_names_get_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_args_names_get_block/result.json |
| v3_args_names_get_pass_no_match | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_args_names_get_pass_no_match/result.json |
| v3_auditlog_serial_fields_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_auditlog_serial_fields_block/result.json |
| v3_operator_pm_digit_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_operator_pm_digit_block/result.json |
| v3_operator_rx_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_operator_rx_block/result.json |
| v3_request_cookies_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_request_cookies_block/result.json |
| v3_request_cookies_names_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_request_cookies_names_block/result.json |
| v3_request_cookies_names_pass_no_match | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_request_cookies_names_pass_no_match/result.json |
| v3_request_cookies_pass_no_match | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_request_cookies_pass_no_match/result.json |
| v3_request_headers_names_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_request_headers_names_block/result.json |
| v3_request_headers_names_duplicate_connector_gap | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_request_headers_names_duplicate_connector_gap/result.json |
| v3_request_headers_names_pass_no_match | with-crs | 200 | 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_request_headers_names_pass_no_match/result.json |
| v3_secaction_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_secaction_block/result.json |
| v3_transformation_trim_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_transformation_trim_block/result.json |
| xml_request_body_block | with-crs | 403 | 403 | /src/ModSecurity-conector-build/logs/haproxy-runtime/xml_request_body_block/result.json |

### HAProxy FAIL Details
| Case | Variant | Expected | Actual | Assessment | Evidence |
|---|---|---:|---:|---|---|
| duplicate_args_encoded_separator_edge | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/duplicate_args_encoded_separator_edge/result.json |
| duplicate_header_case_normalization_gap | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/duplicate_header_case_normalization_gap/result.json |
| edge_semicolon_query_args_names | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/edge_semicolon_query_args_names/result.json |
| files_names_mixed_case_filename_gap | with-crs | 403 | 501 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/files_names_mixed_case_filename_gap/result.json |
| multipart_duplicate_field_names_gap | with-crs | 403 | 501 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/multipart_duplicate_field_names_gap/result.json |
| parser_xml_partial_body_future_target | with-crs | 403 | 501 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/parser_xml_partial_body_future_target/result.json |
| phase3_response_headers_multi_value_connector_gap | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase3_response_headers_multi_value_connector_gap/result.json |
| phase3_response_headers_set_cookie_multi_gap | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase3_response_headers_set_cookie_multi_gap/result.json |
| phase4_auditlog_outbound_multiline_section_gap | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_auditlog_outbound_multiline_section_gap/result.json |
| response_headers_multi_value_runtime_gap | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/response_headers_multi_value_runtime_gap/result.json |
| sqli_like_keyword_spacing_probe | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/sqli_like_keyword_spacing_probe/result.json |
| sqli_like_quote_encoding_runtime_difference | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/sqli_like_quote_encoding_runtime_difference/result.json |
| tfn_chain_lowercase_trim_pass_through | with-crs | 200 | 0 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/tfn_chain_lowercase_trim_pass_through/result.json |
| unicode_double_encoded_uri_runtime_difference | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/unicode_double_encoded_uri_runtime_difference/result.json |
| unicode_whitespace_normalization_gap | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/unicode_whitespace_normalization_gap/result.json |
| v3_action_nolog_pass_no_audit | with-crs | 200 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_action_nolog_pass_no_audit/result.json |
| v3_request_cookies_names_case_runtime_difference | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_request_cookies_names_case_runtime_difference/result.json |
| v3_request_headers_names_lowercase_runtime_difference | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_request_headers_names_lowercase_runtime_difference/result.json |
| xml_deep_nesting_future_target | with-crs | 403 | 501 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/xml_deep_nesting_future_target/result.json |
| xml_namespace_edge_connector_gap | with-crs | 403 | 501 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/xml_namespace_edge_connector_gap/result.json |
| xml_request_body_malformed_connector_gap | with-crs | 403 | 501 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/xml_request_body_malformed_connector_gap/result.json |
| xss_like_encoded_angles_normalization_probe | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/xss_like_encoded_angles_normalization_probe/result.json |
| xss_like_mixed_case_script_token_gap | with-crs | 403 | 200 | live HAProxy runtime result mismatch | /src/ModSecurity-conector-build/logs/haproxy-runtime/xss_like_mixed_case_script_token_gap/result.json |

### HAProxy Non-PASS Summary
| Status | Count | Note |
|---|---:|---|
| FAIL | 23 | Live-executed HAProxy runtime mismatches only; PASS/FAIL require live execution. |
| BLOCKED | 0 | Relevant HAProxy rows blocked by current harness or prerequisites. |
| NOT_EXECUTABLE | 6 | Rows outside the current HAProxy runtime surface. |
| MAPPED_ONLY | 0 | Import inventory only; not runtime-executable YAML evidence. |

- Detailed BLOCKED, NOT_EXECUTABLE, and MAPPED_ONLY rows are reported in `docs/testing/generated/haproxy-runtime-results.generated.md`.
- BLOCKED, NOT_EXECUTABLE, and MAPPED_ONLY rows are not runtime FAIL rows.

## Runtime Verified Status
- Runtime matrix records current local Apache, NGINX, and HAProxy per-case smoke evidence when available.
- PASS in this snapshot means the case was executed by that connector's smoke harness and matched the case expectation in the summary JSON.
- Pending, connector-gap, runtime-difference, future, and mapped-only inventory are not promoted by this snapshot.
- FORCE_ALL_CASES=1 attempts all materializable YAML cases where they are applicable to the connector.
- HAProxy PASS is scoped to live HAProxy evidence only; current HAProxy coverage is partial request-side YAML execution.
- RESPONSE_BODY remains non-verified/non-promoted.
- Runtime passed, but this does not verify RESPONSE_BODY support.
- make smoke-all was not run by runtime-matrix; full-smoke PASS counts remain unknown.

## Open Runtime Issues
- Mapped-only import inventory entries are not executable YAML runtime cases.
- Pending/future/connector-gap/runtime-difference topics require live evidence before any support claim.
- RESPONSE_BODY remains experimental/non-verified.

## Open Gaps
- See `docs/testing/generated/connector-gap-summary.generated.md` for detailed entries.

## Verified Runtime Coverage
- Runtime-verified means only cases explicitly classified as `runtime_verified=true`.

## Pending Runtime Verification
- Cases with `runtime_verified=false` or `runtime_verified=unknown` are not runtime PASS proof.

## Former XFAIL / Known Gap Coverage
- Former XFAIL cases are listed in the migration summary with their current YAML status.
- Pending and gap topics need local runtime validation before promotion.

## Connector Gap / Runtime Difference Coverage
- Connector-gap and runtime-difference classes are reported separately.

## Phase 3/4 Outbound Coverage
- Phase 3/4 cases are visible in `docs/testing/generated/phase-coverage.generated.md` and in the runtime matrix.

## RESPONSE_BODY Status
- RESPONSE_BODY remains not verified and not promoted.

## Cloud / Quick / Full Smoke Meaning
- Generated coverage is not runtime evidence by itself.
- Full runtime validation is local and evidence-based.
- GitHub/Codex checks are intentionally lightweight.
- Pending and gap topics need local runtime validation.
- `make smoke-all` is authoritative only if it was actually executed successfully.

## Generated Artifacts
- `docs/testing/generated/case-matrix.generated.md`
- `docs/testing/generated/coverage-summary.generated.md`
- `docs/testing/generated/xfail-summary.generated.md`
- `docs/testing/generated/connector-gap-summary.generated.md`
- `docs/testing/generated/phase-coverage.generated.md`

## Note
- Generated summaries do not replace full-smoke runtime evidence.
- No RESPONSE_BODY promotion is made without stable runtime evidence.
