Generated file — do not edit manually.

# ModSecurity Connector Test Coverage Summary

## Summary Status
- Total YAML cases: **141**
- Verified/pass (`runtime_verified=true`): **0**
- XFAIL cases: **80**
- Pending runtime verification (`runtime_verified=false`): **91**
- Pending runtime verification (`runtime_verified=unknown`): **50**
- Connector-gap cases: **11**
- Runtime-difference cases: **13**
- Future/experimental cases: **17**
- RESPONSE_BODY cases: **24**
- Default runtime-executable YAML cases: **61**
- Force-all runtime-executable YAML cases: **141**
- Apache attempted YAML cases in default runtime snapshot: **133**
- NGINX attempted YAML cases in default runtime snapshot: **140**
- HAProxy attempted YAML cases in default runtime snapshot: **55**
- HAProxy attempted YAML cases in force-all runtime snapshot: **133**
- HAProxy force-all raw runtime PASS/FAIL/BLOCKED/NOT_EXECUTABLE: **104** / **23** / **0** / **6**
- Mapped-only import inventory entries: **10**

## Important Reporting Semantics
- PASS/FAIL are rendered only from live runtime evidence recorded in connector summaries and decision/result artifacts.
- BLOCKED remains reserved for harness, environment, dependency, build, or runtime blockers.
- NOT_EXECUTABLE means the case is structurally unmappable for that connector/run mode; it is not a blocker and not a pass.
- Force-all evidence does not promote YAML feature support.
- RESPONSE_BODY remains experimental/non-promoted, including bounded phase-4 pass-through evidence.

## Framework Integration
- This framework-owned file is the source of truth for root coverage reporting: `TEST-COVERAGE-SUMMARY.md` in `ModSecurity-test-Framework`.
- Connector repositories should link to this Framework summary instead of maintaining their own root coverage summary.
- Shared YAML cases, runners, normalizers, generators, and detailed testing documentation are owned by `ModSecurity-test-Framework`.
- The connector repository owns connector source, harnesses, adapter metadata, `config/testing/import-status.json`, and connector-specific generated evidence under `reports/testing/`.
- `FRAMEWORK_ROOT` and `CONNECTOR_ROOT` are explicit integration paths; there is no absolute workspace fallback.

## Case Inventory
- Common YAML cases: **134**
- Apache-specific YAML cases: **0**
- NGINX-specific YAML cases: **7**
- XFAIL cases: **80**
- Mapped-only import inventory entries: **10** (not counted as runnable YAML cases)
- Runtime-blocked import inventory entries: **0** (environment/harness blockers, not PASS or XFAIL promotions)
- Pending/future compatibility cases: **17** future/experimental; **141** not runtime-verified

## Status Classes
| Status | Count |
|---|---:|
| active | 8 |
| imported | 53 |
| xfail | 80 |

## Scope
| Scope | Count |
|---|---:|
| common | 134 |
| apache | 0 |
| nginx | 7 |
| unknown | 0 |

## Coverage By Variable / Collection
| Variable / Collection | Count |
|---|---:|
| `ARGS` | 49 |
| `ARGS_NAMES` | 7 |
| `REQUEST_HEADERS` | 5 |
| `REQUEST_HEADERS_NAMES` | 5 |
| `REQUEST_COOKIES` | 2 |
| `REQUEST_COOKIES_NAMES` | 4 |
| `REQUEST_URI` | 7 |
| `REQUEST_BODY` | 10 |
| `FILES` | 2 |
| `FILES_NAMES` | 2 |
| `XML` | 5 |
| `RESPONSE_HEADERS` | 11 |
| `RESPONSE_BODY` | 20 |
| `AUDIT_LOG` | 0 |

## Coverage By Phase
| Phase | Count |
|---|---:|
| Phase 1 | 36 |
| Phase 2 | 74 |
| Phase 3 | 12 |
| Phase 4 | 20 |

## Coverage By Topic
| Topic | Count |
|---|---:|
| Operators | 135 |
| Transformations | 31 |
| Multipart / FILES | 11 |
| JSON | 7 |
| XML | 5 |
| Unicode / Encoding | 17 |
| XSS-like compatibility probes | 2 |
| SQLi-like compatibility probes | 2 |
| Audit-log probes | 24 |
| Response header probes | 11 |
| Response body experimental probes | 2 |

## Default Runtime Matrix Status
| Status | Apache | NGINX | HAProxy |
|---|---:|---:|---:|
| PASS | 53 | 56 | 54 |
| RESPONSE_BODY_PASS_THROUGH | 1 | 4 | 1 |
| XFAIL_PASS | 16 | 16 | 0 |
| XFAIL_FAIL | 20 | 21 | 0 |
| PENDING_FAIL | 1 | 1 | 0 |
| FUTURE_PASS | 6 | 6 | 0 |
| FUTURE_RESPONSE_BODY_PASS_THROUGH | 1 | 1 | 0 |
| FUTURE_FAIL | 10 | 10 | 0 |
| CONNECTOR_GAP_PASS | 4 | 5 | 0 |
| CONNECTOR_GAP_FAIL | 7 | 6 | 0 |
| RUNTIME_DIFFERENCE_PASS | 6 | 6 | 0 |
| RUNTIME_DIFFERENCE_FAIL | 8 | 8 | 0 |
| NOT_EXECUTABLE | 8 | 1 | 86 |
| MAPPED_ONLY | 10 | 10 | 10 |

- Apache attempted YAML cases from default summary: **133**
- NGINX attempted YAML cases from default summary: **140**
- HAProxy attempted YAML cases from default summary: **55**
- Apache raw runtime XFAIL observations from default summary: **0**
- NGINX raw runtime XFAIL observations from default summary: **0**
- HAProxy raw runtime XFAIL observations from default summary: **0**
- Apache NOT EXECUTED YAML rows: **0**
- NGINX NOT EXECUTED YAML rows: **0**
- HAProxy NOT EXECUTED YAML rows: **0**
- Apache NOT_EXECUTABLE YAML rows: **8**
- NGINX NOT_EXECUTABLE YAML rows: **1**
- HAProxy NOT_EXECUTABLE YAML rows: **86**
- Mapped-only import inventory entries: **10**
- Runtime matrix detail: `reports/testing/generated/runtime-matrix.generated.md`
- Apache per-case results: `reports/testing/generated/apache-runtime-results.generated.md`
- NGINX per-case results: `reports/testing/generated/nginx-runtime-results.generated.md`
- HAProxy per-case results: `reports/testing/generated/haproxy-runtime-results.generated.md`
- PASS/BLOCKED/FAIL counts here come only from tracked runtime snapshot evidence; XFAIL and pending cases are not promoted.
- RESPONSE_BODY remains non-verified even when a pass-through runtime case returns HTTP 200.

## Force-All Runtime Matrix Status
| Connector | Status | Attempted | PASS | FAIL | BLOCKED | NOT_EXECUTABLE | Evidence |
|---|---|---:|---:|---:|---:|---:|---|
| Apache | NOT_AVAILABLE | 0 | unknown | unknown | unknown | unknown | /src/ModSecurity-conector-build/results/force-all/apache-summary.json |
| NGINX | NOT_AVAILABLE | 0 | unknown | unknown | unknown | unknown | /src/ModSecurity-conector-build/results/force-all/nginx-summary.json |
| HAProxy | FAIL | 133 | 104 | 23 | 0 | 6 | /src/ModSecurity-conector-build/results/force-all/haproxy-summary.json |

- HAProxy force-all attempted YAML cases: **133**
- HAProxy force-all result JSONL: `/src/ModSecurity-conector-build/results/force-all/haproxy-results.jsonl`
- HAProxy force-all per-case evidence root: `/src/ModSecurity-conector-build/logs/haproxy-runtime`
- Apache and NGINX force-all render `NOT_AVAILABLE` when no force-all summaries are present.
- Force-all evidence is traceable runtime evidence but does not promote xfail/pending/future/gap feature support.

## HAProxy Default Runtime Details
- Runtime mode: `default`
- Command: `make smoke-haproxy`
- Status: **PASS**
- Exit code: `0`
- Attempted YAML cases: **55**
- Total cases in summary: **55**
- Evidence root: `/src/ModSecurity-conector-build/results/with-crs`
- JSONL evidence: `/src/ModSecurity-conector-build/results/with-crs/haproxy-results.jsonl`
- Per-case result root: `/src/ModSecurity-conector-build/logs/haproxy-runtime`

| Status | Count |
|---|---:|
| PASS | 55 |
| FAIL | 0 |
| BLOCKED | 0 |
| NOT_EXECUTABLE | 0 |
| SKIPPED | 0 |
| XFAIL | 0 |

## HAProxy Force-All Runtime Details
- Runtime mode: `force-all`
- Command: `FORCE_ALL_CASES=1 make smoke-haproxy`
- Status: **FAIL**
- Exit code: `2`
- Attempted YAML cases: **133**
- Total cases in summary: **133**
- Evidence root: `/src/ModSecurity-conector-build/results/force-all`
- JSONL evidence: `/src/ModSecurity-conector-build/results/force-all/haproxy-results.jsonl`
- Per-case result root: `/src/ModSecurity-conector-build/logs/haproxy-runtime`

| Status | Count |
|---|---:|
| PASS | 104 |
| FAIL | 23 |
| BLOCKED | 0 |
| NOT_EXECUTABLE | 6 |
| SKIPPED | 0 |
| XFAIL | 0 |

- Force-all exited nonzero because live-executed rows mismatched expected runtime outcomes.

### HAProxy Force-All FAIL Rows
| Case | Expected | Observed | Reason | Evidence | Decision Log |
|---|---:|---:|---|---|---|
| duplicate_args_encoded_separator_edge | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/duplicate_args_encoded_separator_edge/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/duplicate_args_encoded_separator_edge/decision.jsonl |
| duplicate_header_case_normalization_gap | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/duplicate_header_case_normalization_gap/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/duplicate_header_case_normalization_gap/decision.jsonl |
| edge_semicolon_query_args_names | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/edge_semicolon_query_args_names/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/edge_semicolon_query_args_names/decision.jsonl |
| files_names_mixed_case_filename_gap | 403 | 501 | expected HTTP 403; observed HTTP 501 | /src/ModSecurity-conector-build/logs/haproxy-runtime/files_names_mixed_case_filename_gap/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/files_names_mixed_case_filename_gap/decision.jsonl |
| multipart_duplicate_field_names_gap | 403 | 501 | expected HTTP 403; observed HTTP 501 | /src/ModSecurity-conector-build/logs/haproxy-runtime/multipart_duplicate_field_names_gap/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/multipart_duplicate_field_names_gap/decision.jsonl |
| parser_xml_partial_body_future_target | 403 | 501 | expected HTTP 403; observed HTTP 501 | /src/ModSecurity-conector-build/logs/haproxy-runtime/parser_xml_partial_body_future_target/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/parser_xml_partial_body_future_target/decision.jsonl |
| phase1_vs_phase2_request_body_gap | 403 | 501 | expected HTTP 403; observed HTTP 501 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase1_vs_phase2_request_body_gap/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase1_vs_phase2_request_body_gap/decision.jsonl |
| phase3_response_headers_multi_value_connector_gap | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase3_response_headers_multi_value_connector_gap/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase3_response_headers_multi_value_connector_gap/decision.jsonl |
| phase3_response_headers_set_cookie_multi_gap | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase3_response_headers_set_cookie_multi_gap/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase3_response_headers_set_cookie_multi_gap/decision.jsonl |
| phase4_auditlog_outbound_multiline_section_gap | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_auditlog_outbound_multiline_section_gap/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_auditlog_outbound_multiline_section_gap/decision.jsonl |
| response_headers_multi_value_runtime_gap | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/response_headers_multi_value_runtime_gap/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/response_headers_multi_value_runtime_gap/decision.jsonl |
| sqli_like_keyword_spacing_probe | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/sqli_like_keyword_spacing_probe/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/sqli_like_keyword_spacing_probe/decision.jsonl |
| sqli_like_quote_encoding_runtime_difference | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/sqli_like_quote_encoding_runtime_difference/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/sqli_like_quote_encoding_runtime_difference/decision.jsonl |
| tfn_chain_lowercase_trim_pass_through | 200 | 0 | expected HTTP 200; observed HTTP 0 | /src/ModSecurity-conector-build/logs/haproxy-runtime/tfn_chain_lowercase_trim_pass_through/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/tfn_chain_lowercase_trim_pass_through/decision.jsonl |
| unicode_double_encoded_uri_runtime_difference | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/unicode_double_encoded_uri_runtime_difference/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/unicode_double_encoded_uri_runtime_difference/decision.jsonl |
| unicode_whitespace_normalization_gap | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/unicode_whitespace_normalization_gap/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/unicode_whitespace_normalization_gap/decision.jsonl |
| v3_request_cookies_names_case_runtime_difference | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_request_cookies_names_case_runtime_difference/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_request_cookies_names_case_runtime_difference/decision.jsonl |
| v3_request_headers_names_lowercase_runtime_difference | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_request_headers_names_lowercase_runtime_difference/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/v3_request_headers_names_lowercase_runtime_difference/decision.jsonl |
| xml_deep_nesting_future_target | 403 | 501 | expected HTTP 403; observed HTTP 501 | /src/ModSecurity-conector-build/logs/haproxy-runtime/xml_deep_nesting_future_target/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/xml_deep_nesting_future_target/decision.jsonl |
| xml_namespace_edge_connector_gap | 403 | 501 | expected HTTP 403; observed HTTP 501 | /src/ModSecurity-conector-build/logs/haproxy-runtime/xml_namespace_edge_connector_gap/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/xml_namespace_edge_connector_gap/decision.jsonl |
| xml_request_body_malformed_connector_gap | 403 | 501 | expected HTTP 403; observed HTTP 501 | /src/ModSecurity-conector-build/logs/haproxy-runtime/xml_request_body_malformed_connector_gap/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/xml_request_body_malformed_connector_gap/decision.jsonl |
| xss_like_encoded_angles_normalization_probe | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/xss_like_encoded_angles_normalization_probe/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/xss_like_encoded_angles_normalization_probe/decision.jsonl |
| xss_like_mixed_case_script_token_gap | 403 | 200 | expected HTTP 403; observed HTTP 200 | /src/ModSecurity-conector-build/logs/haproxy-runtime/xss_like_mixed_case_script_token_gap/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/xss_like_mixed_case_script_token_gap/decision.jsonl |

### HAProxy Force-All NOT_EXECUTABLE Rows
| Case | Reason | Evidence | Decision Log |
|---|---|---|---|
| files_empty_part_future_compatibility | structurally not executable for this connector/runtime mode; see evidence_path and decision_log_path | /src/ModSecurity-conector-build/logs/haproxy-runtime/files_empty_part_future_compatibility/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/files_empty_part_future_compatibility/decision.jsonl |
| json_empty_body_future_compatibility | structurally not executable for this connector/runtime mode; see evidence_path and decision_log_path | /src/ModSecurity-conector-build/logs/haproxy-runtime/json_empty_body_future_compatibility/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/json_empty_body_future_compatibility/decision.jsonl |
| multipart_empty_filename_connector_gap | structurally not executable for this connector/runtime mode; see evidence_path and decision_log_path | /src/ModSecurity-conector-build/logs/haproxy-runtime/multipart_empty_filename_connector_gap/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/multipart_empty_filename_connector_gap/decision.jsonl |
| phase3_response_headers_server_presence_pending | structurally not executable for this connector/runtime mode; see evidence_path and decision_log_path | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase3_response_headers_server_presence_pending/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase3_response_headers_server_presence_pending/decision.jsonl |
| phase4_response_body_empty_future_target | structurally not executable for this connector/runtime mode; see evidence_path and decision_log_path | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_response_body_empty_future_target/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/phase4_response_body_empty_future_target/decision.jsonl |
| v2_transformation_url_decode_invalid_sequence_mapped_candidate | structurally not executable for this connector/runtime mode; see evidence_path and decision_log_path | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_transformation_url_decode_invalid_sequence_mapped_candidate/result.json | /src/ModSecurity-conector-build/logs/haproxy-runtime/v2_transformation_url_decode_invalid_sequence_mapped_candidate/decision.jsonl |

### HAProxy Force-All BLOCKED Rows
| Status | Count | Note |
|---|---:|---|
| BLOCKED | 0 | No rows were reported. |

## HAProxy Production SPOA Status
- HAProxy runtime evidence is produced by the production `haproxy-modsecurity-spoa` binary/code path used by the harness.
- The deprecated synthetic HAProxy matrix writer remains excluded from PASS generation.

## RESPONSE_BODY / Phase 4 Status
- RESPONSE_BODY remains non-promoted. Bounded phase-4 strict-abort rows are rendered as experimental runtime evidence only.

## Runtime Smoke Status

## Default Runtime Smoke Evidence
| Connector | Command | Status | Exit | Attempted | PASS | FAIL | BLOCKED | NOT_EXECUTABLE | Evidence |
|---|---|---|---|---|---|---|---|---|---|
| apache | FORCE_ALL_CASES=1 REFRESH=1 make smoke-apache | FAIL | 2 | 133 | 87 | 46 | 0 | unknown | /src/ModSecurity-conector-build/results/apache-summary.json |
| nginx | FORCE_ALL_CASES=1 REFRESH=1 make smoke-nginx | FAIL | 2 | 140 | 94 | 46 | 0 | unknown | /src/ModSecurity-conector-build/results/nginx-summary.json |
| haproxy | make smoke-haproxy | PASS | 0 | 55 | 55 | 0 | 0 | 0 | /src/ModSecurity-conector-build/results/haproxy-summary.json |
| all | REFRESH=1 make smoke-all | NOT_RUN | not_run | 0 | unknown | unknown | unknown | unknown | not available |

## Force-All Runtime Smoke Evidence
| Connector | Command | Status | Exit | Attempted | PASS | FAIL | BLOCKED | NOT_EXECUTABLE | Evidence |
|---|---|---|---|---|---|---|---|---|---|
| apache | FORCE_ALL_CASES=1 REFRESH=1 make smoke-apache | NOT_AVAILABLE | not_run | 0 | unknown | unknown | unknown | unknown | /src/ModSecurity-conector-build/results/force-all/apache-summary.json |
| nginx | FORCE_ALL_CASES=1 REFRESH=1 make smoke-nginx | NOT_AVAILABLE | not_run | 0 | unknown | unknown | unknown | unknown | /src/ModSecurity-conector-build/results/force-all/nginx-summary.json |
| haproxy | FORCE_ALL_CASES=1 make smoke-haproxy | FAIL | 2 | 133 | 104 | 23 | 0 | 6 | /src/ModSecurity-conector-build/results/force-all/haproxy-summary.json |

## Validation Snapshot
- Snapshot: **2026-06-06** (2026-06-06 22:19:59 CEST)
- Git: branch `integrate-new-connectors-local`, commit `1a09900`
- BUILD_ROOT: `/src/ModSecurity-conector-build`
- Snapshot file: `reports/testing/runtime-validation-snapshot.json`

## New Connector Runtime-Smoke Evidence

This generated section reads local connector smoke/matrix summaries from `$BUILD_ROOT/results` when present, then falls back to tracked snapshot evidence or BLOCKED/not-verified status. It is reporting only and does not invent PASS values.

| Connector | Status | Runtime status | Runtime verified | CRS verified | RESPONSE_BODY verified | Verified cases | CRS/split detail | Evidence |
|---|---|---|---:|---:|---:|---|---|---|
| envoy | BLOCKED | blocked | no | no | no | `-` | - | `/src/ModSecurity-conector-build/results/envoy-summary.json` |
| haproxy | PARTIAL | live-yaml-runtime | yes | yes | no | `action_allow_phase1_pass, action_deny_phase1, action_deny_phase2, action_status_401_phase1_block, audit_log_phase1_block, collection_args_combined_size_block, collection_args_get_block, collection_args_names_block, crs_sqli_anomaly_block, json_request_body_block, multipart_basic_block, multipart_filename_block, multipart_files_combined_size, multipart_files_names_block, multipart_files_value_block, phase1_header_block, phase2_args_block, phase2_args_pass, pr70_phase1_audit_request_header, pr70_phase2_audit_urlencoded_body, pr70_phase3_audit_response_header, request_body_args_post_names_block, request_body_json_block, request_body_raw_text_block, request_body_urlencoded_block, response_body_pass, response_header_basic, rule_chain_both_match_block, rule_chain_first_only_pass, rule_chain_second_only_pass, v2_operator_begins_with_block, v2_operator_contains_block, v2_operator_contains_word_block, v2_operator_ends_with_block, v2_operator_pm_block, v2_operator_streq_block, v2_transformation_html_entity_decode_block, v2_transformation_lowercase_block, v2_transformation_trim_block, v2_transformation_url_decode_block, v2_transformation_url_decode_pass_no_match, v3_args_names_get_block, v3_args_names_get_pass_no_match, v3_auditlog_serial_fields_block, v3_operator_pm_digit_block, v3_operator_rx_block, v3_request_cookies_block, v3_request_cookies_names_block, v3_request_cookies_names_pass_no_match, v3_request_cookies_pass_no_match, v3_request_headers_names_block, v3_request_headers_names_pass_no_match, v3_secaction_block, v3_transformation_trim_block, xml_request_body_block` | - | `/src/ModSecurity-conector-build/results/haproxy-summary.json` |
| lighttpd | BLOCKED | blocked | no | no | no | `-` | - | `/src/ModSecurity-conector-build/results/lighttpd-summary.json` |
| traefik | BLOCKED | blocked | no | no | no | `-` | - | `/src/ModSecurity-conector-build/results/traefik-summary.json` |

- HAProxy CRS verification is derived from live with-CRS YAML rows in the latest HAProxy summary.
- Envoy, lighttpd, and Traefik remain not runtime-verified unless their own summary files report runtime PASS evidence.
- RESPONSE_BODY remains not verified for these new connector smoke summaries.

## Open Runtime Issues / Remaining Gaps
- Runtime verification pending: cases with `runtime_verified=false` or `runtime_verified=unknown` are not runtime PASS proof.
- RESPONSE_BODY remains non-verified and non-promoted.
- GitHub/Codex checks are intentionally lightweight and do not prove runtime compatibility.
- XFAIL, pending, future, connector-gap, and runtime-difference cases require local runtime evidence before any status change.
- Runtime-blocked import entries are environment or harness blockers and do not imply connector-gap/runtime-difference promotion.
- `installed-readiness` is diagnostic detection, not runtime execution.
- There is no separate artifact-reuse smoke path; runtime validation uses source-build execution.
- `make smoke-all` is authoritative only when it is actually executed successfully.

## Commands
- `make quick-check`
- `make quick-all`
- `make cloud-quick-check`
- `make installed-readiness`
- `make runtime-matrix`
- `make runtime-matrix-all`
- `make runtime-matrix-haproxy`
- `make smoke-apache`
- `make smoke-nginx`
- `make smoke-haproxy`
- `make smoke-all`
- `make generate-test-matrix`
- `make check-test-matrix`

## Detail Reports
- `reports/testing/test-coverage-overview.md`
- `reports/testing/generated/case-matrix.generated.md`
- `reports/testing/generated/coverage-summary.generated.md`
- `reports/testing/generated/xfail-summary.generated.md`
- `reports/testing/generated/connector-gap-summary.generated.md`
- `reports/testing/generated/phase-coverage.generated.md`
- `reports/testing/generated/runtime-matrix.generated.md`
- `reports/testing/generated/apache-runtime-results.generated.md`
- `reports/testing/generated/nginx-runtime-results.generated.md`
- `reports/testing/generated/haproxy-runtime-results.generated.md`
- `reports/testing/runtime-validation-snapshot.json`

## Important Note
Generated coverage is reporting only; it is not runtime evidence by itself.
Full runtime validation is local and evidence-based.
GitHub/Codex checks are intentionally lightweight.
XFAIL, pending, future, and gap cases need local runtime validation before promotion.
`make smoke-all` is authoritative only if it was actually executed successfully.
No PASS numbers are inferred from this file when `make smoke-all` was not run successfully.
No RESPONSE_BODY promotion is made without stable full-smoke runtime evidence.
