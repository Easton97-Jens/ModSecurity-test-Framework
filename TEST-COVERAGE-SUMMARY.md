Generated file — do not edit manually.

# ModSecurity Connector Test Coverage Summary

## Summary Status
- Total YAML cases: **140**
- Verified/pass (`runtime_verified=true`): **0**
- XFAIL cases: **80**
- Pending runtime verification (`runtime_verified=false`): **90**
- Pending runtime verification (`runtime_verified=unknown`): **50**
- Connector-gap cases: **11**
- Runtime-difference cases: **13**
- Future/experimental cases: **17**
- RESPONSE_BODY cases: **24**
- Default runtime-executable YAML cases: **60**
- Force-all runtime-executable YAML cases: **140**
- Apache attempted YAML cases in latest runtime snapshot: **133**
- NGINX attempted YAML cases in latest runtime snapshot: **140**
- Mapped-only import inventory entries: **10**

**RESPONSE_BODY is not verified or promoted.** This file is generated reporting, not runtime proof.

## Framework Integration
- Shared YAML cases, runners, normalizers, generators, and detailed testing documentation are owned by `ModSecurity-test-Framework`.
- The connector repository owns connector source, harnesses, adapter metadata, `config/testing/import-status.json`, and connector-specific generated evidence under `reports/testing/`.
- `FRAMEWORK_ROOT` and `CONNECTOR_ROOT` are explicit integration paths; there is no absolute workspace fallback.

## Case Types
- Common YAML cases: **133**
- Apache-specific YAML cases: **0**
- NGINX-specific YAML cases: **7**
- XFAIL cases: **80**
- Mapped-only import inventory entries: **10** (not counted as runnable YAML cases)
- Runtime-blocked import inventory entries: **0** (environment/harness blockers, not PASS or XFAIL promotions)
- Pending/future compatibility cases: **17** future/experimental; **140** not runtime-verified

## Status Classes
| Status | Count |
|---|---:|
| active | 7 |
| imported | 53 |
| xfail | 80 |

## Scope
| Scope | Count |
|---|---:|
| common | 133 |
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
| Phase 2 | 73 |
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

## Runtime Matrix Status
| Status | Apache | NGINX |
|---|---:|---:|
| PASS | 53 | 56 |
| RESPONSE_BODY_PASS_THROUGH | 1 | 4 |
| XFAIL_PASS | 16 | 16 |
| XFAIL_FAIL | 20 | 21 |
| PENDING_FAIL | 1 | 1 |
| FUTURE_PASS | 6 | 6 |
| FUTURE_RESPONSE_BODY_PASS_THROUGH | 1 | 1 |
| FUTURE_FAIL | 10 | 10 |
| CONNECTOR_GAP_PASS | 4 | 5 |
| CONNECTOR_GAP_FAIL | 7 | 6 |
| RUNTIME_DIFFERENCE_PASS | 6 | 6 |
| RUNTIME_DIFFERENCE_FAIL | 8 | 8 |
| NOT_EXECUTABLE | 7 | 0 |
| MAPPED_ONLY | 10 | 10 |

- Apache attempted YAML cases from latest summary: **133**
- NGINX attempted YAML cases from latest summary: **140**
- Apache raw runtime XFAIL observations from latest summary: **0**
- NGINX raw runtime XFAIL observations from latest summary: **0**
- Apache NOT EXECUTED YAML rows: **0**
- NGINX NOT EXECUTED YAML rows: **0**
- Apache NOT_EXECUTABLE YAML rows: **7**
- NGINX NOT_EXECUTABLE YAML rows: **0**
- Mapped-only import inventory entries: **10**
- Runtime matrix detail: `docs/testing/generated/runtime-matrix.generated.md`
- Apache per-case results: `docs/testing/generated/apache-runtime-results.generated.md`
- NGINX per-case results: `docs/testing/generated/nginx-runtime-results.generated.md`
- PASS/BLOCKED/FAIL counts here come only from tracked runtime snapshot evidence; XFAIL and pending cases are not promoted.
- RESPONSE_BODY remains non-verified even when a pass-through runtime case returns HTTP 200.

## Latest Local Runtime Validation Snapshot
- Snapshot: **2026-05-24** (2026-05-24 00:48:12 CEST)
- Git: branch `master`, commit `3b7b958`
- BUILD_ROOT: `/root/.local/state/ModSecurity-conector-build`
- This is a manual local runtime snapshot rendered from tracked snapshot data and local smoke summary files.
- Runtime matrix snapshot generated from local Apache and NGINX smoke summary JSON files.
- Per-case PASS/FAIL/BLOCKED/XFAIL values are runtime evidence for this local run only.
- No xfail/pending YAML case is promoted by this snapshot.
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

## Runtime Smoke Status
| Command | Status | Exit | PASS | FAIL | BLOCKED | XFAIL | Evidence |
|---|---|---|---|---|---|---|---|
| FORCE_ALL_CASES=1 REFRESH=1 make smoke-apache | FAIL | 2 | 87 | 46 | 0 | 0 | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json |
| FORCE_ALL_CASES=1 REFRESH=1 make smoke-nginx | FAIL | 2 | 94 | 46 | 0 | 0 | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json |
| REFRESH=1 make smoke-all | NOT_RUN | not_run | unknown | unknown | unknown | unknown | not available |

## Connector Runtime Availability
| Connector | Status | Build | Per-case results | Attempted cases | Summary evidence | Note |
|---|---|---|---|---:|---|---|
| Apache | FAIL | unknown | available | 133 | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json | Per-case results are copied from the local smoke summary JSON; they are runtime evidence only and do not promote YAML xfail/pending status. |
| NGINX | FAIL | unknown | available | 140 | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json | Per-case results are copied from the local smoke summary JSON; they are runtime evidence only and do not promote YAML xfail/pending status. |

## Runtime FAIL Details

### Apache FAIL Details
| Case | Expected | Actual | Assessment | Evidence |
|---|---|---|---|---|
| duplicate_args_encoded_separator_edge | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=duplicate_args_encoded_separator_edge; status=fail; expected=403; actual=200 |
| duplicate_header_case_normalization_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=duplicate_header_case_normalization_gap; status=fail; expected=403; actual=200 |
| edge_semicolon_query_args_names | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=edge_semicolon_query_args_names; status=fail; expected=403; actual=200 |
| files_empty_part_future_compatibility | 403 | - | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=files_empty_part_future_compatibility; status=fail; expected=403; actual=None |
| files_names_mixed_case_filename_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=files_names_mixed_case_filename_gap; status=fail; expected=403; actual=200 |
| json_empty_body_future_compatibility | 403 | - | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=json_empty_body_future_compatibility; status=fail; expected=403; actual=None |
| multipart_duplicate_field_names_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=multipart_duplicate_field_names_gap; status=fail; expected=403; actual=200 |
| multipart_empty_filename_connector_gap | 403 | - | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=multipart_empty_filename_connector_gap; status=fail; expected=403; actual=None |
| parser_xml_partial_body_future_target | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=parser_xml_partial_body_future_target; status=fail; expected=403; actual=200 |
| phase1_vs_phase2_request_body_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase1_vs_phase2_request_body_gap; status=fail; expected=403; actual=200 |
| phase3_response_headers_content_type_charset_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase3_response_headers_content_type_charset_gap; status=fail; expected=403; actual=200 |
| phase3_response_headers_duplicate_value_runtime_difference | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase3_response_headers_duplicate_value_runtime_difference; status=fail; expected=403; actual=200 |
| phase3_response_headers_encoded_value_future_target | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase3_response_headers_encoded_value_future_target; status=fail; expected=403; actual=200 |
| phase3_response_headers_location_encoded_runtime_diff | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase3_response_headers_location_encoded_runtime_diff; status=fail; expected=403; actual=200 |
| phase3_response_headers_mixed_case_connector_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase3_response_headers_mixed_case_connector_gap; status=fail; expected=403; actual=200 |
| phase3_response_headers_multi_value_connector_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase3_response_headers_multi_value_connector_gap; status=fail; expected=403; actual=200 |
| phase3_response_headers_server_presence_pending | 200 | - | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase3_response_headers_server_presence_pending; status=fail; expected=200; actual=None |
| phase3_response_headers_set_cookie_multi_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase3_response_headers_set_cookie_multi_gap; status=fail; expected=403; actual=200 |
| phase4_auditlog_outbound_escaped_value_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase4_auditlog_outbound_escaped_value_gap; status=fail; expected=403; actual=200 |
| phase4_auditlog_outbound_matched_var_future | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase4_auditlog_outbound_matched_var_future; status=fail; expected=403; actual=200 |
| phase4_auditlog_outbound_message_connector_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase4_auditlog_outbound_message_connector_gap; status=fail; expected=403; actual=200 |
| phase4_auditlog_outbound_multiline_section_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase4_auditlog_outbound_multiline_section_gap; status=fail; expected=403; actual=200 |
| phase4_auditlog_outbound_rule_id_runtime_difference | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase4_auditlog_outbound_rule_id_runtime_difference; status=fail; expected=403; actual=200 |
| phase4_response_body_buffering_order_future_target | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase4_response_body_buffering_order_future_target; status=fail; expected=403; actual=200 |
| phase4_response_body_chunk_assumption_connector_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase4_response_body_chunk_assumption_connector_gap; status=fail; expected=403; actual=200 |
| phase4_response_body_compressed_assumption_experimental | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase4_response_body_compressed_assumption_experimental; status=fail; expected=403; actual=200 |
| phase4_response_body_empty_future_target | 403 | - | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase4_response_body_empty_future_target; status=fail; expected=403; actual=None |
| phase4_response_body_html_entity_decode_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase4_response_body_html_entity_decode_gap; status=fail; expected=403; actual=200 |
| phase4_response_body_html_text_normalization_probe | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase4_response_body_html_text_normalization_probe; status=fail; expected=403; actual=200 |
| phase4_response_body_unicode_runtime_difference | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=phase4_response_body_unicode_runtime_difference; status=fail; expected=403; actual=200 |
| pr70_phase4_response_body_audit_xfail | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=pr70_phase4_response_body_audit_xfail; status=fail; expected=403; actual=200 |
| response_body_basic_block | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=response_body_basic_block; status=fail; expected=403; actual=200 |
| response_headers_multi_value_runtime_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=response_headers_multi_value_runtime_gap; status=fail; expected=403; actual=200 |
| sqli_like_keyword_spacing_probe | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=sqli_like_keyword_spacing_probe; status=fail; expected=403; actual=200 |
| sqli_like_quote_encoding_runtime_difference | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=sqli_like_quote_encoding_runtime_difference; status=fail; expected=403; actual=200 |
| tfn_chain_lowercase_trim_pass_through | 200 | 0 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=tfn_chain_lowercase_trim_pass_through; status=fail; expected=200; actual=0 |
| unicode_double_encoded_uri_runtime_difference | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=unicode_double_encoded_uri_runtime_difference; status=fail; expected=403; actual=200 |
| unicode_whitespace_normalization_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=unicode_whitespace_normalization_gap; status=fail; expected=403; actual=200 |
| v2_transformation_url_decode_invalid_sequence_mapped_candidate | 403 | - | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=v2_transformation_url_decode_invalid_sequence_mapped_candidate; status=fail; expected=403; actual=None |
| v3_request_cookies_names_case_runtime_difference | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=v3_request_cookies_names_case_runtime_difference; status=fail; expected=403; actual=200 |
| v3_request_headers_names_lowercase_runtime_difference | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=v3_request_headers_names_lowercase_runtime_difference; status=fail; expected=403; actual=200 |
| xml_deep_nesting_future_target | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=xml_deep_nesting_future_target; status=fail; expected=403; actual=200 |
| xml_namespace_edge_connector_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=xml_namespace_edge_connector_gap; status=fail; expected=403; actual=200 |
| xml_request_body_malformed_connector_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=xml_request_body_malformed_connector_gap; status=fail; expected=403; actual=200 |
| xss_like_encoded_angles_normalization_probe | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=xss_like_encoded_angles_normalization_probe; status=fail; expected=403; actual=200 |
| xss_like_mixed_case_script_token_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json; case=xss_like_mixed_case_script_token_gap; status=fail; expected=403; actual=200 |

### NGINX FAIL Details
| Case | Expected | Actual | Assessment | Evidence |
|---|---|---|---|---|
| duplicate_args_encoded_separator_edge | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=duplicate_args_encoded_separator_edge; status=fail; expected=403; actual=200 |
| duplicate_header_case_normalization_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=duplicate_header_case_normalization_gap; status=fail; expected=403; actual=200 |
| edge_semicolon_query_args_names | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=edge_semicolon_query_args_names; status=fail; expected=403; actual=200 |
| files_empty_part_future_compatibility | 403 | - | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=files_empty_part_future_compatibility; status=fail; expected=403; actual=None |
| files_names_mixed_case_filename_gap | 403 | 405 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=files_names_mixed_case_filename_gap; status=fail; expected=403; actual=405 |
| json_empty_body_future_compatibility | 403 | - | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=json_empty_body_future_compatibility; status=fail; expected=403; actual=None |
| multipart_duplicate_field_names_gap | 403 | 405 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=multipart_duplicate_field_names_gap; status=fail; expected=403; actual=405 |
| multipart_empty_filename_connector_gap | 403 | - | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=multipart_empty_filename_connector_gap; status=fail; expected=403; actual=None |
| nginx_phase4_strict_connection_abort | 403 | 0 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=nginx_phase4_strict_connection_abort; status=fail; expected=403; actual=0 |
| parser_xml_partial_body_future_target | 403 | 405 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=parser_xml_partial_body_future_target; status=fail; expected=403; actual=405 |
| phase1_vs_phase2_request_body_gap | 403 | 405 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase1_vs_phase2_request_body_gap; status=fail; expected=403; actual=405 |
| phase3_response_headers_content_type_charset_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase3_response_headers_content_type_charset_gap; status=fail; expected=403; actual=200 |
| phase3_response_headers_duplicate_value_runtime_difference | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase3_response_headers_duplicate_value_runtime_difference; status=fail; expected=403; actual=200 |
| phase3_response_headers_encoded_value_future_target | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase3_response_headers_encoded_value_future_target; status=fail; expected=403; actual=200 |
| phase3_response_headers_location_encoded_runtime_diff | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase3_response_headers_location_encoded_runtime_diff; status=fail; expected=403; actual=200 |
| phase3_response_headers_multi_value_connector_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase3_response_headers_multi_value_connector_gap; status=fail; expected=403; actual=200 |
| phase3_response_headers_server_presence_pending | 200 | - | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase3_response_headers_server_presence_pending; status=fail; expected=200; actual=None |
| phase3_response_headers_set_cookie_multi_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase3_response_headers_set_cookie_multi_gap; status=fail; expected=403; actual=200 |
| phase4_auditlog_outbound_escaped_value_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase4_auditlog_outbound_escaped_value_gap; status=fail; expected=403; actual=200 |
| phase4_auditlog_outbound_matched_var_future | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase4_auditlog_outbound_matched_var_future; status=fail; expected=403; actual=200 |
| phase4_auditlog_outbound_message_connector_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase4_auditlog_outbound_message_connector_gap; status=fail; expected=403; actual=200 |
| phase4_auditlog_outbound_multiline_section_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase4_auditlog_outbound_multiline_section_gap; status=fail; expected=403; actual=200 |
| phase4_auditlog_outbound_rule_id_runtime_difference | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase4_auditlog_outbound_rule_id_runtime_difference; status=fail; expected=403; actual=200 |
| phase4_response_body_buffering_order_future_target | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase4_response_body_buffering_order_future_target; status=fail; expected=403; actual=200 |
| phase4_response_body_chunk_assumption_connector_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase4_response_body_chunk_assumption_connector_gap; status=fail; expected=403; actual=200 |
| phase4_response_body_compressed_assumption_experimental | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase4_response_body_compressed_assumption_experimental; status=fail; expected=403; actual=200 |
| phase4_response_body_empty_future_target | 403 | - | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase4_response_body_empty_future_target; status=fail; expected=403; actual=None |
| phase4_response_body_html_entity_decode_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase4_response_body_html_entity_decode_gap; status=fail; expected=403; actual=200 |
| phase4_response_body_html_text_normalization_probe | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase4_response_body_html_text_normalization_probe; status=fail; expected=403; actual=200 |
| phase4_response_body_unicode_runtime_difference | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=phase4_response_body_unicode_runtime_difference; status=fail; expected=403; actual=200 |
| pr70_phase4_response_body_audit_xfail | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=pr70_phase4_response_body_audit_xfail; status=fail; expected=403; actual=200 |
| response_body_basic_block | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=response_body_basic_block; status=fail; expected=403; actual=200 |
| response_headers_multi_value_runtime_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=response_headers_multi_value_runtime_gap; status=fail; expected=403; actual=200 |
| sqli_like_keyword_spacing_probe | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=sqli_like_keyword_spacing_probe; status=fail; expected=403; actual=200 |
| sqli_like_quote_encoding_runtime_difference | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=sqli_like_quote_encoding_runtime_difference; status=fail; expected=403; actual=200 |
| tfn_chain_lowercase_trim_pass_through | 200 | 0 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=tfn_chain_lowercase_trim_pass_through; status=fail; expected=200; actual=0 |
| unicode_double_encoded_uri_runtime_difference | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=unicode_double_encoded_uri_runtime_difference; status=fail; expected=403; actual=200 |
| unicode_whitespace_normalization_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=unicode_whitespace_normalization_gap; status=fail; expected=403; actual=200 |
| v2_transformation_url_decode_invalid_sequence_mapped_candidate | 403 | - | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=v2_transformation_url_decode_invalid_sequence_mapped_candidate; status=fail; expected=403; actual=None |
| v3_request_cookies_names_case_runtime_difference | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=v3_request_cookies_names_case_runtime_difference; status=fail; expected=403; actual=200 |
| v3_request_headers_names_lowercase_runtime_difference | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=v3_request_headers_names_lowercase_runtime_difference; status=fail; expected=403; actual=200 |
| xml_deep_nesting_future_target | 403 | 405 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=xml_deep_nesting_future_target; status=fail; expected=403; actual=405 |
| xml_namespace_edge_connector_gap | 403 | 405 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=xml_namespace_edge_connector_gap; status=fail; expected=403; actual=405 |
| xml_request_body_malformed_connector_gap | 403 | 405 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=xml_request_body_malformed_connector_gap; status=fail; expected=403; actual=405 |
| xss_like_encoded_angles_normalization_probe | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=xss_like_encoded_angles_normalization_probe; status=fail; expected=403; actual=200 |
| xss_like_mixed_case_script_token_gap | 403 | 200 | runtime summary reported non-pass | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json; case=xss_like_mixed_case_script_token_gap; status=fail; expected=403; actual=200 |

## Runtime Verified Status
- Runtime matrix records current local Apache and NGINX per-case smoke evidence.
- PASS in this snapshot means the case was executed by that connector's smoke harness and matched the case expectation in the summary JSON.
- XFAIL, pending, connector-gap, runtime-difference, future, and mapped-only inventory are not promoted by this snapshot.
- FORCE_ALL_CASES=1 attempts xfail/pending/future/gap YAML cases where they are applicable to the connector.
- RESPONSE_BODY remains non-verified/non-promoted.
- Runtime passed, but this does not verify RESPONSE_BODY support.
- make smoke-all was not run by runtime-matrix; full-smoke PASS counts remain unknown.

## Open Runtime Issues
- Mapped-only import inventory entries are not executable YAML runtime cases.
- XFAIL/pending/future/connector-gap/runtime-difference cases require separate evidence before any status change.
- RESPONSE_BODY remains experimental/non-verified.

## Open Areas / Gaps
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
- `make smoke-apache`
- `make smoke-nginx`
- `make smoke-all`
- `make generate-test-matrix`
- `make check-test-matrix`

## Detail Reports
- `docs/testing/test-coverage-overview.md`
- `docs/testing/generated/case-matrix.generated.md`
- `docs/testing/generated/coverage-summary.generated.md`
- `docs/testing/generated/xfail-summary.generated.md`
- `docs/testing/generated/connector-gap-summary.generated.md`
- `docs/testing/generated/phase-coverage.generated.md`
- `docs/testing/generated/runtime-matrix.generated.md`
- `docs/testing/generated/apache-runtime-results.generated.md`
- `docs/testing/generated/nginx-runtime-results.generated.md`
- `docs/testing/runtime-validation-snapshot.json`

## Important Note
Generated coverage is reporting only; it is not runtime evidence by itself.
Full runtime validation is local and evidence-based.
GitHub/Codex checks are intentionally lightweight.
XFAIL, pending, future, and gap cases need local runtime validation before promotion.
`make smoke-all` is authoritative only if it was actually executed successfully.
No PASS numbers are inferred from this file when `make smoke-all` was not run successfully.
No RESPONSE_BODY promotion is made without stable full-smoke runtime evidence.
