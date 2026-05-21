Generated file — do not edit manually.

# ModSecurity Connector Test Coverage Overview

## Summary
- Total cases: **133**
- Verified/pass count (`runtime_verified=true`): **0**
- XFAIL count: **79**
- Pending runtime verification count: **86**
- Connector-gap count: **11**
- Runtime-difference count: **13**
- Future/experimental count: **16**
- RESPONSE_BODY cases: **19** (still **not verified/promoted**)
- Mapped-only import inventory entries: **10**

## Coverage By Variable / Collection
| Variable | Count |
|---|---:|
| `RESPONSE_BODY` | 19 |
| `ARGS:q` | 18 |
| `REQUEST_BODY` | 10 |
| `ARGS_NAMES` | 7 |
| `REQUEST_URI` | 7 |
| `ARGS:test` | 6 |
| `REQUEST_HEADERS_NAMES` | 5 |
| `ARGS:param1` | 4 |
| `ARGS:a` | 4 |
| `REQUEST_COOKIES_NAMES` | 4 |
| `XML` | 4 |
| `ARGS` | 4 |
| `RESPONSE_HEADERS:Set-Cookie` | 4 |
| `ARGS:probe` | 4 |
| `MULTIPART_FILENAME` | 3 |
| `FILES_NAMES` | 2 |
| `TX:SCORE` | 2 |
| `REQUEST_COOKIES:USER_TOKEN` | 2 |
| `RESPONSE_HEADERS:Location` | 2 |
| `ARGS:audit` | 1 |

## Coverage By Phase
| Phase | Count |
|---|---:|
| 1 | 35 |
| 2 | 69 |
| 3 | 11 |
| 4 | 19 |

## Coverage By Status
| Status | Count |
|---|---:|
| imported | 47 |
| unknown | 7 |
| xfail | 79 |

## Coverage By Scope
| Scope | Count |
|---|---:|
| common | 126 |
| apache | 0 |
| nginx | 7 |
| unknown | 0 |

## Runtime Matrix Status
- Default runtime-executable YAML cases: **54**
- Force-all runtime-executable YAML cases: **133**
- Apache attempted YAML cases from latest summary: **126**
- NGINX attempted YAML cases from latest summary: **133**
| Status | Apache | NGINX |
|---|---:|---:|
| PASS | 48 | 54 |
| XFAIL_PASS | 16 | 16 |
| XFAIL_FAIL | 20 | 21 |
| PENDING_FAIL | 1 | 1 |
| FUTURE_PASS | 7 | 7 |
| FUTURE_FAIL | 9 | 9 |
| CONNECTOR_GAP_PASS | 4 | 5 |
| CONNECTOR_GAP_FAIL | 7 | 6 |
| RUNTIME_DIFFERENCE_PASS | 6 | 6 |
| RUNTIME_DIFFERENCE_FAIL | 8 | 8 |
| NOT_EXECUTABLE | 7 | 0 |
| MAPPED_ONLY | 10 | 10 |
- Details: `docs/testing/generated/runtime-matrix.generated.md`

## Latest Local Runtime Validation Snapshot
- Snapshot: **2026-05-21** (2026-05-21 18:02:19 CEST)
- Git: branch `master`, commit `aea6d52`
- BUILD_ROOT: `/root/.local/state/ModSecurity-conector-build`
- This is a manual local runtime snapshot rendered from tracked snapshot data and local smoke summary files.
- Runtime matrix snapshot generated from local Apache and NGINX smoke summary JSON files.
- Per-case PASS/FAIL/BLOCKED/XFAIL values are runtime evidence for this local run only.
- No xfail/pending YAML case is promoted by this snapshot.
- RESPONSE_BODY remains non-verified/non-promoted, including pass-through response-body probes.
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
| FORCE_ALL_CASES=1 REFRESH=1 make smoke-apache | FAIL | 2 | 81 | 45 | 0 | 0 | /root/.local/state/ModSecurity-conector-build/results/apache-summary.json |
| FORCE_ALL_CASES=1 REFRESH=1 make smoke-nginx | FAIL | 2 | 88 | 45 | 0 | 0 | /root/.local/state/ModSecurity-conector-build/results/nginx-summary.json |
| REFRESH=1 make smoke-all | NOT_RUN | not_run | unknown | unknown | unknown | unknown | not available |

## Runtime FAIL Details
| Connector | Case | Expected | Actual | Assessment |
|---|---|---|---|---|
| apache | duplicate_args_encoded_separator_edge | 403 | 200 | runtime summary reported non-pass |
| apache | duplicate_header_case_normalization_gap | 403 | 200 | runtime summary reported non-pass |
| apache | edge_semicolon_query_args_names | 403 | 200 | runtime summary reported non-pass |
| apache | files_empty_part_future_compatibility | 403 | None | runtime summary reported non-pass |
| apache | files_names_mixed_case_filename_gap | 403 | 200 | runtime summary reported non-pass |
| apache | json_empty_body_future_compatibility | 403 | None | runtime summary reported non-pass |
| apache | multipart_duplicate_field_names_gap | 403 | 200 | runtime summary reported non-pass |
| apache | multipart_empty_filename_connector_gap | 403 | None | runtime summary reported non-pass |
| apache | parser_xml_partial_body_future_target | 403 | 200 | runtime summary reported non-pass |
| apache | phase1_vs_phase2_request_body_gap | 403 | 200 | runtime summary reported non-pass |
| apache | phase3_response_headers_content_type_charset_gap | 403 | 200 | runtime summary reported non-pass |
| apache | phase3_response_headers_duplicate_value_runtime_difference | 403 | 200 | runtime summary reported non-pass |
| apache | phase3_response_headers_encoded_value_future_target | 403 | 200 | runtime summary reported non-pass |
| apache | phase3_response_headers_location_encoded_runtime_diff | 403 | 200 | runtime summary reported non-pass |
| apache | phase3_response_headers_mixed_case_connector_gap | 403 | 200 | runtime summary reported non-pass |
| apache | phase3_response_headers_multi_value_connector_gap | 403 | 200 | runtime summary reported non-pass |
| apache | phase3_response_headers_server_presence_pending | 200 | None | runtime summary reported non-pass |
| apache | phase3_response_headers_set_cookie_multi_gap | 403 | 200 | runtime summary reported non-pass |
| apache | phase4_auditlog_outbound_escaped_value_gap | 403 | 200 | runtime summary reported non-pass |
| apache | phase4_auditlog_outbound_matched_var_future | 403 | 200 | runtime summary reported non-pass |
| apache | phase4_auditlog_outbound_message_connector_gap | 403 | 200 | runtime summary reported non-pass |
| apache | phase4_auditlog_outbound_multiline_section_gap | 403 | 200 | runtime summary reported non-pass |
| apache | phase4_auditlog_outbound_rule_id_runtime_difference | 403 | 200 | runtime summary reported non-pass |
| apache | phase4_response_body_buffering_order_future_target | 403 | 200 | runtime summary reported non-pass |
| apache | phase4_response_body_chunk_assumption_connector_gap | 403 | 200 | runtime summary reported non-pass |
| apache | phase4_response_body_compressed_assumption_experimental | 403 | 200 | runtime summary reported non-pass |
| apache | phase4_response_body_empty_future_target | 403 | None | runtime summary reported non-pass |
| apache | phase4_response_body_html_entity_decode_gap | 403 | 200 | runtime summary reported non-pass |
| apache | phase4_response_body_html_text_normalization_probe | 403 | 200 | runtime summary reported non-pass |
| apache | phase4_response_body_unicode_runtime_difference | 403 | 200 | runtime summary reported non-pass |
| apache | response_body_basic_block | 403 | 200 | runtime summary reported non-pass |
| apache | response_headers_multi_value_runtime_gap | 403 | 200 | runtime summary reported non-pass |
| apache | sqli_like_keyword_spacing_probe | 403 | 200 | runtime summary reported non-pass |
| apache | sqli_like_quote_encoding_runtime_difference | 403 | 200 | runtime summary reported non-pass |
| apache | tfn_chain_lowercase_trim_pass_through | 200 | 0 | runtime summary reported non-pass |
| apache | unicode_double_encoded_uri_runtime_difference | 403 | 200 | runtime summary reported non-pass |
| apache | unicode_whitespace_normalization_gap | 403 | 200 | runtime summary reported non-pass |
| apache | v2_transformation_url_decode_invalid_sequence_mapped_candidate | 403 | None | runtime summary reported non-pass |
| apache | v3_request_cookies_names_case_runtime_difference | 403 | 200 | runtime summary reported non-pass |
| apache | v3_request_headers_names_lowercase_runtime_difference | 403 | 200 | runtime summary reported non-pass |
| apache | xml_deep_nesting_future_target | 403 | 200 | runtime summary reported non-pass |
| apache | xml_namespace_edge_connector_gap | 403 | 200 | runtime summary reported non-pass |
| apache | xml_request_body_malformed_connector_gap | 403 | 200 | runtime summary reported non-pass |
| apache | xss_like_encoded_angles_normalization_probe | 403 | 200 | runtime summary reported non-pass |
| apache | xss_like_mixed_case_script_token_gap | 403 | 200 | runtime summary reported non-pass |
| nginx | duplicate_args_encoded_separator_edge | 403 | 200 | runtime summary reported non-pass |
| nginx | duplicate_header_case_normalization_gap | 403 | 200 | runtime summary reported non-pass |
| nginx | edge_semicolon_query_args_names | 403 | 200 | runtime summary reported non-pass |
| nginx | files_empty_part_future_compatibility | 403 | None | runtime summary reported non-pass |
| nginx | files_names_mixed_case_filename_gap | 403 | 405 | runtime summary reported non-pass |
| nginx | json_empty_body_future_compatibility | 403 | None | runtime summary reported non-pass |
| nginx | multipart_duplicate_field_names_gap | 403 | 405 | runtime summary reported non-pass |
| nginx | multipart_empty_filename_connector_gap | 403 | None | runtime summary reported non-pass |
| nginx | nginx_phase4_strict_connection_abort | 403 | 0 | runtime summary reported non-pass |
| nginx | parser_xml_partial_body_future_target | 403 | 405 | runtime summary reported non-pass |
| nginx | phase1_vs_phase2_request_body_gap | 403 | 405 | runtime summary reported non-pass |
| nginx | phase3_response_headers_content_type_charset_gap | 403 | 200 | runtime summary reported non-pass |
| nginx | phase3_response_headers_duplicate_value_runtime_difference | 403 | 200 | runtime summary reported non-pass |
| nginx | phase3_response_headers_encoded_value_future_target | 403 | 200 | runtime summary reported non-pass |
| nginx | phase3_response_headers_location_encoded_runtime_diff | 403 | 200 | runtime summary reported non-pass |
| nginx | phase3_response_headers_multi_value_connector_gap | 403 | 200 | runtime summary reported non-pass |
| nginx | phase3_response_headers_server_presence_pending | 200 | None | runtime summary reported non-pass |
| nginx | phase3_response_headers_set_cookie_multi_gap | 403 | 200 | runtime summary reported non-pass |
| nginx | phase4_auditlog_outbound_escaped_value_gap | 403 | 200 | runtime summary reported non-pass |
| nginx | phase4_auditlog_outbound_matched_var_future | 403 | 200 | runtime summary reported non-pass |
| nginx | phase4_auditlog_outbound_message_connector_gap | 403 | 200 | runtime summary reported non-pass |
| nginx | phase4_auditlog_outbound_multiline_section_gap | 403 | 200 | runtime summary reported non-pass |
| nginx | phase4_auditlog_outbound_rule_id_runtime_difference | 403 | 200 | runtime summary reported non-pass |
| nginx | phase4_response_body_buffering_order_future_target | 403 | 200 | runtime summary reported non-pass |
| nginx | phase4_response_body_chunk_assumption_connector_gap | 403 | 200 | runtime summary reported non-pass |
| nginx | phase4_response_body_compressed_assumption_experimental | 403 | 200 | runtime summary reported non-pass |
| nginx | phase4_response_body_empty_future_target | 403 | None | runtime summary reported non-pass |
| nginx | phase4_response_body_html_entity_decode_gap | 403 | 200 | runtime summary reported non-pass |
| nginx | phase4_response_body_html_text_normalization_probe | 403 | 200 | runtime summary reported non-pass |
| nginx | phase4_response_body_unicode_runtime_difference | 403 | 200 | runtime summary reported non-pass |
| nginx | response_body_basic_block | 403 | 200 | runtime summary reported non-pass |
| nginx | response_headers_multi_value_runtime_gap | 403 | 200 | runtime summary reported non-pass |
| nginx | sqli_like_keyword_spacing_probe | 403 | 200 | runtime summary reported non-pass |
| nginx | sqli_like_quote_encoding_runtime_difference | 403 | 200 | runtime summary reported non-pass |
| nginx | tfn_chain_lowercase_trim_pass_through | 200 | 0 | runtime summary reported non-pass |
| nginx | unicode_double_encoded_uri_runtime_difference | 403 | 200 | runtime summary reported non-pass |
| nginx | unicode_whitespace_normalization_gap | 403 | 200 | runtime summary reported non-pass |
| nginx | v2_transformation_url_decode_invalid_sequence_mapped_candidate | 403 | None | runtime summary reported non-pass |
| nginx | v3_request_cookies_names_case_runtime_difference | 403 | 200 | runtime summary reported non-pass |
| nginx | v3_request_headers_names_lowercase_runtime_difference | 403 | 200 | runtime summary reported non-pass |
| nginx | xml_deep_nesting_future_target | 403 | 405 | runtime summary reported non-pass |
| nginx | xml_namespace_edge_connector_gap | 403 | 405 | runtime summary reported non-pass |
| nginx | xml_request_body_malformed_connector_gap | 403 | 405 | runtime summary reported non-pass |
| nginx | xss_like_encoded_angles_normalization_probe | 403 | 200 | runtime summary reported non-pass |
| nginx | xss_like_mixed_case_script_token_gap | 403 | 200 | runtime summary reported non-pass |

## Runtime Verified Status
- Runtime matrix records current local Apache and NGINX per-case smoke evidence.
- PASS in this snapshot means the case was executed by that connector's smoke harness and matched the case expectation in the summary JSON.
- XFAIL, pending, connector-gap, runtime-difference, future, and mapped-only inventory are not promoted by this snapshot.
- FORCE_ALL_CASES=1 attempts xfail/pending/future/gap YAML cases where they are applicable to the connector.
- RESPONSE_BODY remains non-verified/non-promoted.
- make smoke-all was not run by runtime-matrix; full-smoke PASS counts remain unknown.

## Open Runtime Issues
- Mapped-only import inventory entries are not executable YAML runtime cases.
- XFAIL/pending/future/connector-gap/runtime-difference cases require separate evidence before any status change.
- RESPONSE_BODY remains experimental/non-verified.

## Open Gaps
- See `docs/testing/generated/connector-gap-summary.generated.md` for detailed entries.

## Verified Runtime Coverage
- Runtime-verified means only cases explicitly classified as `runtime_verified=true`.

## Pending Runtime Verification
- Cases with `runtime_verified=false` or `runtime_verified=unknown` are not runtime PASS proof.

## XFAIL / Known Gap Coverage
- XFAIL, pending, future, and experimental cases are listed in the XFAIL summary.
- XFAIL, pending, and gap cases need local runtime validation before promotion.

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
- XFAIL, pending, and gap cases need local runtime validation.
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
