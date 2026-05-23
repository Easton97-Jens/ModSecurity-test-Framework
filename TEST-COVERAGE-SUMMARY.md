Generated file — do not edit manually.

# ModSecurity Connector Test Coverage Summary

## Summary Status
- Total YAML cases: **137**
- Verified/pass (`runtime_verified=true`): **0**
- XFAIL cases: **80**
- Pending runtime verification (`runtime_verified=false`): **87**
- Pending runtime verification (`runtime_verified=unknown`): **50**
- Connector-gap cases: **11**
- Runtime-difference cases: **13**
- Future/experimental cases: **17**
- RESPONSE_BODY cases: **24**
- Default runtime-executable YAML cases: **57**
- Force-all runtime-executable YAML cases: **137**
- Apache attempted YAML cases in latest runtime snapshot: **130**
- NGINX attempted YAML cases in latest runtime snapshot: **0**
- Mapped-only import inventory entries: **10**

**RESPONSE_BODY is not verified or promoted.** This file is generated reporting, not runtime proof.

## Framework Integration
- Shared YAML cases, runners, normalizers, generators, and detailed testing documentation are owned by `ModSecurity-test-Framework`.
- The connector repository owns connector source, harnesses, adapter metadata, `config/testing/import-status.json`, and connector-specific generated evidence under `reports/testing/`.
- `FRAMEWORK_ROOT` and `CONNECTOR_ROOT` are explicit integration paths; there is no absolute workspace fallback.

## Case Types
- Common YAML cases: **130**
- Apache-specific YAML cases: **0**
- NGINX-specific YAML cases: **7**
- XFAIL cases: **80**
- Mapped-only import inventory entries: **10** (not counted as runnable YAML cases)
- Runtime-blocked import inventory entries: **0** (environment/harness blockers, not PASS or XFAIL promotions)
- Pending/future compatibility cases: **17** future/experimental; **137** not runtime-verified

## Status Classes
| Status | Count |
|---|---:|
| active | 7 |
| imported | 50 |
| xfail | 80 |

## Scope
| Scope | Count |
|---|---:|
| common | 130 |
| apache | 0 |
| nginx | 7 |
| unknown | 0 |

## Coverage By Variable / Collection
| Variable / Collection | Count |
|---|---:|
| `ARGS` | 43 |
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
| Phase 2 | 70 |
| Phase 3 | 12 |
| Phase 4 | 20 |

## Coverage By Topic
| Topic | Count |
|---|---:|
| Operators | 132 |
| Transformations | 28 |
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
| PASS | 50 | 0 |
| RESPONSE_BODY_PASS_THROUGH | 1 | 0 |
| FAIL | 0 | 137 |
| XFAIL_PASS | 16 | 0 |
| XFAIL_FAIL | 20 | 0 |
| PENDING_FAIL | 1 | 0 |
| FUTURE_PASS | 6 | 0 |
| FUTURE_RESPONSE_BODY_PASS_THROUGH | 1 | 0 |
| FUTURE_FAIL | 10 | 0 |
| CONNECTOR_GAP_PASS | 4 | 0 |
| CONNECTOR_GAP_FAIL | 7 | 0 |
| RUNTIME_DIFFERENCE_PASS | 6 | 0 |
| RUNTIME_DIFFERENCE_FAIL | 8 | 0 |
| NOT_EXECUTABLE | 7 | 0 |
| MAPPED_ONLY | 10 | 10 |

- Apache attempted YAML cases from latest summary: **130**
- NGINX attempted YAML cases from latest summary: **0**
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
- Snapshot: **2026-05-23** (2026-05-23 21:47:19 CEST)
- Git: branch `master`, commit `bc83967`
- BUILD_ROOT: `/root/.local/state/ModSecurity-test-framework-build`
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
| FORCE_ALL_CASES=1 make smoke-apache CONNECTOR_ROOT=/root/conecter/ModSecurity-conector | FAIL | 2 | 84 | 46 | 0 | 0 | /root/.local/state/ModSecurity-test-framework-build/results/apache-summary.json |
| FORCE_ALL_CASES=1 make smoke-nginx CONNECTOR_ROOT=/root/conecter/ModSecurity-conector | FAIL | 2 | 0 | 1 | 0 | 0 | /root/.local/state/ModSecurity-test-framework-build/results/nginx-summary.json |
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
| apache | pr70_phase4_response_body_audit_xfail | 403 | 200 | runtime summary reported non-pass |
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
