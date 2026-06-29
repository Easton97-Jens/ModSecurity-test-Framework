**Language:** English | [Deutsch](TEST-COVERAGE-SUMMARY.de.md)

Generated file - do not edit manually.

# ModSecurity Connector Test Coverage Summary

## Summary Status
- Total YAML cases: **540**
- Verified/pass (`runtime_verified=true`): **0**
- Current XFAIL cases: **0**
- Former XFAIL cases tracked: **80**
- Pending runtime verification (`runtime_verified=false`): **410**
- Pending runtime verification (`runtime_verified=unknown`): **130**
- Connector-gap cases: **11**
- Runtime-difference cases: **13**
- Future/experimental cases: **17**
- RESPONSE_BODY cases: **32**
- Default runtime-executable YAML cases: **61**
- Force-all runtime-executable YAML cases: **540**
- Apache attempted YAML cases in default runtime snapshot: **54**
- NGINX attempted YAML cases in default runtime snapshot: **60**
- HAProxy attempted YAML cases in default runtime snapshot: **134**
- Apache attempted YAML cases in force-all runtime snapshot: **133**
- NGINX attempted YAML cases in force-all runtime snapshot: **140**
- HAProxy attempted YAML cases in force-all runtime snapshot: **133**
- Apache force-all raw runtime PASS/FAIL/BLOCKED/NOT_EXECUTABLE: **100** / **27** / **0** / **6**
- NGINX force-all raw runtime PASS/FAIL/BLOCKED/NOT_EXECUTABLE: **95** / **39** / **0** / **6**
- HAProxy force-all raw runtime PASS/FAIL/BLOCKED/NOT_EXECUTABLE: **104** / **23** / **0** / **6**
- Mapped-only import inventory entries: **0**

## MRTS Source Summary
- Total MRTS imported cases: **399**
- Active MRTS cases: **0**
- Pending MRTS cases: **399**
- Unclassified MRTS cases: **399**
- Phase 4 / RESPONSE_BODY MRTS cases: **110**
- Runtime-executable MRTS cases: **0**
- MRTS overlay classifications: **unclassified(399)**
- Apache observed classifications: **-**
- NGINX observed classifications: **-**
- HAProxy observed classifications: **-**

| Corpus | Category | Definitions | Golden tests | Golden rules | Framework cases | Active | Pending | Unclassified | Phase 4 / RESPONSE_BODY | Runtime-executable |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| upstream-config-tests | runnable | 16 | 157 | 15 | 383 | 0 | 383 | 383 | 110 | 0 |
| feature-demo | optional/demo | 9 | 13 | 8 | 16 | 0 | 16 | 16 | 0 | 0 |
| upstream-generated | golden-only | - | 157 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| framework-curated | legacy/reference | 16 | - | - | 0 | 0 | 0 | 0 | 0 | 0 |

### MRTS Golden Drift
| Reference | Generated | Golden | Matched | Mismatch | Missing generated | Extra generated |
|---|---:|---:|---:|---:|---:|---:|
| upstream_tests | 157 | 157 | 157 | 0 | 0 | 0 |
| upstream_rules | 15 | 15 | 15 | 0 | 0 | 0 |
| feature_demo_tests | 13 | 13 | 0 | 0 | 13 | 13 |
| feature_demo_rules | 8 | 8 | 7 | 1 | 0 | 0 |

- Duplicate MRTS rule IDs across imported runnable/demo corpora: **13**
- Golden-only references under `tools/MRTS/generated/**` and `tools/MRTS/feature_demo/generated/**` are drift inputs only.
- Feature-demo cases are report-visible as optional/demo and pending unless `MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1` passes collision checks.

## Important Reporting Semantics
- PASS/FAIL are rendered only from live runtime evidence recorded in connector summaries and decision/result artifacts.
- BLOCKED remains reserved for harness, environment, dependency, build, or runtime blockers.
- NOT_EXECUTABLE means the case is structurally unmappable for that connector/run mode; it is not a blocker and not a pass.
- Force-all evidence does not promote YAML feature support.
- RESPONSE_BODY remains experimental/non-promoted, including bounded phase-4 and strict-abort evidence.

## Framework Integration
- This framework-owned file is the source of truth for root coverage reporting: `TEST-COVERAGE-SUMMARY.md` in `ModSecurity-test-Framework`.
- Connector repositories should link to this Framework summary instead of maintaining their own root coverage summary.
- Shared YAML cases, runners, normalizers, generators, and detailed testing documentation are owned by `ModSecurity-test-Framework`.
- The connector repository owns connector source, harnesses, adapter metadata, `config/testing/import-status.json`, and connector-specific generated evidence under `reports/testing/`.
- `FRAMEWORK_ROOT` and `CONNECTOR_ROOT` are explicit integration paths; there is no absolute workspace fallback.

## Case Inventory
- Common YAML cases: **533**
- Apache-specific YAML cases: **0**
- NGINX-specific YAML cases: **7**
- Current XFAIL cases: **0**
- Former XFAIL cases tracked: **80**
- Mapped-only import inventory entries: **0** (not counted as runnable YAML cases)
- Runtime-blocked import inventory entries: **0** (environment/harness blockers, not PASS promotions)
- Pending/future compatibility cases: **17** future/experimental; **540** not runtime-verified

## Status Classes
| Status | Count |
|---|---:|
| active | 8 |
| imported | 133 |
| pending | 399 |

## Scope
| Scope | Count |
|---|---:|
| common | 533 |
| apache | 0 |
| nginx | 7 |
| unknown | 0 |

## Coverage By Variable / Collection
| Variable / Collection | Count |
|---|---:|
| `ARGS` | 121 |
| `ARGS_NAMES` | 62 |
| `REQUEST_HEADERS` | 5 |
| `REQUEST_HEADERS_NAMES` | 5 |
| `REQUEST_COOKIES` | 62 |
| `REQUEST_COOKIES_NAMES` | 64 |
| `REQUEST_URI` | 7 |
| `REQUEST_BODY` | 10 |
| `FILES` | 2 |
| `FILES_NAMES` | 2 |
| `XML` | 8 |
| `RESPONSE_HEADERS` | 11 |
| `RESPONSE_BODY` | 28 |
| `AUDIT_LOG` | 0 |

## Coverage By Phase
| Phase | Count |
|---|---:|
| Phase 1 | 105 |
| Phase 2 | 192 |
| Phase 3 | 114 |
| Phase 4 | 126 |

## Coverage By Topic
| Topic | Count |
|---|---:|
| Operators | 523 |
| Transformations | 32 |
| Multipart / FILES | 11 |
| JSON | 7 |
| XML | 8 |
| Unicode / Encoding | 17 |
| XSS-like compatibility probes | 2 |
| SQLi-like compatibility probes | 2 |
| Audit-log probes | 24 |
| Response header probes | 11 |
| Response body experimental probes | 10 |

## Runtime Matrix Status
| Status | Apache | NGINX | HAProxy |
|---|---:|---:|---:|
| PASS | 54 | 60 | 105 |
| FAIL | 0 | 0 | 23 |
| NOT_EXECUTABLE | 486 | 480 | 412 |

- Apache attempted YAML cases from default summary: **54**
- NGINX attempted YAML cases from default summary: **60**
- HAProxy attempted YAML cases from default summary: **134**
- Apache NOT EXECUTED YAML rows: **0**
- NGINX NOT EXECUTED YAML rows: **0**
- HAProxy NOT EXECUTED YAML rows: **0**
- Apache NOT_EXECUTABLE YAML rows: **486**
- NGINX NOT_EXECUTABLE YAML rows: **480**
- HAProxy NOT_EXECUTABLE YAML rows: **412**
- Mapped-only import inventory entries: **0**
- Runtime matrix detail: `docs/testing/generated/runtime-matrix.generated.md`
- Apache per-case results: `docs/testing/generated/apache-runtime-results.generated.md`
- NGINX per-case results: `docs/testing/generated/nginx-runtime-results.generated.md`
- HAProxy per-case results: `docs/testing/generated/haproxy-runtime-results.generated.md`
- PASS/BLOCKED/FAIL counts here come only from tracked runtime snapshot evidence.
- RESPONSE_BODY remains non-verified even when a pass-through runtime case returns HTTP 200.

- HAProxy force-all attempted YAML cases: **133**
- HAProxy force-all result JSONL: `/src/ModSecurity-conector-build/results/force-all/haproxy-results.jsonl`
- HAProxy force-all per-case evidence root: `/src/ModSecurity-conector-build/logs/haproxy-runtime`
- Force-all evidence is traceable runtime evidence but does not promote pending/future/gap feature support.

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
- Snapshot: **2026-06-07** (2026-06-07 13:02:53 CEST)
- Git: branch `integrate-new-connectors-local`, commit `b5b983d`
- BUILD_ROOT: `/src/ModSecurity-conector-build`
- Snapshot file: `docs/testing/runtime-validation-snapshot.json`

### Default Runtime Smoke Status
| Connector | Command | Status | Exit | Attempted | PASS | FAIL | BLOCKED | NOT_EXECUTABLE | Evidence |
|---|---|---|---|---|---|---|---|---|---|
| apache | make smoke-apache | PASS | 0 | 54 | 54 | 0 | 0 | 0 | /src/ModSecurity-conector-build/results/apache-summary.json |
| nginx | make smoke-nginx | PASS | 0 | 60 | 60 | 0 | 0 | 0 | /src/ModSecurity-conector-build/results/nginx-summary.json |
| haproxy | make smoke-haproxy | FAIL | 2 | 134 | 105 | 23 | 0 | 6 | /src/ModSecurity-conector-build/results/haproxy-summary.json |
| all | REFRESH=1 make smoke-all | NOT_RUN | not_run | 0 | unknown | unknown | unknown | unknown | not available |

### Force-All Runtime Smoke Status
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

### HAProxy FAIL Details
| Case | Expected | Actual | Assessment | Evidence |
|---|---|---|---|---|
| duplicate_args_encoded_separator_edge | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=duplicate_args_encoded_separator_edge; status=fail; expected=403; actual=200 |
| duplicate_header_case_normalization_gap | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=duplicate_header_case_normalization_gap; status=fail; expected=403; actual=200 |
| edge_semicolon_query_args_names | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=edge_semicolon_query_args_names; status=fail; expected=403; actual=200 |
| files_names_mixed_case_filename_gap | 403 | 501 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=files_names_mixed_case_filename_gap; status=fail; expected=403; actual=501 |
| multipart_duplicate_field_names_gap | 403 | 501 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=multipart_duplicate_field_names_gap; status=fail; expected=403; actual=501 |
| parser_xml_partial_body_future_target | 403 | 501 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=parser_xml_partial_body_future_target; status=fail; expected=403; actual=501 |
| phase3_response_headers_multi_value_connector_gap | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=phase3_response_headers_multi_value_connector_gap; status=fail; expected=403; actual=200 |
| phase3_response_headers_set_cookie_multi_gap | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=phase3_response_headers_set_cookie_multi_gap; status=fail; expected=403; actual=200 |
| phase4_auditlog_outbound_multiline_section_gap | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=phase4_auditlog_outbound_multiline_section_gap; status=fail; expected=403; actual=200 |
| response_headers_multi_value_runtime_gap | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=response_headers_multi_value_runtime_gap; status=fail; expected=403; actual=200 |
| sqli_like_keyword_spacing_probe | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=sqli_like_keyword_spacing_probe; status=fail; expected=403; actual=200 |
| sqli_like_quote_encoding_runtime_difference | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=sqli_like_quote_encoding_runtime_difference; status=fail; expected=403; actual=200 |
| tfn_chain_lowercase_trim_pass_through | 200 | 0 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=tfn_chain_lowercase_trim_pass_through; status=fail; expected=200; actual=0 |
| unicode_double_encoded_uri_runtime_difference | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=unicode_double_encoded_uri_runtime_difference; status=fail; expected=403; actual=200 |
| unicode_whitespace_normalization_gap | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=unicode_whitespace_normalization_gap; status=fail; expected=403; actual=200 |
| v3_action_nolog_pass_no_audit | 200 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=v3_action_nolog_pass_no_audit; status=fail; expected=200; actual=200 |
| v3_request_cookies_names_case_runtime_difference | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=v3_request_cookies_names_case_runtime_difference; status=fail; expected=403; actual=200 |
| v3_request_headers_names_lowercase_runtime_difference | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=v3_request_headers_names_lowercase_runtime_difference; status=fail; expected=403; actual=200 |
| xml_deep_nesting_future_target | 403 | 501 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=xml_deep_nesting_future_target; status=fail; expected=403; actual=501 |
| xml_namespace_edge_connector_gap | 403 | 501 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=xml_namespace_edge_connector_gap; status=fail; expected=403; actual=501 |
| xml_request_body_malformed_connector_gap | 403 | 501 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=xml_request_body_malformed_connector_gap; status=fail; expected=403; actual=501 |
| xss_like_encoded_angles_normalization_probe | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=xss_like_encoded_angles_normalization_probe; status=fail; expected=403; actual=200 |
| xss_like_mixed_case_script_token_gap | 403 | 200 | runtime summary reported non-pass | /src/ModSecurity-conector-build/results/haproxy-summary.json; case=xss_like_mixed_case_script_token_gap; status=fail; expected=403; actual=200 |

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

## Open Areas / Gaps
- Runtime verification pending: cases with `runtime_verified=false` or `runtime_verified=unknown` are not runtime PASS proof.
- RESPONSE_BODY remains non-verified and non-promoted.
- GitHub/Codex checks are intentionally lightweight and do not prove runtime compatibility.
- Pending, future, connector-gap, and runtime-difference topics require local runtime evidence before any support claim.
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
- `docs/testing/test-coverage-overview.md`
- `docs/testing/generated/case-matrix.generated.md`
- `docs/testing/generated/coverage-summary.generated.md`
- `docs/testing/generated/xfail-summary.generated.md`
- `docs/testing/generated/connector-gap-summary.generated.md`
- `docs/testing/generated/phase-coverage.generated.md`
- `docs/testing/generated/runtime-matrix.generated.md`
- `docs/testing/generated/apache-runtime-results.generated.md`
- `docs/testing/generated/nginx-runtime-results.generated.md`
- `docs/testing/generated/haproxy-runtime-results.generated.md`
- `docs/testing/runtime-validation-snapshot.json`

## Important Note
Generated coverage is reporting only; it is not runtime evidence by itself.
Full runtime validation is local and evidence-based.
GitHub/Codex checks are intentionally lightweight.
Pending, future, and gap topics need local runtime validation before promotion.
`make smoke-all` is authoritative only if it was actually executed successfully.
No PASS numbers are inferred from this file when `make smoke-all` was not run successfully.
Phase 4 / RESPONSE_BODY remains non-promoted; bounded strict-abort evidence is reported as runtime evidence only.
