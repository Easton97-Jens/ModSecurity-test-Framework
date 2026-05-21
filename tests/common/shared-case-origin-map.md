# Shared Case Origin Map

Status: implemented

Only connector-neutral rule/request/expectation fragments are mapped here. The
original Apache::Test and Test::Nginx harness mechanics remain
connector-specific and are not copied.

## Shared Minimal Cases

| Shared case | original_path | source_repo | category | purpose | portable | status | required_capabilities | known_limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `minimal/audit_log_phase1_block.yaml` | `tests/regression/action/10-logging.t`; `tests/modsecurity-config-auditlog.t` | apache/nginx | audit-log | Serial audit log with stable rule/URI/message fields | yes | imported | query args, phase1, audit log | Does not assert volatile audit fields or concurrent audit storage |
| `minimal/phase1_header_block.yaml` | `tests/regression/rule/15-json.t`; `tests/modsecurity.t` | apache/nginx | request-headers | Phase:1 header intervention | yes | imported | request headers, phase1, intervention | Header target adapted to `User-Agent` to avoid JSON parser assumptions |
| `minimal/phase2_args_block.yaml` | `tests/regression/rule/00-basics.t`; `tests/modsecurity.t` | apache/nginx | phase-processing | Phase:2 ARGS intervention | yes | imported | query args, phase2, intervention | Does not assert debug/error log text |
| `minimal/phase2_args_pass.yaml` | `tests/regression/rule/00-basics.t`; `tests/modsecurity.t` | apache/nginx | phase-processing | Non-matching ARGS rule passes through | yes | imported | query args, pass-through | Does not prove allow-listing |
| `minimal/request_body_json_block.yaml` | `tests/regression/rule/15-json.t`; `tests/modsecurity-request-body.t` | apache/nginx | request-body | Raw JSON request-body block | yes | imported | request body, phase2 | Does not require parsed JSON collections |
| `minimal/request_body_urlencoded_block.yaml` | `tests/regression/target/00-targets.t`; `tests/modsecurity-request-body.t` | apache/nginx | request-body | Form body `ARGS_POST` intervention | yes | imported | request body, form urlencoded, phase2 | Does not cover request-body limits or chunking |
| `minimal/response_header_basic.yaml` | `tests/regression/misc/00-phases.t`; `src/ngx_http_modsecurity_header_filter.c` | apache/nginx | response-headers | Basic phase:3 response header intervention | yes | imported | response headers, phase3 | Depends on static response exposing `Last-Modified` |

## Shared Imported Cases

| Shared case | original_path | source_repo | category | purpose | portable | status | required_capabilities | known_limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `imported/action_deny_phase1.yaml` | `tests/regression/action/00-disruptive-actions.t`; `tests/modsecurity.t` | apache/nginx | actions | Unconditional phase:1 deny returns HTTP 403 | yes | imported | phase1, intervention | Does not assert connector log text |
| `imported/action_deny_phase2.yaml` | `tests/regression/action/00-disruptive-actions.t`; `tests/modsecurity.t` | apache/nginx | actions | Unconditional phase:2 deny returns HTTP 403 | yes | imported | phase2, intervention | Does not assert connector log text |
| `imported/action_allow_phase1_pass.yaml` | `tests/regression/action/00-disruptive-actions.t` | apache | actions | Phase:1 allow bypasses later phase:1 deny and reaches origin | yes | imported | phase1, pass-through | Does not assert debug/error log text |
| `imported/collection_args_names_block.yaml` | `tests/regression/target/00-targets.t` | apache | collections | `ARGS_NAMES` query argument name match | yes | imported | query args, collections, phase2 | Converted from log/pass assertion to HTTP intervention assertion |
| `imported/collection_args_get_block.yaml` | `tests/regression/target/00-targets.t`; `tests/modsecurity.t` | apache/nginx | collections | `ARGS_GET` query argument value match | yes | imported | query args, collections, phase2 | Converted from log/pass assertion to HTTP intervention assertion |
| `imported/collection_args_combined_size_block.yaml` | `tests/regression/target/00-targets.t` | apache | collections | `ARGS_COMBINED_SIZE` for two query args | yes | imported | query args, collections, phase2 | Size expectation mirrors the upstream Apache regression value |
| `imported/request_body_args_post_names_block.yaml` | `tests/regression/target/00-targets.t`; `tests/modsecurity-request-body.t` | apache/nginx | request-body | Form body `ARGS_POST_NAMES` match | yes | imported | request body, form urlencoded, collections | Does not cover method matrix or limits |
| `imported/request_body_raw_text_block.yaml` | `tests/modsecurity-request-body.t`; `tests/regression/rule/15-json.t` | nginx/apache | request-body | Raw `REQUEST_BODY` text match | yes | imported | request body, phase2 | Does not cover streaming or chunked body delivery |
| `imported/json_request_body_block.yaml` | `tests/regression/rule/15-json.t`; `tests/modsecurity-request-body.t` | apache/nginx | body-processors | Raw JSON request body match | yes | fully-imported-common | request body, JSON content type, phase2 | Does not prove parsed JSON collections such as `ARGS:foo` |
| `imported/multipart_basic_block.yaml` | `tests/regression/misc/00-multipart-parser.t`; `tests/modsecurity-request-body.t` | apache/nginx | multipart | Simple multipart text field match through `ARGS:name` | yes | fully-imported-common | request body, multipart, collections, phase2 | Does not cover file storage, parser errors, streaming, or part header folding |
| `imported/response_body_pass.yaml` | `tests/regression/config/10-response-directives.t`; `tests/modsecurity-response-body.t` | apache/nginx | response-body | Response-body access configured with non-matching rule and HTTP 200 pass-through | yes | fully-imported-common | response body, phase4, pass-through | Does not prove response-body blocking |
| `imported/action_status_401_phase1_block.yaml` | `tests/modsecurity.t`; `tests/regression/action/00-disruptive-actions.t` | nginx/apache | actions | Phase:1 query-argument block returns HTTP 401 | yes | fully-imported-common | actions, query args, phase1, intervention | Makes disruptive deny explicit because the NGINX source supplies deny through `SecDefaultAction` |

## Connector-Specific Imported Cases

| Case | original_path | source_repo | category | purpose | portable | status | target_location | required_capabilities | known_limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `nginx_redirect_phase1_302.yaml` | `tests/modsecurity.t` | nginx | actions | NGINX-observed phase:1 redirect action | no | imported | `tests/nginx/cases/imported/` | query args, phase1, redirect | NGINX-only until Apache equivalence is explicitly tested |
| `nginx_tx_scoring_absolute_block.yaml` | `tests/modsecurity-scoring.t` | nginx | actions | Absolute `tx.score` assignment blocks on threshold | no | imported | `tests/nginx/cases/imported/` | query args, TX collection, phase2 | NGINX-only until promoted after cross-connector proof |
| `nginx_tx_scoring_iterative_block.yaml` | `tests/modsecurity-scoring.t` | nginx | actions | Iterative `tx.score` increments block on threshold | no | imported | `tests/nginx/cases/imported/` | query args, TX collection, phase2 | NGINX-only until promoted after cross-connector proof |
| `nginx_phase4_minimal_log_only.yaml` | PR #377 `tests/modsecurity-phase4-modes.t` | nginx | response-body/phase4 | Minimal mode logs late phase-4 intervention while preserving HTTP 200 response | no | imported | `tests/nginx/cases/imported/` | response body, phase4, logging, pass-through | NGINX-only; not a response-body blocking promotion |
| `nginx_phase4_safe_log_only.yaml` | PR #377 `tests/modsecurity-phase4-modes.t` | nginx | response-body/phase4 | Safe mode logs late phase-4 intervention while preserving HTTP 200 response | no | imported | `tests/nginx/cases/imported/` | response body, phase4, logging, pass-through | NGINX-only; not a response-body blocking promotion |
| `nginx_phase4_content_type_out_of_scope.yaml` | PR #377 `tests/modsecurity-phase4-content-types.t` | nginx | response-body/phase4 | Out-of-scope response content type logs and preserves HTTP 200 response | no | imported | `tests/nginx/cases/imported/` | response body, phase4, logging, pass-through | NGINX-only; not a response-body blocking promotion |

## V2-Derived Common Cases

| Shared case | original_path | source_repo | category | purpose | portable | status | required_capabilities | known_limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `v2-imported/v2_operator_streq_block.yaml` | `tests/op/streq.t` | ModSecurity_V2 | operators | `@streq` equality semantics | yes | fully-imported-common | operators, query args, phase2 | Converted from V2 Perl operator harness to HTTP intervention |
| `v2-imported/v2_operator_contains_block.yaml` | `tests/op/contains.t` | ModSecurity_V2 | operators | `@contains` substring semantics | yes | fully-imported-common | operators, query args, phase2 | Empty-string edge cases remain mapped |
| `v2-imported/v2_operator_begins_with_block.yaml` | `tests/op/beginsWith.t` | ModSecurity_V2 | operators | `@beginsWith` with param `abcdef`, input `abcdefghi` | yes | fully-imported-common | operators, query args, phase2 | Empty-string and mismatch branches remain mapped |
| `v2-imported/v2_operator_ends_with_block.yaml` | `tests/op/endsWith.t` | ModSecurity_V2 | operators | `@endsWith` with param `ghi`, input `abcdefghi` | yes | fully-imported-common | operators, query args, phase2 | NUL-containing branch remains mapped |
| `v2-imported/v2_operator_pm_block.yaml` | `tests/op/pm.t` | ModSecurity_V2 | operators | `@pm` with param `abc`, input `abcdefghi` | yes | fully-imported-common | operators, query args, phase2 | Long phrase-list and no-match branches remain mapped |
| `v2-imported/v2_operator_contains_word_block.yaml` | `tests/op/containsWord.t` | ModSecurity_V2 | operators | `@containsWord` with param `abc`, input `abc def ghi` | yes | fully-imported-common | operators, query args, phase2 | Word-boundary negative branches remain mapped |
| `v2-imported/v2_transformation_lowercase_block.yaml` | `tests/tfn/lowercase.t` | ModSecurity_V2 | transformations | `t:lowercase` semantic check | yes | fully-imported-common | transformations, query args, phase2 | Embedded NUL cases remain mapped |
| `v2-imported/v2_transformation_trim_block.yaml` | `tests/tfn/trim.t` | ModSecurity_V2 | transformations | `t:trim` semantic check | yes | fully-imported-common | transformations, query args, phase2 | Complex whitespace/NUL cases remain mapped |
| `v2-imported/v2_transformation_url_decode_block.yaml` | `tests/tfn/urlDecode.t` | ModSecurity_V2 | transformations | `t:urlDecode` with input `Test+Case`, output `Test Case` | yes | fully-imported-common | transformations, request URI, phase1 | Uses `REQUEST_URI` because ARGS parsing can pre-decode `+` |
| `v2-imported/v2_transformation_html_entity_decode_block.yaml` | `tests/tfn/htmlEntityDecode.t` | ModSecurity_V2 | transformations | `t:htmlEntityDecode` fragment `&lt;&gt;` -> `<>` | yes | fully-imported-common | transformations, request headers, phase1 | NUL, nbsp, non-ASCII, and invalid entities remain mapped |

## V3-Derived Common Cases

| Shared case | original_path | source_repo | category | purpose | portable | status | required_capabilities | known_limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `v3-imported/multipart_files_value_block.yaml` | `test/test-cases/regression/variable-FILES.json` | ModSecurity_V3 | multipart | Uploaded file value collection match | yes | fully-imported-common | multipart, files, collections, phase2 | Small deterministic file body only |
| `v3-imported/multipart_files_names_block.yaml` | `test/test-cases/regression/variable-FILES_NAMES.json` | ModSecurity_V3 | multipart | Uploaded file field-name collection match | yes | fully-imported-common | multipart, files, collections, phase2 | Debug-log assertion converted to HTTP intervention |
| `v3-imported/multipart_files_combined_size.yaml` | `test/test-cases/regression/variable-FILES_COMBINED_SIZE.json` | ModSecurity_V3 | multipart | Uploaded file combined size collection match | yes | fully-imported-common | multipart, files, collections, phase2 | Exact byte-accounting matrix remains mapped |
| `v3-imported/multipart_filename_block.yaml` | `test/test-cases/regression/variable-MULTIPART_FILENAME.json` | ModSecurity_V3 | multipart | Multipart filename variable match | yes | fully-imported-common | multipart, files, phase2 | Filename encoding and parser flags remain mapped |
| `v3-imported/xml_request_body_block.yaml` | `test/test-cases/regression/variable-XML.json` | ModSecurity_V3 | body-processors | XML body processor and XML collection match | yes | fully-imported-common | XML, body processors, collections, phase2 | Schema/DTD/parser-error cases remain mapped |
| `v3-imported/v3_operator_rx_block.yaml` | `test/test-cases/regression/operator-rx.json` | ModSecurity_V3 | operators | `@rx` operator match | yes | fully-imported-common | operators, query args, phase2 | Regex error branches remain mapped |
| `v3-imported/v3_operator_pm_digit_block.yaml` | `test/test-cases/regression/operator-pm.json` | ModSecurity_V3 | operators | `@pm 1 2 3` matches request `param1=123` | yes | fully-imported-common | operators, query args, phase1 | No-match branch remains mapped |
| `v3-imported/v3_request_cookies_block.yaml` | `test/test-cases/regression/variable-REQUEST_COOKIES.json` | ModSecurity_V3 | collections | `REQUEST_COOKIES:USER_TOKEN` value `Yes` | yes | fully-imported-common | collections, request cookies, phase1 | Cookie parsing edge cases remain mapped |
| `v3-imported/v3_request_cookies_names_block.yaml` | `test/test-cases/regression/variable-REQUEST_COOKIES_NAMES.json` | ModSecurity_V3 | collections | `REQUEST_COOKIES_NAMES` contains `USER_TOKEN` | yes | fully-imported-common | collections, request cookies, phase1 | Cookie name normalization edge cases remain mapped |
| `v3-imported/v3_request_headers_names_block.yaml` | `test/test-cases/regression/variable-REQUEST_HEADERS_NAMES.json` | ModSecurity_V3 | collections | `REQUEST_HEADERS_NAMES` sees a stable custom header name | yes | fully-imported-common | collections, request headers, phase1 | Standard/implicit header name matrix remains mapped |
| `v3-imported/v3_args_names_get_block.yaml` | `test/test-cases/regression/variable-ARGS_NAMES.json` | ModSecurity_V3 | collections | `ARGS_NAMES` contains GET argument name `key1` | yes | fully-imported-common | collections, args names, query args, phase2 | Duplicate name edge cases remain mapped |
| `v3-imported/v3_auditlog_serial_fields_block.yaml` | `test/test-cases/regression/auditlog.json`; `test/test-cases/regression/issue-2000.json` | ModSecurity_V3 | audit-log | Serial audit log contains stable rule, URI, and message fields | yes | fully-imported-common | audit log, query args, phase1 | Does not compare volatile audit sections |
| `xfail/v3_action_nolog_pass_no_audit.yaml` | `test/test-cases/regression/issue-2196.json` | ModSecurity_V3 | actions | `nolog,pass` rule should not create audit output | partial | xfail | actions, audit-log-absent, query args, phase1 | Local Apache/NGINX observed empty audit logs, but GitHub Actions observed a non-empty audit log; not counted as common PASS |
| `v3-imported/v3_transformation_trim_block.yaml` | `test/test-cases/regression/transformations.json` | ModSecurity_V3 | transformations | Trim transformation match | yes | fully-imported-common | transformations, query args, phase2 | Full upstream cookie/header matrix remains mapped |
| `v3-imported/v3_secaction_block.yaml` | `test/test-cases/regression/secruleengine.json` | ModSecurity_V3 | actions | Minimal disruptive `SecAction` | yes | fully-imported-common | actions, phase2 | DetectionOnly/off branches remain mapped |

## Mapped/XFail Body And Filter Cases

| Source case | original_path | source_repo | category | portable | status | reason | required_capabilities | known_limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `response_body_basic_block` | `tests/modsecurity-response-body.t`; `tests/regression/config/10-response-directives.t`; `test/test-cases/regression/variable-RESPONSE_BODY.json`; ModSecurity-nginx PR #377 | nginx/apache/v3 | response-body | partial | xfail | Dedicated Phase 9 probe kept outside active smoke: Apache and NGINX both returned HTTP 200 instead of stable HTTP 403. PR #377 source is applied but not promoted. | response body, phase4, intervention, audit log | Not counted as common PASS and not executed by `smoke-common`; see `docs/testing/response-body-blocking-investigation.md` |
| `multipart_parser_edge_cases` | `tests/regression/misc/00-multipart-parser.t`; v3 multipart variable regressions | apache/v3 | multipart | partial | mapped-only | Basic FILES/FILES_NAMES/FILES_COMBINED_SIZE/MULTIPART_FILENAME smokes are active; parser errors, temp paths, and malformed bodies are not | multipart, file collections | Active common YAML does not cover malformed multipart or temp-file paths |
| `xml_schema_dtd_parser_cases` | `tests/regression/rule/10-xml.t`; v3 XML parser regressions | apache/v3 | body-processors | partial | mapped-only | Basic XML body processing is active; schema/DTD/parser-error fixtures are not | XML, request body, fixtures | Needs fixture materialization and separate failure-mode expectations |
