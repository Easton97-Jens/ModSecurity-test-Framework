# ModSecurity v3 Regression Map

Status: implemented

Local source: `<local ModSecurity v3 checkout>/test/`
Upstream source: https://github.com/owasp-modsecurity/ModSecurity

The v3 tree is the primary architecture/API reference. Only source-derived,
connector-neutral YAML cases are imported into this monorepo; no upstream JSON
test file is copied verbatim.

Observed local inventory on 2026-05-15: 264 files under `test/`, including 195
JSON regression cases under `test/test-cases/regression/`.

| original_path | source_repo | version | category | purpose | portable | connector_specific | engine_specific | target_location | status | required_capabilities | known_limitations |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `test/test-cases/regression/variable-FILES.json` | ModSecurity_V3 | v3/master observed 3.0.15 | multipart | Uploaded file value collection | yes | no | yes | `tests/common/cases/v3-imported/multipart_files_value_block.yaml` | imported | multipart, files, collections | Converted to minimal deterministic multipart body and HTTP intervention |
| `test/test-cases/regression/variable-FILES_NAMES.json` | ModSecurity_V3 | v3/master observed 3.0.15 | multipart | Uploaded file field-name collection | yes | no | yes | `tests/common/cases/v3-imported/multipart_files_names_block.yaml` | imported | multipart, files, collections | Debug-log assertion converted to HTTP intervention |
| `test/test-cases/regression/variable-FILES_COMBINED_SIZE.json` | ModSecurity_V3 | v3/master observed 3.0.15 | multipart | Uploaded file size aggregation | yes | no | yes | `tests/common/cases/v3-imported/multipart_files_combined_size.yaml` | imported | multipart, files, collections | Uses a small body and lower threshold for deterministic smoke execution |
| `test/test-cases/regression/variable-MULTIPART_FILENAME.json` | ModSecurity_V3 | v3/master observed 3.0.15 | multipart | Multipart filename variable | yes | no | yes | `tests/common/cases/v3-imported/multipart_filename_block.yaml` | imported | multipart, files | Filename encoding and malformed headers remain mapped only |
| `test/test-cases/regression/variable-XML.json` | ModSecurity_V3 | v3/master observed 3.0.15 | xml | XML request-body processor and XML collection | yes | no | yes | `tests/common/cases/v3-imported/xml_request_body_block.yaml` | imported | xml, body-processors, collections | Schema/DTD/parser-error branches remain mapped |
| `test/test-cases/regression/operator-rx.json` | ModSecurity_V3 | v3/master observed 3.0.15 | operators | Regex operator behavior | yes | no | yes | `tests/common/cases/v3-imported/v3_operator_rx_block.yaml` | imported | operators, query-args | Regex error branches remain mapped only |
| `test/test-cases/regression/operator-pm.json` | ModSecurity_V3 | v3/master observed 3.0.15 | operators | Phrase-match operator behavior, including `@pm 1 2 3` with `param1=123` | yes | no | yes | `tests/common/cases/v3-imported/v3_operator_pm_digit_block.yaml` | imported | operators, query-args, phase1 | No-match branch remains mapped only |
| `test/test-cases/regression/transformations.json` | ModSecurity_V3 | v3/master observed 3.0.15 | transformations | Transformation behavior | yes | no | yes | `tests/common/cases/v3-imported/v3_transformation_trim_block.yaml` | imported | transformations, query-args | Full cookie/header fixture matrix remains mapped |
| `test/test-cases/regression/secruleengine.json` | ModSecurity_V3 | v3/master observed 3.0.15 | actions | SecAction and rule-engine behavior | yes | no | yes | `tests/common/cases/v3-imported/v3_secaction_block.yaml` | imported | actions, phase2 | DetectionOnly and disabled-engine branches remain mapped |
| `test/test-cases/regression/variable-REQUEST_COOKIES.json` | ModSecurity_V3 | v3/master observed 3.0.15 | collections | Cookie collection values, including `REQUEST_COOKIES:USER_TOKEN` value `Yes` | yes | no | yes | `tests/common/cases/v3-imported/v3_request_cookies_block.yaml` | imported | collections, request-cookies, phase1 | Cookie parsing edge cases remain mapped only |
| `test/test-cases/regression/variable-REQUEST_COOKIES_NAMES.json` | ModSecurity_V3 | v3/master observed 3.0.15 | collections | Cookie-name collection, including name `USER_TOKEN` | yes | no | yes | `tests/common/cases/v3-imported/v3_request_cookies_names_block.yaml` | imported | collections, request-cookies, phase1 | Name normalization edge cases remain mapped only |
| `test/test-cases/regression/variable-REQUEST_HEADERS_NAMES.json` | ModSecurity_V3 | v3/master observed 3.0.15 | collections | Request header-name collection | yes | no | yes | `tests/common/cases/v3-imported/v3_request_headers_names_block.yaml` | imported | collections, request-headers, phase1 | Uses stable custom header; implicit connector-added header matrix remains mapped |
| `test/test-cases/regression/variable-ARGS_NAMES.json` | ModSecurity_V3 | v3/master observed 3.0.15 | collections | Request argument-name collection, including GET names `key1` and `key2` | yes | no | yes | `tests/common/cases/v3-imported/v3_args_names_get_block.yaml` | imported | collections, args-names, query-args, phase2 | Duplicate and POST name branches remain mapped only |
| `test/test-cases/regression/auditlog.json` | ModSecurity_V3 | v3/master observed 3.0.15 | audit-log | Serial/parallel/JSON audit log behavior | partial | no | yes | `tests/common/cases/v3-imported/v3_auditlog_serial_fields_block.yaml` | imported/mapped | audit-log, query-args, phase1 | Active smoke checks only stable serial substrings; format variants remain mapped |
| `test/test-cases/regression/issue-2000.json` | ModSecurity_V3 | v3/master observed 3.0.15 | audit-log | Audit log part H output on deny | partial | no | yes | `tests/common/cases/v3-imported/v3_auditlog_serial_fields_block.yaml` | imported/mapped | audit-log, query-args, phase1 | Complete part comparison remains mapped |
| `test/test-cases/regression/issue-2196.json` | ModSecurity_V3 | v3/master observed 3.0.15 | actions | `nolog,pass` should not write audit output | partial | no | yes | `tests/common/cases/xfail/v3_action_nolog_pass_no_audit.yaml` | xfail | actions, audit-log-absent, query-args, phase1 | Local Apache/NGINX observed empty audit logs, but GitHub Actions observed audit output; not active common PASS |
| `test/test-cases/regression/request-body-parser-json.json` | ModSecurity_V3 | v3/master observed 3.0.15 | json | JSON body processor and parsed collections | partial | no | yes | maps | mapped-only | json, body-processors | Parsed JSON collection parity needs dedicated proof before active common import |
| `test/test-cases/regression/request-body-parser-xml*.json` | ModSecurity_V3 | v3/master observed 3.0.15 | xml | XML schema, DTD, and parser behavior | partial | no | yes | maps | mapped-only | xml, fixtures | External fixture/schema materialization not yet part of active smoke |
| `test/test-cases/regression/debug_log.json` | ModSecurity_V3 | v3/master observed 3.0.15 | logging | Debug log behavior | partial | partial | yes | maps | mapped-only | logging | Debug log text is volatile and connector-specific |
| `test/test-cases/regression/operator-*.json` | ModSecurity_V3 | v3/master observed 3.0.15 | operators | Operator matrix | partial | no | yes | future YAML imports or maps | mapped | operators | Optional-library and file-backed operators need capability gates/fixtures |
| `test/test-cases/regression/config-*.json` | ModSecurity_V3 | v3/master observed 3.0.15 | rule-parser | Directive/config behavior | partial | no | yes | maps | mapped-only | rule-parser | Some cases require files, network, or logging fixtures |
| `test/test-cases/regression/issue-*.json` | ModSecurity_V3 | v3/master observed 3.0.15 | regression | Specific bug regressions | unknown | unknown | unknown | maps | todo | case-specific | Requires per-case review before import |
| `test/test-cases/*.json` outside `regression/` | ModSecurity_V3 | v3/master observed 3.0.15 | api-smoke | C/C++ test harness data | partial | no | yes | `src/v3-api-smoke/` or maps | mapped-only | api-smoke | API-only cases are not folded into connector `smoke-all` yet |

## Active V3-Derived Imports

These active cases were observed locally through `make smoke-common` with
`BUILD_ROOT=<local-build-root>`; Apache and NGINX both returned
the expected HTTP 403.

| case | source | status |
| --- | --- | --- |
| `multipart_files_value_block.yaml` | `variable-FILES.json` | fully-imported-common |
| `multipart_files_names_block.yaml` | `variable-FILES_NAMES.json` | fully-imported-common |
| `multipart_files_combined_size.yaml` | `variable-FILES_COMBINED_SIZE.json` | fully-imported-common |
| `multipart_filename_block.yaml` | `variable-MULTIPART_FILENAME.json` | fully-imported-common |
| `xml_request_body_block.yaml` | `variable-XML.json` | fully-imported-common |
| `v3_operator_rx_block.yaml` | `operator-rx.json` | fully-imported-common |
| `v3_operator_pm_digit_block.yaml` | `operator-pm.json` | fully-imported-common |
| `v3_request_cookies_block.yaml` | `variable-REQUEST_COOKIES.json` | fully-imported-common |
| `v3_request_cookies_names_block.yaml` | `variable-REQUEST_COOKIES_NAMES.json` | fully-imported-common |
| `v3_request_headers_names_block.yaml` | `variable-REQUEST_HEADERS_NAMES.json` | fully-imported-common |
| `v3_args_names_get_block.yaml` | `variable-ARGS_NAMES.json` | fully-imported-common |
| `v3_auditlog_serial_fields_block.yaml` | `auditlog.json`; `issue-2000.json` | fully-imported-common |
| `v3_transformation_trim_block.yaml` | `transformations.json` | fully-imported-common |
| `v3_secaction_block.yaml` | `secruleengine.json` | fully-imported-common |
