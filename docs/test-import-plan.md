# Test Import Plan

Status: implemented

This document records the current import policy for local connector tests. The
source repositories under `<workspace>/*` are read-only references. No
upstream Apache or NGINX test file is copied verbatim into this repository.

## Inventory

Observed local source inventory on 2026-05-15:

| Source | Relevant files analyzed | Notes |
| --- | ---: | --- |
| `<workspace>/ModSecurity-apache/tests/` | 29 | Apache regression `.t`, `.t.in`, and harness files |
| `<workspace>/ModSecurity-nginx/tests/` | 17 | NGINX `.t`, README, and converter files |
| `<workspace>/ModSecurity_V2/tests/` | 115 | v2 operator, transformation, and regression files used only as semantics/reference material |
| `<workspace>/ModSecurity_V3/test/` | 264 | v3 API/regression files; 195 JSON regression cases under `test/test-cases/regression/` |

Every relevant source file is mapped in:

- `tests/apache/apache-regression-map.md`
- `tests/nginx/nginx-regression-map.md`
- `docs/imports/common/shared-case-origin-map.md`
- `docs/imports/common/v2-regression-map.md`
- `docs/imports/common/v3-regression-map.md`
- `docs/v2-vs-v3-test-compatibility.md`

## Import Rules

- Common cases are allowed only when the rule, request, and expectation are
  connector-neutral and can run through both Apache and NGINX PoC harnesses.
- Apache-only cases belong under `tests/cases/connector-specific/apache/`.
- NGINX-only cases belong under `tests/cases/connector-specific/nginx/`.
- Cases that need HTTP/2, proxy topology, multipart parsing, streaming,
  response-body filters, config inheritance, debug log text, remote rules, or
  external data files remain mapped until the harness has explicit support.
- Simple multipart text-field bodies are supported; multipart parser errors,
  file-storage collections, and part-header edge cases remain mapped.
- Response-body pass-through may be imported when both connectors return the
  expected HTTP status. Response-body blocking is not counted as common PASS
  unless both connectors return stable HTTP 403.
- Imported YAML must include `origin`, `category`, `capabilities`, `portable`,
  `status`, and `known_limitations`; connector-specific YAML must include
  `connector`.
- Active V2/V3-derived common cases must pass on both Apache and NGINX before
  they are counted as `fully-imported-common`.
- API-only v3 cases stay mapped to the connector-free v3 API smoke area until a
  dedicated API smoke target exists; they are not folded into connector
  `smoke-all`.

## Imported Common Cases

The following source-derived common cases were added under
`tests/cases/`:

| Case | Source basis | Category | Expected behavior |
| --- | --- | --- | --- |
| `action_deny_phase1.yaml` | Apache disruptive actions; NGINX phase action tests | actions | HTTP 403 |
| `action_deny_phase2.yaml` | Apache disruptive actions; NGINX phase action tests | actions | HTTP 403 |
| `action_allow_phase1_pass.yaml` | Apache allow-before-deny action test | actions | HTTP 200 origin body |
| `collection_args_names_block.yaml` | Apache `ARGS_NAMES` target test | collections | HTTP 403 |
| `collection_args_get_block.yaml` | Apache `ARGS_GET` target test; NGINX ARGS tests | collections | HTTP 403 |
| `collection_args_combined_size_block.yaml` | Apache `ARGS_COMBINED_SIZE` target test | collections | HTTP 403 |
| `request_body_args_post_names_block.yaml` | Apache `ARGS_POST_NAMES`; NGINX request-body tests | request-body | HTTP 403 |
| `request_body_raw_text_block.yaml` | NGINX raw `REQUEST_BODY`; Apache raw body pattern | request-body | HTTP 403 |
| `json_request_body_block.yaml` | Apache JSON parser coverage; NGINX request-body tests | body-processors | HTTP 403 |
| `multipart_basic_block.yaml` | Apache normal multipart parser coverage; NGINX request-body tests | multipart | HTTP 403 |
| `response_body_pass.yaml` | Apache response directives; NGINX response-body access tests | response-body | HTTP 200 |
| `action_status_401_phase1_block.yaml` | NGINX `modsecurity.t` block401; Apache disruptive-action compatibility | actions | HTTP 401 |
| `v2_operator_streq_block.yaml` | V2 `tests/op/streq.t` | operators | HTTP 403 |
| `v2_operator_contains_block.yaml` | V2 `tests/op/contains.t` | operators | HTTP 403 |
| `v2_operator_begins_with_block.yaml` | V2 `tests/op/beginsWith.t` with param `abcdef`, input `abcdefghi` | operators | HTTP 403 |
| `v2_operator_ends_with_block.yaml` | V2 `tests/op/endsWith.t` with param `ghi`, input `abcdefghi` | operators | HTTP 403 |
| `v2_operator_pm_block.yaml` | V2 `tests/op/pm.t` with param `abc`, input `abcdefghi` | operators | HTTP 403 |
| `v2_operator_contains_word_block.yaml` | V2 `tests/op/containsWord.t` with param `abc`, input `abc def ghi` | operators | HTTP 403 |
| `v2_transformation_lowercase_block.yaml` | V2 `tests/tfn/lowercase.t` | transformations | HTTP 403 |
| `v2_transformation_trim_block.yaml` | V2 `tests/tfn/trim.t` | transformations | HTTP 403 |
| `v2_transformation_url_decode_block.yaml` | V2 `tests/tfn/urlDecode.t` with input `Test+Case`, output `Test Case` | transformations | HTTP 403 |
| `v2_transformation_html_entity_decode_block.yaml` | V2 `tests/tfn/htmlEntityDecode.t` fragment `&lt;&gt;` -> `<>` | transformations | HTTP 403 |
| `multipart_files_value_block.yaml` | V3 `variable-FILES.json` | multipart/files | HTTP 403 |
| `multipart_files_names_block.yaml` | V3 `variable-FILES_NAMES.json` | multipart/files | HTTP 403 |
| `multipart_files_combined_size.yaml` | V3 `variable-FILES_COMBINED_SIZE.json` | multipart/files | HTTP 403 |
| `multipart_filename_block.yaml` | V3 `variable-MULTIPART_FILENAME.json` | multipart/files | HTTP 403 |
| `xml_request_body_block.yaml` | V3 `variable-XML.json` | xml/body-processors | HTTP 403 |
| `v3_operator_rx_block.yaml` | V3 `operator-rx.json` | operators | HTTP 403 |
| `v3_operator_pm_digit_block.yaml` | V3 `operator-pm.json` with rule `@pm 1 2 3`, request `param1=123` | operators | HTTP 403 |
| `v3_request_cookies_block.yaml` | V3 `variable-REQUEST_COOKIES.json` with `USER_TOKEN=Yes` | collections | HTTP 403 |
| `v3_request_cookies_names_block.yaml` | V3 `variable-REQUEST_COOKIES_NAMES.json` with cookie name `USER_TOKEN` | collections | HTTP 403 |
| `v3_request_headers_names_block.yaml` | V3 `variable-REQUEST_HEADERS_NAMES.json`, adapted to stable custom header name | collections | HTTP 403 |
| `v3_args_names_get_block.yaml` | V3 `variable-ARGS_NAMES.json` with GET argument name `key1` | collections | HTTP 403 |
| `v3_auditlog_serial_fields_block.yaml` | V3 `auditlog.json` and `issue-2000.json` stable serial audit fields | audit-log | HTTP 403 plus audit fields |
| `v3_transformation_trim_block.yaml` | V3 `transformations.json` | transformations | HTTP 403 |
| `v3_secaction_block.yaml` | V3 `secruleengine.json` | actions | HTTP 403 |

These cases are imported as portable candidates. They count as proven only in an
environment where both connector smokes observe the expected HTTP behavior.

Observed locally on 2026-05-15 with
`BUILD_ROOT=/src/ModSecurity-test-Framework-build`, targeted `make smoke-common`
runs reported the V2/V3-derived active imports as `PASS` on Apache and NGINX.
The second import wave added 13 active PASS cases using source-confirmed values
for `urlDecode`, `htmlEntityDecode`, `pm`, and `containsWord`; none of these
cases uses invented example values.

`v3_action_nolog_pass_no_audit.yaml` was moved out of active common discovery
after GitHub Actions reported `expected audit log to be absent or empty`.
Local Apache and NGINX runs observed HTTP 200 with empty audit logs, so the case
remains probeable under `tests/cases/` but is not counted as stable
common PASS.

## Body And Filter Import Notes

The response-body block candidate is deliberately not active common coverage.
`ModSecurity-nginx/tests/modsecurity-response-body.t` marks the blocking branch
as TODO. The dedicated local probe in
`tests/cases/response/body/response_body_basic_block.yaml` ran three repeats:
Apache returned HTTP 200 without the required audit hit, while NGINX matched the
phase 4 `RESPONSE_BODY` rule and wrote audit/error evidence but returned an
empty client reply (`000`) instead of stable HTTP 403. The source rows remain
`xfail`/`mapped-only`, while `response_body_pass.yaml` remains a pass-through
smoke only.

`multipart_basic_block.yaml` covers a simple multipart text field visible
through `ARGS:name`. V3-derived FILES, FILES_NAMES, FILES_COMBINED_SIZE, and
MULTIPART_FILENAME smoke cases are now active common coverage. Upload temporary
paths, malformed multipart bodies, streaming, and part-header edge cases remain
mapped until they can be proven without connector-specific setup.

`json_request_body_block.yaml` matches raw `REQUEST_BODY` content. Parsed JSON
collection extraction from Apache `rule/15-json.t` remains mapped because the
current shared smoke path does not prove `ARGS:foo` parity.

## Imported Connector-Specific Cases

The following NGINX-specific cases were added under
`tests/cases/connector-specific/nginx/`:

| Case | Source basis | Category | Expected behavior | Why connector-specific now |
| --- | --- | --- | --- | --- |
| `nginx_redirect_phase1_302.yaml` | `tests/modsecurity.t` redirect302 | actions | HTTP 302 | Imported from NGINX tests and not yet proven against Apache |
| `nginx_tx_scoring_absolute_block.yaml` | `tests/modsecurity-scoring.t` absolute score | actions | HTTP 403 | Imported from NGINX tests and not yet proven against Apache |
| `nginx_tx_scoring_iterative_block.yaml` | `tests/modsecurity-scoring.t` iterative score | actions | HTTP 403 | Imported from NGINX tests and not yet proven against Apache |

Apache-specific candidates reviewed in this pass mostly require Apache::Test
context, httpd config inheritance, or Apache-specific runtime setup, so they
are mapped rather than ported.

Observed locally on 2026-05-15 with
`BUILD_ROOT=/src/ModSecurity-test-Framework-build`, `make smoke-all` reported all
three NGINX-specific imported cases as `PASS` on NGINX.

## Smoke Scopes

The smoke targets use explicit scopes:

```sh
make smoke-common  # common minimal + common imported cases on Apache and NGINX
make smoke-apache  # common cases + Apache-specific imported cases on Apache
make smoke-nginx   # common cases + NGINX-specific imported cases on NGINX
make smoke-all     # all applicable cases on the matching connector
```

`SMOKE_CASES` can still name individual cases or paths. The Python case CLI now
resolves names within the selected scope, validates portability metadata, and
writes detailed result summaries under `$BUILD_ROOT/results/`.

## Deferred Categories

| Category | Status | Reason |
| --- | --- | --- |
| multipart | imported | Simple text-field and V3-derived FILES/FILES_NAMES/FILES_COMBINED_SIZE/MULTIPART_FILENAME cases are active common coverage |
| http2 | blocked | Current harnesses are HTTP/1.1 local smokes |
| proxy | todo | No upstream topology support yet |
| streaming-buffering | todo | No streaming assertions or chunk control yet |
| response-body | todo | Connector filter ordering needs explicit support |
| response-body blocking | xfail | NGINX upstream marks block behavior TODO and local probing did not yield stable HTTP 403 |
| response-body pass-through | imported | `response_body_pass.yaml` verifies no regression when response-body access is enabled |
| multipart basic text field | imported | `multipart_basic_block.yaml` covers simple portable multipart parsing |
| multipart file collections | imported | FILES, FILES_NAMES, FILES_COMBINED_SIZE, and MULTIPART_FILENAME have active common smoke coverage; FILES_TMPNAMES remains mapped |
| XML | imported | Tiny XML body processor case is active common coverage; schema/DTD/parser-error cases remain mapped |
| v2 engine semantics | imported | Operator and transformation cases are active common coverage, including beginsWith, endsWith, pm, containsWord, urlDecode, and htmlEntityDecode |
| v3 regression JSON | imported | Multipart/XML/operator/action/cookie/header-name/ARGS_NAMES/audit cases are active common coverage; `issue-2196` nolog/pass is xfail due local/CI audit divergence |
| external file operators | todo | Needs fixture-file materialization |
| debug logs | mapped | Text is volatile and connector-specific |

## PR #3564 RAW Argument Collections

PR #3564 adds six RAW URL-encoded argument collections:

- `ARGS_RAW`
- `ARGS_GET_RAW`
- `ARGS_POST_RAW`
- `ARGS_NAMES_RAW`
- `ARGS_GET_NAMES_RAW`
- `ARGS_POST_NAMES_RAW`

The currently configured local `ModSecurity_V3` source does not contain these
collections, so they are not active YAML cases. The import status is
`mapped-only/unsupported-local-source`.

Future promotion requires:

1. `MODSECURITY_V3_SOURCE_DIR` points at a v3 source that contains RAW
   collection support.
2. The YAML cases are derived from that source's RAW regression data rather than
   invented examples.
3. Apache and NGINX both return the YAML-expected HTTP behavior through
   `make smoke-all`.
