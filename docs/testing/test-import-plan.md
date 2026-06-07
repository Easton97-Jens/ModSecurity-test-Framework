# Test Import Plan

Status: implemented

This document records the current import policy for connector tests. Historical
local source repositories were read-only references during import; upstream
GitHub repositories remain the portable attribution references for reviews. No
upstream Apache or NGINX test file is copied verbatim into this repository, and
runtime connector source now comes from this repository by default.

## Inventory

Observed local source inventory on 2026-05-15:

| Source | Reference role | Upstream | Relevant files analyzed | Notes |
| --- | --- | --- | ---: | --- |
| ModSecurity-apache tests | historical import/reference | https://github.com/owasp-modsecurity/ModSecurity-apache | 29 | Apache regression `.t`, `.t.in`, and harness files |
| ModSecurity-nginx tests | historical import/reference | https://github.com/owasp-modsecurity/ModSecurity-nginx | 17 | NGINX `.t`, README, and converter files |
| ModSecurity v2 tests | historical semantics reference | https://github.com/owasp-modsecurity/ModSecurity | 115 | v2 operator, transformation, and regression files used only as semantics/reference material |
| ModSecurity v3 tests | configured engine source reference | https://github.com/owasp-modsecurity/ModSecurity | 264 | v3 API/regression files; 195 JSON regression cases under `test/test-cases/regression/` |

Every relevant source file is mapped in:

- `docs/testing/imports/apache-regression-map.md`
- `docs/testing/imports/nginx-regression-map.md`
- `docs/imports/common/shared-case-origin-map.md`
- `docs/imports/common/v2-regression-map.md`
- `docs/imports/common/v3-regression-map.md`
- `docs/testing/v2-vs-v3-test-compatibility.md`

ModSecurity-nginx PR #377 tests are inventoried separately in
`docs/testing/pr377-test-import-map.md` because they come from a temporary
`$BUILD_ROOT` PR checkout rather than the read-only local NGINX reference repo.

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

Observed locally on 2026-05-15 with an explicit external `BUILD_ROOT`, targeted
`make smoke-common` runs reported the V2/V3-derived active imports as `PASS` on
Apache and NGINX.
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
as TODO. ModSecurity-nginx PR #377
(https://github.com/owasp-modsecurity/ModSecurity-nginx/pull/377) source
changes are now applied to adapter-owned NGINX source, but that source intake is
not a response-body promotion. The dedicated local probe in
`tests/cases/response/body/response_body_basic_block.yaml` ran three repeats:
Apache and NGINX both returned HTTP 200 instead of stable HTTP 403. The source
rows remain `former expected-failure`/`mapped-only`, while `response_body_pass.yaml` remains a
pass-through smoke only. In the latest 2026-05-21 NGINX run that pass-through
case returned HTTP 200 after the harness permission fix, but it is still not
RESPONSE_BODY promotion.

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
| `nginx_phase4_minimal_log_only.yaml` | PR #377 `tests/modsecurity-phase4-modes.t` minimal branch | response-body/phase4 | HTTP 200 body preserved plus phase4 `log_only`/`mode_minimal` evidence | NGINX-only directive behavior; not a response-body blocking promotion |
| `nginx_phase4_safe_log_only.yaml` | PR #377 `tests/modsecurity-phase4-modes.t` safe branch | response-body/phase4 | HTTP 200 body preserved plus phase4 `log_only`/`mode_safe` evidence | NGINX-only directive behavior; not a response-body blocking promotion |
| `nginx_phase4_content_type_out_of_scope.yaml` | PR #377 `tests/modsecurity-phase4-content-types.t` out-of-scope branch | response-body/phase4 | HTTP 200 body preserved plus `content_type_not_in_scope` phase4 evidence | NGINX-only directive behavior; not a response-body blocking promotion |

Apache-specific candidates reviewed in this pass mostly require Apache::Test
context, httpd config inheritance, or Apache-specific runtime setup, so they
are mapped rather than ported.

Observed locally on 2026-05-15 with an explicit external `BUILD_ROOT`,
`make smoke-all` reported the original NGINX-specific imported cases as `PASS`
on NGINX. A 2026-05-20 NGINX source-built run exposed a harness permission
blocker for the PR #377 expected-200 phase-4 probes, but the 2026-05-21 rerun
after the harness permission fix returned HTTP 200 for all three active
phase-4 log-only probes. Strict/invalid-config/large-response response-body
branches remain former expected-failure or mapped-only in
`docs/testing/pr377-test-import-map.md`.

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
| response-body blocking | non-promoted | NGINX upstream marks block behavior TODO and local probing did not yield stable HTTP 403 |
| response-body pass-through | pass-through evidence in latest NGINX run | `response_body_pass.yaml` returned HTTP 200 after the NGINX harness permission fix; this is not RESPONSE_BODY blocking verification |
| multipart basic text field | imported | `multipart_basic_block.yaml` covers simple portable multipart parsing |
| multipart file collections | imported | FILES, FILES_NAMES, FILES_COMBINED_SIZE, and MULTIPART_FILENAME have active common smoke coverage; FILES_TMPNAMES remains mapped |
| XML | imported | Tiny XML body processor case is active common coverage; schema/DTD/parser-error cases remain mapped |
| v2 engine semantics | imported | Operator and transformation cases are active common coverage, including beginsWith, endsWith, pm, containsWord, urlDecode, and htmlEntityDecode |
| v3 regression JSON | imported | Multipart/XML/operator/action/cookie/header-name/ARGS_NAMES/audit cases are active common coverage; `issue-2196` nolog/pass keeps former expected-failure history due local/CI audit divergence |
| external file operators | todo | Needs fixture-file materialization |
| debug logs | mapped | Text is volatile and connector-specific |

## Incremental Negative/Pass-through Additions (2026-05-19)

Added source-derived portable negative/pass-through cases without changing connector runtime semantics:

- `tests/cases/negative-pass-through/v3_request_cookies_names_pass_no_match.yaml` (source: `ModSecurity_V3` `variable-REQUEST_COOKIES_NAMES.json`)
- `tests/cases/negative-pass-through/v3_args_names_get_pass_no_match.yaml` (source: `ModSecurity_V3` `variable-ARGS_NAMES.json`)
- `tests/cases/negative-pass-through/v2_transformation_url_decode_pass_no_match.yaml` (source: `ModSecurity_V2` `tests/tfn/urlDecode.t`)
- `tests/cases/negative-pass-through/v3_request_cookies_pass_no_match.yaml` (source: `ModSecurity_V3` `variable-REQUEST_COOKIES.json`)
- `tests/cases/negative-pass-through/v3_request_headers_names_pass_no_match.yaml` (source: `ModSecurity_V3` `variable-REQUEST_HEADERS_NAMES.json`)

These cases are intentionally pass-through (`expect.status: 200`) and serve as
negative-branch evidence for REQUEST_COOKIES/REQUEST_COOKIES_NAMES,
REQUEST_HEADERS_NAMES, ARGS_NAMES, and REQUEST_URI+t:urlDecode coverage. Apache
and NGINX passed them in the latest source-built runs after the NGINX harness
permission fix. They are current local runtime pass-through evidence, not
automatic promotion for broader former expected-failure/future edge cases.

## Compatibility Expansion Wave (2026-05-19, pending/former expected-failure)

Added 10 source-derived YAML compatibility candidates under `tests/cases/` for known gaps and future targets:

- header/cookie/ARGS name runtime-difference or connector-gap probes
- transformation edge probes (`trim` tab branch, `urlDecode` invalid sequence, `removeNulls`)
- parser/runtime gap probes (invalid JSON, malformed XML)
- response-header multi-value runtime-gap probe

These are intentionally not promoted to active verified PASS coverage and remain former expected-failure/pending runtime verification.

## Operator/Transformation/Phase Expansion (2026-05-19)

Added 16 additional source-derived `former expected-failure` common cases for:
- operators: `@contains`, `@beginsWith`, `@endsWith`, `@streq`, `@rx` (mostly no-match/pass-through targets)
- transformations: `t:none`, `t:lowercase`, `t:trim`, `t:urlDecode`, `t:urlDecodeUni`, `t:compressWhitespace`
- phase handling: phase-1 vs phase-2 behavior probes
- edge/parser: semicolon query, missing header, plus-vs-space decode, empty JSON body

These cases are intentionally tracked as pending/former expected-failure compatibility targets and are not promoted to verified PASS without full runtime evidence.

## Audit/Normalization/Parser Expansion (2026-05-19)

Added 12 additional source-derived former expected-failure compatibility probes for:
- audit-log presence/normalization/multiline and matched-var evidence
- duplicate collection/name normalization (headers/cookies/args)
- parser partial-body edges (JSON/XML)
- transformation-chain behavior (`lowercase+trim`, `urlDecode+compressWhitespace`)

All remain pending runtime verification and are excluded from verified PASS accounting.

## Multipart/FILES/Unicode/Parser Expansion (2026-05-19)

Added 16 additional source-derived former expected-failure compatibility probes covering:
- FILES/FILES_NAMES and multipart edge behavior (boundary, duplicate fields, filename normalization)
- Unicode/encoding normalization and decode-chain behavior
- complex JSON/XML structure and parser-edge probes
- benign XSS-like and SQLi-like normalization/transformation compatibility probes

All are tracked as pending runtime verification and are not promoted to verified PASS.

## Phase-3/Phase-4 Expansion (2026-05-19)

Added 12 source-derived former expected-failure probes focused on outbound processing:
- phase-3 response-header normalization/duplicate/multi-value/missing behavior
- phase-4 response-body experimental probes (empty/unicode/chunk/compressed/html)
- phase-4 outbound audit-log behavior probes (rule-id/message expectations)

These remain non-verified compatibility probes. RESPONSE_BODY is intentionally not promoted to verified PASS.

## Phase-3/4 follow-up expansion (2026-05-19)

Added 10 additional source-derived former expected-failure probes for:
- phase-3 response header presence/charset/location/set-cookie behavior
- phase-4 response-body no-match/buffering/entity-decode assumptions
- phase-4 outbound audit matched-var/escaped/multiline assumptions

These remain compatibility probes only and are not promoted to verified PASS.

## Generated Coverage Reporting

The repository now provides generated matrix/coverage reporting:

- Human entry page: `docs/testing/test-coverage-overview.md`
- Machine-generated detail pages under `docs/testing/generated/*.generated.md`

Commands:

```sh
make generate-test-matrix
make check-test-matrix
```

Data sources include test case YAML files under `tests/cases/`, `tests/cases/connector-specific/apache/`, `tests/cases/connector-specific/nginx/`, plus `config/testing/import-status.json`.

Important: generated reports are **not** runtime PASS proof. Authoritative runtime verification remains `make smoke-all`.
