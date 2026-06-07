# TODO Inventory

Status: implemented

This inventory tracks actionable work markers and status-labelled planning
entries. It intentionally excludes runtime status strings such as shell
`blocked()` functions, JSON counters, and ordinary result vocabulary.

## Summary

| Category | Count | Notes |
| --- | ---: | --- |
| Owned open/planned items | 23 | Common, schema, normalizer, connector, and future-connector planning |
| Owned former expected-failure/mapped evidence | 4 | `RESPONSE_BODY`, `v3_action_nolog_pass_no_audit`, RAW-ARGS, response-body pass-through caveat |
| Resolved owned items | 1 | Common metadata helper implementations added in Refactor Phase 3 |
| Imported/upstream-derived markers | 22 | Kept untouched in adapter-owned Apache and NGINX source; classified as adapter-owned-source |
| Obsolete/resolved markers cleaned | 11 | Owned `TODO:` headings replaced with tracked inventory references |

## Inventory

| file | line | marker | text | category | status | priority | owner_area | action |
| --- | ---: | --- | --- | --- | --- | --- | --- | --- |
| `common/docs/design.md` | 58 | open work | Define ownership rules for header and body buffers | refactor | planned | P1 | common | Design before moving adapter logic into `common/` |
| `common/docs/design.md` | 59 | open work | Decide where neutral status values become part of future adapter APIs | refactor | planned | P2 | common | Revisit during first adapter API proposal |
| `common/docs/design.md` | 60 | open work | Add compile tests proving headers remain connector-independent | test | planned | P2 | common | Add when Common headers become build inputs |
| `common/src/README.md` | 19 | phase 3 resolved | Add implementation files only after a connector-neutral need exists | refactor | resolved | P3 | common | Metadata-only Common C helpers now exist; broader runtime extraction remains deferred |
| `docs/imports/common/schema.md` | 67 | open work | Define a machine-readable JSON schema | test | planned | P1 | docs/imports/common | Add schema after YAML shape stabilizes |
| `docs/imports/common/schema.md` | 68 | open work | Reject connector-specific fields in common schema validation | test | planned | P1 | docs/imports/common | Add with machine-readable schema |
| `modules/ModSecurity-test-Framework/tests/normalizers/README.md` | 18 | open work | Header order normalization | test | planned | P2 | normalizers | Add artifact-specific parser |
| `modules/ModSecurity-test-Framework/tests/normalizers/README.md` | 19 | open work | Audit log section parsing | audit-log | planned | P2 | normalizers | Add stable section-aware parser |
| `modules/ModSecurity-test-Framework/tests/normalizers/README.md` | 20 | open work | Connector-specific log formats | connector | deferred | P3 | connector tests | Keep in connector-specific normalizers |
| `connectors/apache/TODO.md` | 1 | planning file | Apache-specific build/runtime/refactor items | connector | planned | P1 | apache | Keep as connector-local checklist linked to this inventory |
| `connectors/nginx/TODO.md` | 1 | planning file | NGINX-specific build/runtime/refactor items | connector | planned | P1 | nginx | Keep as connector-local checklist linked to this inventory |
| `connectors/haproxy/TODO.md` | 3 | `Status: unknown` | Integration path undecided | future-connector | planned | P2 | haproxy | Decide after Common stabilization |
| `connectors/envoy/TODO.md` | 3 | `Status: unknown` | Integration path undecided | future-connector | planned | P2 | envoy | Decide after Common stabilization |
| `connectors/lighttpd/TODO.md` | 3 | `Status: unknown` | Integration path undecided | future-connector | planned | P2 | lighttpd | Decide after Common stabilization |
| `connectors/traefik/TODO.md` | 3 | `Status: unknown` | Integration path undecided | future-connector | planned | P2 | traefik | Decide after Common stabilization |
| `connectors/apache/docs/architecture.md` | 16 | open work | Exact hook order for a new adapter | connector | planned | P1 | apache | Document before maintained Apache adapter changes |
| `connectors/apache/docs/build.md` | 56 | open work | Minimum Apache/APR/APR-util/PCRE requirements | ci | planned | P2 | apache | Record from reproducible build matrix |
| `connectors/nginx/docs/architecture.md` | 17 | open work | Exact phase/filter ordering for this repo | connector | planned | P1 | nginx | Document before maintained NGINX adapter changes |
| `connectors/nginx/docs/build.md` | 44 | open work | Supported NGINX versions and static module proof | ci | planned | P2 | nginx | Keep dynamic module as active PoC path |
| `connectors/*/docs/build.md` | 7 | open work | Future connector build docs | future-connector | planned | P2 | future-connectors | Fill only when a connector path is selected |
| `docs/testing/v3-api-smoke-test.md` | 281 | open work | Keep v3 build-copy path reproducible and document fallback behavior | test | planned | P2 | v3-api-smoke | Keep API smoke separate from connector proof |
| `docs/imports/import-analysis-modsecurity-v2.md` | 57 | open work | Per-test map from v2 Perl structures to v3 YAML cases | test | planned | P2 | imports | Continue source-derived mapping only |
| `docs/roadmap/roadmap.md` | 12 | RAW-ARGS | PR #3564-dependent RAW argument collection cases | raw-args | mapped | P1 | docs/imports/common | Activate only after local source support plus Apache/NGINX PASS |
| `docs/evidence/raw-args-pr3564.md` | 8 | PR #3564 | RAW argument collection evidence | raw-args | mapped | P1 | evidence | Keep mapped-only until support is proven |
| `docs/testing/response-body-blocking-investigation.md` | 1 | former expected-failure | Response-body blocking probe | response-body | former expected-failure | P1 | connectors | Do not promote until both connectors return stable HTTP 403 |
| `tests/cases/response/body/response_body_basic_block.yaml` | 1 | former expected-failure case | Shared response-body blocking probe | response-body | former expected-failure | P1 | docs/imports/common | Explicit probe only; excluded from normal discovery |
| `tests/cases/audit-log/v3_action_nolog_pass_no_audit.yaml` | 1 | former expected-failure case | `nolog,pass` audit absence differs locally vs CI | audit-log | former expected-failure | P2 | docs/imports/common | Keep probeable but not active common PASS |
| `connectors/apache/src/msc_filters.c` | 65 | upstream-derived FIXME | Apache response/body filter sanity note | response-body | mapped | P2 | adapter-owned-source | Leave untouched; track during response-filter refactor |
| `tests/cases/connector-specific/apache/run-regression-tests.pl.in` | 482 | upstream-derived TODO | Use `select()`/`poll()` in upstream harness | cleanup | deferred | P3 | adapter-owned-source | Not used by active smokes |
| `tests/cases/connector-specific/apache/regression/server_root/conf/httpd.conf.in` | 3 | upstream-derived TODO | Upstream regression template configurability | cleanup | deferred | P3 | adapter-owned-source | Retained as configure template |
| `connectors/nginx/src/ngx_http_modsecurity_module.c` | 245 | upstream-derived FIXME | Audit log response-code accuracy | audit-log | mapped | P2 | adapter-owned-source | Relevant to audit metadata review; do not edit without a dedicated NGINX adapter change |
| `connectors/nginx/src/ngx_http_modsecurity_module.c` | 826 | upstream-derived TODO | Log phase parity with Apache | audit-log | mapped | P2 | adapter-owned-source | Track before logging helper extraction |
| `connectors/nginx/src/ngx_http_modsecurity_header_filter.c` | 423 | upstream-derived XXX | `NOT_MODIFIED` header-filter behavior | response-body | mapped | P2 | adapter-owned-source | Relevant to response-filter evidence |
| `connectors/nginx/src/ngx_http_modsecurity_header_filter.c` | 439 | upstream-derived XXX | Already processed request question | response-body | mapped | P2 | adapter-owned-source | Relevant to response-filter evidence |
| `connectors/nginx/src/ngx_http_modsecurity_header_filter.c` | 440 | upstream-derived XXX | `ModSecurity off` behavior | response-body | mapped | P2 | adapter-owned-source | Relevant to response-filter evidence |
| `connectors/nginx/src/ngx_http_modsecurity_header_filter.c` | 445 | upstream-derived FIXME | Verify already processed request state | response-body | mapped | P2 | adapter-owned-source | Relevant to response-filter evidence |
| `connectors/nginx/src/ngx_http_modsecurity_header_filter.c` | 454 | upstream-derived FIXME | `SecResponseBody` disabled flag handling | response-body | mapped | P2 | adapter-owned-source | Relevant to PR #377 evidence |
| `connectors/nginx/src/ngx_http_modsecurity_body_filter.c` | 35 | upstream-derived XXX | Multiple body-filter behavior | response-body | mapped | P2 | adapter-owned-source | Relevant to response-filter evidence |
| `connectors/nginx/src/ngx_http_modsecurity_body_filter.c` | 168 | upstream-derived XXX | Last buffer / last chain handling | response-body | mapped | P2 | adapter-owned-source | Relevant to PR #377 evidence |
| `connectors/nginx/src/ngx_http_modsecurity_body_filter.c` | 182 | upstream-derived XXX | ModSecurity body transfer and content-length adjustment | response-body | mapped | P1 | adapter-owned-source | Relevant to PR #377 evidence |
| `connectors/nginx/src/ngx_http_modsecurity_body_filter.c` | 206 | upstream-derived XXX | Filter return behavior | response-body | mapped | P2 | adapter-owned-source | Relevant to response-filter evidence |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 80 | upstream-derived FIXME | Address metadata type choice | connector | mapped | P3 | adapter-owned-source | Candidate for request metadata mapping review |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 95 | upstream-derived FIXME | Earlier NGINX hook phase | connector | mapped | P2 | adapter-owned-source | Candidate for phase timing review |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 172 | upstream-derived FIXME | Finalizing request safely | connector | mapped | P1 | adapter-owned-source | Relevant before intervention extraction |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 291 | upstream-derived FIXME | Empty upstream marker | cleanup | deferred | P3 | adapter-owned-source | Leave untouched until adapter-owned cleanup is separately scoped |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 338 | upstream-derived TODO | `request_body_in_single_buf` benefit | request-body | mapped | P2 | adapter-owned-source | Candidate for request-body buffering review |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 386 | upstream-derived TODO | Stream chunks as they arrive | request-body | mapped | P2 | adapter-owned-source | Streaming remains out of active scope |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 425 | upstream-derived XXX | Chain processing and intervention timing | connector | mapped | P2 | adapter-owned-source | Candidate for intervention review |
| `connectors/nginx/src/ngx_http_modsecurity_access.c` | 445 | upstream-derived XXX | Body mutation/content-length adjustment | response-body | mapped | P1 | adapter-owned-source | Relevant to response-filter evidence |

## Cleaned Markers

The following owned markers were removed or replaced by inventory references:

- `common/docs/design.md` old `## TODO` heading.
- `common/src/README.md` old `TODO:` heading.
- `docs/imports/common/schema.md` old `TODO:` heading.
- `modules/ModSecurity-test-Framework/tests/normalizers/README.md` old `TODO:` heading.
- Connector-local `TODO.md` titles now use “Planning” while retaining the file
  names expected by workflow structure checks.
- Connector build/architecture docs now use “Open work” wording and point here.
- Apache and NGINX PoC docs now use “Tracked Open Work” and point here instead
  of keeping standalone TODO lists.
