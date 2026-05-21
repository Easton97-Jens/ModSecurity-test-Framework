# Response-Body Blocking Investigation

Status: xfail/mapped-only

This investigation checks whether a shared `RESPONSE_BODY` blocking case can be
promoted to active common connector coverage. It uses real connector paths only:

```text
Client -> Apache/NGINX -> connector module -> libmodsecurity -> RESPONSE_BODY -> HTTP response
```

The direct libmodsecurity API smoke is not counted here.

Related upstream PR: https://github.com/owasp-modsecurity/ModSecurity-nginx/pull/377
Related upstream repository: https://github.com/owasp-modsecurity/ModSecurity-nginx
Observed PR #377 head: `3d72b004ff27a78ea19c6b945870e2cae62a97ac`

## Source Evidence

| Source | Evidence | Import decision |
| --- | --- | --- |
| `ModSecurity-apache/tests/regression/config/10-response-directives.t` from https://github.com/owasp-modsecurity/ModSecurity-apache | Contains `SecResponseBodyAccess On`, `SecResponseBodyMimeType text/plain null`, and a `RESPONSE_BODY` deny rule expecting HTTP 403. | Source-derived probe candidate |
| `ModSecurity-nginx/tests/modsecurity-response-body.t` from https://github.com/owasp-modsecurity/ModSecurity-nginx | Contains a comparable `RESPONSE_BODY` deny test, but the upstream Test::Nginx case marks it `TODO: not yet`. PR #377 documents the phase-4/late intervention issue space. | xfail source |
| `ModSecurity_V2/tests/regression/config/10-response-directives.t` from https://github.com/owasp-modsecurity/ModSecurity | Historical response directive coverage, including response-body blocking expectations. | Compatibility reference |
| `ModSecurity_V3/test/test-cases/regression/variable-RESPONSE_BODY.json` from https://github.com/owasp-modsecurity/ModSecurity | V3 regression expects `SecRule RESPONSE_BODY "@contains denystring" ... deny` to return HTTP 403. | Engine/reference evidence |

## PR #377 Source Intake

Phase 9 applies the relevant PR #377 source changes to adapter-owned NGINX
files only:

- `connectors/nginx/src/ngx_http_modsecurity_body_filter.c`
- `connectors/nginx/src/ngx_http_modsecurity_common.h`
- `connectors/nginx/src/ngx_http_modsecurity_module.c`

The PR introduces phase-4/late-intervention configuration such as
`modsecurity_phase4_mode`, `modsecurity_phase4_content_types_file`, and
`modsecurity_phase4_log`. Raw PR tests and docs are not copied into the active
smoke suite.

This source intake does not change the classification below. A passing source
build and `smoke-nginx` prove only that the adapter-owned NGINX source compiles
and preserves active smoke behavior. `RESPONSE_BODY` still requires a separate
real-world Apache+NGINX blocking proof before promotion.

No upstream test file was copied. The local YAML is a minimal derived probe at
`tests/common/cases/xfail/response_body_basic_block.yaml`.

Phase 10 inventories the PR #377 tests in `pr377-test-import-map.md`. Three
NGINX-only mode/log probes were imported after 3/3 stable NGINX PASS results,
but they intentionally expect HTTP 200 pass-through and therefore do not verify
response-body blocking.

## Probe

Command:

```sh
BUILD_ROOT=$HOME/.local/state/ModSecurity-conector-build make probe-response-body || true
```

Probe defaults:

- `RESPONSE_BODY_PROBE_REPEAT=3`
- Probe root: `$BUILD_ROOT/response-body-probe`
- Summary: `$BUILD_ROOT/response-body-probe/results/response-body-probe-summary.json`

The probe case enables serial audit logging and requires the ModSecurity audit
entry for rule `1801`. This prevents a server-generated 403 from being counted
as a ModSecurity response-body block.

## Observed Result

Observed locally on 2026-05-17 after the Phase 9 NGINX adapter-owned source
migration and PR #377 source intake:

| Connector | Repeats | HTTP result | Evidence | Classification |
| --- | ---: | --- | --- | --- |
| Apache | 0 pass / 3 fail / 0 blocked | HTTP 200 each run | Response body contained `safe response-attack body`; audit log was empty. | fail |
| NGINX | 0 pass / 3 fail / 0 blocked | HTTP 200 each run | The active response-body blocking probe still did not return HTTP 403. | fail |

The previous pre-Phase-9 NGINX probe observed an empty client reply after a
phase-4 match. The current PR #377 source intake changes that observed symptom,
but it still does not provide the required real HTTP 403. That is not a
connector PASS under this repository's rules.

Relevant logs, under the configured `BUILD_ROOT`:

- Apache repeat 1:
  `$BUILD_ROOT/response-body-probe/logs/apache/repeat-1/response_body_basic_block/`
- NGINX repeat 1:
  `$BUILD_ROOT/response-body-probe/logs/nginx/repeat-1/response_body_basic_block/`

## Decision

`response_body_basic_block` remains `xfail`/`mapped-only`.

It is not promoted to:

- `tests/common/cases/imported/`
- `tests/apache/cases/imported/`
- `tests/nginx/cases/imported/`

`RESPONSE_BODY` remains excluded from `verified_variables`. Active
`response_body_pass.yaml` is only a pass-through probe with response-body access
enabled; it does not prove response-body blocking. In the latest NGINX runtime
snapshot, that pass-through probe returned HTTP 200 after the harness
permission fix. This is request/runtime pass-through evidence only; it does not
promote `RESPONSE_BODY` support or response-body blocking compatibility.

## Next Steps

- Investigate why Apache does not apply the phase 4 `RESPONSE_BODY` rule to the
  static fixture in this minimal harness.
- Investigate why the NGINX PR #377 source intake still leaves the shared
  blocking probe at HTTP 200 instead of HTTP 403.
- Try a connector-specific response fixture path only after documenting why the
  current static fixture path is insufficient.

## Additional phase-4 experimental probes (2026-05-19)

A dedicated xfail expansion added experimental phase-4 response-body probes (empty/unicode/chunk/compressed/html assumptions) plus outbound audit-log probes. These are compatibility tracking artifacts only and do not change the non-verified RESPONSE_BODY classification.

## Follow-up phase-4 probe wave (2026-05-19)

Additional phase-4 response-body and outbound audit probes were added as xfail/future/connector-gap tracking only. They do not alter the RESPONSE_BODY non-verified decision.
