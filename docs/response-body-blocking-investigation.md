# Response-Body Blocking Investigation

Status: xfail/mapped-only

This investigation checks whether a shared `RESPONSE_BODY` blocking case can be
promoted to active common connector coverage. It uses real connector paths only:

```text
Client -> Apache/NGINX -> connector module -> libmodsecurity -> RESPONSE_BODY -> HTTP response
```

The direct libmodsecurity API smoke is not counted here.

## Source Evidence

| Source | Evidence | Import decision |
| --- | --- | --- |
| `ModSecurity-apache/tests/regression/config/10-response-directives.t` | Contains `SecResponseBodyAccess On`, `SecResponseBodyMimeType text/plain null`, and a `RESPONSE_BODY` deny rule expecting HTTP 403. | Source-derived probe candidate |
| `ModSecurity-nginx/tests/modsecurity-response-body.t` | Contains a comparable `RESPONSE_BODY` deny test, but the upstream Test::Nginx case marks it `TODO: not yet`. | xfail source |
| `ModSecurity_V2/tests/regression/config/10-response-directives.t` | Historical response directive coverage, including response-body blocking expectations. | Compatibility reference |
| `ModSecurity_V3/test/test-cases/regression/variable-RESPONSE_BODY.json` | V3 regression expects `SecRule RESPONSE_BODY "@contains denystring" ... deny` to return HTTP 403. | Engine/reference evidence |

No upstream test file was copied. The local YAML is a minimal derived probe at
`tests/common/cases/xfail/response_body_basic_block.yaml`.

## Probe

Command:

```sh
BUILD_ROOT=/src/ModSecurity-test-Framework-build make probe-response-body || true
```

Probe defaults:

- `RESPONSE_BODY_PROBE_REPEAT=3`
- Probe root: `/src/ModSecurity-test-Framework-build/response-body-probe`
- Summary: `/src/ModSecurity-test-Framework-build/response-body-probe/results/response-body-probe-summary.json`

The probe case enables serial audit logging and requires the ModSecurity audit
entry for rule `1801`. This prevents a server-generated 403 from being counted
as a ModSecurity response-body block.

## Observed Result

Observed locally on 2026-05-15:

| Connector | Repeats | HTTP result | Evidence | Classification |
| --- | ---: | --- | --- | --- |
| Apache | 0 pass / 3 fail / 0 blocked | HTTP 200 each run | Response body contained `safe response-attack body`; audit log was empty. | fail |
| NGINX | 0 pass / 3 fail / 0 blocked | Curl observed `000` / empty reply | NGINX error/audit logs show phase 4 `RESPONSE_BODY` rule `1801` matched, then NGINX logged `header already sent while sending response to client`. | fail |

Important distinction: NGINX did reach libmodsecurity and matched
`RESPONSE_BODY`, but it did not return a stable HTTP 403 to the client. That is
not a connector PASS under this repository's rules.

Relevant logs:

- Apache repeat 1:
  `/src/ModSecurity-test-Framework-build/response-body-probe/logs/apache/repeat-1/response_body_basic_block/`
- NGINX repeat 1:
  `/src/ModSecurity-test-Framework-build/response-body-probe/logs/nginx/repeat-1/response_body_basic_block/`

## Decision

`response_body_basic_block` remains `xfail`/`mapped-only`.

It is not promoted to:

- `tests/common/cases/imported/`
- `tests/apache/cases/imported/`
- `tests/nginx/cases/imported/`

`RESPONSE_BODY` remains excluded from `verified_variables`. Active
`response_body_pass.yaml` continues to prove only pass-through behavior with
response-body access enabled; it does not prove response-body blocking.

## Next Steps

- Investigate why Apache does not apply the phase 4 `RESPONSE_BODY` rule to the
  static fixture in this minimal harness.
- Investigate the NGINX filter path that matches `RESPONSE_BODY` but produces an
  empty client reply instead of HTTP 403.
- Try a connector-specific response fixture path only after documenting why the
  current static fixture path is insufficient.
