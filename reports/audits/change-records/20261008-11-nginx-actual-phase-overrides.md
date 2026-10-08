# Change record

**Language:** English | [Deutsch](20261008-11-nginx-actual-phase-overrides.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-11-nginx-actual-phase-overrides |
| UTC date | 2026-10-08 |
| Framework base revision | `9f74f9b742af1498bd642f83306f40549f163f63` |

## Motivation and problem statement

NGX-only actual phase registrations. The body-pointer mapper guard and pre-commit soft Engine budget are observed at request_headers, not the generic Phase2/Phase4 contract views.

## Affected components and security boundaries

Only the two closed NGX descriptor overrides and strict case schema change. Generic case phases, other connectors, central normalization and native producers remain unchanged.

## Acceptance criteria

Exactly two NGX overrides phase=1; generic phases remain 2 and 4. Wrong, absent or non-integer overrides fail schema validation.

## Alternatives considered

Accepting generic Phase2/4 as native observation would invent a phase. Connector-local override preserves the generic contract while exposing actual P1.

## Implementation decision

Source access.c validates the Common request mapper before Engine processing; initialization failures enter request_result with REQUEST_HEADERS. The synchronous request-headers call is bracketed by engine_call_begin/finish. This is source proof of the observation boundary, not runtime PASS.

Root integration also binds `clean_shutdown` to the actual NGINX wire HTTP200 via a closed native-only `expected_status` override. The generic expected status0 remains unchanged; actual process exit0 and completed cleanup are separately required by the strict original sequence receipt. HTTP0 is never substituted for the real request status.

| case_id | Generic phase | NGX phase |
| --- | --- | --- |
| body_size_nonzero_with_null_data | 2 | 1 |
| engine_timeout_before_commit | 4 | 1 |

## Changed files and tests

catalog.json, case-catalog.schema.json, test_nginx_native_invocation_catalog.py, paired record.

## Commands and results

The initial focused run failed with two missing-phase errors and one expected-descriptor mismatch. After catalog/schema updates, 20 registry/selection controls passed. External log: stream-c-phase-override-green.log.

The missing clean-shutdown wire override produced a red projection control before its explicit catalog/schema registration. Fresh integrated registry/projection tests are required before committing this follow-up.

## Security impact

Closed per-ID schema rejects generic-phase substitution, boolean/string/null phase values and removal. No Required IDs or capabilities are removed.

## Documentation and runtime evidence

Source review: ngx_http_modsecurity_access.c mapper guard and request-result P1 boundary; actual request-headers budget glue. Native execution remains independently required.

## Checks not run

No native build or runtime ran. Root owns normalizer overlay and integrated evidence verification.

## Limitations and residual risk

The registry describes expected observation inputs; it does not itself produce or validate native observations.

## Final diff and review status

Focused Framework catalog/schema/test slice only; no Root worktree edits, central normalizer changes, Parent Gitlinks or MRTS changes.
