# NGINX response content-type fixtures

**Language:** English | [Deutsch](20261008-14-nginx-content-type-fixtures.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20261008-14-nginx-content-type-fixtures` |
| UTC date | 2026-10-08 |
| Framework base revision | `11e1d20990d4ecbbcf18641782b04f0bb6369c69` |
| Issue or pull request | Framework PR #137 follow-up; not published |

## Motivation and problem statement

Four Required MIME cases lacked executable case fixtures.

## Affected components and security boundaries

Only case YAML, focused tests and this bilingual record change. Native Common
producer and canonical validator integration remain coordinator-owned.

## Acceptance criteria

Distinct real requests, Engine MIME policy, SAFE visible HTTP 200, and explicit
bounded Content-Type omission for the missing-header case.

## Alternatives considered

Do not restore the removed connector MIME-file API or synthesize scope events.

## Implementation decision

Use the canonical baseline rule 1100301 and actual text/plain, charset, image/png
or missing Content-Type. Do not clear and refill MIME types in one rules load:
the inspected Engine merge clears the subsequent values too. SAFE late deny is
visible 200, not an invented retroactive 403. Missing-header fixture uses
`omit_headers: [Content-Type]` with empty NGINX default type.

## Changed files and tests

Four case fixtures and `tests/no_crs/test_nginx_content_type_cases.py` exercise
real materializer output and exact case semantics.

## Commands and results

Missing-file RED exit 1; focused two tests GREEN exit 0. Full no-CRS contract
suite exit 0. Four isolated diagnostic harness invocations returned exit 0 and
HTTP 200; in-scope and charset raw native logs contain rule 1100301/log_only.

## Security impact

No Required selection, validator, MRTS, native policy or guardrail weakening.

## Documentation and runtime evidence

External task `nginx-all-required-20261008T124555Z/stream-a-r4` retains config,
requests, root-master/nobody-worker identities, artifact maps and cleanup.
Old verified native build is explicitly diagnostic, not a current Exact Head.
Out-of-scope and missing-header logs are empty and do not prove completion.
The harness does not retain wire headers; separate backend wire tests prove
omission only at that layer. Native completion/scoping evidence remains required.

## Checks not run

Final integrated canonical run, full lint, remote CI and Sonar remain pending.

## Limitations and residual risk

Fixture declarations and HTTP success do not establish canonical coverage.

## Final diff and review status

Focused changes only. No push, gitlink update, merge or full-E2E PASS claim.
