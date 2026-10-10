# Change record

**Language:** English | [Deutsch](20261008-12-nginx-raw-h1-contracts.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-12-nginx-raw-h1-contracts |
| UTC date | 2026-10-08 |
| Framework base revision | `178c10d` |

## Motivation and problem statement

Four Required malformed H1 inputs are rejected by NGINX before connector admission. An HTTP status alone cannot prove the intended parser rejection or an Engine transaction.

## Affected components and security boundaries

Closed Framework input and observation helper; focused tests only. Parent execution, normalization, catalog, MRTS and Gitlinks are unchanged.

## Acceptance criteria

Bound case/run identities and actual wire bytes; require a complete unambiguous HTTP400 response, exact native access identity and native parser diagnostic. Missing, truncated or mismatched observations fail.

## Alternatives considered

Inferring a successful scenario from HTTP400 or creating an Engine event for a pre-connector rejection would invent evidence.

## Implementation decision

Register four exact malformed headers and independent valid control inputs. Validate complete Content-Length framing, actual method/URI/status and the source-specific native diagnostic. No generic raw request injection interface is added.

## Changed files and tests

`tests/runners/nginx_raw_h1.py`, four controls in `tests/no_crs/test_nginx_raw_h1.py`, and this paired record.

## Commands and results

The four focused unit tests pass. They exercise controlled byte observations, not a new NGINX runtime.

## Security impact

Unknown cases, path/control-character identities, duplicate or incomplete framing, incorrect access identity and absent diagnostics remain rejected. No synthetic transaction, rule or event is produced.

## Documentation and runtime evidence

This record documents the bounded source contract only. Existing old-artifact diagnostic requests are not new Exact-Head evidence.

## Checks not run

New-artifact native execution and integrated final Canonical validation remain pending.

## Limitations and residual risk

The helper does not authenticate artifact ownership, source identity or Root/worker roles; the integrated bundle reader must prove those separately.

## Final diff and review status

Focused helper/test/record slice. No Required scope reduction or validator relaxation.
