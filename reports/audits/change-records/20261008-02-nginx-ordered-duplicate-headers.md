# Change record

**Language:** English | [Deutsch](20261008-02-nginx-ordered-duplicate-headers.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-02-nginx-ordered-duplicate-headers |
| UTC date | 2026-10-08 |
| Framework base revision | `dc41bd22c335156cae02d9049098b92af65b7c57` |
| Issue or pull request | Authorized follow-up branch `fix/nginx-seven-contracts-20261008`; external Parent PR #396 remains Draft. |

## Motivation and problem statement

`duplicate_header_names` lacked a runnable fixture. A mapping-only header model
cannot represent two fields with the same name without loss.

## Affected components and security boundaries

`tests/runners/runner_core.py`, the No-CRS fixture/catalog, and focused runner
tests. Parent H1 transport and genuine connector observations remain external
runtime boundaries. No request-smuggling, H2/H3, or product-source work is added.

## Acceptance criteria

Ordered name/value entries retain repetitions, distinct values, empty values,
and relevant order. Existing simple mappings stay compatible. Malformed entries
and forbidden control characters remain rejected. A single or merged header
must not satisfy the duplicate-specific native proof.

## Alternatives considered

Dictionary overwrite, set deduplication, sorting, and comma joining lose the
required representation. Preserve the existing parser's list representation
through validation and materialization instead.

## Implementation decision

The fixture sends `X-No-Crs-Duplicate` twice with `one` then `two`. A dedicated
phase-1 rule `1100504` requires count `2` and both values. HTTP `200` alone is
insufficient: genuine native rule evidence is required. This tests transport
ordering and native count/value observation, not undocumented Engine iteration
order. The Parent driver must retain its actual H1 multi-field behavior.

## Changed files and tests

`tests/runners/runner_core.py`,
`tests/cases/no-crs-baseline/duplicate_header_names.yaml`,
`tests/cases/no-crs-baseline/catalog.json`,
`tests/no_crs/test_duplicate_header_runner.py`; this EN/DE pair.

## Commands and results

Focused logs under
`nginx-seven-contracts-20261008T080604Z` (external analysis run ID):
`framework-headers-red.log` records the pre-fix failure;
`framework-headers-green.log` records 31 passing tests. Exact command and final
catalog/suite reconciliation remain integration work. These tests do not prove
that a native host received the fixture.

## Security impact

Header-name/value validation remains mandatory; payload-derived native events
are not synthesized. Selection and Required are not reduced. No security
remediation or protected-runtime certification is claimed.

## Documentation and runtime evidence

This EN/DE pair records Framework-only behavior. Fresh actual H1 invocation,
Root-Master/nobody-Worker identity, correlated native rule event, negative
single-header control, and cleanup remain required external integration proof.
No such new-head runtime coverage is claimed here.

## Checks not run

Complete Framework lint/API/Canonical regressions, fresh integrated host run,
and CI/Sonar at the eventual delivery SHA are not concluded at record
preparation time.

## Limitations and residual risk

Client arguments alone are insufficient. An unrelated `200`, rule, phase,
transaction, or run must not pass. Engine-internal iteration order is not
asserted. Other required coverage gaps remain outside this change.

## Final diff and review status

Implementation-stage record awaiting final diff, full-suite, runtime, and
delivery reconciliation. The pair contains no secrets, raw bodies, or embedded
unreviewed logs.
