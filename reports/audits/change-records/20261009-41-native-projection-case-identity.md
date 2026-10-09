# Change record

**Language:** English | [Deutsch](20261009-41-native-projection-case-identity.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261009-41-native-projection-case-identity |
| UTC date | 2026-10-09 |
| Framework base revision | 7db219af6b6e911b73de8b437f82e63efdb06bde |
| Issue or pull request | None |

## Motivation and problem statement

Shared run IDs require distinct case-bound projection children.

## Affected components and security boundaries

Reader original receipt/config identity; authority and seals unchanged.

## Acceptance criteria

Exact hash; old names and wrong case/run/parent/config rejected.

## Alternatives considered

No legacy fallback because it would re-admit collisions.

## Implementation decision

phase4- plus24 SHA256 hex characters of actual run_id:case_id; E child run IDs bound.

## Changed files and tests

New identity test; existing decorate_phase4 fixture corrected exactly.

## Commands and results

Framework Python unittest:28 tests, exit0. Original:18 errors and1 failed negative, exit1.

## Security impact

No relaxed source, receipt, schema, status or payload checks.

## Documentation and runtime evidence

Paired record; no native runtime evidence.

## Checks not run

Native build/runtime/publication unauthorized.

## Limitations and residual risk

Root integrates producer and reader together;97 Required unchanged.

## Final diff and review status

Focused unstaged diff reviewed; no Git writes.
