# Change record

**Language:** English | [Deutsch](20261010-03-removed-phase4-body-limit-contract.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261010-03-removed-phase4-body-limit-contract |
| UTC date | 2026-10-10 |
| Framework base revision | 3a1932ef9060103d3a63b47d87c36006af954ee6 |
| PR | Framework137; Parent integration396 separately |

## Motivation and problem statement

The user explicitly removes the Parent's compatibility-only `modsecurity_phase4_body_limit` API repository-wide and approves migration of the existing Required `invalid_size` record to a real removed-API rejection test.

## Affected components and security boundaries

Framework closed configuration catalog, validation mapping, tests, generated package catalog and paired documentation. Parent product changes and subsequent Gitlink update are separate. MRTS remains read-only.

## Acceptance criteria

Retain Required identity and selection; reject the formerly valid value 1048576 with exact unknown-directive diagnostic and process exit 1. Old size-parser failure, unrelated diagnostics and identity/artifact mismatches must not pass. The four Engine response-limit cases remain unchanged.

## Alternatives considered

Removing the Required record, accepting arbitrary nonzero exits, fabricating HTTP/events and weakening validators were rejected.

## Implementation decision

Use error class `removed_directive`, input `modsecurity_phase4_body_limit 1048576;` and diagnostic `unknown directive "modsecurity_phase4_body_limit"`. The stable Required ID remains `invalid_size`; its title explicitly describes the new approved contract. No schema widening is necessary.

## Changed files and tests

`ci/checks/catalog/no_crs_baseline.py`, source catalog, `tests/no_crs/test_configtest_size.py`, generated package catalog and `docs/testing-and-evidence.md` / German companion.

## Commands and results

Through RTK and Framework Python: focused size-contract unittest RED (9 tests, three failures and one closed-template error against the old descriptor); GREEN (9 tests, exit 0). Entire no-crs suite:415 tests, exit0, no SKIPs; public contract API:30 tests, exit0. Native current-worktree catalog166, generated catalog freshness and documentation checks exit0. The negative controls rehash tampered stderr before validation, preventing digest mismatch alone from hiding a diagnostic acceptance defect. Integrated clean-head checks remain separate coordinator evidence.

## Security impact

Actual configtest exit, exact diagnostic, case/run/source identity and original binary/module/config/log digest requirements remain mandatory. No Required reduction, protocol relabelling or synthetic runtime evidence.

## Documentation and runtime evidence

Unit fixtures are not host proof. Fresh Parent build and genuine configtest execution are required for the new exact tuple; old size-parser evidence cannot fulfill the migrated record.

## Checks not run

Fresh Parent runtime, Full97, protected workflow and server CI/Sonar are separate integration evidence, not claimed here.

## Limitations and residual risk

This is an approved breaking API removal. Local Framework Python3.14.7 is not exact CI3.14.8.

## Final diff and review status

Coordinator reviews this independent Framework change and handles publication and the separate Parent Gitlink update; no history rewriting.
