# Change record

**Language:** English | [Deutsch](20261008-05-framework-receipt-quality.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-05-framework-receipt-quality |
| UTC date | 2026-10-08 |
| Framework base revision | aa58f8bc913f0731e5cdbf4d28416343fb8445e1 |
| Issue or pull request | Captured quality baseline 11e1d20990d4ecbbcf18641782b04f0bb6369c69; no PR |

## Motivation and problem statement

Address six captured maintainability findings without changing receipt acceptance:
S1192 AaEa6YQON0iWDQNM6rae and AaEa6YQON0iWDQNM6raf;
S3776 AaEa6YQON0iWDQNM6rag and AaEa6YQON0iWDQNM6rah;
S9073 AaEa6YPXN0iWDQNM6rad and AaEa6YNGN0iWDQNM6rac.
Local validation does not establish remote Sonar closure.

## Affected components and security boundaries

Framework receipt validators and their tests only. Catalog, schema, expectations,
connector product code and required scope are unchanged. Strict raw-byte, identity,
role and cleanup validation remain the same.

## Acceptance criteria

Preserve successful receipts, rejection messages and error precedence. Keep exact
filename and template bytes. Pass focused characterization, the complete native
No-CRS contract target and documentation checks.

## Alternatives considered

Suppressions or relaxed validation would not address maintainability safely.
Small helper extraction preserves the existing validation branches.

## Implementation decision

Name the two repeated rules filenames. Extract native probe event checks and the
valid-rules startup bundle branch into helpers without changing conditions,
ordering or diagnostics. Split loader prerequisites into individual assertions.

## Changed files and tests

Changed ci/checks/catalog/no_crs_baseline.py and the valid-rules receipt and
duplicate-header test modules. Added test_valid_rules_quality_characterization.py
for success, typed roles, cleanup, native metadata and diagnostic precedence.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Owning Python unittest: characterization, valid-rules receipt, duplicate-header | 0 | 23 tests before and after refactoring | nginx-all-required-20261008T124555Z |
| make test-no-crs-contract with explicit owning Python and external BUILD_ROOT | 0 | Complete repository-native contract suite passed | nginx-all-required-20261008T124555Z |
| make check-documentation with explicit owning Python and external roots | 0 | Links, variables, paths and Change Record contract passed | nginx-all-required-20261008T124555Z |
| git diff --check | 0 | No whitespace errors | Isolated Framework worktree |

All shell commands used RTK and the owning Framework Python with external temporary
and cache paths.

## Security impact

No security remediation performed. No validation weakening or exclusions added.

## Documentation and runtime evidence

This paired English/German record documents the focused refactor. No native
NGINX runtime or connector lifecycle evidence was collected for this quality slice.

## Checks not run

Remote Sonar analysis was not run; captured issue IDs are not a closure report.
Ruff is unavailable in the owning environment; no dependency installation requested.

## Limitations and residual risk

Remote findings and quality-gate status require separate remote verification.
Integration may overlap coordinator-owned configuration additions; preserve those
additions when applying the filename-only contract changes.

## Final diff and review status

Focused unstaged diff, whitespace and secret review completed. Documentation and
the complete contract suite passed. Only the owned files are included in the
isolated commit; no remote delivery or history rewriting is authorized.
