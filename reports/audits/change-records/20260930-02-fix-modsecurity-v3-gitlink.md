# Correct ModSecurity v3.0.17 nested Gitlink provenance

**Language:** English | [Deutsch](20260930-02-fix-modsecurity-v3-gitlink.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260930-02-fix-modsecurity-v3-gitlink |
| Related issue / PR | Parent PR #398 |
| Status | Draft Framework fix; CI and runtime verification pending |
| Base revision | `bc8217d325809b9aba9a1d8c16964d71a01933ee` |

## Motivation and problem statement

The approved ModSecurity v3.0.17 source commit `1925753989ccce977cdaae417b55c9726c7cf02c` tracks `test/test-cases/secrules-language-tests` at `f73c73027ef49ccf99c7911744929a71d15ff419`. The Framework still expects `a3d4405e5a2c90488c387e589c5534974575e35b`, so its exact Gitlink guard blocks provisioning.

## Affected components and security boundaries

Only Framework-owned `ci/lib/common.sh`, its security-regression fixture, and this paired record change. No Parent or MRTS file is edited. Parent gitlink disposition: `update_required` after a separately authorized Framework merge; MRTS impact: `default_read_only`.

## Acceptance criteria

- Match both Framework checks and both test fixtures to the exact Gitlink in the approved upstream Git tree.
- Preserve exact graph verification, official origins, commit pins, and fail-closed behavior for mismatches.
- Obtain current-head Framework CI and separate Parent runtime evidence before integration claims.

## Alternatives considered

Disabling recursive Gitlink verification would hide a provenance mismatch and is not used. Changing the approved upstream ModSecurity commit would be a different release decision and is not needed for this correction.

## Implementation decision

Replace the four stale `secrules-language-tests` SHA literals with the verified `f73c73027ef49ccf99c7911744929a71d15ff419`. Other root and nested Gitlinks remain unchanged.

## Changed files and tests

`ci/lib/common.sh` (two literals), `tests/security_regression/git_provenance_test_support.py` (two fixture literals), and this English/German Change Record pair. Existing provenance tests remain enabled; no test or guard is removed.

## Commands and results

A read-only GitHub Git-tree query of `owasp-modsecurity/ModSecurity` at `1925753989ccce977cdaae417b55c9726c7cf02c` found exactly one `160000` entry at `test/test-cases/secrules-language-tests`, SHA `f73c73027ef49ccf99c7911744929a71d15ff419`. Repository search found the stale SHA only in the two changed files. Framework CI is pending; no local test is claimed as passed.

## Security impact

The exact provenance guard is retained and now matches the approved upstream graph. It still rejects unexpected nested Gitlinks and does not accept arbitrary recursive submodules. No credentials, payloads, or raw logs are recorded.

## Documentation and runtime evidence

This paired record documents the fix. No generated documentation or report changes. The Parent NGINX job's `modsecurity_v3_framework_provisioning_failed` is supporting failure evidence, not a passed runtime test; rerun after a new Parent gitlink is pinned.

## Checks not run

Framework-local unit, lint, documentation, and runtime checks were not run in this projectless Windows task. Hosted current-head checks and reviews must provide delivery evidence.

## Limitations and residual risk

Static Git-tree evidence proves the pin mismatch, not full build compatibility. The Framework PR must be reviewed and separately merged before Parent integration can target its new commit. No automatic merge or Parent gitlink change is authorized here.

## Final diff and review status

This is a Draft Framework-only correction. The scoped diff and current-head CI must be reviewed before marking it verified; Parent PR #398 remains a separate Draft delivery unit.
