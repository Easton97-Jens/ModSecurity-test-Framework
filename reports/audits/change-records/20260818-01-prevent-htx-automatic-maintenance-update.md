# Prevent automatic HAProxy HTX maintenance update

**Language:** English | [Deutsch](20260818-01-prevent-htx-automatic-maintenance-update.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260818-01-prevent-htx-automatic-maintenance-update` |
| UTC date | 2026-08-18 |
| Framework base revision | `59b17f26b09ade5a6a354cec86e78b03da2717a4` |
| Issue or pull request | Framework PR [#96](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/96) |

## Motivation and problem statement

PR #96's canonical-maintenance update classified the independently pinned
HAProxy HTX tuple as automatic. It replaced the reviewed HTX 3.2.21 tuple with
the generic HAProxy 3.2.22 tuple, causing the runtime-inventory distinction
control to fail in Actions run `32065088898`, job `95543983427`.

## Affected components and security boundaries

- `ci/tools/check-common-versions.py` controls the upstream-listing to
  maintenance-plan boundary.
- `ci/lib/common.sh` is the canonical reviewed-pin authority.
- `ci/provisioning/runtime-component-lock.json` is the generated runtime-lock
  projection consumed by provisioning.

The HTX profile remains an independently reviewed release, URL, and digest
tuple; automatic maintenance must not silently substitute the generic HAProxy
artifact.

## Acceptance criteria

- A newer HTX release or a HTX checksum drift produces manual review and no
  automatic update.
- The generic HAProxy update path remains automatic.
- The checked-in HTX tuple and generated lock again retain 3.2.21 and its
  reviewed SHA-256.
- The original runtime-inventory failure and an alternate checksum-drift path
  are covered by deterministic tests.

## Alternatives considered

- Updating or deleting the HTX-versus-generic distinction assertions was
  rejected because it would remove the independent-provenance control.
- Changing only the descriptor policy was rejected because the planner admits
  every `outdated` result regardless of that metadata.

## Implementation decision

The HTX descriptor is classified as `manual_review`, with its full independent
atomic tuple registered as byte-exact manual provenance. Both resolver paths
that formerly emitted automatic updates now emit review-required results with
no updates. The generated lock was regenerated from the restored canonical
3.2.21 tuple. Generic HAProxy keeps its automatic policy.

## Changed files and tests

- `ci/tools/check-common-versions.py`
- `ci/lib/common.sh`
- `ci/provisioning/runtime-component-lock.json` (generated)
- `tests/security_regression/test_common_versions_sonar_provenance.py`
- This English/German Change Record pair.

The tests cover the original newer-release path, checksum-only drift, manual
plan exclusion, and the legitimate generic-HAProxy automatic update path.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused pre-fix runtime sync test module | 1 | Reproduced the two exact HTX assertions from the selected Actions job. | Actions run `32065088898`, job `95543983427` |
| `python ci/tools/sync-runtime-components.py --write` | 0 | Regenerated the runtime lock from canonical pins. | Local isolated worktree |
| Focused 37-test security/runtime suite | 0 | HTX manual-review, checksum-drift, lock, sync, and descriptor controls passed. | Local isolated worktree |
| `python ci/tools/sync-runtime-components.py --check` | 0 | Generated projections are current. | Local isolated worktree |
| `./ci/tools/safe-make.sh -s lint` | 0 | Complete Framework lint, security, runtime-lock, documentation, and workflow-contract suite passed. | Local isolated worktree with a project-allowed report root |
| `python -m ruff check ...` | 1 | Ruff is not installed in the selected Framework environment; no dependency installation was performed. | Local environment evidence |

## Security impact

The original path (`official listing → HTX resolver → automatic plan → common
pins → generated lock`) no longer yields an automatic HTX update. The new
version-transition test proves this, and the checksum-drift test covers the
alternate resolver branch. No host allowlist, digest validation, action pin,
or quality control was weakened.

## Documentation and runtime evidence

This paired Change Record is the reader-facing documentation update. No live
connector runtime was executed because this correction changes maintenance
classification and generated metadata, not connector behavior.

## Checks not run

- Current-head hosted checks remain pending until this correction is committed
  and pushed to PR #96.
- Ruff is unavailable in the existing Framework environment; installing it is
  outside this correction's dependency scope.

## Limitations and residual risk

The HTX 3.2.22 candidate is intentionally deferred for a separate reviewed
provenance and compatibility decision. This task does not merge PR #96 or
change Parent or MRTS state.

## Final diff and review status

Focused source and generated-lock diff review is complete; `git diff --check`
passes. No commit, push, PR merge, credentials, or raw sensitive logs are
recorded here.
