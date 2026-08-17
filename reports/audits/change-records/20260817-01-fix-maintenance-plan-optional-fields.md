# Change record: 20260817-01-fix-maintenance-plan-optional-fields

**Language:** English | [Deutsch](20260817-01-fix-maintenance-plan-optional-fields.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260817-01-fix-maintenance-plan-optional-fields` |
| UTC date | `2026-08-17` |
| Framework base revision | `b2816eb3e7fcdd974125d801b49e545f43d47f44` |
| Issue or pull request | Newly confirmed producer/reconciler compatibility defect; no pull-request or merge result is established by this record. |

## Motivation and problem statement

The canonical maintenance producer emits the optional `component_results`
fields `current`, `latest_compatible`, `latest_upstream`, and `source` on its
records. When no value is available, it emits an empty string. The validate-only
reconciler must accept that producer output as a valid bounded plan shape, while
still validating non-empty source values as HTTPS URLs. The defect was confirmed
as a CI-contract compatibility gap after the mandatory-global-scope fix.

## Affected components and security boundaries

The affected Framework boundary is the trusted canonical-maintenance JSON plan
contract between `ci/tools/canonical_maintenance.py` and
`ci/tools/reconcile-common-version-review-issues.py`, with focused CI-security
regression coverage. Parent, connector runtime, and the read-only `tools/MRTS`
checkout are outside scope.

## Acceptance criteria

1. Producer-emitted empty strings for the four optional result fields are
   accepted by validate-only normalization.
2. Non-empty optional values remain bounded, and non-empty `source` values must
   remain HTTPS URLs.
3. The compatibility behavior applies to mandatory global and selected
   runtime/source result records without weakening plan, digest, scope, or
   issue-reconciliation validation.
4. English and German documentation describe the same optional-field contract.

## Alternatives considered

- Removing the optional fields from producer output was rejected because the
  plan schema and hosted summary consumers use their stable presence.
- Treating empty strings as invalid required values was rejected because the
  producer intentionally uses them to represent unavailable advisory data.
- Disabling validate-only normalization was rejected because it would remove a
  fail-closed integrity boundary from the maintenance workflow.

## Implementation decision

The producer/reconciler contract preserves the four optional fields, accepts
their bounded empty-string representation, and retains the non-empty HTTPS
validation for `source`. Required identity, scope, digest, collection, and
issue-reconciliation checks remain unchanged. The paired security guides
document this compatibility boundary.

## Changed files and tests

The implementation scope is the canonical maintenance/reconciler contract and
its focused CI-security regression tests. The exact source and test file list,
test counts, and final commit remain part of the implementation agent's
delivery update and are not claimed as complete by this documentation record.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `git rev-parse HEAD` | `0` | Framework task base observed as `b2816eb3e7fcdd974125d801b49e545f43d47f44`. | Framework task worktree |
| `rtk proxy ./ci/tools/safe-make.sh check-documentation` | `0` | Documentation links, bilingual variable/path references, and the Change Record contract passed. | Framework task worktree |
| `rtk proxy git diff --check -- docs/security/ci-security-tooling.md docs/security/ci-security-tooling.de.md reports/audits/change-records/20260817-01-fix-maintenance-plan-optional-fields.md reports/audits/change-records/20260817-01-fix-maintenance-plan-optional-fields.de.md` | `0` | Scoped whitespace validation passed for the four documentation/record files. | Framework task worktree |

## Security impact

This compatibility correction preserves bounded-field validation and the
non-empty HTTPS source gate. It adds no permission, credential, network
authority, artifact path, or automatic-write capability, and does not weaken
mandatory global-scope or digest validation.

## Documentation and runtime evidence

The English and German security guides document the producer/reconciler
optional-field contract. No new hosted runtime, pull-request, SonarQube Cloud,
or merge evidence is established by this record.

## Checks not run

- Focused reconciler and canonical-maintenance tests are owned by the
  implementation work and are not represented as passed here.
- Full Framework lint, hosted checks, SonarQube Cloud analysis, and delivery
  checks are not represented as passed here.

## Limitations and residual risk

The contract remains unverified in hosted CI until the implementation change
and its regression tests are delivered and a later workflow run completes. The
user-specified SonarQube Cloud conditions remain required before any merge.

## Final diff and review status

This documentation subtask changes only the paired security guides and this
paired Change Record. No source/test, Git, GitHub, Parent gitlink, or MRTS
action was performed by this subtask.
