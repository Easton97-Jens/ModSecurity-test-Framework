# Change record: 20260817-02-fix-reconciler-plan-normalization

**Language:** English | [Deutsch](20260817-02-fix-reconciler-plan-normalization.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260817-02-fix-reconciler-plan-normalization` |
| UTC date | `2026-08-17` |
| Framework base revision | `d195b32e301fee31a72309c8c2b8bb5fe6f9f081` |
| Issue or pull request | Resulting-master workflow `32010750544` exposed the defect; no corrective pull request or merge result is established by this record. |

## Motivation and problem statement

The configured review-issue App reached the trusted reconciliation path. A producer-valid plan whose active review omitted optional `state` passed raw validation, then failed closed because the CLI passed the normalized representation through a second raw-plan digest validation. The first normalization inserts `state: "active"`, which is not part of the signed producer plan.

## Affected components and security boundaries

The affected Framework boundary is the canonical maintenance-plan artifact between the bounded file reader, schema/digest validator, and review-issue reconciliation core. The correction retains raw-plan SHA-256 validation before issue operations, trusted-default-branch and App-token gates, and leaves Parent source, the Parent gitlink, connector runtime, and the read-only `tools/MRTS` checkout outside scope.

## Acceptance criteria

1. A raw signed plan which omits optional active-review `state` completes CLI dry-run reconciliation.
2. The public reconciliation API still validates raw caller input before normalized records are used.
3. Tampered digests, unsafe schemas, trusted-branch conditions, and token boundaries remain rejected.
4. English and German security documentation describe the same raw-plan and normalization boundary.

## Alternatives considered

- Returning raw JSON from the reader and validating it twice would preserve the digest but adds duplicate validation.
- Recomputing `plan_sha256` after normalization was rejected because it replaces the producer-signed representation.
- Removing digest validation or accepting an unbound newly resolved plan was rejected because it weakens the maintenance supply-chain boundary.

## Implementation decision

The reader continues to validate the bounded raw plan before admission and returns its validated normalized representation. A private reconciliation core consumes that representation directly. The public `reconcile()` API validates raw direct-call data before entering the same core, so normalized defaults are never treated as a second signed artifact.

## Changed files and tests

The intended Framework scope is the reconciliation tool, a focused CI-security regression, paired security documentation, and this paired Change Record. The regression exercises CLI dry-run reconciliation with omitted active-review `state`; existing digest-tampering and unsafe-schema negative controls remain.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy gh run view 32010750544 --job 95329847123 --log` | `0` | Observed trusted reconciliation failure after successful App token mint; safe error: `plan_sha256 does not match canonical plan`. | GitHub Actions run `32010750544` |
| Focused reconciler, validate-only, lifecycle, resolver, canonical-maintenance, and workflow unittest suite | `0` | 48 tests passed, including the new CLI dry-run regression. | Framework task worktree |
| Scoped Ruff check for reconciler source and test | `0` | No lint findings. | Framework task worktree |
| `rtk proxy ./ci/tools/safe-make.sh check-documentation` | `0` | Documentation links, variable/path references, and Change Record contract passed. | Framework task worktree |
| `rtk proxy env RUFF_CACHE_DIR=<task-owned-external-cache> ./ci/tools/safe-make.sh lint` | `0` | Full Framework lint passed, including security, runtime, documentation, and terminal `git diff --check` validation. | Framework task worktree |

## Security impact

The correction preserves raw artifact validation and prevents a normalized default from being mistaken for producer-signed input. It adds no network, credential, permission, artifact-path, or automatic-write authority. Existing tampered-digest, unsafe-input, trusted-branch, App-token, scope, and issue-mutation controls remain in force.

## Documentation and runtime evidence

The paired English/German security guides document the raw-plan and normalization contract. Workflow `32010750544` is observed failure evidence; no successful hosted runtime, pull request, SonarQube Cloud, or merge evidence is claimed by this record.

## Checks not run

- Hosted checks, SonarQube Cloud analysis, and delivery checks are not yet represented as passed.
- A resulting-master workflow after this correction cannot exist until a corrective PR passes the user-required gates and is normally merged.

## Limitations and residual risk

The correction remains local until the exact PR head passes hosted checks and SonarQube Cloud reports the user-required zero new issues and zero new-code duplication. No GitHub App secret or token value is recorded.

## Final diff and review status

The source/test change and paired documentation passed focused and full local review. No commit, pull request, hosted-check success, SonarQube Cloud result, or merge is asserted by this record.
