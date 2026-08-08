# Change record

**Language:** English | [Deutsch](20260808-01-update-codeql-action-4374.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260808-01-update-codeql-action-4374 |
| UTC date | 2026-08-08 |
| Framework base revision | `8362b569406cabc5237a41e4e46f0505fb04c51f` |
| Issue or pull request | Replacement for Dependabot PRs #61 and #62; replacement pull request to be created after local validation |

## Motivation and problem statement

The selected Dependabot PRs updated CodeQL `init` and `analyze` separately but
left the canonical action lock, provenance guide, and change-traceability
evidence inconsistent with v4.37.4. The security contract rejects that split
state, so this Framework-only replacement keeps those inputs coherent.

## Affected components and security boundaries

The two CodeQL workflows, the action lock, and the English/German immutable
provenance guide are affected. The change preserves PR `contents: read`,
non-persisted checkout credentials, no submodules, and the existing
trusted-master-only `security-events: write` permission. Connector and MRTS
behavior are not affected.

## Acceptance criteria

- All four CodeQL Action uses, the lock, and both provenance tables identify
  v4.37.4 commit `f205ea1c3313d32999d8d6a48b4f6530d4437b38`.
- Workflow security, pin, documentation, and change-record checks pass without
  changing permissions, triggers, checkout behavior, or MRTS.
- The replacement pull request is verified at its exact head before merge.

## Alternatives considered

Separately merging the two bot PRs is rejected because both current heads fail
mandatory checks. Relaxing a check is rejected because it weakens CI
supply-chain controls. A combined coherent update is selected.

## Implementation decision

Update `init` and `analyze` in both CodeQL workflows to the reviewed full SHA
and exact v4.37.4 comment. Update the canonical lock and paired guide in the
same atomic change. Do not change actions, permissions, triggers, or MRTS.

## Changed files and tests

- Two CodeQL workflows, `ci/tooling/security-tools.lock.yml`, paired workflow
  provenance documentation, and this paired Change Record.
- No Framework runner, connector, or MRTS source/test changes.
- Focused workflow-contract, pin, documentation, record, diff, and hosted PR
  checks are recorded after they execute.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `git diff --check origin/master...origin/pr-61` | 0 | Selected `init` update has no whitespace error. | Isolated task clone |
| `git diff --check origin/master...origin/pr-62` | 0 | Selected `analyze` update has no whitespace error. | Isolated task clone |
| `finalize_scan_contract.py` for #61 | 0 | Focused CI workflow review found no reportable regression. | Task-owned external scan report |
| `check-workflow-action-pins.py` | 0 | All external workflow actions are pinned to full Git SHAs. | Isolated task clone |
| `check-github-actions-workflows.py --check all` | 0 | All 16 workflow files satisfy the workflow checker. | Isolated task clone |
| `make test-ci-security-contract` | 0 | 137 CI-security contract tests passed. | Isolated task clone |
| `make check-documentation` | 0 | Link, variable, path, and Change Record checks passed. | Isolated task clone |
| `git diff --cached --check` | 0 | Final staged replacement diff has no whitespace error. | Isolated task clone |
| Hosted replacement-PR validation | not_run | Requires the published exact task-branch head. | GitHub Actions |

## Security impact

This is CI supply-chain provenance maintenance, not a vulnerability fix. Full
SHA pinning, least privilege, untrusted-PR credential protections, and no-
submodule behavior remain intact. A focused review of #61 found no reportable
new issue; the corresponding `analyze` update is rechecked on the combined
diff before merge.

## Documentation and runtime evidence

The English and German workflow-security guides now match the workflow and lock
identity. No connector runtime or lifecycle evidence applies to a GitHub
Actions pin update.

## Checks not run

- Connector and MRTS runtime matrices are not applicable: no runner, connector,
  or MRTS behavior changes.
- Hosted replacement-PR checks are not run until the exact task branch is
  published.

## Limitations and residual risk

The upstream release-to-commit identity comes from the selected Dependabot PR
metadata and is retained by the repository immutable-pin contract. Hosted
GitHub Actions results remain separately required before integration.

## Final diff and review status

Focused local validation passed; final scoped review, commit, and exact-head PR
verification remain. No secret, token, raw payload, Parent file, or MRTS change
is included.
