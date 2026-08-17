# Change record: 20260817-03-fix-common-maintenance-publisher-workflows-permission

**Language:** English | [Deutsch](20260817-03-fix-common-maintenance-publisher-workflows-permission.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260817-03-fix-common-maintenance-publisher-workflows-permission` |
| UTC date | `2026-08-17` |
| Framework base revision | `c547c7692f0226e4318b64950af0126e514ba65a` |
| Issue or pull request | Resulting-master workflow `32045596674` exposed the publisher failure; a corrective pull request is pending. |

## Motivation and problem statement

The trusted full common-maintenance workflow correctly re-resolved and validated a safe plan whose fixed generated allowlist contains workflow files. GitHub then rejected the publisher's remote write because its otherwise repository-limited App token omitted `workflows: write`. The failure was fail-closed: no unauthorized update was published, but a legitimate validated Draft-PR publication could not complete.

## Affected components and security boundaries

The affected Framework CI boundary is the publisher App-token mint in `check-common-versions.yml` and its remote write through the immutable Draft-PR Action. The patch preserves the native read-only job token, current-repository selector, trusted-default-branch/candidate/digest gates, fixed generated allowlist, Draft-only behavior, and no-auto-merge rule. Parent source and gitlink plus the read-only `tools/MRTS` checkout remain outside scope.

## Acceptance criteria

1. Only the existing repository-limited common-maintenance publisher requests `contents`, `pull-requests`, and `workflows` write access.
2. The CI-security contract rejects a missing workflow permission and an unrelated additional permission.
3. The separate issue-reconciler token remains issue-only and all existing path and publication controls remain exact.
4. The full resulting-master workflow can complete the legitimate publisher path, subject to the installed App having the same repository `Workflows: read/write` grant.
5. The corrective PR may merge only after current-head GitHub checks and SonarQube Cloud report zero new issues and zero new-code duplication.

## Alternatives considered

- Replacing the App token with `GITHUB_TOKEN`, a PAT, or SSH credentials was rejected because it broadens or changes the publisher trust boundary.
- Expanding the repository selector, path allowlist, or App-token profile beyond the exact required workflow permission was rejected as unnecessary privilege.
- Removing workflow paths from the approved maintenance output was rejected because canonical CI pins must remain included in the common maintenance plan.
- Changing GitHub App installation settings is not part of this repository patch; if the existing installation lacks the requested permission, hosted validation remains an external blocker.

## Implementation decision

The existing publisher token now requests the single missing `workflows: write` capability alongside its existing two write capabilities. The security contract pins the complete profile, and focused tests prove both permission removal and unrelated permission addition fail. The paired security guide now matches the actual fixed generated allowlist and explains why this publisher needs workflow authority.

## Changed files and tests

The intended scope is `check-common-versions.yml`, the CI-security contract, focused common-maintenance and contract tests, the English/German workflow-security guide, and this paired Change Record. The new positive control checks the exact publisher profile and the issue-token separation; negative controls remove workflow authority or add `actions: write` and require contract rejection.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy gh run view 32045596674 --json ...` | `0` | Observed successful resolver/candidate/reconciler jobs and a failed publisher write caused by absent workflow permission. | GitHub Actions run `32045596674` |
| Focused pre-fix publisher-profile unittest | `1` | Expected regression failure: the publisher profile lacked `permission-workflows: write`. | Framework task worktree |
| Focused unified-maintenance, CI-security-contract, and Change-Record unittests | `0` | 52 tests passed, including the exact positive publisher profile and both negative permission mutations. | Framework task worktree |
| `ci/checks/security/check-ci-security-contract.py` | `0` | The live CI-security contract accepted the reviewed workflow profile. | Framework task worktree |
| `safe-make.sh check-github-actions-workflows` and `check-workflow-action-pins.py` | `0` | All workflow pins and permission profiles passed. | Framework task worktree |
| `safe-make.sh lint` | `0` | Full project-native lint suite, including security, provenance, runtime, workflow, documentation, and whitespace checks, passed. | Framework task worktree |

## Security impact

This is a fail-closed least-privilege availability correction, not an authorization bypass. The original path is encoded as an exact-profile regression; alternate profiles with a missing required permission or extra `actions` permission are rejected. The patch does not add a native-token fallback, a broader repository scope, a path expansion, a force push, or auto-merge authority.

## Documentation and runtime evidence

The paired English/German workflow-security guides now describe the same exact publisher permission and generated allowlist boundary, including the current Draft-PR title and marker. Workflow `32045596674` is failure evidence only; no successful hosted publisher, pull request, SonarQube Cloud result, or merge is claimed yet.

## Checks not run

- Hosted PR checks, SonarQube Cloud analysis, and resulting-master validation are pending the candidate pull request.
- No GitHub App configuration change was attempted; the installed App grant will be proved or blocked by the fresh hosted run.

## Limitations and residual risk

The source correction cannot grant an installation permission that the GitHub App does not already have. If the App token cannot be minted with `workflows: write`, the workflow remains safely blocked and needs an authorized external App-installation update rather than a credential fallback.

## Final diff and review status

The pre-fix regression, final scoped source review, focused security review, whitespace check, and complete local quality suite are recorded as passed. Pull-request, SonarQube Cloud, and resulting-master review remain pending; no commit, pull request, hosted success, or merge is asserted by this record.
