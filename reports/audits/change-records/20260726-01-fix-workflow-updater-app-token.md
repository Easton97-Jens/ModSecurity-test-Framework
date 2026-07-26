# Change record: Fix workflow-updater App-token publisher

**Language:** English | [Deutsch](20260726-01-fix-workflow-updater-app-token.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260726-01-fix-workflow-updater-app-token |
| UTC date | 2026-07-26 |
| Framework base revision | 7e9a560f3acda65510c93f649b6ed4977e4cd6cb |
| Issue or pull request | Task branch `agent/update-workflow-publisher-app-token`; Draft PR pending at record creation. No merge or auto-merge is authorized. |

## Motivation and problem statement

The scheduled Framework workflow-tool publisher validated an immutable,
five-file maintenance candidate but could not push it because its built-in
`github.token` lacked the GitHub App `Workflows: write` authority needed to
change `.github/workflows/*`. The error was observed after the publisher had
already validated the candidate and created a runner-local commit. A normal
workflow `permissions:` entry cannot grant that App-level authority.

## Affected components and security boundaries

- `.github/workflows/update-workflow-tools.yml` is the only writer. Its
  resolver and validator remain token-free/read-only; the trusted,
  default-branch-gated publisher receives the short-lived publishing token.
- The publisher's built-in `GITHUB_TOKEN` is reduced to `contents: read`. A
  pinned GitHub App-token action receives one repository variable and one
  secret, limits its token to the current repository, and requests only
  `Contents`, `Pull requests`, and `Workflows` write permission.
- The CI-security contract, its focused tests, immutable-action lock, and
  paired workflow-security documentation bind that credential boundary.
- Parent files, the Parent Framework gitlink, MRTS source, and the Framework
  MRTS gitlink are outside this Framework-only change.

## Acceptance criteria

- The publisher has no `github.token` publishing fallback and only its four
  reviewed API/Git consumers receive `publisher_app_token.outputs.token`.
- Resolver and validator remain read-only and contain no App-variable or
  private-key reference.
- The new Action is full-SHA pinned, lock-recorded, and documented in English
  and German.
- The publisher profile rejects an altered App permission, repository scope,
  or legacy publishing-token route, while the real workflow passes the native
  contracts.
- The source patch is delivered through a normal Framework Draft PR. A hosted
  end-to-end publisher run is left pending the separately authorized App
  installation, variable, and secret configuration.

## Alternatives considered

- Adding `workflows: write` to the workflow's native `permissions:` map was
  rejected: it cannot grant the platform App's repository permission and would
  be an invalid control claim.
- Storing a broad personal access token was rejected because it would introduce
  a long-lived write credential into a maintenance workflow.
- Skipping workflow-file updates or weakening the updater's scope/validation
  gates was rejected because it would leave the immutable-pin maintenance path
  incomplete.

## Implementation decision

The publisher now uses immutable
`actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1`
(`v3.2.0`). Its exact profile requires
`vars.WORKFLOW_UPDATER_APP_CLIENT_ID` and
`secrets.WORKFLOW_UPDATER_APP_PRIVATE_KEY`, scopes the request to the current
repository, and requests only the three required write permissions. The action
output is the sole credential supplied to both reviewed `github-script` calls
and both `PUBLISH_TOKEN` environments. The action's default post-job revocation
remains enabled.

The source cannot create the App installation, repository variable, or private
key secret. An authorized repository owner must install the App only on this
Framework repository and grant exactly the documented permissions before a
real publisher run can prove the remote branch-push path.

## Changed files and tests

- `.github/workflows/update-workflow-tools.yml` and
  `ci/checks/security/check-ci-security-contract.py`.
- `tests/ci_security/test_ci_security_contract.py` and
  `tests/ci_security/test_update_workflow_tools.py`, including negative legacy
  token, permission, and repository-scope mutations.
- `ci/tooling/security-tools.lock.yml` and both
  `docs/github-actions-workflow-security` language variants.
- This paired Change Record.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `make test-ci-security-contract` | 0 | 134 focused CI-security tests passed, including the new App-token regressions. | Local Framework task worktree. |
| `make test-workflow-action-pins` | 0 | 25 immutable Action-pin regression tests passed. | Local Framework task worktree. |
| `make test-workflow-security-contract` | 0 | 7 workflow-trust-boundary regressions passed. | Local Framework task worktree. |
| `make check-github-actions-workflows` | 0 | Python version, immutable pin, and permission checks accepted all 15 workflows. | Local Framework task worktree. |
| `make check-documentation` | 0 | Bilingual documentation, link, repository-path, and Change Record contracts passed. | Local Framework task worktree. |
| `make lint` | 0 | The complete repository lint target passed, including syntax, focused contracts, pins, workflow checks, documentation, and final whitespace checking. | Local Framework task worktree. |
| `git diff --check` | 0 | The final unstaged source diff had no whitespace errors. | Local Framework task worktree. |

## Security impact

This is a CI credential-boundary remediation. The original static path is
removed: the publisher no longer supplies `github.token` to its API or Git
write consumers. The exact profile permits the private key only in the
publisher's pinned App-token action and permits its output only in reviewed
consumers. Focused negative mutations prove rejection of a legacy token,
reduced workflow authority, or an unreviewed repository scope. The legitimate
control is the unmodified real workflow passing the same contracts; the hosted
branch-push control remains pending external configuration.

## Documentation and runtime evidence

The English/German workflow-security guide documents the immutable Action,
variable/secret names, native-token reduction, exact App permissions, scope,
and no-fallback rule. No token value, external configuration, or connector/MRTS
runtime evidence was collected. The original failed-run receipt remains under
the Parent control plane as `FND-GITHUB-0008` evidence.

## Checks not run

- A real `Update pinned workflow tools` publisher run is not run because the
  required repository App installation,
  `WORKFLOW_UPDATER_APP_CLIENT_ID` variable, and
  `WORKFLOW_UPDATER_APP_PRIVATE_KEY` secret are absent and are outside the
  user's authorization for this task.
- Hosted Actions checks, SonarQube Cloud, review threads, and branch-protection
  evaluation are exact-Draft-PR-head controls and will be observed only after
  the PR is pushed.

## Limitations and residual risk

The source and local contracts cannot prove that the future GitHub App is
installed only on this repository or actually grants the requested permissions.
Until an authorized owner configures it and a candidate changing a workflow file
successfully creates or updates the constrained Draft PR, the automated
workflow-maintenance path remains externally blocked. No direct `master` push,
permission bypass, personal-token fallback, Parent action, or MRTS action is
part of this change.

## Final diff and review status

The scoped source diff and credential data flow received a focused security
review; no plausible source-to-sink defect was found. The final workflow scan
found neither a legacy `github.token`/`GITHUB_TOKEN` publishing route nor
private-key material; the reviewed App-token output has exactly four consumers.
Documentation and whitespace validation passed. Commit, push, and exact
Draft-PR-head receipt are recorded only after their observed results. No merge
is authorized by this record.
