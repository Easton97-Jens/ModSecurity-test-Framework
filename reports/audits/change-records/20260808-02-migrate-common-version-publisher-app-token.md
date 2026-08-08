# Change record: Migrate the Common-version publisher to a GitHub App token

**Language:** English | [Deutsch](20260808-02-migrate-common-version-publisher-app-token.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260808-02-migrate-common-version-publisher-app-token` |
| UTC date | 2026-08-08 |
| Framework base revision | `da28e6da58fa8b1135d3631612a78e73ff98584b` |
| Issue or pull request | Source-fix Draft PR is authorized but had not been created when this record was first prepared; it must target Framework `master` and never authorizes a merge. |

## Motivation and problem statement

`check-common-versions.yml` already resolved and independently validated a
bounded `ci/lib/common.sh` candidate, but its publisher used the native
GitHub-token path. That path does not prove the requested repository-limited
GitHub App authority or reliable ordinary pull-request event delivery. Hosted
run `31254801083` further showed that the candidate validator stopped before
publisher execution because the directly invoked CRS provenance test could not
import its local test helper.

## Affected components and security boundaries

This Framework-only change covers the Common-version GitHub Actions publisher,
its CI-security contract and mutation suite, the CRS provenance regression
test import boundary, action-use metadata, paired workflow-security guidance,
and this record. The security boundary is the transition from a validated
default-branch candidate to a narrowly scoped Draft pull request. Parent,
MRTS, Gitlinks, runtime connectors, and a merge are outside scope.

## Acceptance criteria

- Resolver and validator remain credential-free, `contents: read`, independent,
  and bound through an exact 64-character SHA-256 candidate digest.
- The native publisher token remains `contents: read`; exactly one pinned App
  token is limited to the current owner/repository with only `contents` and
  `pull-requests`: write.
- The App configuration gate, state check, fixed maintenance identity, body
  marker, and `ci/lib/common.sh` path restriction fail closed on deviation.
- No native-token, PAT, SSH, direct-default-branch-push, force-push, broad
  staging, PR takeover, merge, or auto-merge path is introduced.
- The required tests, paired documentation, action-pin contract, Change Record
  contract, and final PR delivery evidence are recorded truthfully.

## Alternatives considered

Keeping the native token would retain an insufficient publishing/event-boundary
claim. A PAT, deploy key, long-lived secret, or runner-driven push would widen
authority. Reimplementing the publisher with custom Git pushes was unnecessary
because the existing full-SHA-pinned `peter-evans/create-pull-request` Action
can use the scoped App token after a fail-closed state check. All alternatives
that permit a direct `master` update, token fallback, or a synthetic candidate
were rejected.

## Implementation decision

The publisher now revalidates the candidate on the trusted default revision,
checks its SHA-256 and exact diff, preserves the validated JSON/Markdown
output, and creates an English/German Draft body from that data only. It stops
with a clear configuration error for an available update when
`WORKFLOW_UPDATER_APP_CLIENT_ID` or `WORKFLOW_UPDATER_APP_PRIVATE_KEY` is
unavailable. The configuration gate derives only a non-secret Boolean because
GitHub Actions does not support a direct secret reference in `if:`. The secret
value is supplied only to the pinned App-token Action;
the resulting short-lived token is supplied only to a read-only GitHub API
state check and the pinned pull-request Action. State A has no branch or open
matching PR; state B has exactly one same-repository, correctly identified
Draft PR whose diff is only `ci/lib/common.sh`. Every other state fails closed.
The trusted default-revision SHA reaches `github-script` through a named action
environment variable rather than template interpolation into JavaScript.

## Changed files and tests

- `.github/workflows/check-common-versions.yml` uses the constrained App token,
  state check, fixed Draft identity, validated body, and default-branch drift
  check.
- `ci/checks/security/check-ci-security-contract.py` defines an exact
  Common-version publisher profile and rejects native-token/permission/scope,
  state, path, SHA, and write-path drift.
- `tests/ci_security/test_ci_security_contract.py` mutation-tests the App
  token, configuration names, permissions, repository/owner scope, branch,
  draft, marker, staging, direct/force pushes, SHA binding, artifact reuse,
  publisher gate, and PR takeover bypasses.
- `tests/security_regression/test_crs_git_ref_provenance.py` makes its local
  provenance helper importable when the test is invoked by its fully qualified
  module name.
- `ci/tooling/security-tools.lock.yml` records the additional use of the
  already pinned App-token Action; no Action version changes.
- `docs/github-actions-workflow-security.md` and its German companion document
  the App-token contract, no-update/configuration behavior, fixed Draft state,
  and normal PR-check expectation.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy gh run view 31254801083 --log` | 0 | Resolver passed; candidate validation failed with `ModuleNotFoundError: git_provenance_test_support`; publisher was skipped. | [Run #14](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31254801083) |
| `make test-ci-security-contract` | 0 | 137 CI-security, Change Record, evidence, updater, and security-contract tests passed. | Task-owned external Framework worktree |
| `make test-workflow-action-pins` | 0 | 25 action-pin regression tests passed. | Same task worktree |
| `make test-workflow-security-contract` | 0 | 7 workflow-security contract tests passed. | Same task worktree |
| `make check-github-actions-workflows` | 0 | Python-version, pin, and permission checks accepted every checked-in workflow. | Same task worktree |
| `make check-documentation` | 0 | Links, bilingual parity, path references, and Change Record contract passed. | Same task worktree |
| `make lint` | 0 | Full local lint and regression matrix passed, including the workflow-security and provenance suites. | Same task worktree |
| `<locked-tools>/actionlint -shellcheck=<locked-tools>/shellcheck` | 0 | All checked-in workflows and embedded shell blocks passed. | SHA-256-locked local tools |
| `<locked-tools>/zizmor --offline .github` | 0 | No findings; 32 repository-approved suppressions remained. | SHA-256-locked local tool |
| `<locked-tools>/ruff check …` and `ruff format --check …` | 0 | Ruff lint accepted the relevant CI-security scope and changed CRS regression test; format check accepted 20 CI-security files. | SHA-256-locked local tool |
| Focused required `unittest` module trio | 0 | 73 tests passed across CI-security, workflow-tool updater, and common-version provenance. | Same task worktree |
| `git diff --check` | 0 | No whitespace errors in the final uncommitted review. | Same task worktree |

## Security impact

This is a CI-authority hardening and CI-validation repair. The original
native-token publisher path is rejected structurally, while the legitimate
control remains a trusted-default-branch candidate with a matching SHA-256,
safe App configuration, allowable state A/B, and exactly one permitted changed
path. The alternate-bypass mutations cover token fallback, App scope/permission
drift, private-key name drift, branch/PR hijacking, broad staging, direct and
force pushes, a short or missing digest, resolver-artifact reuse, and an
untrusted publisher gate. No credential value is recorded.

## Documentation and runtime evidence

The English/German workflow-security pair is updated. No connector or MRTS
runtime was needed. Run #14 is hosted failure evidence for the test import
defect, not proof of the App publisher: its publisher was correctly skipped.
The repository App metadata check found the required variable and secret absent
without reading either value. A real publisher end-to-end run can occur only
after a separately authorized merge to `master` and must use real upstream
results rather than a fabricated candidate.

## Checks not run

The repository-local Node runtime required by the hash-locked Pyright package
is unavailable (`node` and `nodejs` are absent), so Pyright is blocked rather
than installed globally. Hosted Draft-PR checks and post-merge publisher
evidence remain pending until normal delivery and a separately authorized
merge. No unavailable or unrun check is presented as passed.

## Limitations and residual risk

The GitHub App configuration is currently absent, so an available update will
now fail closed with the documented error rather than create a PR. The normal
event/check behavior of an App-created Draft PR remains unobserved until the
source-fix PR is merged with separate authorization. The state check reduces
branch/PR takeover and default-branch-drift risk but does not authorize a
merge, branch-protection bypass, or a change outside `ci/lib/common.sh`.

## Final diff and review status

The source-fix worktree is isolated on
`fix/common-version-draft-publisher-app-token`; no Framework `master`, Parent,
MRTS, or Gitlink change is authorized. The final source review includes a
clean `git diff --check`, exact static publisher-profile checks, no native
token fallback, no `workflows` write request, no direct/force push, and no
unreviewed App-token consumer. Normal push, exactly one Framework Draft PR,
and its current-head hosted checks remain the delivery evidence still pending
at this record revision.
