# Change record: Add Framework MRTS submodule updater

**Language:** English | [Deutsch](20260726-02-add-framework-mrts-submodule-updater.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260726-02-add-framework-mrts-submodule-updater |
| UTC date | 2026-07-26 |
| Framework base revision | c27c644e088904b71b8380d16ee34f1b36f2c001 |
| Issue or pull request | Framework PR #47, `Easton97-Jens-patch-1` into `master`. This record authorizes neither a merge nor a direct default-branch push. |

## Motivation and problem statement

PR #47 previously added three unused submodule environment variables to the
workflow-tool updater. The Framework needs an actual, separately constrained
MRTS gitlink-maintenance lifecycle: resolve one immutable remote commit,
validate it without a write credential, and create or update only a matching
Draft pull request. The Parent `update-submodules.yml` establishes the desired
resolver/validator/publisher shape, but its Parent path, upstream reference,
and publisher mechanics cannot be copied verbatim across the repository
boundary.

## Affected components and security boundaries

- `.github/workflows/update-submodules.yml` is a Framework-only scheduled or
  manually dispatched updater for the Framework-owned `tools/MRTS` gitlink.
- Its resolver and validator have `contents: read`, no secret, no explicit
  token reference, and credentials are not persisted. The validator first
  checks out the trusted Framework default revision, then explicitly
  initializes only the declared direct submodule before checking out the
  resolved immutable SHA.
- The default-branch-gated publisher has only `contents: write` and
  `pull-requests: write`. It re-resolves the SHA, confines both existing and
  staged changes to `tools/MRTS`, performs no force push, and creates a Draft
  PR only. It has no PR trigger, merge operation, default-branch target, App
  private key, or MRTS source-writing step.
- `ci/tools/update-workflow-tools.py` explicitly allowlists the new workflow
  for immutable Action-pin maintenance. The CI-security contract fixes the
  required job topology, permissions, ref, path, and non-force controls.
- Parent source and Gitlink, MRTS source/branch/commit, and any Framework
  gitlink update outside the future maintenance Draft PR remain out of scope.

## Acceptance criteria

- `update-submodules.yml` resolves only the full SHA at
  `Easton97-Jens/MRTS` `refs/heads/main`, compares it with `tools/MRTS`, and
  does nothing when the gitlink already matches.
- Validation is read-only, uses a credentials-free checkout with
  `submodules: false`, explicitly initializes only `tools/MRTS`, checks out
  the candidate detached, and runs `make quick-check`.
- A successful publisher can alter only the `tools/MRTS` gitlink on the fixed
  maintenance branch, makes a normal non-force push, and creates or updates
  one matching Draft PR; it never merges or updates `master` directly.
- The existing immutable Action-pin updater covers the new workflow, and
  focused positive/negative CI-security tests reject an MRTS `master` ref,
  reader credential injection, and force push.
- English and German documentation and this Change Record describe the same
  constrained design.

## Alternatives considered

- Keeping the unused variables in `update-workflow-tools.yml` was rejected:
  they provide no candidate resolution, validation, or gitlink update.
- Copying the Parent workflow verbatim was rejected because it would target
  the wrong path/repository and copy a Parent publisher force-with-lease
  behavior that Framework policy does not permit.
- Making the existing workflow-tool publisher update MRTS was rejected because
  Action/tool lock maintenance and a gitlink update have different allowed
  paths and credential boundaries.
- Recursive automatic checkout was rejected by the Framework workflow contract;
  the validator initializes only the declared direct submodule after the
  credentials-free default-branch checkout.

## Implementation decision

The new workflow follows the Parent lifecycle structurally while preserving
the Framework's stricter controls. It uses `tools/MRTS`,
`https://github.com/Easton97-Jens/MRTS.git`, and the repository's observed
default `refs/heads/main`, rather than the obsolete PR #47 `master` reference.
It resolves and revalidates a full SHA before updating the gitlink. The stable
maintenance branch is `automation/update-framework-mrts-submodule`; it is
accepted only when an existing matching Draft PR has the exact title/base and
changes no path other than `tools/MRTS`.

The existing tool-updater workflow's reviewed publisher body digest was
intentionally refreshed after its explicit path allowlist gained the new
workflow. No semantic broadening of that publisher occurs: its normal push,
Draft-only behavior, and staged-scope verification are unchanged.

## Changed files and tests

- `.github/workflows/update-submodules.yml` adds the constrained MRTS
  resolver, validator, and Draft-PR publisher.
- `.github/workflows/update-workflow-tools.yml` and
  `ci/tools/update-workflow-tools.py` add that workflow to the exact Action-pin
  maintenance allowlist; the obsolete PR #47 environment-only change is
  removed.
- `ci/checks/security/check-ci-security-contract.py` and
  `tests/ci_security/test_ci_security_contract.py` bind and test the new
  workflow profile, including negative ref/token/force-push mutations.
- The paired workflow-security and CI-tooling guides document the same
  boundaries in English and German.
- This paired Change Record provides delivery traceability.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `make PYTHON=.venv/bin/python test-ci-security-contract` | 127 | The clean external worktree has no local `.venv`; no source failure was inferred. | Framework task worktree. |
| `make PYTHON=<reviewed Framework test interpreter> test-ci-security-contract` | 0 | 136 CI-security, workflow, updater, and Python-contract tests passed after the reviewed workflow/profile corrections. | Framework task worktree; approved external pycache root. |
| `make PYTHON=<reviewed Framework test interpreter> check-github-actions-workflows` | 0 | Immutable Action-pin and permission checks accepted all 16 workflows, including the new updater. | Framework task worktree. |
| `make PYTHON=<reviewed Framework test interpreter> test-workflow-action-pins` | 0 | 25 immutable Action-pin regression tests passed. | Framework task worktree. |
| `make PYTHON=<reviewed Framework test interpreter> check-documentation` | 0 | Link, bilingual, repository-path, and Change Record contracts passed. | Framework task worktree. |
| `make PYTHON=<reviewed Framework test interpreter> lint` | 0 | The project-native full lint target passed, including shell/Python syntax, contracts, security checks, documentation, and whitespace validation. | Framework task worktree. |
| `git diff --check` | 0 | The in-progress source diff had no whitespace errors before final review. | Framework task worktree. |
| `gh pr view 47 --repo Easton97-Jens/ModSecurity-test-Framework --json headRefOid,baseRefOid,statusCheckRollup` | 0 | Confirmed base `c27c644…`, observed head `36a81c…`, and the external OSV check failure. | Run `20260726T094125Z-rebuild-pr-47-submodule-aligned`, OSV service receipt. |
| `gh run view 30196691788 --repo Easton97-Jens/ModSecurity-test-Framework --log-failed` | 0 | The failed OSV job reported external RPC service unavailability and scanner exit 127. | Same retained receipt. |

## Security impact

This is CI maintenance and trust-boundary hardening, not a product security
remediation. The positive control is the real workflow satisfying the native
CI-security contract. Negative mutations prove rejection of a stale MRTS
`master` ref, a reader `github.token` injection, and a force-with-lease push.
The workflow never executes untrusted PR code and keeps the only write token
out of resolver and validator. The Parent's `--force-with-lease` operation was
intentionally not reproduced.

## Documentation and runtime evidence

Both workflow-security and CI-tooling guides gain matching English/German
entries. No hosted maintenance run is manually dispatched because a successful
run could create or update a remote maintenance branch and Draft PR; that
delivery action remains contingent on the PR update and normal hosted checks.
The pre-existing PR OSV service failure is retained as a secret-free external
receipt. Its canonical Parent finding allocation is currently blocked because
the mounted `.codex/findings` storage rejects creation of the required new
`FND-GITHUB-0009` directory with `Read-only file system`.

## Checks not run

- A hosted `Update MRTS submodule` run was not manually dispatched, to avoid a
  remote branch/PR side effect before the source PR has passed normal review.
- Hosted Actions, SonarQube Cloud, review threads, and branch protection are
  exact-PR-head controls and will be observed only after the updated branch is
  pushed.

## Limitations and residual risk

Local source and contract checks cannot prove GitHub-hosted behavior, remote
MRTS availability, or Draft-PR creation until a scheduled/manual run is
permitted. The known OSV service failure is external to this diff and remains a
release-blocking hosted check until it is rerun successfully; no scanner,
quality gate, test, or permission has been weakened. The unavailable Parent
finding-store write access prevents canonical allocation of its new finding,
but the evidence receipt and this limitation are retained. No merge or direct
default-branch action is authorized.

## Final diff and review status

The scoped source diff received a focused workflow/security review: the only
write path is default-branch-gated, is limited to the MRTS gitlink, and does
not use a force push or MRTS source write. The final local full-lint,
documentation, immutable-pin, CI-security, and whitespace checks passed. The
remaining exact controls are the future PR-head hosted checks and, after a
permitted dispatch, the hosted maintenance lifecycle. This record does not
represent a merge, a Gitlink change, or verification of that future lifecycle.
