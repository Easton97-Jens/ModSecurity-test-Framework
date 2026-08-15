# Change record — 20260815-01-fix-python-maintenance-pr-base

**Language:** English | [Deutsch](20260815-01-fix-python-maintenance-pr-base.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260815-01-fix-python-maintenance-pr-base` |
| UTC date | `2026-08-15` |
| Framework base revision | `01952978772995c054ba6a4cba86adc5d0cd1e7d` |
| Issue or pull request | Reported GitHub Actions run `31899169302`; the current user authorized one task-owned Draft-PR delivery follow-on after the reviewed local change. Concrete PR and head-SHA evidence is retained outside this versioned record. |

## Motivation and problem statement

The scheduled CPython maintenance publisher could validate a candidate and then
fail in `peter-evans/create-pull-request` because a checked-out maintenance
branch became the action's implicit pull-request base. The publisher must
always construct its candidate from a local `master` that exactly matches
`origin/master`, while still validating an existing maintenance branch before
it is reused.

## Affected components and security boundaries

The Framework-only change affects the GitHub Actions publisher trust boundary
in `.github/workflows/check-python-version.yml`, its static CI-security
contract checker, and its regression tests. The workflow retains the scoped
GitHub App token, immutable action pin, least-privilege permissions, fixed
maintenance branch, and `.python-version`-only publish allowlist. No Parent,
connector-runtime, or MRTS content is affected.

## Acceptance criteria

1. The workflow fetches `origin/master`, validates an existing matching
   maintenance branch from a detached checkout, then force-creates and hard
   resets local `master` to `origin/master` before candidate application.
2. The candidate path proves that it starts clean on `master` and leaves only
   `.python-version` different from `origin/master`.
3. The pull-request action names `base: master` and the fixed maintenance
   branch separately; the no-existing-branch path does not create a local
   maintenance branch.
4. The CI-security contract rejects regressions of the trusted-base lifecycle,
   base/branch separation, and changed-path constraints.
5. Required focused and native workflow-contract checks pass locally.

## Alternatives considered

- Adding only `base: master` would not repair the untrusted checked-out
  working base and is insufficient.
- Checking out the existing maintenance branch as a local branch would leave
  the publisher state ambiguous; detached validation is retained instead.
- Creating the maintenance branch before candidate validation would violate
  the no-update-path requirement, so the false branch remains a no-op.

## Implementation decision

The existing maintenance branch is fetched and constrained to a descendant of
`origin/master` with a `.python-version`-only, whitespace-clean diff. It is
checked out detached solely for existing-branch contract checks. The workflow
then force-creates local `master` at `origin/master`, hard-resets it to that
remote ref, and proves the selected branch and clean tree before applying the
candidate. The post-update diff is anchored directly to `origin/master`, and
the publisher action explicitly uses `base: master` with
`automation/update-framework-python-314` as its branch.

## Changed files and tests

- `.github/workflows/check-python-version.yml` adds the trusted-base restore,
  explicit pull-request base, detached existing-branch validation, and
  master-anchored candidate assertions.
- `ci/checks/security/check-ci-security-contract.py` locks the new step,
  action inputs, and reviewed step digests into the CI-security contract.
- `tests/ci_security/test_ci_security_contract.py` adds negative regressions
  for implicit/same base, non-detached reuse, premature branch creation,
  missing trusted reset, and missing master/diff assertions.
- This English/German Change Record pair documents the Framework-only change.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Selected virtual-environment `python -m unittest tests.ci_security.test_ci_security_contract tests.ci_security.test_python_version_contract tests.ci_security.test_update_python_version -v` | `0` | 57 focused CI-security, Python-version, and updater tests passed. | Task-owned external validation root |
| `ci/checks/security/check-ci-security-contract.py --root .` | `0` | CI security contract passed. | Task-owned external validation root |
| `make test-ci-security-contract` | `0` | 174 CI-security contract tests passed. | Task-owned external validation root |
| `make check-github-actions-workflows` | `0` | Workflow syntax, pin, permission, and version-contract checks passed. | Task-owned external validation root |
| `make test-workflow-security-contract` | `0` | 9 workflow-security regression tests passed. | Task-owned external validation root |
| `python -m py_compile` for the changed CI checker and test | `0` | Both changed Python modules compiled successfully. | Task-owned external validation root |
| `make check-documentation` | `0` | Link, bilingual-variable, repository-path, and Change Record checks passed. | Task-owned external validation root |
| `make test-change-record-contract` | `0` | 4 Change Record contract tests passed. | Task-owned external validation root |

## Security impact

This is a CI trust-boundary remediation. It eliminates the publisher's
maintenance-branch working-base ambiguity without expanding token scope,
permissions, allowed write paths, action mutability, or auto-merge behavior.
The focused security diff review found no separate reportable security finding;
the original availability defect is addressed through the checked-in workflow
and fail-closed contract tests.

## Documentation and runtime evidence

This paired Change Record is the English/German documentation change. Local
contract evidence was collected; no hosted workflow was dispatched, so the
actual GitHub Actions runner, GitHub App installation, and
`create-pull-request` service interaction have not been re-executed.

## Checks not run

- No live GitHub Actions dispatch or hosted exact-head run was performed,
  because the authorized scope is normal Draft-PR delivery, not workflow
  execution.
- No merge, Parent change, MRTS change, Gitlink update, force push, or direct
  `master` write is authorized or performed.

## Limitations and residual risk

The local contract proves the intended YAML and negative regressions but cannot
prove GitHub-hosted runner semantics or GitHub App permissions. A manual or
scheduled trusted-`master` run is still required to observe the original
`create-pull-request` failure path end to end.

## Final diff and review status

The scoped diff, whitespace check, and CI-security contract review are
completed locally. No credential, token, raw log, or sensitive payload is
recorded. The current user has authorized the focused commit, normal push, and
Draft-PR follow-on; concrete remote/PR evidence is retained outside this
versioned record.
