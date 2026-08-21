# Change record

**Language:** English | [Deutsch](20260821-04-fix-common-version-updater-bootstrap.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260821-04-fix-common-version-updater-bootstrap |
| UTC date | 2026-08-21 |
| Framework base revision | 798bff0c921ab8c7f10b2ca949304d58e7f205a2 |
| Issue or pull request | None at record creation; delivery creates a task-owned Draft PR from the reviewed commit. |

## Motivation and problem statement

The hosted common-version candidate job failed on a fresh runner because
update-workflow-tools.py imports PyYAML before that job installed the existing
hash-locked CI requirements. The publisher had the same latent ordering defect.
The repair must preserve the lock, fail-closed bootstrap, snapshot-before-apply
binding, and existing publisher boundary.

## Affected components and security boundaries

- .github/workflows/check-common-versions.yml: candidate and publisher runner
  bootstrap before native helper import.
- ci/checks/security/check-ci-security-contract.py and CI-security tests:
  reviewed body digests and a semantic ordering control.
- English/German workflow-security documentation: the fresh-runner dependency
  boundary.

Parent source and gitlink are unchanged. MRTS remains read-only and unchanged.

## Acceptance criteria

1. Candidate and publisher install requirements-ci.lock with --require-hashes
   and complete pip check before their first native workflow-tool helper
   invocation.
2. The snapshot remains before caller-bound plan application; no workflow step,
   permission, token path, lock content, or publisher scope changes.
3. Positive and negative tests reject missing, commented, echoed, late, or
   pre-snapshot bootstraps.
4. A Framework Draft PR contains only the reviewed task-owned change and its
   exact head is checked by the available hosted controls.

## Alternatives considered

Adding a new bootstrap step was rejected because the reviewed workflow
topology, sensitive-reference paths, and publisher profile already bind the
existing step positions. Leaving installation after the first helper import or
loosening the lock would retain the failure or weaken supply-chain controls.

## Implementation decision

The existing locked install and pip check are moved into the unchanged snapshot
run body in both fresh jobs, directly before the helper. The later
plan-application body no longer duplicates them. The security checker now
enforces the command order independently of its reviewed run-body digests.

## Changed files and tests

- Updated the common-version workflow, security contract, and its focused
  positive/negative regression tests.
- Updated English/German workflow-security documentation.
- Added this paired Change Record.

The negative cases cover missing hash enforcement, missing pip check, commented
or echoed bootstrap text, an updater before bootstrap, and an updater in a
prior step.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused unified-workflow and CI-security contract tests | 0 | 47 tests passed, including the new positive and negative ordering controls. | Task-owned Framework worktree |
| Complete CI-security test suite | 0 | 286 tests passed. | Task-owned Framework worktree |
| Direct CI security contract | 0 | The reviewed workflow, pin, token, and bootstrap contract passed. | Task-owned Framework worktree |
| Workflow metadata, permission, and Action-pin checks | 0 | All 16 workflows and all external Action pins passed. | Task-owned Framework worktree |
| Workflow-security and documentation checks | 0 | 9 workflow-security tests plus link, bilingual, path, and Change Record checks passed. | Task-owned Framework worktree |
| Pinned Ruff lint and format checks | 0 | The hash-verified Ruff 0.16.3 accepted all three changed Python files. | Task-owned external runner-temporary directory |
| No-bytecode Python syntax compilation of the three changed Python files | 0 | All files compiled without writing bytecode into the external worktree. | Task-owned Framework worktree |

## Security impact

The original source ordering has been retested structurally: the candidate and
publisher now bootstrap the hash-locked PyYAML dependency before importing the
helper. The semantic contract independently rejects the documented ordering
bypasses. No credential, permission, checkout, lock, publisher, or PR-merge
control was expanded.

## Documentation and runtime evidence

The English/German workflow-security documents now state the bootstrap-before-
helper invariant. No hosted execution of the proposed source exists at record
creation; the normal PR checks and a later trusted default-branch run provide
the remaining runtime evidence.

## Checks not run

No manual hosted maintenance dispatch was performed from this branch because
the trusted workflow checks out the default-branch source; it would not execute
this unmerged repair. Runtime candidate/publisher behavior remains a
post-integration evidence requirement.

The local pinned Pyright check was not run because Node.js is absent in this
execution environment; the normal PR quality workflow remains the authoritative
type-check evidence.

## Limitations and residual risk

The repair removes the missing-PyYAML bootstrap failure but does not fabricate
an upstream update to exercise the candidate and publisher paths. A successful
PR contract run is source-level evidence, not a substitute for a later trusted
default-branch maintenance run.

## Final diff and review status

At record creation, the task worktree contains only the scoped repair and has
not been committed, pushed, or merged. A final whitespace, secret, scope, and
exact-head review is required before delivery.
