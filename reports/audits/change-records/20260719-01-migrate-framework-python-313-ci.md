# Change record — 20260719-01-migrate-framework-python-313-ci

**Language:** English | [Deutsch](20260719-01-migrate-framework-python-313-ci.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260719-01-migrate-framework-python-313-ci` |
| UTC date | `2026-07-19` |
| Framework base revision | `047c11140ba7f2bd170b6f313d0223d0cd37f1be` |
| Issue or pull request | [Framework PR #33](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/33) — ready for review against `master`; this record's traceability-only follow-up requires a new exact-head validation round |

## Motivation and problem statement

Current Framework master selected Python 3.13 broadly but left the strict CI
dependency lock bound to CPython 3.12.13's CP312 PyYAML wheel. Hosted jobs
correctly failed closed because a CP313 wheel has a different SHA-256. The
source-owned security checker still required 3.12.13 and every `setup-python`
use lacked `check-latest: false`.

The same static contract exposed a distinct provenance drift: workflows already
pin `actions/upload-artifact` to v7.0.1's immutable commit while the custom
action lock still recorded v5.0.0. This record covers the minimal combined
repair necessary for a coherent, fail-closed Python 3.13 CI contract.

## Affected components and security boundaries

- Twelve `actions/setup-python` uses across eight workflows now use exact
  CPython `3.13.14` with `check-latest: false`.
- `requirements-ci.lock` names the reviewed CP313 PyYAML 6.0.3 Linux x86_64
  wheel and its verified SHA-256.
- `ci/checks/security/check-ci-security-contract.py` enforces the same exact
  version and continues to require hash-locked installation.
- `ci/tooling/security-tools.lock.yml` matches the active immutable
  `actions/upload-artifact` v7.0.1 pin.
- The paired CI-security tooling guide documents the exact CP313 contract.

The boundary is CI dependency and action provenance. No permission, artifact
retention, mutable tag, `--require-hashes`, Parent, Parent gitlink, or MRTS
behavior is changed.

## Acceptance criteria

1. Every active in-scope Python CI use is exact `3.13.14` with
   `check-latest: false`.
2. The CP313 filename and SHA-256 in `requirements-ci.lock` agree with the
   official artifact and pass target-ABI `pip download --require-hashes`.
3. The CI-security checker and action lock accept current source while their
   negative controls continue to reject mismatches.
4. English and German security documentation remain equivalent.
5. Exact PR-head and resulting-master hosted validation remain required.

## Alternatives considered

- Restoring CPython 3.12.13 would leave the old lock usable but would not meet
  the requested Python 3.13 migration.
- Deleting or relaxing `--require-hashes` would conceal the defect and weaken
  a supply-chain control; it was rejected.
- Reverting the active v7.0.1 action pins would be unrelated rollback work.
  Updating only the stale provenance record is the smallest consistent repair.
- Direct `master` push is prohibited; delivery uses a normal task-branch PR.

## Implementation decision

The chosen contract is exact CPython `3.13.14` with `check-latest: false`.
The reviewed CP313 wheel SHA-256 is
`0f29edc409a6392443abf94b9cf89ce99889a1dd5376d94316ae5145dfedd5d6`.
The active action lock now records v7.0.1 immutable commit
`043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`.

No dependency is installed into the checkout. Target-ABI validation downloads
only the pinned wheel into the task-owned external run directory. Parent and
MRTS remain unchanged.

## Changed files and tests

- Eight workflow files: `lint.yml`, `check-action-versions.yml`,
  `check-common-versions.yml`, `ci-security-osv.yml`,
  `ci-security-quality.yml`, `ci-security-scorecard.yml`,
  `ci-security-secrets.yml`, and `ci-security-workflow-lint.yml`.
- `requirements-ci.lock`, `ci/checks/security/check-ci-security-contract.py`,
  and `ci/tooling/security-tools.lock.yml`.
- `docs/security/ci-security-tooling.md` and its German companion.
- This English/German Change Record pair.

No test source changes were needed. Existing
`test_current_workflows_and_lock_pass` fails with the old inconsistent source
and passes with the repaired source. The suite retains negative tests for
missing exact version, missing `check-latest`, missing hash locking, and
malformed or mutable action references.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `ci/checks/security/check-ci-security-contract.py --root .` using the existing Framework virtual environment | 0 | Current CI-security contract passed. | `20260719T211529Z-framework-python-313-master-migration-939e61b5` |
| `make ... test-ci-security-contract check-github-actions-workflows test-workflow-action-pins` with external `BUILD_ROOT` and `TMP_ROOT` | 0 | 69 CI-security tests, action pins, and permissions passed. | Task-owned `downloads/build` |
| `pip download --require-hashes` for CP313, `manylinux2014_x86_64`, and ABI `cp313` | 0 | Downloaded only the reviewed wheel; local SHA-256 matched the lock. | Task-owned `downloads/pyyaml-cp313` |
| `gh api repos/actions/upload-artifact/git/ref/tags/v7.0.1 --jq .object.sha` | 0 | Official tag resolves to `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`. | External GitHub API evidence |
| `git diff --check` | 0 | No scoped whitespace error. | Task worktree |

## Security impact

The original CP313/CP312 mismatch remains fail closed: `--require-hashes` and
the negative contract coverage are preserved. The legitimate CP313 path has an
exact reviewed wheel digest. The stale action lock is synchronized to the
already active immutable commit, not a mutable tag. No bypass, suppression,
permission expansion, scanner waiver, or quality-gate change was made.

Original hosted failure and alternate-bypass evidence remain required on the
exact PR head and resulting master before either finding can be verified.

## Documentation and runtime evidence

The paired CI-security tooling guide now records CPython `3.13.14` and the
CP313 wheel. This record documents static CI and target-artifact evidence only;
it makes no connector-runtime, lifecycle, or hosted CPython-runtime claim.

## Checks not run

- Aggregate `make lint`: launched twice with task-owned external output, but
  this execution wrapper did not return a terminal exit code after its verbose
  output. Every remaining Makefile component was then executed individually
  with exit code 0: workflow contracts, CI-security tests, change-record,
  CRS-provenance, action-pin, documentation, data-flow, catalog, and shell
  contract checks. It is therefore recorded as `not_run_to_terminal`, not as a
  full aggregate pass.
- Before this traceability-only status update, ready-for-review PR #33 at exact
  head `823d66ac049ba6fcd5d459682610687fc388f809` had passed GitHub Actions and
  SonarQube Cloud Quality Gate evidence, with no reviews or review threads.
  This status update changes the PR head, so the new exact-head Actions,
  SonarQube Cloud, review, merge, and resulting-master validation remain
  mandatory and pending.
- Local CPython 3.13.14 runtime: unavailable on this host. CP313 target-wheel
  resolution is artifact-selection evidence, not hosted runtime proof.

## Limitations and residual risk

The existing Framework virtual environment uses CPython 3.14.4. It validates
the static contract but cannot substitute for hosted CPython 3.13.14 behavior.
Master continues to contain the failing contract until the task PR is merged.
Existing master-only SonarCloud backlog and unrelated GitHub configuration
findings are neither changed nor waived.

## Final diff and review status

The scoped diff has been reviewed and `git diff --check` passed. No credential,
token, raw log, or sensitive payload is recorded. PR #33 is ready for review;
before this status-only update, its exact head was clean and mergeable with
passed GitHub Actions, a passed SonarQube Cloud Quality Gate, and no review
feedback. The post-update exact-head and merge/master evidence remain pending
and are retained in task completion evidence without a self-referential commit
loop.
