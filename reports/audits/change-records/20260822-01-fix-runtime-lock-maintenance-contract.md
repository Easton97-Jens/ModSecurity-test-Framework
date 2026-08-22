# Change record

**Language:** English | [Deutsch](20260822-01-fix-runtime-lock-maintenance-contract.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260822-01-fix-runtime-lock-maintenance-contract` |
| UTC date | 2026-08-22 |
| Framework base revision | `b5575f7bbf53ca901a813d9bc32945f3b460c156` |
| Issue or pull request | `FND-FRAMEWORK-0111`; Framework Draft PR pending |

## Motivation and problem statement

Trusted master maintenance run `32543831249` generated Framework PR #106 with
a valid NGINX update. Its Lint checks failed because the runtime-lock test
treated the old `release-1.31.3` tag, archive, and digest as the only valid
environment although the generated lock correctly used `release-1.31.4`.
The candidate workflow did not run the runtime-lock suite before publishing the
Draft PR.

## Affected components and security boundaries

- `tests/security_regression/test_runtime_component_lock.py`: derives the
  legitimate `nginx-h1` environment tuple from the canonical runtime lock and
  retains a tag-drift negative control.
- `.github/workflows/check-common-versions.yml`: runs the runtime-lock suite in
  the candidate focused controls before the publisher job can run.
- `ci/checks/security/check-ci-security-contract.py`: updates the reviewed,
  hash-bound candidate run profile for that explicit new control.
- `tests/ci_security/test_unified_common_maintenance_workflow.py` and
  `tests/ci_security/test_ci_security_contract.py`: protect the pre-publication
  runtime-lock requirement and reject its removal.

The candidate/publisher dependency, byte-for-byte candidate validation,
publisher allowlist, Draft-only reuse guard, repository-limited App token, and
branch protections remain unchanged.

## Acceptance criteria

1. The current `nginx-h1` lock tuple is accepted; a different tag with the
   current asset and SHA-256 is rejected.
2. Candidate focused controls execute the runtime-lock suite before publisher
   credentials or any Draft-PR write path.
3. The precise candidate run body remains hash-bound and a test rejects removal
   of the runtime-lock control.
4. Focused and complete repository-native validation pass with no Parent
   gitlink or MRTS change.
5. A future Framework Draft PR has current-head CI, SonarQube Cloud, review,
   and thread evidence before any separately authorized merge.

## Alternatives considered

- Expanding the publisher allowlist to rewrite test source was rejected: an
  updater must not receive broader source-write authority to repair a test.
- Hard-coding the current NGINX release was rejected because every valid future
  update would recreate the same test drift.
- Removing the strict run-body digest was rejected because it would weaken the
  reviewed candidate security profile.

## Implementation decision

The positive test reads `source_provenance`, `asset_name`, and `sha256` from
the checked-in `nginx-h1` lock profile. The negative test changes only the
derived release tag. The candidate runs the existing whole runtime-lock test
module; its exact run body is deliberately re-hashed in the security contract.
No generated PR, write allowlist, token scope, or mutable runtime pin was
changed by this corrective branch.

## Changed files and tests

- `.github/workflows/check-common-versions.yml`
- `ci/checks/security/check-ci-security-contract.py`
- `tests/security_regression/test_runtime_component_lock.py`
- `tests/ci_security/test_unified_common_maintenance_workflow.py`
- `tests/ci_security/test_ci_security_contract.py`
- this paired Change Record

The legitimate control is the current lock-derived tuple. The negative control
uses the same asset and digest but a distinct tag, and must emit the existing
`NGINX_RELEASE_TAG drift` diagnostic. The contract mutation test removes the
new test module and must fail the exact reviewed workflow profile.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy …python -B -m unittest tests.security_regression.test_runtime_component_lock -v` | 0 | 13 runtime-lock tests passed, including the lock-derived NGINX positive and negative controls. | Isolated Framework worktree |
| `rtk proxy …python -B -m unittest tests.ci_security.test_unified_common_maintenance_workflow -v` | 0 | 14 unified-workflow contract tests passed, including candidate pre-publication runtime-lock coverage. | Isolated Framework worktree |
| `rtk proxy make … test-runtime-component-lock` | 0 | Native lock checker and 13-test target passed. | Task-owned external build/TMP root |
| `rtk proxy …python -B -m unittest tests.ci_security.test_ci_security_contract tests.ci_security.test_framework_ci_security_contract -v` | 0 | 47 CI security-contract tests passed; removal of the runtime-lock control is rejected. | Isolated Framework worktree |
| `rtk proxy …python -B ci/checks/security/check-ci-security-contract.py --root .` | 0 | Exact reviewed workflow security profile passed. | Isolated Framework worktree |
| `rtk proxy make … lint` | 0 | Complete Framework native lint passed, including 288 CI-security tests, runtime/pin/workflow contracts, and documentation checks. | Isolated Framework worktree and task-owned build/TMP root |

## Security impact

This repairs CI-maintenance availability without changing a privileged sink.
The original reproduction remains a stale fixture only; a changed tag continues
to fail, and removing the new candidate control is rejected by the exact
workflow profile. Direct callers were reviewed: the candidate remains a
read-only job and `publish` still requires candidate success before its
repository-limited token steps.

## Documentation and runtime evidence

This English/German Change Record documents the Framework-only change. The
retained hosted-failure receipt is recorded in Parent's canonical
`FND-FRAMEWORK-0111` evidence ledger (SHA-256
`0c932428f325f94d5fcbcfceecdb66cdd020f04402a828fb9ff1225a7565a7e0`). No
connector runtime was changed or run.

## Checks not run

Current-head hosted CI, SonarQube Cloud, and review/thread validation remain
pending until the corrective Draft PR exists. No master merge authority exists
for this change.

## Limitations and residual risk

The branch cannot itself prove GitHub-hosted publisher credentials or a future
generated PR's complete check suite. Existing PR #106 was externally changed
from Draft to ready for review; this repair neither changes that PR nor claims
an automated Draft-state bypass.

## Final diff and review status

Implementation is in an isolated task-owned Framework worktree. Complete native
lint and focused security-diff review passed; final scope/whitespace/secret
review, commit, PR, and current-head hosted evidence remain before delivery can
be reported as `verified_pr`.
