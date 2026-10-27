# Framework Ubuntu 26.04 runner migration

**Language:** English | [Deutsch](20261026-03-framework-ubuntu26.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261026-03-framework-ubuntu26 |
| UTC date | 2026-10-26 |
| Framework base revision | 312a298 |
| Issue or pull request | [PR #138](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/138) |

## Motivation and problem statement

The user requested every active Ubuntu version to move to 26. Floating ubuntu-latest still selects an older image, and Python installability preflight must match the actual runner.

## Affected components and security boundaries

All Framework active GitHub Actions jobs, strict runner profiles, the shared Python manifest selector and relevant offline regressions. Parent gitlink unchanged; MRTS read-only. No host operating system upgrade.

## Acceptance criteria

Every active Framework job explicitly selects ubuntu-26.04. Exact Python metadata checks require Linux 26.04/x64 artifacts. Strict security profiles and meaningful negative mutations continue to pass without permission, gate or dependency changes.

## Alternatives considered

Keeping ubuntu-latest does not honor the requested version. Updating only workflows leaves the installability selector inconsistent. Historical evidence and unrelated security-fixture inputs should not be rewritten.

## Implementation decision

Pin all 31 jobs across 18 workflows to ubuntu-26.04, retaining existing x64 architecture. Update exact reviewed profiles, including a runner-only whole-publisher digest change. Require the official setup-python manifest 26.04 tuple and matching filename. Canonical Python 3.14.8 and candidate 3.14.10 both have official stable matching builds, so Python pins remain unchanged.

## Changed files and tests

Workflows, two security checkers, Python manifest helper, relevant updater/security fixtures and paired current workflow documentation. Add offline checks for every active workflow runner and rejection of a previous Ubuntu 24.04 artifact.

## Commands and results

106 focused updater, workflow, security and Sonar contract methods passed; the final readiness suite passed 12 methods after adding the exact actionlint-label regression. Canonical common/workflow pins and GitHub Actions pin/permission checks passed. Actionlint with ShellCheck, offline Zizmor (zero findings), documentation and final diff checks passed. Ruff lint passed all six changed Python files; format checks passed five, while the workflow checker has a reproduced pre-existing formatting failure and remains a one-line runner change. The actionlint configuration adds only the official exact label, with no ignored errors.

## Security impact

Permission maps, publisher programs, action pins, token handling and gates remain unchanged. The MRTS updater publisher digest was recalculated only after proving that reverting its runner field alone reproduces the previous reviewed digest.

## Documentation and runtime evidence

Paired workflow-security documentation now describes 26.04. Historical change records, run logs, version-bound snapshots and generic nonexecuted workflow fixtures retain their original platforms. No active Ubuntu container reference was found outside the read-only MRTS boundary.

## Checks not run

Hosted jobs, candidate installation, updater publication, connector runtime, E2E and I12 campaigns were not executed by this worker.

## Limitations and residual risk

Offline validation and official artifact availability do not prove hosted runner execution. Ubuntu image tools can differ; fresh hosted evidence remains required after delivery.

## Final diff and review status

Prepared for coordinator review and ordinary PR follow-up. No Git or provider writes by this worker.
