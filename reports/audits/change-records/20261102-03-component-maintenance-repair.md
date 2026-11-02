# Repair component maintenance imports and diagnostics

**Language:** English | [Deutsch](20261102-03-component-maintenance-repair.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261102-03-component-maintenance-repair |
| UTC date | 2026-11-02 |
| Framework base revision | 67483d5140b531e77c12f8a32252f72bc889f8ee |
| Issue or pull request | Follow-up to Actions run 41403875624; task branch codex/component-maintenance-repair-20261102 |

## Motivation and problem statement

The common maintenance resolver launches the CRS view synchronizer directly.
Without a caller-provided import path, that script failed to import the Framework
package and blocked the complete plan. Failure details were omitted from the
report and the plan artifact was skipped after a failed step.

## Affected components and security boundaries

Framework-owned generator imports, canonical maintenance diagnostics, and the
trusted workflow artifact boundary. Parent source, its Framework gitlink, and
MRTS are unchanged. Upstream diagnostic text must not become Markdown markup or
GitHub runner commands.

## Acceptance criteria

Direct CRS checks and writes work without `PYTHONPATH` from a separate data
directory. Failed generated checks retain the final exception cause. Reports
contain bounded, escaped reasons; logs disable command interpretation while
printing them. Failed resolver/reconciliation jobs retain their same-run plan
without allowing downstream publication.

## Alternatives considered

Setting `PYTHONPATH` only in the initial job leaves other direct callers exposed.
Installing the package adds an unnecessary prerequisite. Ignoring generated-check
failures would weaken the existing contract and was rejected.

## Implementation decision

Bootstrap the trusted package path from the resolved script location, independently
of `--root`. Preserve the last nonempty error line for failed generators. Escape
bounded diagnostic text and print the report between unpredictable runner
stop/resume markers. Upload the run-and-attempt-bound plan with `!cancelled()`;
resolver exit codes, digest checks, permissions and downstream gates are retained.

## Changed files and tests

- `ci/tools/sync-crs-contract-views.py` and its existing real-subprocess tests.
- `ci/tools/canonical_maintenance.py` and `tests/ci_security/test_canonical_maintenance.py`.
- `.github/workflows/check-common-versions.yml` and `tests/ci_security/test_unified_common_maintenance_workflow.py`.
- `docs/github-actions-workflow-security.md` / `docs/github-actions-workflow-security.de.md` and this record pair.

The import regression removes `PYTHONPATH` and runs from the fixture directory.
Diagnostics coverage includes a long traceback, HTML/Markdown/control text, and
execution of the workflow's report block with a fatal exit and command-like text.

## Commands and results

Commands ran in the Framework task worktree with bytecode disabled and temporary
files under the external task root. In the portable commands below,
`$FRAMEWORK_PYTHON` denotes the existing Framework virtual-environment interpreter
and `$ACTIONLINT` the existing actionlint v1.7.12 binary. The local task plan
retains their exact host paths.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk bypass env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 PYTHONSAFEPATH=1 "$FRAMEWORK_PYTHON" ci/tools/sync-crs-contract-views.py --check` | 0 | Original import failure reproduced before the fix; direct check passes after it | Task worktree |
| `rtk bypass env PYTHONDONTWRITEBYTECODE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_sync_crs_contract_views -v` | 0 | 10 existing test methods passed, including direct check/write and portable contract cases | Task worktree |
| `rtk bypass env PYTHONDONTWRITEBYTECODE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_canonical_maintenance tests.ci_security.test_unified_common_maintenance_workflow` | 0 | 30 tests passed, including inert diagnostics and fatal report exit | Task worktree |
| `rtk bypass "$ACTIONLINT" -config-file .github/actionlint.yaml .github/workflows/check-common-versions.yml` | 0 | Changed workflow passes actionlint v1.7.12 | Task worktree |

The existing locked Ruff 0.16.10 binary passed `check --no-cache` and
`format --check` for all five changed Python files. No tool was installed.

## Security impact

The import source is the trusted script checkout rather than caller-selected
contract data. Newly displayed reasons are bounded and escaped; log command
processing is disabled around the report. No secret values, complete logs,
credentials, or payloads were added. Retained artifacts do not convert a failed
plan into permission to apply or publish it.

## Documentation and runtime evidence

Updated the paired workflow security guide and this record pair. Real local
subprocess execution proves the import correction. No connector runtime or hosted
maintenance publication evidence is claimed; the original checkout and gitlinks
remain unchanged.

## Checks not run

No live publishing maintenance workflow was dispatched. Full connector builds and
historical runtime matrices are outside this CI-helper change. Hosted PR checks
and applicable quality gates are separate delivery evidence.

## Limitations and residual risk

Upstream API availability can still block a plan. Earlier anonymous online
inspection reached a GitHub rate limit; deterministic local checks do not prove
live upstream availability or successful publication. Cancelled runs do not
guarantee artifact upload.

## Final diff and review status

Task-owned code was reviewed and `git diff --check` passed. Documentation and
remote delivery checks are recorded separately in the task plan and PR. This
record contains no claim of merge, hosted qualification, or automatic publication.
