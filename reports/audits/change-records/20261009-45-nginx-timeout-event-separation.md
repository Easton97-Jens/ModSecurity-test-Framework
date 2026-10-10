# Change record

**Language:** English | [Deutsch](20261009-45-nginx-timeout-event-separation.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261009-45-nginx-timeout-event-separation |
| UTC date | 2026-10-09 |
| Framework base revision | 567d36acc010a68882462b5ffe23b9e94bff5d73 |
| Issue or pull request | Draft Framework PR #137 follow-up |

## Motivation and problem statement

The genuine R11 Phase-1 and Phase-4 soft-budget invocations emitted measured
Engine-return telemetry before the caller chose its terminal host action.
The Framework incorrectly required that early telemetry to carry the later
terminal commitment, status and connection-abort fields. Both invocations
therefore failed validation despite retaining their distinct real events.

## Affected components and security boundaries

The reusable NGINX lifecycle sequence validator and its Engine-budget tests.
The Required selection remains 97. Source authority, receipts, event identity,
monotonic timing, wire evidence, Root/nobody roles and cleanup remain required.
Parent product code and MRTS are unchanged by this Framework change.

## Acceptance criteria

Validate early timing telemetry and later terminal host action according to
their respective emission points. Require the same phase, transaction, URI,
technical timeout classification and empty rule identity in both events.
Reject missing, duplicate, foreign or mismatched events, invalid budget
measurements and incorrect terminal stage, commitment, status or abort facts.

## Alternatives considered

Copying terminal host-action fields into the early measurement would invent
facts that were unavailable at its emission point. Dropping event identity or
terminal action checks would hide mismatches. Neither approach is used.

## Implementation decision

Keep shared identity and classification checks for both events. Check the
measurement against its initialized transport defaults and actual measured
Engine return. Check the terminal timeout event separately for its required
stage and final host action. Phase 1 retains a complete HTTP 504 response;
Phase 4 retains the already visible HTTP 200 and connection abort after commit.
The measured Engine return remains 1 and the rejected phase remains incomplete.

## Changed files and tests

`tests/runners/nginx_lifecycle_sequence.py`,
`tests/no_crs/test_nginx_engine_budget_sequence.py`, and this paired record.
Regression fixtures represent the observed separation of the two events.
Negative controls mutate shared identity, early transport defaults and required
terminal fields independently in both phases.

## Commands and results

The focused command was:

```text
rtk proxy env PYTHONDONTWRITEBYTECODE=1 "${FRAMEWORK_PYTHON}" -m unittest tests.no_crs.test_nginx_engine_budget_sequence -v
```

Before implementation it exited 1 with 6 tests and 2 failures. After
implementation it exited 0 with all 9 tests passing.

The neighboring contract command was:

```text
rtk proxy env PYTHONDONTWRITEBYTECODE=1 "${FRAMEWORK_PYTHON}" -m unittest tests.no_crs.test_nginx_engine_budget_sequence tests.no_crs.test_nginx_native_operation_projection tests.no_crs.test_nginx_native_operation_bundle tests.no_crs.test_nginx_lifecycle_sequence -q
```

It exited 0 with 61 tests passing in 4.851 seconds. `rtk proxy git diff
--check` exited 0. `FRAMEWORK_PYTHON` denotes the reviewed Framework-owned
interpreter; host-specific paths remain in the external task handoff.

`rtk make check-documentation PYTHON="${FRAMEWORK_PYTHON}"` exited 0:
links, bilingual variables, repository path references and Change Records
passed.

The complete Framework lint command was:

```text
rtk make lint PYTHON="${FRAMEWORK_PYTHON}" FRAMEWORK_ROOT="${FRAMEWORK_WORKTREE}" CONNECTOR_ROOT="${FRAMEWORK_WORKTREE}" OUTPUT_ROOT="${FRAMEWORK_WORKTREE}" BUILD_ROOT="${TASK_ROOT}/build" TMP_ROOT="${TASK_ROOT}/tmp" LOG_ROOT="${TASK_ROOT}/logs" MRTS_BUILD_ROOT="${TASK_ROOT}/mrts" SOURCE_ROOT="${TASK_ROOT}/source" EVIDENCE_ROOT="${TASK_ROOT}/evidence" CI_ROOT="${FRAMEWORK_WORKTREE}/ci"
```

It completed with exit 0 on the combined R11 follow-up worktree. The retained
log contains no FAIL, ERROR or SKIP markers and has SHA-256
`08672fd886ab8aebb02af89b77114a08c344f3e54a9c4b935bf55ba4f755ff17`.
Final documentation checks covered 300 bilingual pairs and 915 files.
`FRAMEWORK_WORKTREE` denotes the reviewed Framework checkout and `TASK_ROOT`
its external task-data root; exact host bindings remain in the task handoff.

The combined worktree contract suite used:

```text
rtk make test-no-crs-contract PYTHON="${FRAMEWORK_PYTHON}" FRAMEWORK_ROOT="${FRAMEWORK_WORKTREE}" CONNECTOR_ROOT="${FRAMEWORK_WORKTREE}" OUTPUT_ROOT="${FRAMEWORK_WORKTREE}" BUILD_ROOT="${TASK_ROOT}/build" TMP_ROOT="${TASK_ROOT}/tmp" LOG_ROOT="${TASK_ROOT}/logs" MRTS_BUILD_ROOT="${TASK_ROOT}/mrts" SOURCE_ROOT="${TASK_ROOT}/source" EVIDENCE_ROOT="${TASK_ROOT}/evidence" CI_ROOT="${FRAMEWORK_WORKTREE}/ci"
```

It exited 0 with 410 tests passing in 165.181 seconds. The retained log
contains no fail, error or skip marker and has SHA-256
`076340b756dc78ea0c2b4a88c6174a1227ef2f1b0f409555f0b1a14980787739`.

A read-only helper recheck accepted both unchanged original R11 timeout
observations. This is diagnostic validation of retained evidence, not a new
sealed or Canonical replay: the original source authority remains bound to
its original Framework revision.

## Security impact

No validator or authority guard is disabled. Early telemetry cannot claim
later terminal action, and terminal evidence must still prove the required
host result. Required records continue to need genuine runtime evidence.

## Documentation and runtime evidence

This English/German Change Record pair documents the event contract. No
runtime evidence is synthesized or relabeled. Original R11 remains terminal
FAIL evidence; acceptance by the changed helper does not establish a fresh
source-bound lifecycle result.

## Checks not run

Fresh runtime, Canonical finalization, remote CI/Sonar and Parent gitlink
integration remain pending.

## Limitations and residual risk

Unit fixtures and read-only rechecks cannot replace a fresh Root/nobody run.
The independent Phase-4 body-reject issue remains outside this change. No
overall E2E PASS is established by the focused tests.

## Final diff and review status

Focused RED/GREEN, neighboring tests, the 410-test contract suite, complete Framework lint, documentation
checks and diff whitespace validation are complete. Delivery remains pending. No secrets,
credentials, request bodies or sensitive raw payloads are included. No merge,
history rewrite or MRTS change is performed.
