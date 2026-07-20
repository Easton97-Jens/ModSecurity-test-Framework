# Change record

**Language:** English | [Deutsch](20260720-02-fix-flow-sequence-action-pins.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260720-02-fix-flow-sequence-action-pins` |
| UTC date | 2026-07-20 |
| Framework base revision | `784977615acfc55567e37b863309abc4a38ac877` |
| Issue or pull request | `FND-FRAMEWORK-0031`; task branch `agent/codex-cloud-action-pin-flow-sequence` |

## Motivation and problem statement

The action-pin validator did not inspect a `uses` entry at the start of a YAML
flow sequence. A mutable external Action could avoid the full-SHA control.

## Affected components and security boundaries

The Framework-only validator consumes PR-controlled YAML before GitHub Actions
executes it. No connector runtime, Parent source, or MRTS content is involved.

## Acceptance criteria

- Reject mutable first-entry and comma-position flow-sequence Actions.
- Accept an equivalent full-SHA Action and retain block/flow-map controls.

## Alternatives considered

Replacing the standard-library parser with a YAML dependency would alter the
pre-dependency pin-check contract.

## Implementation decision

Recognize `[` in collection position, track `]`, and use the existing
depth-aware scanner and syntax guard for flow-sequence entries.

## Changed files and tests

- `ci/checks/security/check-workflow-action-pins.py`
- `tests/security_regression/test_workflow_action_pins.py`
- `docs/github-actions-workflow-security.md` and `.de.md`

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 python3 -m unittest …flow_sequence…` before fix | 1 | Negative regression reproduced the bypass; positive control passed. | Isolated Framework worktree |
| `PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.security_regression.test_workflow_action_pins` | 0 | 25 focused standard-library tests passed. | Isolated Framework worktree |
| `PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 python3 -m py_compile …` | 0 | Changed Python files compiled. | Isolated Framework worktree |
| `git diff --check` | 0 | No whitespace errors. | Isolated Framework worktree |

## Security impact

The original path and comma-position bypass were retested through the real
validator; a full SHA is the same-boundary legitimate control.

## Documentation and runtime evidence

English/German guidance names flow-sequence mappings. No host runtime evidence
was collected because this is a static validator remediation.

## Checks not run

The full dependency-backed Framework lint/permission suite is blocked by the
absence of a Framework-owned virtual environment; no Parent environment was
substituted. GitHub, Sonar, review, and Cloud rescan await PR delivery.

## Limitations and residual risk

Unsupported complex YAML must remain fail-closed. Cloud closure needs a fresh
authenticated scan of final Framework master.

## Final diff and review status

Focused diff and whitespace review are complete. No secrets, Parent changes,
or MRTS changes are included. The scoped local commit exists; push and Draft
PR remain pending the pre-push exact-SHA check.
