# Change record: No-CRS Sonar maintainability

**Language:** English | [Deutsch](20261003-02-no-crs-sonar-maintainability.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20261003-02-no-crs-sonar-maintainability` |
| UTC date | `2026-10-03` |
| Framework base revision | `b9b9534b7e0b15edad31393699ebd0617748148d` |
| Issue or pull request | Framework PR #135; external Parent PR #396 remains draft |

## Motivation and problem statement

The current Framework PR #135 Sonar analysis passed its Quality Gate but retained
28 open maintainability issues: four `python:S3776`, seventeen `python:S9073`,
three `python:S1192`, two `python:S5713`, one `python:S8714` and one
`python:S5778`. This is not the unrelated historical Parent PR #135.
A passed gate does not mean that these issues are absent.

## Affected components and security boundaries

`ci/checks/catalog/no_crs_baseline.py` and the thirteen affected
`tests/no_crs` modules are Framework-owned. Selection, evidence matching,
status precedence, descriptor-backed artifact authority and receipt validation
must remain unchanged. MRTS stays unchanged. A later Parent gitlink update is
a separately authorized Parent operation, not a Framework source change.

## Acceptance criteria

Remove the actual source causes without suppressions, exclusions, rule changes,
synthetic runtime evidence or reduced required selection. Preserve ordered error
messages, exact run/case/rule/phase identities, retained file bytes and bounds,
closed config templates, no-follow admission, cleanup and explicit reuse.
Require focused and native Framework gates and fresh exact-head remote readback.

## Alternatives considered

Weakening validators or changing Sonar settings would not fix these causes.
A new generic validation abstraction would expand the contract unnecessarily.
Use small helper extractions, existing-style filename constants and narrowly
scoped test assertion/exception hygiene instead.

## Implementation decision

First centralize the unchanged `nginx.conf`, `stdout.log` and `stderr.log`
leaf names in constants. Separate follow-up commits address test diagnostics,
redundant subclass exception entries and the four complex functions.
No catalog, schema, runner case, capability, public contract or runtime behavior
is intentionally changed.

## Changed files and tests

The product file above, the thirteen Sonar-identified test modules, this paired
record and its paired archive index. The test changes preserve ordered spec and
loader checks; the exception test prepares collaborators outside its one
throwing invocation; the positive FIFO test retains its timeout and fails
naturally on an unexpected exception.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| RTK-wrapped owning interpreter: immutable-base No-CRS unittest discovery | 0 | 166 tests, no skips, before edits | External coordinator baseline log |
| RTK-wrapped owning interpreter: source-pattern regression controls | 1 / 0 | Baseline 0/19, corrected tests 19/19 | External test hygiene controls |
| RTK-wrapped owning interpreter: thirteen affected test modules | 0 | 65 tests pass | External test hygiene focus log |
| RTK-wrapped owning interpreter: config artifact/receipt/size focus | 0 | 25 tests pass after constant extraction | External product-owner verification |
| RTK-wrapped owning interpreter: baseline/current characterization | 0 | 1,218 comparisons agree before complexity extraction | External product parity harness |
| `rtk proxy git diff --check` | 0 | Whitespace reviewed | Framework task worktree |

These are source/unit checks, not connector promotion or runtime certification.
Integrated and postcommit native gates and fresh remote analysis remain pending
at this first cause-separated checkpoint and are recorded only after execution.

## Security impact

No security control is relaxed and no new runtime evidence is created.
This maintainability work preserves, rather than repairs or strengthens, the
existing authority and validation contract. Descriptor lifetime, exact diagnostic
matching and selected-required missing-evidence behavior remain obligations.

## Documentation and runtime evidence

This paired English/German record and index document the exact scope.
No connector lifecycle or Full Exact-Head E2E is started in this work step.
No old evidence is relabeled as current-head evidence.

## Checks not run

Full E2E is explicitly prohibited. Remote checks for new commits and final
integrated native checks cannot be claimed before they actually execute.

## Limitations and residual risk

Parity fixtures do not prove genuine host execution. Final Sonar acceptance
requires the newly published exact Framework head, not the baseline gate.
Framework delivery and Parent integration remain separate; neither is a merge.

## Final diff and review status

The first filename-constant slice has whole-module AST equivalence after
substituting the unchanged constant values, plus focused checks and diff review.
The remaining slices require independent review and final integrated validation.
No secrets, generated runtime results, MRTS changes or suppression configuration
belong to this change.
