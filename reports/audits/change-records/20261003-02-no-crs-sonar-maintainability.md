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

Centralize the unchanged `nginx.conf`, `stdout.log` and `stderr.log` leaf
names in constants. Cause-separated commits address test diagnostics and
redundant subclass exception entries. Extract eight narrowly scoped helpers
from the four complex functions, preserving their original signatures,
validation order, descriptor ownership and explicit evidence-reuse conditions.
No catalog, schema, runner case, capability, public contract or runtime behavior
is intentionally changed.

## Changed files and tests

The product file above, the thirteen Sonar-identified test modules, this paired
record and its paired archive index. The test changes preserve ordered spec and
loader checks; the exception test prepares collaborators outside its one
throwing invocation; the positive FIFO test retains its timeout and fails
naturally on an unexpected exception.

## Commands and results

Portable command abbreviations denote the executed bindings retained in
`A/framework-pr135-sonar-plan.md`: `A` is the approved external analysis
directory, `FW` the task Framework worktree, `PY` the Framework-owned interpreter,
`P` the separate Parent integration worktree, and `N` / `L` the external
`framework-pr135-sonar-final` / `framework-pr135-sonar-lint` build directories.
Machine-specific absolute paths belong to that external record, not this
versioned document. All argv and flags below are preserved.

Commands run from `FW`; Python uses `PYTHONNOUSERSITE=1` and
`PYTHONDONTWRITEBYTECODE=1`. The immutable-b9 baseline passed 166 tests before
edits (`A/framework-pr135-sonar-baseline-no-crs.log`). Intermediate checks
passed 65 affected tests and 25 config tests; their commands/scope are retained
in `A/framework-pr135-test-hygiene-result.md` and
`A/framework-pr135-product-result.md`.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 "$PY" -B "$A/framework-pr135-test-sonar-controls.py" --baseline` / same command without `--baseline` | 1 / 0 | Baseline 0/19, corrected tests 19/19 | `A/framework-pr135-test-hygiene-source-red.log` / `A/framework-pr135-test-hygiene-source-green.log` |
| `rtk proxy env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$N/tmp" timeout 300 make test-no-crs-contract PYTHON="$PY" BUILD_ROOT="$N" TMP_ROOT="$N/tmp"` | 0 | 166 tests pass, no skips | `A/framework-pr135-sonar-final-no-crs.log` / `.exit` |
| `rtk proxy env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$A" "$PY" -B "$A/framework-pr135-product-parity.py" "$FW"` | 0 | 2,081 comparisons agree after all extractions | `A/framework-pr135-product-parity.log` |
| `rtk proxy env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$A" "$PY" -B -m unittest -v tests.no_crs.test_configtest_artifacts tests.no_crs.test_configtest_receipt tests.no_crs.test_configtest_runtime_facts tests.no_crs.test_configtest_size tests.no_crs.test_exact_reuse_mapping tests.no_crs.test_case_event_binding` | 0 | 41 tests pass; source and authority review finds no regression blocker | `A/framework-pr135-independent-product-focus.log`; review `A/framework-pr135-independent-product-review.md` |
| `rtk proxy timeout 600 env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$L/tmp" make lint PYTHON="$PY" BUILD_ROOT="$L" TMP_ROOT="$L/tmp"` | 124 | Budget exhausted after passing 21 ModSecurity provenance tests; not a complete lint pass | `A/framework-pr135-sonar-final-lint.log` / `.exit` |
| `rtk proxy timeout 1800 env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$L/tmp" make lint PYTHON="$PY" BUILD_ROOT="$L" TMP_ROOT="$L/tmp"` | 2 | Inherited `FRAMEWORK_ROOT` points to a different checkout; exact-root guard correctly rejects it | `A/framework-pr135-sonar-final-lint-retry.log` / `.exit` |
| Root-bound native target preflight, exact invocation in `A/framework-pr135-sonar-plan.md` | 2 | 94 unit checks pass; documentation rejects machine-specific absolute paths, corrected in this pair without changing the checker | `A/framework-pr135-sonar-root-preflight.log` / `.exit` |
| `rtk proxy timeout 3600 env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$L/tmp" make lint PYTHON="$PY" CI_ROOT="$FW/ci" FRAMEWORK_ROOT="$FW" CONNECTOR_ROOT="$P" OUTPUT_ROOT="$FW" BUILD_ROOT="$L" TMP_ROOT="$L/tmp"` | 0 | Complete native lint passes with explicit exact-worktree roots and unchanged gates, including API, workflow, catalog, documentation and diff checks | `A/framework-pr135-sonar-final-lint-root-bound.log` / `.exit` |
| `rtk proxy git diff --check` | 0 | Whitespace reviewed | Framework task worktree |

These are source/unit checks, not connector promotion or runtime certification.
Complete native lint passes after explicitly binding the worktree roots;
fresh remote analysis remains pending. Interrupted/rejected runs are retained.
The portable record correction also passes all native documentation gates.

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

Full E2E is explicitly prohibited. Remote checks for newly published commits
remain pending and cannot be claimed before they actually execute.

## Limitations and residual risk

Parity fixtures do not prove genuine host execution. Final Sonar acceptance
requires the newly published exact Framework head, not the baseline gate.
Framework delivery and Parent integration remain separate; neither is a merge.

## Final diff and review status

The filename-constant slice has whole-module AST equivalence after substituting
the unchanged constant values. Original APIs and the module AST outside the four
extracted functions and their eight helpers are unchanged. Independent review,
finite baseline/current parity controls, final No-CRS tests and complete native
lint pass. Newly published SHA-bound Sonar/CI remain outstanding.
No secrets, generated runtime results, MRTS changes or suppression configuration
belong to this change.
