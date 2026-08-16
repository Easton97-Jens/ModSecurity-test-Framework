# Change record: 20260816-03-repair-canonical-maintenance-and-python-pin-sync

**Language:** English | [Deutsch](20260816-03-repair-canonical-maintenance-and-python-pin-sync.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260816-03-repair-canonical-maintenance-and-python-pin-sync` |
| UTC date | `2026-08-16` |
| Framework base revision | `fec22255a8d8663ed578a84b052dfd00631288ca` |
| Issue or pull request | Framework PR #85 is a Draft. This record does not authorize a merge or direct `master` write. |

## Motivation and problem statement

Dispatch run `31958961125` imported a YAML-using resolver before installing the reviewed PyYAML dependency. PR #84 also changed only the generated `.python-version` view to `3.14.7`, while `CI_CANONICAL_PYTHON_VERSION` in `ci/lib/common.sh` remained `3.14.6`. The resulting source/view divergence failed runs `31959220077` and `31959297702`.

## Affected components and security boundaries

The repair covers the trusted common-version maintenance workflow, its hash-locked dependency boundary, and the canonical Python source/view update path. The publisher remains Draft-only, uses its scoped GitHub App token, and may publish only the canonical assignment plus generated view. Parent, connector runtime, and MRTS are outside scope.

## Acceptance criteria

1. Each resolver job executes the reviewed hash-locked bootstrap before resolving.
2. The updater changes only the canonical Python assignment and the workflow regenerates and verifies `.python-version`.
3. A reusable CPython Draft branch may contain exactly the expected two files and one candidate-bound `common.sh` assignment hunk.
4. Contracts reject commented or echo-only bootstrap text and every other publisher or source-scope expansion.

## Alternatives considered

- An unpinned dependency install was rejected because it bypasses the reviewed lock.
- Updating only `.python-version` was rejected because it is generated.
- A broad `common.sh` allowlist, automatic merge, or direct push was rejected because each weakens the trust boundary.

## Implementation decision

Every resolver body is now bound to an exact reviewed SHA-256, making comments or echoed commands insufficient. The Python updater atomically replaces the one canonical assignment; the workflow synchronizes and checks its view. Existing Draft branches must show a single source assignment replacement to the freshly resolved candidate, with no metadata or additional `common.sh` changes.

## Changed files and tests

- `check-common-versions.yml` prepares resolver dependencies using the existing lock.
- `check-python-version.yml` constrains source updates, views, and reusable Draft diffs.
- The updater and CI contract implement source parsing, atomic update, exact run binding, and narrow path enforcement.
- Focused regression tests cover omitted, commented, and echo-only bootstrap commands, view-only publication, unbounded source changes, malformed/duplicate/stale assignments, and symlinks.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused updater, Python/CI contract, framework-CI contract, and maintenance tests | `0` | 97 tests passed after the final security closures. | Task worktree; bytecode writes disabled. |
| Earlier expanded focused suite including pin sync and descriptor series | `0` | 96 tests passed before the final security closures. | Task worktree; superseded by the current focused suite where overlapping. |
| Full Framework lint | `0` | Passed on the final implementation state before this results-only record update. | Task worktree; bytecode writes disabled. |
| Initial PR #85 hosted quality checks | failed, then remediated | ShellCheck found an invalidly indented here-document terminator and Ruff found formatting drift; the correction retains the candidate-bound guard and updates its exact run-body hash. | GitHub runs `31964051925` and `31964051902`. |
| Repeated Full Framework lint | `0` | Passed after the hosted-quality remediation. | Task worktree; bytecode writes disabled. |
| First corrected exact-head SonarCloud analysis | not accepted | Quality Gate passed and duplication on new code was `0.0%`, but SonarCloud reported four new code-smell issues. | PR #85 SonarCloud bot comment; remediated before final delivery. |
| Fresh final exact-head hosted checks | pending after Sonar remediation | Must validate the final published pull-request head. | PR #85; not yet available at this record update. |

## Security impact

This is a CI supply-chain integrity repair. The original missing-PyYAML path now has a reviewed bootstrap. Exact resolver-body hashes reject fake command text. The original generated-view-only path is rejected, and a pre-existing Draft cannot smuggle arbitrary sourced `common.sh` content. No permissions, credential scope, auto-merge, or direct-push capability is added.

## Documentation and runtime evidence

This English/German pair is the reader-facing documentation update. Framework
PR #85 initially exposed local-quality defects that were remediated and
revalidated locally. Hosted evidence remains required: its corrected exact head
must have successful required checks and SonarQube Cloud must report zero new
issues before the authorized squash merge.

The first corrected exact-head analysis still reported four new code-smell
issues despite its passing Quality Gate and `0.0%` new-code duplication. The
final narrow refactors remove those findings without suppressions or weakened
controls; a fresh exact-head analysis must prove zero new issues.

## Checks not run

- Fresh final-head PR checks, SonarQube Cloud, review state, exact-head merge,
  and resulting-master dispatches require publication or integration.

## Limitations and residual risk

Local validation cannot prove GitHub-hosted App-token behavior, protected-branch enforcement, or SonarQube Cloud analysis. These controls remain mandatory before integration.

## Final diff and review status

The task remains limited to Framework workflows, canonical pin updates,
contracts, regressions, and this paired record. PR #85 exists as a Draft; no
merge, Parent Gitlink update, or MRTS action has occurred. Whitespace,
independent security review, and the final security-diff review have passed;
the tracked Sonar refactors and fresh hosted verification remain required before
delivery.
