# Change record: 20260817-04-bind-canonical-maintenance-plan-artifact

**Language:** English | [Deutsch](20260817-04-bind-canonical-maintenance-plan-artifact.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260817-04-bind-canonical-maintenance-plan-artifact` |
| UTC date | `2026-08-17` |
| Framework base revision | `dcf0dde410b0afe59fead01ee011c3ec3de1dbdd` |
| Issue or pull request | Resulting-master workflow `32010750544` exposed the plan-digest failure; corrective Framework PR [#97](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/97) is pending final exact-head verification and normal merge. |

## Motivation and problem statement

The unified common-maintenance workflow independently resolved mutable upstream
inputs in canonical, candidate, trusted reconciliation, and publisher jobs.
An upstream change between jobs could therefore produce a fail-closed digest
mismatch late in the run, even though every individual resolution was valid.
The workflow needs one caller-bound plan for its complete execution rather
than repeated live resolution.

## Affected components and security boundaries

The Framework-only boundary covers `check-common-versions.yml`, the canonical
plan reader and reconciler, and the CI-security contract that enforces their
artifact profile. The plan is a bounded JSON/Markdown artifact named with the
GitHub run ID and attempt. Candidate, trusted issue reconciliation, and the
Draft-PR publisher validate its SHA-256 before work. Parent source and gitlink,
connector runtime behavior, GitHub App configuration, and the read-only
`tools/MRTS` checkout are outside scope.

## Acceptance criteria

1. Canonical maintenance uploads exactly one run- and attempt-bound plan
   artifact with its JSON and Markdown members.
2. Every downstream consumer downloads that same artifact, validates the
   canonical digest, and does not re-resolve live dependency sources.
3. The plan reader remains restricted to the direct `RUNNER_TEMP` boundary;
   digest, schema, symlink, traversal, trusted-branch, and least-privilege
   token controls remain fail-closed.
4. Focused contract and workflow regressions, full native lint, exact-head
   hosted checks, and SonarQube Cloud pass without suppression or gate
   weakening.
5. A full resulting-master `workflow_dispatch` run proves canonical,
   candidate, reconciliation, publisher, and result behavior after a normal
   merge.

## Alternatives considered

- Re-resolving every downstream job was rejected because mutable inputs can
  invalidate the earlier caller-bound digest.
- Passing plan contents through job outputs was rejected because it provides
  no bounded file transport for both plan members.
- Downloading into a nested temporary directory or broadening the approved
  reader root was rejected; direct `RUNNER_TEMP` preserves the fixed reader
  boundary.
- Passing a read token or component input downstream was rejected because it
  would recreate live-resolution authority outside canonical maintenance.

## Implementation decision

Canonical maintenance now uploads the validated JSON and Markdown plan through
checksum-pinned `actions/upload-artifact`. Downstream jobs use the matching
checksum-pinned download action directly into `RUNNER_TEMP`, bind the plan to
the canonical output digest with `--expected-plan-sha256`, and perform no
fresh resolution. The reconciler validates expected-digest syntax before
reading and fails before output or mutation on mismatch. The CI-security
contract encodes the exact profiles; its artifact helper was split into
focused fail-closed checks and uses shared step-label constants to remove the
task-owned SonarQube Cloud duplicate/complexity findings without changing
validation order.

## Changed files and tests

The Framework changes cover the common-maintenance workflow; reconciler and
canonical-pin tooling; CI-security contract; locked artifact-action
provenance; paired English/German workflow-security documentation; focused
workflow, contract, reconciler, and runtime-lock tests; and this paired Change
Record. Positive controls require the one artifact and matching digest.
Negative controls reject malformed expected digests, changed artifact names or
paths, missing downloads, nested or unapproved files, symlink escapes, digest
tampering, downstream live resolution, and downstream read-token input.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy gh run view 32010750544 --repo Easton97-Jens/ModSecurity-test-Framework --json status,conclusion,headSha,jobs` | `0` | Observed the original full-workflow plan-digest failure after independently resolved inputs changed. | GitHub Actions run `32010750544` |
| Focused workflow/security/reconciler/canonical-pin/runtime-lock unittest suite | `0` | 166 focused tests passed during the artifact implementation. | Framework task worktree |
| Final focused CI-security, unified-maintenance, and validate-only unittest suite | `0` | 60 tests passed after the artifact-contract Sonar remediation. | Framework task worktree |
| `ci/checks/security/check-ci-security-contract.py --root .` and `check-ci-security-evidence-contract.py --root .` | `0` | Reviewed artifact, token, pin, and evidence contracts passed. | Framework task worktree |
| `sync-canonical-workflow-pins.py --root . --check`, checksum-locked Ruff `check` and `format --check`, and `git diff --check` | `0` | Canonical pins, source style, and whitespace passed. | Framework task worktree |
| `make lint` with task worktree `FRAMEWORK_ROOT` | `0` | Full native lint suite passed. | Framework task worktree |
| PR #97 current code head `7e77624ee676188b27b1fa197c5a4c0410e825f1` hosted checks and SonarQube Cloud check `95485455629` | `0` | All visible hosted checks passed; Quality Gate had 0 new issues, 0 accepted issues, 0 hotspots, and 0.0% new-code duplication. | PR #97 pre-Change-Record evidence |

## Security impact

This is a supply-chain integrity and availability repair, not a permission
expansion or bypass. It removes repeated live resolution below the canonical
producer while retaining exact pinned actions, direct approved-path handling,
digest validation, default-branch gates, App-token separation, fixed output
allowlists, and Draft-only publication. Independent review rechecked malformed
artifact and downstream-input paths; no new trust-boundary bypass was found.

## Documentation and runtime evidence

`docs/github-actions-workflow-security.md` and its German counterpart document
the locked artifact action and caller-bound maintenance plan. Workflow
`32010750544` is retained as failure evidence and PR #97's pre-Change-Record
head supplies hosted static-analysis evidence. No successful resulting-master
maintenance publication is claimed by this record.

## Checks not run

- Hosted checks and SonarQube Cloud for the final Change-Record commit are not
  yet available at record creation; they must be re-run for its new exact PR
  head.
- A full resulting-master `workflow_dispatch` run cannot occur until the PR
  passes the user-required gates and is normally merged.
- No GitHub App setting, secret, or installation permission was changed or
  inspected beyond normal workflow behavior.

## Limitations and residual risk

The artifact transport does not make a failed canonical resolution safe; such
plans remain fail-closed. The installed GitHub App must still possess its
already-reviewed repository permissions for later trusted reconciliation and
Draft publication. Until the final PR head and resulting master are observed,
the repair remains `fixed`/pending verification rather than verified.

## Final diff and review status

The implementation diff, final artifact-contract refactor, documentation, and
focused tests received direct and independent security review; native lint and
the pre-Change-Record hosted head passed. This paired record is intentionally
added before final delivery, so no final commit, merge, resulting-master SHA,
or resulting-master workflow success is asserted here. No secrets or raw
sensitive payloads are recorded.
