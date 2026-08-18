# Repair the atomic CRS rule-digest maintenance contract

**Language:** English | [Deutsch](20260818-03-repair-crs-rule-digest-contract.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260818-03-repair-crs-rule-digest-contract |
| UTC date | 2026-08-18 |
| Framework base revision | c6add258c3ffb50c89a3cb94bd56102dd636b2f1 |
| Issue or pull request | Draft [PR #99](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/99) |

## Motivation and problem statement

PR #99 updated the canonical OWASP Core Rule Set release from v4.28.0 to
v4.29.0 but left the checked SQLi rule-file fingerprint and an event-schema
view at the previous release. The fail-closed portable and contract jobs
therefore rejected the inconsistent source provenance.

## Affected components and security boundaries

- `ci/lib/common.sh` is the canonical CRS provenance-pin authority.
- `ci/tools/check-common-versions.py` crosses the approved GitHub release and
  contents APIs to prepare bounded maintenance candidates.
- `ci/tools/crs_contract_pins.py`, `sync-crs-contract-views.py`, and the
  catalog contract consume only the canonical values.

The boundary is external release and file metadata to immutable local pins.
The repair retains the repository allowlist, stable-v4 constraint, immutable
peeled commit, bounded content decoding, and fail-closed generated views.

## Acceptance criteria

1. The v4.29.0 CRS tag, peeled commit, and checked rule-file SHA-256 agree.
2. Automated CRS maintenance proposes those three values atomically and never
   applies an incomplete candidate.
3. Generated schemas and the CRS test fixture are derived from the canonical
   pins and reject malformed or missing rule digests.
4. Existing security and quality controls remain enabled and relevant local
   contracts pass.

## Alternatives considered

- Hard-coding the v4.29.0 digest in individual schemas was rejected because it
  would leave a second provenance authority.
- Removing the checked-rule fingerprint from the contract was rejected because
  it would weaken the fail-closed control that exposed the defect.
- Treating the updated tag and commit as sufficient was rejected because the
  selected rule file is an additional consumed source identity.

## Implementation decision

`CRS_RULE_FILE_SHA256` is a strictly parsed canonical literal. The maintenance
resolver reads the reviewed SQLi rule file through GitHub's contents API at the
already verified immutable commit, bounds and verifies its Base64 content and
Git blob identity, and produces a SHA-256 update in the existing atomic CRS
group. Contract views project the digest and derive their `crs_git_ref` from
the canonical release tag, preventing independently stale values.

The Git blob SHA-1 comparison is protocol-format validation only, never a
security or provenance pin; it is explicitly marked `usedforsecurity=False`.
The security-relevant source identity remains the separately derived SHA-256.
The two `dataclasses.replace` returns are explicitly typed as
`ComponentResult`, and the redundant Base64 exception superclass is removed.

## Changed files and tests

- Canonical CRS pin, parser, active-pin inheritance, maintenance resolver, and
  catalog ownership check.
- CRS contract-view synchronizer and all generated CRS views.
- Regression coverage for digest parsing, atomic update planning, stale digest
  repair, malformed GitHub content, and generated event provenance.
- Regression coverage that the Git blob-format SHA-1 is called only with
  `usedforsecurity=False`.
- English and German variable documentation plus this paired Change Record.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `sync-crs-contract-views.py --check --root <task-worktree>` | 0 | Generated CRS contract views match canonical pins. | Task-owned external validation environment |
| `make -s test-canonical-crs-contract-pins` | 0 | Canonical view check and 9 synchronizer tests passed. | Task-owned external validation environment |
| `make -s test-crs-provenance-contract` | 0 | 22 CRS provenance regression tests passed. | Task-owned external validation environment |
| `make -s test-ci-security-contract` | 0 | 282 CI-security contract tests passed with the task worktree bound explicitly. | Task-owned external validation environment |
| CRS pin shell syntax, catalog check, and canonical-version validation | 0 | Canonical pin and shell contracts passed. | Task-owned external validation environment |
| `make -s lint` | 0 | Complete native lint and its contract, provenance, runtime, workflow, documentation, and Change Record suites passed. | Task-owned external validation environment |
| `git diff --check` | 0 | No whitespace errors in the Framework-only remediation diff. | Task-owned external validation environment |

## Security impact

This is a supply-chain hardening repair. The original failure path—an updated
CRS release with an old checked-rule digest—is retested. Alternate malformed,
missing, duplicate, or non-canonical digests and malformed GitHub content are
rejected; no allowlist, provenance, test, Quality Gate, or workflow control is
disabled.

## Documentation and runtime evidence

The English and German variable references now describe the complete atomic
CRS provenance group. No connector runtime, production behavior, credential,
or GitHub-App evidence was collected or inferred.

## Checks not run

- Fresh exact-head GitHub Actions and SonarQube Cloud analysis are pending the
  Framework-only follow-up remediation commit and PR update.
- No connector integration or production runtime was required for this
  CI-maintenance contract correction.

## Limitations and residual risk

The remote contents lookup is bounded to the reviewed CRS repository, an
immutable commit, and the one fixed SQLi rule path. If GitHub metadata is
unavailable or malformed, maintenance fails closed rather than updating a pin.

## Final diff and review status

The first Framework-only remediation commit passed native lint, whitespace
review, and an independent security-diff review. A small follow-up diff now
addresses SonarCloud's four exact Quality-Gate annotations; its focused
23-test CRS provenance suite, complete native `make -s lint`, whitespace
review, and revised independent security-diff review passed. A second
deliberately separate PR commit/push and exact-head hosted verification remain
pending. Parent and MRTS remain outside the change.
