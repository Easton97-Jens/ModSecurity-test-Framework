# Change record — expand Framework CI security

**Language:** English | [Deutsch](20260718-01-expand-framework-ci-security.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260718-01-expand-framework-ci-security |
| UTC date | 2026-07-18 |
| Framework base revision | cdc91a398d6c156eaff927d742b23018a3817fb6 |
| Implementation commit | c897c481025fd005a2908d5124d238784d6182f4 |
| Issue or pull request | [Framework Draft PR #27](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/27) |

## Motivation and problem statement

The Framework used mutable Action tags and had no Framework-owned CI security
scanner/provenance contract. The initial scanner-action design also exposed a
task-owned transitive mutable-container path. This change replaces that path
with checksum-verified CLIs and adds Framework controls without changing the
Parent repository, its gitlink, or MRTS. Independently governed common-
structure behavior remains outside this scope.

## Affected components and security boundaries

- Workflows and Dependabot: untrusted PR tokens, checkout, scanner, SARIF,
  dependency, cancellation, and maintenance boundaries.
- CI tooling, downloader, and contract checker: remote Action/tool provenance,
  archive extraction, and source-level policy validation.
- Tests, fixtures, Makefile, and Python tooling: positive and negative control
  coverage.
- Security documentation: paired English/German guidance.

tools/MRTS is not initialized or modified. Scanner checkouts use
submodules false; CodeQL additionally ignores tools/MRTS.

## Acceptance criteria

1. Every remote Action is pinned to a reviewed 40-character SHA with an exact
   version comment and lock record.
2. PR workflows avoid pull_request_target, persisted credentials, broad
   default permissions, unsafe cache/artifact behavior, and unbounded jobs.
3. Gitleaks, OSV, CodeQL, Scorecard, dependency review, actionlint, ShellCheck,
   zizmor, Ruff, Pyright, and dependency hygiene have truthful Framework scope
   and no automatic remediation.
4. The security contract has positive and negative fixture evidence; it covers
   Action pinning, permission declarations, triggers, checkout, timeouts,
   concurrency, and tool-lock structure without changing the common-structure
   product assertion.
5. Documentation, this record, focused checks, security diff review, and exact
   PR-head evidence are complete before delivery.

## Alternatives considered

- Mutable major tags or unverified package installation: rejected because the
  CI security boundary needs immutable provenance.
- Unbounded or generic scanner artifact upload: rejected. CodeQL uses the
  narrower code-scanning SARIF channel, Gitleaks findings require redaction,
  and OSV/Scorecard retain only validated bounded JSON evidence for one day.
- Go or JavaScript/TypeScript CodeQL: rejected because current Framework source
  evidence supports Actions, Python, and C/C++ only.
- Changing the independently governed test-common catalog invariant: rejected
  as out of scope for this CI/security expansion.

## Implementation decision

A Framework-native YAML lock records Action and CLI provenance. A Python
downloader verifies direct HTTPS GitHub release assets before atomically
publishing a raw executable or safely extracting an archive to runner-owned
directories. OSV Scanner and Scorecard run as checksum-verified CLIs rather
than container-backed Actions. Workflow and test contracts reject mutable pins,
unsafe triggers, unexpected write permissions, unsafe checkout settings,
non-exact Python selection, unprovisioned downloader dependencies, and missing
timeouts/concurrency. CI dependency installation is limited to the hash-locked
PyYAML wheel; standalone security CLIs remain outside the checkout.

The scheduled common-version and artifact-cleanup workflows retain their
necessary write capabilities but use non-persisted checkout, narrow
permissions, exact Action pins, explicit timeouts, and non-cancelling
maintenance concurrency.

## Changed files and tests

- Hardened all existing tracked workflows; added CI security, quality, secrets,
  OSV, CodeQL, Scorecard, and dependency-review workflows.
- Added a CI dependency lock, tool lock/downloader, security and bounded-JSON
  evidence checkers, seventeen focused unit tests, positive/negative zizmor
  fixtures, Ruff config, and Pyright config.
- Replaced task-owned mutable-container OSV/Scorecard Action internals with
  checksum-verified release CLIs; selected exact CPython 3.12.13 with
  `check-latest: false`; and bound CodeQL to its linked tool bundle.
- Added English/German CI-security documentation and documentation-index links.
- Hardened the `test-common.yml` execution envelope without changing its
  independently governed catalog-count assertion or materialization behavior.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused Framework CI-security and Change-Record tests | 0 | Seventeen task-owned positive/negative contract, runner-containment, OSV/Scorecard-evidence, and Change-Record tests passed. | `20260718T083435Z-expand-framework-ci-security-32892be1` |
| CI-security contract and workflow-YAML checker | 0 | Contract passed and all 12 tracked workflow files parsed. | Same run |
| Locked tool downloader | 0 | Eight release assets, including raw OSV Scanner and Scorecard, matched their locked SHA-256 values. | Same run |
| actionlint with locked ShellCheck | 0 | All 12 tracked workflows passed. | Same run |
| zizmor over `.github` | 0 | No reportable findings; zizmor reported 19 offline tool suppressions. | Same run |
| zizmor unsafe fixture | 14 expected | Rejected dangerous trigger and PR-title interpolation. | Same run |
| Ruff lint and format check | 0 | Task-owned CI-security Python scope passed with cache disabled locally. | Same run |
| OSV manifest coverage | 0 | OSV recognized one package in each bounded `requirements-dev.txt` and normalized CI lock manifest, then the JSON-evidence checker passed. | Same run |
| OSV Scanner and Scorecard CLI smoke controls | 0 | Checksum-verified CLIs scanned the current Framework tree without writing inside the checkout. | Same run |

## Security impact

This is CI/security hardening, not a connector-runtime remediation. The
original mutable Action path is replaced by a lock-enforced immutable SHA
contract. The discovered mutable Docker images inside the OSV and Scorecard
Actions are not retained: both scanners run only after their independently
verified release binary is fetched to runner-temporary storage. Positive
controls cover current workflows and the safe zizmor fixture; the negative
control proves that a dangerous trigger plus untrusted interpolation is
rejected. Direct download validation covered raw-binary and archive policies.
The PR OSV control compares exact-base and exact-head reports and fails only
for newly introduced vulnerability groups; its retained evidence is size-,
regular-file-, and JSON-validated. The focused source-diff assessment remains
pending until the implementation diff is finalized.

## Documentation and runtime evidence

Added the paired CI-security guide and linked it from both documentation
indexes. No connector runtime or lifecycle evidence was collected or claimed;
the observed evidence is static CI/source validation.

## Checks not run

- Local Pyright: blocked because no local Node.js runtime is installed. CI
  provisions exact Node.js 24.18.0 through a pinned Action.
- CodeQL, Dependency Review, Gitleaks PR range, SonarQube Cloud, and
  GitHub-hosted workflow execution: pending exact Draft PR head and remote CI.
- Clean-candidate `make lint`, documentation checks, final whitespace/secret
  review, focused security-diff review, commit, push, and Draft PR creation:
  passed. The excluded FND-FRAMEWORK-0004 CRS validator emitted RTK-read-only
  `/tmp` diagnostics during the full lint and is not claimed as a passing CRS
  control.

## Limitations and residual risk

GitHub repository-level Actions defaults, SHA-enforcement settings, branch
protection, Dependabot alerts, and SonarQube Cloud configuration are external
governance controls and are not changed by this Framework-only task. The
current SonarQube Cloud failure remains separately tracked. Full-history
Gitleaks and scheduled OSV scans are intentionally advisory until findings are
triaged.

## Final diff and review status

Implementation commit `c897c481025fd005a2908d5124d238784d6182f4` was pushed
to `agent/expand-framework-ci-security`, and Framework Draft PR #27 is open.
The staged diff, whitespace/secret review, and focused security-diff assessment
passed before delivery. There is no merge, Parent gitlink update, Parent
product/workflow change, or MRTS change. Exact PR-head CI, SonarQube Cloud,
review, and review-thread verification remain required.
