# AWS-LC release maintenance

**Language:** English | [Deutsch](20260929-02-enable-aws-lc-maintenance.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260929-02-enable-aws-lc-maintenance |
| UTC | 2026-09-29 |
| Base | e18f112f0089098cb9d8cb48ab9b8f93cd6d381a |
| PR | [PR #122](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/122) |

## Motivation and problem statement

New AWS-LC releases previously required manual edits. Maintain the latest stable release through the existing canonical Draft PR workflow.

## Affected components and security boundaries

Only AWS-LC pins, descriptor policy, tests, and paired documentation change. Fixed repository identity, bounded tag peeling, current-pin verification, atomic updates, candidate revalidation, and publisher permissions remain intact.

## Acceptance criteria

Select stable numeric releases across major lines; exclude drafts, prereleases, incomplete release flags, and FIPS-specific tags. Reject unapproved repositories, malformed or retargeted current pins, downgrades, missing candidate commits, and incomplete atomic updates. The rendered candidate must settle to a no-op and reach the unified planner without manual review.

## Alternatives considered

A one-time bump does not maintain future releases. Another updater duplicates existing machinery. Unpinned branches and weakened provenance checks are not acceptable.

## Implementation decision

Set the existing descriptor to automatic latest-stable maintenance and remove its obsolete manual-variable entry. Reuse the existing automatic Git provenance resolver and unified planner. Update v5.10.0 with peeled commit 3fe7e081e62131b6776f0d923312b5e6756907ce. Verify the Git reference independently of release metadata. Preserve the existing weekly schedule and Draft PR review boundary.

## Changed files and tests

`ci/lib/common.sh`, `ci/tools/check-common-versions.py`, `tests/security_regression/test_common_version_atomic_provenance.py`, `tests/ci_security/test_aws_lc_maintenance.py`, both variable references, and this record pair. Fourteen focused tests include lightweight/annotated tags, unchanged commit identities, and the real planner seam. The earlier CodeQL fix remains unchanged.

## Commands and results

[Verified preparation run](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/36554336208). Python 3.14.7.

Baseline regression: expected assertion failure (exit 1) against the original manual policy. Then all 14 AWS-LC tests passed.

| Command | Exit |
| --- | --- |
| `python3 -m unittest tests.ci_security.test_aws_lc_maintenance -v` | 0 |
| `python3 -m unittest tests.security_regression.test_common_version_atomic_provenance -v` | 0 |
| `./ci/tools/safe-make.sh test-ci-security-contract` | 0 |
| `./ci/tools/safe-make.sh lint` | 0 |
| `./ci/tools/safe-make.sh check-documentation` | 0 |
| `ruff check tests/ci_security/test_aws_lc_maintenance.py` | 0 |
| `ruff format --check tests/ci_security/test_aws_lc_maintenance.py` | 0 |
| `pyright --project pyrightconfig.json` | 0 |
| `python3 ci/tools/check-common-versions.py --check --component AWS-LC --json` | 0 |
| `git diff --check` | 0 |


## Security impact

No security remediation or TLS-provider change is claimed. Existing fail-closed checks remain. New major releases are reviewable pin candidates, not evidence of downstream runtime compatibility.

## Documentation and runtime evidence

English and German variable references describe the same policy. No AWS-LC build, TLS handshake, connector smoke, or runtime evidence was collected. No generated runtime report was hand-edited.

## Checks not run

Local Python is 3.13.5 and cannot parse the existing Python 3.14 syntax. Acceptance tests use the repository-pinned CI interpreter instead. Live AWS-LC connector builds and end-to-end runtime checks are outside this provenance-maintenance change.

## Limitations and residual risk

Scheduled automation takes effect after PR merge. Existing publisher reuse checks may reject this manually extended maintenance branch until merge; no bypass is introduced. Auto-merge stays disabled and NGINX retains its OpenSSL build path.

## Final diff and review status

The candidate contains only these eight files and excludes temporary preparation workflows and scripts. Publication preserves the PR parent using a non-forced fast-forward. Post-push CI is checked separately.
