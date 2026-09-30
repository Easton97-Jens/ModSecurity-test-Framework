# Prepare automatic ModSecurity v3 release update PRs

**Language:** English | [Deutsch](20260930-01-automate-modsecurity-v3-release-prs.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260930-01-automate-modsecurity-v3-release-prs |
| Related issue / PR | #129 / #131 |
| Status | Draft implementation; not verified for integration or runtime use |
| Base revision | `5cd7a7f96811b6d3021ce3c1e36bbc5d308806fb` |
| Core implementation commit | `6b8f698cf1a8e83767b3cfd45b53da3c9b18e289` |
| CI remediation baseline | `4e0173618fd543b57d5bf79bd9002e533107b346` |

## Motivation and problem statement

Issue #129 reports a ModSecurity v3 release transition from `v3.0.16` to
`v3.0.17` as a manual provenance review. The existing maintenance workflow
already resolves dependency candidates and publishes update PRs. The
ModSecurity-v3 descriptor and specialized resolver still select the manual
path. This draft publishes the previously prepared core change for review.

The first PR lint run failed because both new change records used custom
headings and bullet-form identities instead of the required template and
table-form Change ID. Correct the records, not the enforcing validator.

## Affected components and security boundaries

Framework-only: the common-version ModSecurity-v3 resolver and this paired
change record. No Parent or MRTS files are changed. Parent gitlink disposition:
`unchanged`; MRTS impact: `default_read_only`. No automatic merge, direct
`master` update, or branch-protection change is authorized by this PR.

## Acceptance criteria

- [x] Publish the core patch on the existing task branch without changing release pins.
- [x] Use the required headings, table-form identity, and reciprocal language links.
- [x] Reproduce the change-record failure and verify the corrected pair with the unchanged checker and its four tests in an isolated snapshot.
- [ ] Complete the remaining implementation, documentation, and validation work below.

- Adapt existing ModSecurity manual-only fixtures and expectations, and
  review the remaining `MANUAL_REVIEW_VARIABLES` classification.
- Verify automatic candidate creation and settlement, atomic tag/commit
  updates, annotated/lightweight tags, moved tags, invalid repositories,
  alias mismatches, prereleases, and releases outside v3.
- Verify canonical-plan application, generated-view consistency, and
  review-issue reconciliation without premature issue closure.
- Update the paired variable-reference and workflow-security documentation.
- Run the affected regression suites and collect required runtime/smoke
  evidence before treating the implementation as integration-ready.

## Alternatives considered

Retaining manual-only updates does not meet the requested automation goal.
Removing provenance guards or enabling automatic merges would change unrelated
security boundaries. Weakening the change-record validator or adding a legacy
exception would conceal a document defect; neither is done.

## Implementation decision

`ci/tools/check-common-versions.py` changes four lines: the ModSecurity-v3
update policy, its compatibility description, the resolver docstring, and
the call from `check_manual_git_provenance` to
`check_automatic_git_provenance`. No release pin is bumped by this change.

The allowed release shape remains `v3.x.y`, including stable minor releases
within v3, rather than patch releases in v3.0 only. Other major versions are
not selected for automatic application. The fixed upstream repository hash,
current tag/commit validation, peeled-commit resolver, alias checks, and
atomic tag/commit group are unchanged. These provenance controls do not
prove connector compatibility or upstream release safety.

The CI correction only restructures this English/German record pair into the
existing thirteen-section contract and moves the identity into a table.

## Changed files and tests

The core patch changes `ci/tools/check-common-versions.py`. The CI correction
changes only this English change record and its German counterpart. The repository's
`ci/checks/documentation/check-change-records.py` and
`tests/ci_security/test_change_record_contract.py` are executed unchanged;
no test, validator, workflow, or generated view is modified by this correction.

## Commands and results

CI evidence at the remediation baseline:
[lint run 36700420156](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/36700420156),
job `scaffold-lint`, ran `./ci/tools/safe-make.sh lint` and exited 2.
The CI-security suite ran 308 tests with one failure:
`test_checked_in_change_records_pass`. It reported invalid headings and
Change ID formatting in both language files. Six other PR workflows,
including `test-common` and CodeQL, succeeded at that baseline.

Local commands were run in an isolated snapshot containing this record pair,
the unchanged checker, and its unchanged test module, using Python 3.13.5:

- `python3 -m unittest discover -s tests/ci_security -p 'test_change_record_contract.py' -v`: before correction, 4 tests, 1 failure, exit 1; after correction, 4 tests passed, exit 0.
- `python3 ci/checks/documentation/check-change-records.py`: corrected pair passed, exit 0.

The checker and test-module Git blob hashes matched the fetched sources
(`d1e5e4a5831670d112d272fbdb0ca100f547cc49` and
`e41e96e3673b4e2d8b7a9ba95842e0d4c97c43b2`). This is scoped document-contract
evidence, not a full-checkout lint result or runtime evidence. The corrected
head's full CI result must be read separately; no pending run is called PASS.

## Security impact

Automated provenance checks replace a manual-only candidate classification;
they do not constitute human review of migration notes. Existing security
checks are retained, but the behavior change remains unverified until the
outstanding tests and documentation work are completed. No secrets, tokens,
private payloads, or runtime logs are included in this change.

## Documentation and runtime evidence

The paired change records now follow the repository's existing template.
The variable-reference and workflow-security documentation updates remain
outstanding. Generated outputs are unchanged because this PR does not bump a
release pin. No runtime/smoke evidence or connector-promotion claim is made.

## Checks not run

Full lint and the complete regression suites were not run locally: cloning the
repository failed with DNS resolution of `github.com`, and the repository's
selected Python 3.14.7 environment and RTK were unavailable. The scoped local
document checks are not a substitute for GitHub CI. Runtime/smoke tests and
end-to-end canonical-plan validation remain outstanding.

## Limitations and residual risk

The core automation patch remains a draft. Existing manual-only ModSecurity
fixtures and `MANUAL_REVIEW_VARIABLES` still require review. Passing the
change-record contract alone does not establish release compatibility,
complete automation coverage, or integration readiness. Issue #129 remains
open; the current release pins are unchanged.

## Final diff and review status

The core commit was read back and contained exactly four intended line
replacements. The CI remediation is limited to the paired change records;
no implementation or check is weakened. Delivery remains the existing draft
PR #131 on `codex/issue-129-automatic-modsecurity-v3`; no merge, Parent gitlink
update, or MRTS mutation is performed.
