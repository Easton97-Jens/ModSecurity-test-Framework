# Change record: 20260812-01-add-atomic-common-version-provenance-resolver

**Language:** English | [Deutsch](20260812-01-add-atomic-common-version-provenance-resolver.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260812-01-add-atomic-common-version-provenance-resolver` |
| UTC date | 2026-08-12 |
| Framework base revision | `209389022c942d83113f6be88bf31d25637352f0` |
| Issue or pull request | Draft, open [PR #76](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/76) targets `master` from `agent/common-version-atomic-provenance`. Its currently published head is `581e1cb2a5f971e5a5b0d83ef2b63ce4f3923795`; this is not a final remediation SHA. |

## Motivation and problem statement

The previous common-version maintenance logic needed a single auditable source
of truth for every tracked external-component provenance input. The change
introduces a data-driven resolver that can distinguish safe automatic version,
URL, and digest updates from provenance decisions that require review or from
metadata that must never become an updater input.

## Affected components and security boundaries

The Framework-only change affects `ci/lib/common.sh`,
`ci/tools/check-common-versions.py`, its workflow and regression/security
checks, and the paired variable reference. The boundary begins with official
upstream release, listing, checksum, and Git-tag metadata and ends at a
validated atomic candidate for `ci/lib/common.sh`. The resolver rejects
unexpected URL redirects, unassigned or multiply owned provenance variables,
and unsafe update states. Parent, MRTS, Gitlinks, connector runtime behavior,
and production deployment are outside this change.

## Acceptance criteria

1. One component registry declares each provenance variable's owner, resolver
   strategy, official source, update policy, checksum strategy, and atomic
   update group.
2. Automatic components update their interdependent version, URL, asset, and
   SHA-256 values as one validated group.
3. CRS and ModSecurity v3 remain manual review decisions based on stable tag
   and immutable peeled-commit provenance.
4. Local-only or non-acquisition metadata is explicitly `not_applicable`.
5. Exact component selection and registry listing are available to the CLI and
   optional manual workflow dispatch.
6. English and German documentation describe the same contract without
   claiming an unobserved delivery result.

## Alternatives considered

- Maintaining per-component resolver policy in independent functions was
  rejected because ownership, compatibility, and atomic-update rules could
  drift.
- Treating every tracked value as automatically renewable was rejected because
  reviewed tag/commit pins and local hints have different trust boundaries.
- Updating a version separately from derived URLs or digests was rejected
  because it can create an inconsistent provenance tuple.

## Implementation decision

`COMPONENT_DEFINITIONS` centralizes the component contracts and dispatches to
small strategy-specific resolvers. The resolver distinguishes `automatic`,
`manual_review`, and `not_applicable` records, preserves reviewed pins, and
fails closed for `unknown`, `blocked`, and `error`. Automatic changes are
rendered and validated as atomic groups, including dynamic URLs that derive
from the updated version. `--list-components` exposes exact registry names;
repeated exact `--component` options restrict resolution. The scheduled
workflow resolves all records unless its optional `workflow_dispatch`
`component` input selects one exact record.

## Changed files and tests

- `ci/lib/common.sh` contains the tracked provenance defaults consumed by the
  resolver.
- `ci/tools/check-common-versions.py` contains the component registry,
  resolver dispatch, atomic candidate handling, and CLI selection contract.
- `.github/workflows/check-common-versions.yml` carries the optional manual
  component selection through the resolver workflow.
- CI-security and provenance regression files cover the changed contract.
- `docs/reference/variables.md` and `docs/reference/variables.de.md` document
  the registry, policies, official-source strategies, atomic URLs, CLI, and
  workflow selection.
- This paired record preserves the Framework-only decision and current
  validation disposition.
- The published PR history currently contains
  `e23152be008c52ecc5b5e8bcc6c7357d7a083408` (`Add atomic common-version
  provenance resolver`) and
  `581e1cb2a5f971e5a5b0d83ef2b63ce4f3923795` (`Format CI security contract
  updates`). The behavior-preserving Sonar code-smell remediation has passed
  local validation; its final commit, published head, and hosted validation
  remain pending.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `git diff --check -- docs/reference/variables.md docs/reference/variables.de.md` | 0 | No whitespace errors in the paired resolver reference update. | Framework working tree |
| `make check-documentation` | 0 | Documentation links, variable documentation, repository paths, and Change Record contract passed before this record pair was added. | Framework working tree |
| `git diff --check -- reports/audits/change-records/20260812-01-add-atomic-common-version-provenance-resolver.md reports/audits/change-records/20260812-01-add-atomic-common-version-provenance-resolver.de.md` | 0 | No whitespace errors in the paired Change Record. | Framework working tree |
| `make check-documentation` | 0 | Documentation links, variable documentation, repository paths, and the final Change Record contract passed with this record pair present. | Framework working tree |
| `gh pr view 76 --json number,url,state,isDraft,headRefName,headRefOid,baseRefName,commits,statusCheckRollup,reviewDecision,mergeStateStatus` | 0 | Observed Draft, open PR #76 on `agent/common-version-atomic-provenance`, targeting `master`, with the two published commits listed above and published head `581e1cb…`. | [PR #76](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/76) |
| Local `test_common_versions_sonar_provenance` + `test_common_version_atomic_provenance` suites | 0 | 44 behavior-preserving Sonar-remediation tests passed in `749.688s`. | Framework working tree |
| Direct `test_common_version_atomic_provenance` suite | 0 | 15 atomic provenance tests passed. | Framework working tree |
| `make test-ci-security-contract` | 0 | 173 CI-security-contract tests passed in `54.902s`. | Framework working tree |
| Local `py_compile` validation | 0 | Changed Python validation code compiled successfully. | Framework working tree |
| `make check-documentation` | 0 | Documentation validation passed after the local Sonar-remediation validation. | Framework working tree |
| `git diff --check` | 0 | The local remediation diff had no whitespace errors. | Framework working tree |

## Security impact

This is provenance and CI-maintenance boundary work. It strengthens the
mapping from official metadata to candidate values by centralizing ownership,
enforcing atomic groups, and retaining manual review for immutable Git
provenance. No runtime security remediation, exploit reproduction, connector
runtime claim, or deployment action was performed in this record subtask.

## Documentation and runtime evidence

The paired variable reference documents the new resolver contract in English
and German. Draft PR #76 and its current published branch/head were observed.
No host runtime, connector lifecycle, merge, Parent action, MRTS action, or
Gitlink update was observed or collected as evidence. A behavior-preserving
remediation for a Sonar code smell has passed the local validation recorded
above. Its final commit, published head, and current-SHA hosted validation have
not yet been observed.

## Checks not run

- Additional focused resolver, CI-security, and regression tests beyond the
  passed suites recorded above were not run by this record-only subtask; their
  execution belongs to the implementation owner.
- The behavior-preserving Sonar code-smell remediation passed local validation,
  but it has no final commit, final published remediation head, current-SHA
  hosted check result, review, or branch-protection disposition yet. Those
  must be re-evaluated against its eventual exact head.

## Limitations and residual risk

Upstream release and checksum data are time-varying. The resolver's local
contract does not replace a future reviewed candidate or hosted validation.
Manual CRS and ModSecurity-v3 provenance decisions deliberately remain human
review boundaries. This record does not establish connector compatibility or
runtime readiness.

## Final diff and review status

This record was included in the published PR #76 history described above. The
currently published branch and `origin/agent/common-version-atomic-provenance`
both resolve to `581e1cb…`, but the behavior-preserving Sonar code-smell
remediation has passed local validation and makes that head non-final. Its
final commit, published SHA, current-SHA hosted checks, review, and merge
status are pending. No Parent change, MRTS change, or Gitlink update is
claimed.
