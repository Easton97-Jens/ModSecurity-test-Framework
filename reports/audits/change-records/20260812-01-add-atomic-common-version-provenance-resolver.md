# Change record: 20260812-01-add-atomic-common-version-provenance-resolver

**Language:** English | [Deutsch](20260812-01-add-atomic-common-version-provenance-resolver.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260812-01-add-atomic-common-version-provenance-resolver` |
| UTC date | 2026-08-12 |
| Framework base revision | `209389022c942d83113f6be88bf31d25637352f0` |
| Issue or pull request | Draft, open [PR #76](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/76) targets `master` from `agent/common-version-atomic-provenance`. At the recorded Sonar evidence observation, the local checkout, `origin/agent/common-version-atomic-provenance`, and PR head all resolved to `fae3b81db491944a21395de80e3c928f82077143`. |

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

### APR-util inherited-provenance follow-up

The APR-util sourceable shell guard now distinguishes a reviewed tuple exported
by an earlier source from an unreviewed environment override. It records both
presence and pre-assignment value under internal `CI_APR_UTIL_*` names, resets
that state on every source, then reasserts the resolver-visible canonical tuple
before deriving expected URLs. Only no inherited APR-util fields or all four
exact canonical fields are accepted. Empty, partial, changed, malformed, and
fully self-consistent alternate tuples fail closed with exit `77` before the
Apache preparer reaches a download or archive command. The four public
provenance fields and resolver-maintained literal/derived structure remain
unchanged; no `APR_UTIL_PINNED_*`, `readonly`, `eval`, or Bash-only behavior was
introduced.

### SonarQube Cloud duplication follow-up

At pre-remediation PR head
`59240c5ac321831dbc72fdd515fd574b6c07b4e4`, the public PR analysis reported
`48` new duplicated lines (`1.4444778814324406%`) in exactly one task-owned
file, `tests/security_regression/test_apr_util_provenance.py`. Its duplication
API identifies the three fake-network preparer setups at lines 130–153,
350–372, and 415–438; the first and third blocks are new while the middle
block is baseline context. The test now shares that fixture setup through one
private helper while each test retains its distinct command, provenance input,
expected exit `77` or legitimate result, and no-network marker assertion. No
production provenance guard, Sonar rule, Quality Gate, exclusion, suppression,
or reader-facing behavior changes.

## Changed files and tests

- `ci/lib/common.sh` contains the tracked provenance defaults consumed by the
  resolver and the APR-util inherited-state guard.
- `tests/security_regression/test_apr_util_provenance.py` adds repeat-source,
  exact inherited child tuple, post-source mutation, coherent replacement, and
  fake-tool-before-network regression coverage; its three fake-network
  preparer tests now reuse one private fixture helper to remove the
  task-owned SonarQube Cloud duplication without reducing their distinct
  security assertions.
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
- At the recorded Sonar evidence observation, the published PR history contained
  `e23152be008c52ecc5b5e8bcc6c7357d7a083408` (`Add atomic common-version
  provenance resolver`) and
  `581e1cb2a5f971e5a5b0d83ef2b63ce4f3923795` (`Format CI security contract
  updates`), followed by
  `ba348a7c28b13edcdc253aef7389c89b8285b241` (`Resolve Sonar code smells in
  provenance resolver`) and then-current exact head
  `fae3b81db491944a21395de80e3c928f82077143` (`Reduce release URL validation
  complexity`). The two latter commits are the behavior-preserving Sonar
  remediation; its local validation passed.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `git diff --check -- docs/reference/variables.md docs/reference/variables.de.md` | 0 | No whitespace errors in the paired resolver reference update. | Framework working tree |
| `make check-documentation` | 0 | Documentation links, variable documentation, repository paths, and Change Record contract passed before this record pair was added. | Framework working tree |
| `git diff --check -- reports/audits/change-records/20260812-01-add-atomic-common-version-provenance-resolver.md reports/audits/change-records/20260812-01-add-atomic-common-version-provenance-resolver.de.md` | 0 | No whitespace errors in the paired Change Record. | Framework working tree |
| `make check-documentation` | 0 | Documentation links, variable documentation, repository paths, and the final Change Record contract passed with this record pair present. | Framework working tree |
| `gh pr view 76 --json number,url,state,isDraft,headRefName,headRefOid,baseRefName,commits,reviewDecision,mergeStateStatus` | 0 | Observed Draft, open PR #76 on `agent/common-version-atomic-provenance`, targeting `master`, with then-current PR head `fae3b81db491944a21395de80e3c928f82077143` and the four published commits listed above. | [PR #76](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/76) |
| Local `test_common_versions_sonar_provenance` + `test_common_version_atomic_provenance` suites | 0 | 44 behavior-preserving Sonar-remediation tests passed in `749.688s`. | Framework working tree |
| Direct `test_common_version_atomic_provenance` suite | 0 | 15 atomic provenance tests passed. | Framework working tree |
| `make test-ci-security-contract` | 0 | 173 CI-security-contract tests passed in `54.902s`. | Framework working tree |
| Local `py_compile` validation | 0 | Changed Python validation code compiled successfully. | Framework working tree |
| `make check-documentation` | 0 | Documentation validation passed after the local Sonar-remediation validation. | Framework working tree |
| `git diff --check` | 0 | The local remediation diff had no whitespace errors. | Framework working tree |
| Exact-head `SonarCloud Code Analysis` for PR #76 | success | Completed at `2026-08-12T20:31:29Z`. | [PR #76 SonarCloud analysis](https://sonarcloud.io/dashboard?id=Easton97-Jens_ModSecurity-test-Framework&pullRequest=76) |
| SonarQube Cloud bot comment on PR #76 | observed | At `2026-08-12T20:31:32Z`, it reported Quality Gate passed, `0 New issues`, `0 Accepted issues`, and `0 Security Hotspots`. | [PR #76 comment](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/76#issuecomment-5272463046) |
| SonarQube Cloud API issue search for PR #76 | 0 | The scoped PR query returned total `0`; it is not a claim about unrelated project or future-head issues. | PR #76 exact-head evidence |
| `sh -n ci/lib/common.sh ci/provisioning/prepare-apache-build.sh` | 0 | Updated sourceable guard and Apache preparer have valid shell syntax. | Task-owned local validation root |
| `python3 -m unittest tests.security_regression.test_apr_util_provenance -v` | 0 | 13 APR-util inheritance/provenance tests passed in `1.755s`. | Task-owned local validation root |
| `python3 -m py_compile ci/tools/check-common-versions.py` | 0 | Common-version checker compiled. | Task-owned local validation root |
| Atomic, common-version provenance, NGINX, and PCRE2 focused suites | 0 | 15 atomic, 29 common-version, 4 NGINX, and 3 PCRE2 tests passed; the common-version suite completed in `735.288s`. | Task-owned local validation root |
| `make test-ci-security-contract` | 0 | 173 CI-security tests passed in `53.682s`. | Task-owned local validation root |
| `make check-documentation` | 0 | Documentation and Change Record contract passed before this follow-up record edit. | Task-owned local validation root |
| `shellcheck -x ci/lib/common.sh ci/checks/catalog/check-common-helpers.sh` | 0 | No ShellCheck finding. | Task-owned local validation root |
| `make lint` | 0 | Final full local aggregate passed after the initial APR-util record edit, including its documentation and `git diff --check` stages. | Task-owned local validation root |
| SonarQube Cloud PR measures and duplication APIs | 0 | Pre-remediation PR head `59240c5ac321831dbc72fdd515fd574b6c07b4e4` had 48 new duplicated lines (`1.4444778814324406%`) only in the APR-util provenance regression file; the identified duplicated spans were used for the focused refactor. | [PR #76 SonarCloud analysis](https://sonarcloud.io/dashboard?id=Easton97-Jens_ModSecurity-test-Framework&pullRequest=76) |
| `make BUILD_ROOT=<task-owned external root> TMP_ROOT=<task-owned external root> test-apr-util-provenance` | 0 | The post-refactor APR-util provenance suite passed all 13 tests in `1.715s`, including clean/re-source controls and fail-closed no-network cases. | Framework task run `20260813T071713Z-framework-pr76-sonar-duplication-master` |

## Security impact

This is provenance and CI-maintenance boundary work. It strengthens the
mapping from official metadata to candidate values by centralizing ownership,
enforcing atomic groups, and retaining manual review for immutable Git
provenance. The APR-util follow-up hardens source/child-source tuple binding
without weakening HTTPS, digest, redirect, or archive controls. A hermetic
preparer fixture confirms invalid inherited or post-source state stops before
network/archive tools. No connector runtime claim or deployment action was
performed.

## Documentation and runtime evidence

The paired variable reference documents the new resolver contract in English
and German. Draft PR #76 and its then-current published branch/head were observed.
No host runtime, connector lifecycle, merge, Parent action, MRTS action, or
Gitlink update was observed or collected as evidence. A behavior-preserving
remediation for a Sonar code smell has passed the local validation recorded
above. The exact-head SonarCloud check succeeded at `2026-08-12T20:31:29Z`;
the subsequent bot comment and scoped API query reported the bounded zero-issue
facts recorded above. Those Sonar facts do not complete the still-running
current-head hosted CI.

The APR-util guard implementation was committed and pushed as
`b3dc9aeda0fda59aae65e0c54785e6b9500d025b` on the same selected Draft PR #76
branch. This traceability reconciliation is a separate, documentation-only
follow-up; its eventual exact PR head, hosted CI, Sonar, review, branch
protection, and any resulting-master evidence remain separate observations and
are not claimed here.

The current duplication-only follow-up is local until its normal task-branch
commit and push. The user has explicitly requested that PR #76 be brought to
`master`, but the required new current-head Sonar, checks, reviews, ruleset,
and exact-head squash-merge evidence remain pending; no merge is claimed by
this record update.

## Checks not run

- Additional focused resolver, CI-security, and regression tests beyond the
  passed suites recorded above were not run by the earlier record-only subtask;
  the APR-util implementation owner subsequently ran the focused suites listed
  above. The final full local `make lint` aggregate then completed with exit
  `0`, including its documentation and `git diff --check` stages. No local
  test gap is claimed here; hosted exact-head evidence remains separate.
- At this observation point, current-head hosted CI still has in-progress
  checks. The earlier OSV attempt on
  `ba348a7c28b13edcdc253aef7389c89b8285b241` encountered an external HTTP 503
  while downloading tooling; it is not evidence for
  `fae3b81db491944a21395de80e3c928f82077143`. The final-head OSV status,
  remaining CI checks, review, and branch-protection disposition remain
  separately pending.

## Limitations and residual risk

Upstream release and checksum data are time-varying. The resolver's local
contract does not replace a future reviewed candidate or hosted validation.
Manual CRS and ModSecurity-v3 provenance decisions deliberately remain human
review boundaries. This record does not establish connector compatibility or
runtime readiness.

## Final diff and review status

This record is included in the published PR #76 history described above. At
the recorded Sonar evidence observation, the local branch, its `origin`
counterpart, and the PR head all resolved to
`fae3b81db491944a21395de80e3c928f82077143`. Exact-head Sonar evidence passed
with the bounded zero-issue facts above, but hosted CI was still in progress;
the final-head OSV status, remaining CI, review, branch protection, and merge
status remain pending. No merge, Parent change, MRTS change, or Gitlink update
is claimed.

The APR-util guard implementation is committed and pushed as
`b3dc9aeda0fda59aae65e0c54785e6b9500d025b` on the same selected PR branch.
This documentation-only reconciliation deliberately does not claim the
subsequent exact PR head before its own normal follow-up commit and push.

The duplication-only test refactor and this paired record update are local at
the current observation point. The pre-remediation PR head was
`59240c5ac321831dbc72fdd515fd574b6c07b4e4`; its next exact head, hosted
checks/Sonar result, review/ruleset disposition, and user-authorized normal
`--squash` integration into `master` remain pending. No Parent change, MRTS
change, Gitlink update, or merge is claimed.
