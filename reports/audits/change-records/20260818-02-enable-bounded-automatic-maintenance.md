# Enable bounded automatic CRS, HTX, and Node maintenance

**Language:** English | [Deutsch](20260818-02-enable-bounded-automatic-maintenance.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260818-02-enable-bounded-automatic-maintenance |
| UTC date | 2026-08-18 |
| Framework base revision | de3fee7df541c3015609d6b46d04ac9e80973f59 |
| Issue or pull request | Draft [PR #98](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/98), whose source-remediation head was `1eaebe2ac27bbeb4ec45592211538cc02d0c0ce4`. This paired documentation reconciliation creates a new PR head that requires fresh hosted validation before an authorized merge. |

## Motivation and problem statement

The requested maintenance policy makes CRS v4 releases, the independent
HAProxy HTX series, and Node.js updates automatic. The previous contracts kept
CRS and HTX manual and stopped Node at a major-line review, which did not meet
the requested maintenance behavior.

## Affected components and security boundaries

- ci/tools/check-common-versions.py owns fixed-origin release, tag, digest,
  and atomic update planning for CRS and HAProxy HTX.
- ci/tools/canonical_maintenance.py selects the canonical Node.js pin that
  generated workflow views consume.
- ci/lib/common.sh remains the canonical pin authority; no pin value or
  generated runtime lock was changed by this policy-only change.

The relevant boundary is external release metadata to canonical pins and then
to provisioning or CI. The change preserves host allowlists, stable-release
filters, immutable peeled commits, per-asset SHA-256 checks, atomic plans, and
the independent HTX profile.

## Acceptance criteria

1. Only stable CRS tags matching v4.x.x can automatically update the fixed
   repository tag and its peeled commit as one atomic pair.
2. HTX automatically resolves only its own configured HAProxy series and
   never changes or reuses the generic HAProxy tuple.
3. Node selects the latest stable numeric release across major lines, while
   generated workflows continue to receive an exact literal pin.
4. Malformed, prerelease, incomplete, foreign, or partial inputs fail closed.
5. English and German variable documentation state the same maintenance
   contract.

## Alternatives considered

- A dynamic workflow node-version latest value was rejected because workflow
  executions must remain literal-pin reproducible.
- Automatic CRS v5 transitions were rejected because the request is bounded to
  v4.x.x.
- Reusing generic HAProxy values for HTX was rejected because the two runtime
  profiles have independent provenance and compatibility tuples.
- Keeping all three paths manual or same-major-only would not meet the
  explicitly selected maintenance policy.

## Implementation decision

CRS enumerates the official release page, accepts only explicit boolean
non-draft/non-prerelease entries, reports later upstream majors, and selects
only the newest stable v4.x.x target. Its tag and peeled commit are planned
together and the generic automatic-plan validator rejects a partial pair.

HTX now uses the normal HAProxy series-constrained automatic disposition while
retaining its own descriptor and variables. The optional checksum-URL input
was made explicit so a future literal HTX source URL cannot be replaced with a
checksum URL. Node's latest compatible release is its latest stable upstream
release, including a major transition; workflow synchronization still renders
the resulting literal version. A `ci/lib/common.sh` candidate also matches the
CI-security-quality pull-request path, which runs Pyright with that literal
candidate Node.js runtime before the Draft PR can be considered for hosted
checks and any separately authorized integration.

The first exact-head SonarQube Cloud analysis of Draft PR #98 then reported
3.5% duplication on new code, above the 3% Quality Gate threshold. Its
duplication API localized the 20 new duplicated lines to the equivalent
fixed-repository setup and precondition blocks in the manual and automatic
Git-provenance resolvers. The shared
`git_release_provenance_context()` helper centralizes that setup without
changing the fixed repository, tag, peeled-commit, alias, or fail-closed
precondition contract. No Sonar rule, threshold, exclusion, or suppression
was changed.

## Changed files and tests

- ci/tools/check-common-versions.py
- ci/tools/canonical_maintenance.py
- .github/workflows/ci-security-quality.yml
- tests/security_regression/test_crs_git_ref_provenance.py
- tests/security_regression/test_common_versions_sonar_provenance.py
- tests/security_regression/test_runtime_component_sync.py
- tests/ci_security/test_canonical_maintenance.py
- tests/ci_security/test_sync_canonical_workflow_pins.py
- tests/ci_security/test_unified_common_maintenance_workflow.py
- docs/reference/variables.md and docs/reference/variables.de.md
- This English/German Change Record pair.

The new regression coverage includes malformed GitHub stability flags, a
stable v5 CRS release that is not selected, partial atomic-plan rejection,
independent HTX updates, a literal HTX source-url checksum confusion attempt,
equal-version HTX/generic profile separation, and a Node major-line transition
with prerelease/malformed alternatives. It also proves that a candidate change
to the canonical Node pin triggers the pull-request quality workflow, keeps a
literal pin rather than `latest`, and invokes Pyright under that candidate
Node runtime.

The follow-up preserves existing manual and automatic CRS provenance coverage
while removing the duplicated resolver precondition implementation identified
by SonarQube Cloud.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused canonical-maintenance resolver tests | 0 | 11 tests passed, including latest-stable Node major and malformed/prerelease cases. | Task-owned external validation environment |
| Focused workflow-pin tests with hash-locked PyYAML | 0 | 12 tests passed; Node 25.0.0 rendered as a literal workflow value. | Task-owned external validation environment |
| CRS provenance regression suite | 0 | 20 tests passed, including the automatic v4 atomic pair, immutable repository identity binding, and malformed stability-field filtering. | Task-owned external validation environment |
| Common-version provenance suite | 0 | 32 tests passed on the final CRS-hardened source. | Task-owned external validation environment |
| Node PR-head quality contract, workflow pin, and CI-security contract suites | 0 | 63 tests passed; the candidate literal Node pin is checked by Pyright on the pull-request head. | Task-owned external validation environment |
| Canonical, workflow-pin, and runtime projection checks | 0 | Canonical pins, workflow views, and runtime components passed. | Task-owned external validation environment |
| Python compile and whitespace diff check | 0 | Changed Python files compiled and no whitespace errors were reported. | Task-owned external validation environment |
| Full native Framework lint | 0 | Repository-native lint, canonical/runtime/workflow checks, documentation, and Change Record checks passed with explicit task-worktree roots. | Task-owned external validation environment |
| Draft PR #98 first SonarQube Cloud analysis | nonzero | Quality Gate failed at 3.5% duplication on new code (threshold <= 3%); 20 new duplicated lines were localized to `ci/tools/check-common-versions.py`. | PR #98 SonarQube Cloud decoration and public duplication API |
| Sonar-remediation provenance and compilation tests | 0 | Python compilation, 20 CRS Git-provenance tests, and 32 common-version provenance tests passed for the shared-helper source. | Task-owned external validation environment |
| Sonar-remediation full native Framework lint | 0 | The complete native `make -s lint` passed with the permitted task-worktree Framework output root; an earlier rejected external output root was an environment-contract failure, not a source failure. | Task-owned external validation environment |
| Terminal security diff review of the Sonar-remediation source | 0 | Complete follow-up coverage with zero reportable findings; the review covers the exact narrow remediation diff. | Sealed report `b18c2bc50fb4_20260818T101455Z/report.md`, SHA-256 `3343ab1a37442dd1e85aa566943476da047f738b155c411a7cea8123d7308450` |
| Exact-head PR #98 GitHub Actions | 0 | All 10 applicable Actions reached terminal success for `1eaebe2ac27bbeb4ec45592211538cc02d0c0ce4`, including native lint and CI-security quality. | GitHub Actions PR #98 exact-head evidence |
| Exact-head PR #98 SonarQube Cloud | 0 | Quality Gate passed with 0 New issues, 0 Security Hotspots, 0.0% Coverage on New Code, and 0.0% Duplication on New Code. | SonarQube Cloud PR #98 exact-head decoration |
| Fresh master-preflight native Framework lint | 0 | A complete `make -s lint` passed before this documentation-only reconciliation. | Task-owned external validation environment |

## Security impact

This is a supply-chain policy change, not a relaxation of trust boundaries.
The original HTX source-to-checksum confusion risk is explicitly retested, and
the alternate CRS metadata-bypass form with missing or non-boolean stability
flags is rejected. Automatic outcomes remain contingent on fixed provenance,
integrity, and complete atomic updates.

The SonarQube duplication remediation preserves those controls by sharing the
same fixed-provenance input validation between the two resolver dispositions;
it does not turn a manual path automatic, loosen any input check, or suppress
the Quality Gate.

## Documentation and runtime evidence

The paired variable references describe the bounded CRS v4, independent HTX,
and latest-stable Node contracts in English and German. No connector runtime
was executed and no connector-support, production, GitHub App, or credential
evidence is claimed. Exact-head PR evidence is recorded above; no merge or
resulting-`master` outcome is claimed.

## Checks not run

- This documentation-only reconciliation is a new PR head. Its fresh
  exact-head GitHub Actions and SonarQube Cloud analysis are not yet run at
  this record's source revision; the successful source-remediation evidence
  above must not be reused as proof for that new head.
- No Framework `master` workflow exists yet because the authorized merge has
  not occurred.

## Limitations and residual risk

The CRS release-list query is bounded to the official first page and fails
closed if no stable v4 release is present there. Future Node major releases
can affect CI-tool compatibility, but the configured update path still creates
a reviewable literal-pin Draft PR and runs Pyright with its candidate Node.js
runtime rather than changing a running workflow.

## Final diff and review status

The initial local source validation, SonarQube duplication remediation,
terminal security review, exact-head hosted checks, and fresh native lint are
recorded above. This paired documentation correction removes stale delivery
claims and is the only new task-owned delta. The current user has authorized
Framework `master` integration, but fresh exact-head checks for this new
documentation revision, the ready-for-review transition, and the protected
squash merge remain outstanding. No merge is claimed by this record.
