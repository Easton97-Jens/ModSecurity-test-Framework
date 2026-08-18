# Enable bounded automatic CRS, HTX, and Node maintenance

**Language:** English | [Deutsch](20260818-02-enable-bounded-automatic-maintenance.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260818-02-enable-bounded-automatic-maintenance |
| UTC date | 2026-08-18 |
| Framework base revision | de3fee7df541c3015609d6b46d04ac9e80973f59 |
| Issue or pull request | No pull request at local-validation finalization; Draft PR publication is the next delivery step. |

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

## Security impact

This is a supply-chain policy change, not a relaxation of trust boundaries.
The original HTX source-to-checksum confusion risk is explicitly retested, and
the alternate CRS metadata-bypass form with missing or non-boolean stability
flags is rejected. Automatic outcomes remain contingent on fixed provenance,
integrity, and complete atomic updates.

## Documentation and runtime evidence

The paired variable references describe the bounded CRS v4, independent HTX,
and latest-stable Node contracts in English and German. No connector runtime
was executed and no connector-support, production, GitHub App, credential, or
merge evidence is claimed.

## Checks not run

- The terminal security diff review and its sealed evidence report are pending
  against this final local source snapshot.
- Hosted PR checks and SonarQube Cloud remain pending until an exact task-head
  Draft PR exists.

## Limitations and residual risk

The CRS release-list query is bounded to the official first page and fails
closed if no stable v4 release is present there. Future Node major releases
can affect CI-tool compatibility, but the configured update path still creates
a reviewable literal-pin Draft PR and runs Pyright with its candidate Node.js
runtime rather than changing a running workflow.

## Final diff and review status

Local source validation is complete and the Framework diff has a clean
whitespace check. No commit, push, pull request, merge, Parent gitlink, or
MRTS change exists at this local-validation point. The terminal security
evidence and exact-head hosted validation remain delivery prerequisites; no
merge is claimed or authorized by this record.
