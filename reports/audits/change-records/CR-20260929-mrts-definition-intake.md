# Framework MRTS definition intake boundary

**Language:** English | [Deutsch](CR-20260929-mrts-definition-intake.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `CR-20260929-mrts-definition-intake` |
| Date (UTC) | 2026-09-29 |
| Base revision | `f9e48b0774b5bdf7aaa8e38ce98eb6c50bf293c8` |
| Source finding | `B03` / `csf_24b4dcf793c63c691309c9af` |
| Unchanged MRTS gitlink | `8a6bb546c4c81d8ffc7be801dceac60c6925685f` |
| Delivery target | Framework Draft PR #128; no merge |

## Motivation and problem statement

B03 identifies unrestricted global attribute assignment inside the separately
owned MRTS generator. The user selected Parent and Framework, not MRTS. This
draft adds a bounded mitigation at the existing Framework generation entrypoint,
without copying or modifying the generator or claiming its root cause is fixed.

The [intake record](../findings/20260929-mrts-intake.json) retains the original
finding ID, reported severity, ownership boundary and pending verification.
The companion Parent draft preserves the 72-source to 59-work-item mapping.
Other findings are not silently treated as completed.

CI on the initial head 95dd0a95d39ea77679832b888aba745d7954d23d rejected the
flow-style branch list and the unavailable runner context in job-level env.
The remediation uses block YAML and step-level runtime/cache variables.
The paired record is aligned with the existing documentation contract;
no checker or quality-gate requirement is relaxed.

## Acceptance criteria

- Reject undocumented global keys and non-mapping global configuration before
  generator execution, including whole-global scalar substitution.
- Validate every selected definition before invoking the generator.
- Pass private snapshots of parsed and validated documents; do not validate a
  source pathname and then ask the generator to reopen it.
- Preserve lexical ordering, supported data, output arguments and unsuccessful
  child exit status, plus the caller's runtime/output-root controls.
- Verify the full pinned default and feature-demo corpus before promotion.
- Keep direct MRTS invocation and its unresolved root fix explicitly separate.
- Require successful dedicated regression and existing checks at the repaired
  head; read the actual Sonar issue before claiming a Sonar correction.

## Implementation decision and rationale

The existing shell wrapper delegates to the new Framework-owned Python launcher.
The launcher constrains definition data before it reaches a trusted,
operator-selected MRTS program. It is not a sandbox for generator code or
hostile same-UID processes and does not replace existing output-path checks.

The schema comes from the pinned MRTS README global keywords and RuleGenerator.
Both default_tests_phase_methods and default_test_phase_methods remain accepted
without translation; default_constants is retained from the implementation.
Other attribute names are rejected. Object introspection is not a schema.

The launcher uses the existing PyYAML safe loader and writes numbered validated
snapshots under the external build root. File mode is 0600 and directory mode
0700; cleanup occurs on normal completion and exceptions. Lexical ordering is
preserved. Changing MRTS directly would cross the selected repository boundary;
validate-then-reopen would retain a replacement window. The snapshot design
avoids that window without importing the generator into Framework.

The existing shell output cleanup still precedes the launcher. Therefore this
draft does not preserve previous generated outputs when later validation fails.
It does not change MRTS rulefile/testfile containment or permit additional global
object attributes.

The dedicated exact-head regression workflow installs only the existing
hash-locked dependencies. Runtime directories are created with private umask.
A temporary, unauthenticated diagnostic reads the original public Sonar check
annotation without checkout or credentials, solely to identify its rule and
location. It is not a new Sonar analysis or a replacement for the Quality Gate
and is to be removed after diagnosis. Action pins and security gates are intact.

## Changed files

- `ci/provisioning/generate-mrts.sh`
- `ci/provisioning/mrts_definition_guard.py`
- `tests/security_regression/test_mrts_definition_guard.py`
- `.github/workflows/ci-findings-regressions.yml`
- `reports/audits/findings/20260929-mrts-intake.json`
- This English/German Change Record pair.

## Commands executed

| Check | Actual evidence and limitation |
| --- | --- |
| Original shell transfer | Complete content matched Git blob SHA-1 before the initial edit |
| Original Python syntax / intake JSON | Parsed as data, not behavioral test execution |
| Local launcher tests | NOT RUN: required RTK is unavailable |
| Generator test double | Defined for arguments, snapshots, permissions, rejection and cleanup; local execution not claimed |
| Full pinned MRTS corpus | NOT RUN; direct generator compatibility remains a separate gate |
| Local shell syntax / git diff --check | NOT RUN in the editing environment |
| Initial action-version job 109307180219 | Failed on flow-style branches in ci-findings-regressions.yml |
| Initial actionlint job 109307181277 | Failed on job-level runner context for TMPDIR and PIP_CACHE_DIR |
| Original Sonar check 109307382232 | Failed new-code security rating; exact annotation retrieval pending |
| Repaired exact-head regression and full CI | Pending fresh results after this commit; no successful result claimed here |

The code-work and Sonar skills were read. The repository-referenced global
execution skill and mandatory local RTK are unavailable. No local project
command silently bypasses that execution policy.

## Security impact

Undocumented object attributes in global configuration are rejected at this
Framework entrypoint. This is intentional; full corpus compatibility remains
unverified. The original generator is unchanged, and direct invocation is
outside the mitigation. B03 cannot be closed on the basis of this wrapper.
The CI repair does not grant write permissions, weaken pinning or disable tests.

## Runtime evidence

No live original-scenario host evidence or complete pinned-corpus run is
established by this record. Test-double success establishes only the tested
launcher behavior. Other green checks cannot substitute for the dedicated
regression or for the actual current-head Sonar result.

## Known limitations

This is candidate_entrypoint_mitigation, not complete remediation or verified
closure of B03. The direct MRTS fix requires its separately authorized task.
Shell output cleanup happens before the new validation boundary. Operator-
selected generator behavior and same-UID process isolation remain out of scope.

## Remaining risks

The full default/feature-demo corpus and existing containment regressions need
execution. Sonar's original security annotation must be diagnosed without
suppressing it or assuming its rule. Any necessary source correction requires
new focused tests and a new head-bound analysis.

## Checks not run and rationale

Local repository execution, native/runtime validation and the full MRTS corpus
were not run because the editing environment lacks the prescribed RTK and
provisioned repository tools. No omitted or skipped check is a PASS. Pending
new-head results are not replaced by old-head successes or source inspection.

## Final diff and review status

The first CI-remediation slice changes the dedicated workflow and this paired
record, not the guard, original tests, dependency locks or quality-gate settings.
The PR remains a draft pending actual current-head checks and independent review.

Parent impact: this separate Framework commit does not change Parent's selected
dependency. Parent gitlink: unchanged. MRTS scope: default_read_only; MRTS
gitlink: unchanged. No merge, force-push, risk acceptance or release claim.
