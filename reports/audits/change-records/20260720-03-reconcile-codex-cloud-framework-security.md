# 20260720-03-reconcile-codex-cloud-framework-security — cumulative Framework security reconciliation

**Language:** English | [Deutsch](20260720-03-reconcile-codex-cloud-framework-security.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260720-03-reconcile-codex-cloud-framework-security` |
| UTC date | 2026-07-20 |
| Framework base revision | `2f4a5d7` (normal, local merge of current Framework master into the existing PR branch) |
| Issue or pull request | Codex Cloud export `4836e7…45daf`; existing Framework Draft PR #37 on `agent/master-post36-sonar-remediation` |

## Motivation and problem statement

The supplied Codex Cloud export has 41 Framework rows. The user requires one
cumulative Framework PR, explicitly forbids `master` integration, and excludes
the Parent repository and MRTS. The changes therefore reconcile every row in
one branch while preserving separate root-cause controls and honest evidence.

## Affected components and security boundaries

The remediation covers GitHub Actions trust boundaries, cache/provenance and
runtime-root containment, generated-report integrity, response/evidence
promotion, protocol payload safety, CRS/MRTS generated-output containment, and
Framework documentation validation. It changes no connector host implementation,
Parent Git state, Parent gitlink, MRTS content, or MRTS gitlink.

## Acceptance criteria

- Account for every one of the 41 Cloud IDs in an English, German, and JSON
  Framework record.
- Keep confirmed feasible controls and their negative/control regressions on
  the one existing PR #37 branch.
- Allow no master merge or direct master push.
- Retain high-impact controls or record concrete already-safe/historical
  evidence; do not suppress a scanner or weaken a test.
- Leave Cloud rescan status explicit when no authenticated Cloud tool exists.

## Alternatives considered

Opening a separate PR, splitting root causes, executing PR checkout code in a
privileged OSV workflow, or accepting generic CRS evidence were rejected.
The selected implementation uses the existing branch, a data-only verified PR
object for OSV, and precise evidence gates.

## Implementation decision

The OSV job is a narrow target-triggered exception that executes the trusted
base revision only, fetches the numbered GitHub pull-request head reference,
verifies its SHA, and
reads only bounded dependency blobs. The Actions validators permit exactly
that shape and retain the general prohibition. Generated outputs, runtime
paths, and MRTS generated roots are contained; non-promotable observations
cannot become PASS. The 401 CRS override now requires local rule `2320` in
the audit record. Hash integrity covers raw event values before display
normalization.

## Changed files and tests

Changes are limited to Framework workflows, CI checks/helpers/reporting,
Framework YAML cases and normalizers, focused regression tests, the paired
English/German workflow-security guides, this Change Record, and the paired
Cloud-finding reconciliation files. The complete per-ID mapping is in
`reports/audits/findings/20260720-01-codex-cloud-framework-reconciliation.*`.

## Commands and results

| Command | Exit code | Concise result |
| --- | ---: | --- |
| Selected Framework virtual environment: `python -m unittest tests.security_regression.test_workflow_security_contract tests.ci_security.test_ci_security_contract tests.ci_security.test_ci_security_evidence_contract` | 0 | 35 workflow-security and semantic-evidence tests passed. |
| `python ci/checks/security/check-github-actions-workflows.py --workflow-root .github/workflows --check all` | 0 | All Framework workflows satisfy immutable-pin and permission/trust controls. |
| `python ci/checks/security/check-ci-security-evidence-contract.py --root .` | 0 | OSV, CodeQL, Scorecard, Gitleaks, and boundary contracts passed. |
| `python ci/checks/security/check-ci-security-contract.py --root .` | 0 | Framework CI security contract passed. |
| `python ci/checks/security/check-security-data-flow-normalizers.py` | 0 | Normal and volatile-field tampering are rejected. |
| `python -m unittest tests.security_regression.test_ci_root_bootstrap_hardening.CiRootBootstrapHardeningTests.test_prepare_crs_rejects_source_and_runtime_paths_outside_task_roots` | 0 | Both CRS root-escape negative cases were rejected. |
| `python -m unittest tests.security_regression.test_second_remediation.SecondRemediationTests.test_with_crs_status_override_requires_the_local_rule_audit_evidence` | 0 | Generic CRS block fails; local-rule audit control passes. |
| `python -m unittest tests.no_crs.test_no_crs_baseline` | 0 | 76 No-CRS baseline tests passed. |
| `python ci/checks/documentation/check-variable-documentation.py` and `check-repository-path-references.py` | 0 | Documentation pairing and path-reference checks passed. |
| `python -m unittest discover -s tests/security_regression -q` | 0 | Aggregate security-regression suite passed. |
| `python -m unittest discover -s tests/no_crs -q` | 0 | Aggregate No-CRS suite passed; expected rejection diagnostics were observed. |
| `python -m unittest discover -s tests/ci_security -q` | 0 | 69 CI-security tests passed. |
| `python -m unittest discover -s tests/protocol_client -q` | 0 | 24 protocol-client tests passed. |
| `python -m unittest discover -s tests/workflow_contract -q` | 0 | 2 workflow-contract tests passed. |
| `sh -n` on every modified Framework shell entrypoint and `git diff --check` | 0 | Shell syntax and the complete pending diff passed. |

## Security impact

Focused regressions reproduce the relevant negative condition and retain a
legitimate control: unsafe cache/provenance inputs, path escape, symlink or
freshness bypass, generic CRS status, serialized workflow contexts, and
volatile hash tampering are rejected. The OSV job does not check out or run PR
head code. No security control was weakened.

## Documentation and runtime evidence

The paired workflow guides document the constrained OSV exception. The paired
finding record and canonical JSON account for every supplied row. No connector
runtime/lifecycle run is claimed; the recorded evidence is static or Framework
test-harness evidence.

## Checks not run

The full GitHub CI matrix, external SonarCloud readback, and a fresh Codex
Cloud scan were not run locally. The available Framework interpreter is
CPython 3.14.4 while CI locks CPython 3.13.14; local focused checks are
behavioral evidence, not replacement CI evidence. No authenticated Codex Cloud
connector/API/UI tool is exposed, so Cloud closure is `blocked_permissions`.

## Limitations and residual risk

The target-triggered OSV workflow takes effect from the trusted default branch;
its own PR edit cannot protect its pre-merge historical run. Subsequent PR
runs use the constrained workflow. The final PR head still requires observed
GitHub checks, review, and Sonar evidence. This record does not authorize
merging PR #37.

## Final diff and review status

The worktree contains the locally verified cumulative Framework-only change set
for existing Draft PR #37. Parent and MRTS remain untouched, and no master ref
has been changed. The remaining delivery steps are a normal commit/push to the
existing PR branch and exact remote-head, GitHub-check, review, and Sonar
verification; the PR must remain unmerged.
