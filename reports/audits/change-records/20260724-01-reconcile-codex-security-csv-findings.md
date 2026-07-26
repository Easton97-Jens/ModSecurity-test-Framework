# Change record: reconcile Codex Security CSV findings

**Language:** English | [Deutsch](20260724-01-reconcile-codex-security-csv-findings.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260724-01-reconcile-codex-security-csv-findings |
| UTC date | 2026-07-24 |
| Framework base revision | 77d73decd094a8f289fbe0ef2582f12430923e24 |
| Issue or pull request | Draft PR [#45](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/45) from agent/fix-codex-security-csv-findings; no merge authority |

## Motivation and problem statement

The supplied Codex Security CSV contains 23 Framework findings whose scan revisions are all ancestors
of current default. Reconciliation must retain an exact disposition per row instead of treating stale
scanner paths or display-only strings as current exploits. Five current open controls required narrow
Framework corrections; the remaining rows were shown already fixed, not applicable, or false positive.

## Affected components and security boundaries

- ci/provisioning/import-mrts-cases.py: emitted MRTS provenance identity.
- ci/lib/runtime-component-common.sh and ci/provisioning/prepare-lighttpd-runtime.sh: staged source containment.
- ci/lib/common.sh: ignored-artifact clean-check admission.
- ci/checks/protocol/check_protocol_evidence.py: forced protocol-selector policy.
- ci/tools/check-common-versions.py: immutable ModSecurity v3 commit-anchor policy.

The changes are supply-chain, filesystem-containment, provenance, and protocol-evidence controls.
They do not update Parent, a gitlink, a remote default branch, or MRTS content.

## Acceptance criteria

- [x] Every one of the 23 CSV rows has exactly one documented disposition.
- [x] The five confirmed CSV rows are fixed through six separate focused root-cause commits.
- [x] Each correction has a negative regression and a legitimate control.
- [x] English/German report and Change Record describe the same result.
- [x] The historical Draft-PR #45 review recorded exact local/remote/PR-head equality and 11
  successful terminal hosted checks at `a025724b2f07d70ffce29c1d6bef5e9b0e93fbcf`; this is not
  evidence for a later head or merge authorization.
- [x] Current local revalidation records exact commands and results below; a fresh hosted analysis
  is required after the next pushed PR head.

## Alternatives considered

Treating every stale scan row as still open would duplicate existing controls and misstate
non-promotable evidence presentation as a runtime bypass. Treating scanner output as proof of Cloud
closure would be unsound without a fresh authenticated re-scan. The selected approach maps each row
to current code and changes only proven gaps.

## Implementation decision

The importer emits the repository that the task actually pins. Lighttpd first confines a staged
path canonically and then refuses every preexisting staged source, so executable source can only
come from the verified missing-source download/extraction flow. The ModSecurity v3 guard checks ignored artifacts alongside
other checkout state. The protocol validator requires exactly one forced selector equal to the
profile selector. The version checker rejects missing or malformed immutable commit anchors before
network work. A follow-up `MODSECURITY_V3_COMPONENT` constant centralizes the repeated component
label without changing provenance decisions, supported variables, or network conditions. All
additions are fail-closed and preserve the existing legitimate controls.

## Changed files and tests

| Change / commit | Production files | Regression coverage |
| --- | --- | --- |
| d2d3320 | ci/provisioning/import-mrts-cases.py | tests/security_regression/test_import_mrts_cases_sonar.py |
| 19d8494 | ci/lib/runtime-component-common.sh; ci/provisioning/prepare-lighttpd-runtime.sh | tests/security_regression/test_ci_root_bootstrap_hardening.py |
| e60cb8c | ci/provisioning/prepare-lighttpd-runtime.sh | tests/security_regression/test_ci_root_bootstrap_hardening.py |
| e94074c | ci/lib/common.sh | tests/security_regression/test_modsecurity_v3_git_ref_provenance.py and support fixture |
| 75f15ab | ci/checks/protocol/check_protocol_evidence.py | tests/protocol_client/test_check_protocol_evidence.py |
| f3aac14 | ci/tools/check-common-versions.py | tests/security_regression/test_common_versions_sonar_provenance.py |
| SonarQube Cloud `python:S1192` follow-up | ci/tools/check-common-versions.py | tests/security_regression/test_common_versions_sonar_provenance.py |

The reconciliation matrix is reports/audits/findings/20260724-01-codex-security-csv-reconciliation
with Markdown, German Markdown, and JSON representations.

## Commands and results

| Command | Exit code | Concise result | Evidence |
| --- | --- | --- | --- |
| `rtk proxy -- python3 -B -m unittest tests.security_regression.test_import_mrts_cases_sonar -v` | 0 | 6 tests passed; emitted source repository is the pinned identity | current local revalidation |
| `rtk proxy -- python3 -B -m unittest discover -s tests/security_regression -p test_ci_root_bootstrap_hardening.py -v` | 0 | 11 tests passed; external, traversal-like, and contained unverified executable Lighttpd stages were rejected before execution | current local revalidation |
| `rtk proxy -- python3 -B -m unittest tests.security_regression.test_modsecurity_v3_git_ref_provenance.ModSecurityV3ProvenanceTests.test_rejects_recursive_topology_bypass_variants -v` | 0 | 1 focused test passed; an ignored checkout artifact was rejected | current local revalidation |
| `rtk proxy -- python3 -B -m unittest tests.protocol_client.test_check_protocol_evidence -v` | 0 | 16 tests passed; fallback, duplicate, and conflicting selectors were rejected | current local revalidation |
| `rtk proxy -- python3 -B -m unittest tests.security_regression.test_common_versions_sonar_provenance -v` | 0 | 16 tests passed; missing/malformed commit anchors block before network use | current local revalidation |
| `rtk proxy -- bash -n ci/lib/common.sh ci/lib/runtime-component-common.sh ci/provisioning/prepare-lighttpd-runtime.sh` | 0 | changed shell sources parse successfully | current local revalidation |
| `rtk proxy -- python3 -m json.tool reports/audits/findings/20260724-01-codex-security-csv-reconciliation.json >/dev/null` | 0 | reconciliation JSON parses successfully | current local revalidation |
| `rtk proxy -- make check-documentation` | 0 | bilingual links, variable documentation, repository-path references, and Change Record contract passed | current local revalidation |
| `rtk proxy -- git diff --check` | 0 | current PR working-tree diff has no whitespace errors | current local revalidation |

## Security impact

Each original negative condition is re-tested by a focused regression: incorrect MRTS provenance
labeling, an externally staged or preexisting in-cache Lighttpd source, ignored ModSecurity v3 checkout residue, an
alternate or ambiguous protocol selector, and absent/malformed immutable version anchor. Legitimate
contained staging, correct selectors, clean checkouts, and valid anchors remain accepted. The design
rejects ambiguous or unverified state before a downstream action.

## Documentation and runtime evidence

This record and the finding matrix have English and German counterparts. No connector runtime,
production lifecycle, Cloud finding closure, Parent action, or MRTS write was collected or performed.
The source CSV and normalized row data are retained in the task evidence run.

## Checks not run

No authenticated Codex Security re-scan was available; Cloud closure is therefore
blocked_permissions. At this record update, no Framework default-branch update, merge, Parent
gitlink update, or MRTS mutation had been attempted. The hosted-check observation at the historical
`a025724b2f07d70ffce29c1d6bef5e9b0e93fbcf` head is retained only as historical evidence; a fresh
current-head analysis is required after a subsequent push.

## Limitations and residual risk

This is a source-level Framework reconciliation. Existing trusted dependency and runtime
prerequisites remain subject to their documented controls. A fresh Cloud scan is required to
supersede the scan service's own status. A Draft PR can be marked ready and merged only after
separate authorization and all current-head controls are observed.

## Final diff and review status

The historical pre-documentation review observed local = remote = PR head at
`a025724b2f07d70ffce29c1d6bef5e9b0e93fbcf`, with 11 executed checks including SonarQube Cloud
and CodeQL Actions/Python/C++. That historical observation does not establish the status of the
later `d8b6d129ad7ccb0978d7932c2a673e87f10f73d1` head or any newer head. This record makes no
current-head hosted-check or merge claim and remains no-merge authority.
