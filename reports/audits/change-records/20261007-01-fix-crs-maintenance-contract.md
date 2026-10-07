# Change record

**Language:** English | [Deutsch](20261007-01-fix-crs-maintenance-contract.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20261007-01-fix-crs-maintenance-contract` |
| UTC date | 2026-10-07 |
| Framework base revision | `dd637f30b249e92274290df9c8507694a29874d9` |
| Issue or pull request | [Framework PR #136](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/136) |

## Motivation and problem statement

The CRS v4.30.0 update correctly synchronized canonical pins, fixture and
schemas. Two CI runs nevertheless failed on historical commit and rule-digest
literals in the portable contract test. The validation preceding automated
maintenance PR publication omitted that test suite.
The broad native check then exposed a second missing derived view: the public
package catalog still held the previous CRS provenance.

## Affected components and security boundaries

Framework contract tests and candidate validation in
`.github/workflows/check-common-versions.yml`, plus its exact reviewed script
profile in `ci/checks/security/check-ci-security-contract.py`, canonical generated
view orchestration and the package catalog. Provenance validation, publisher
permissions, Action pins and exact publication path controls remain enforced.
The Parent gitlink and MRTS are unchanged.

## Acceptance criteria

- Reproduce the original failure and correct it through the test fix.
- A further synthetic CRS update passes the full portable suite after
  synchronization; stale fixture and schema data remain rejected.
- The public package catalog follows the synchronized CRS fixture and is
  checked, published and restored on failure with the other generated views.
- Failure of that suite prevents `validated=true` before publication.
- Record relevant local checks and CI for the new PR head.

## Alternatives considered

Replacing the historical literals would make the next update fail again.
Removing provenance checks would weaken a valid control.

## Implementation decision

Expectations follow the reviewed pins in `ci/lib/common.sh`. Each present CRS
schema constant is checked against those pins. The offline regression changes
the tag, commit and digest in an isolated copy, then uses the real synchronizer
and all 29 portable contract tests. Negative controls detect omitted
synchronization and schema drift. Candidate validation runs that suite under
`set -euo pipefail` before `validated=true`; a workflow test enforces ordering.
The CI security contract continues to compare that script exactly against its
reviewed profile, which includes the added suite.
Canonical maintenance regenerates and checks the public catalog after CRS view
synchronization. Only its exact generated path is added to the existing candidate
and publisher allowlists and transaction snapshots. The future-release regression
rejects a stale catalog and verifies fresh profile provenance; rollback coverage
checks restoration after a partially regenerated catalog fails validation.

## Changed files and tests

- `.github/workflows/check-common-versions.yml`
- `ci/checks/security/check-ci-security-contract.py`
- `ci/tools/canonical_maintenance.py`
- `modsecurity_test_framework/data/framework-contract-catalog.json`
- `docs/framework-contract-api.md` and its German companion
- `tests/ci_security/test_canonical_maintenance.py`
- `tests/ci_security/test_five_connector_with_crs_no_mrts_contract.py`
- `tests/ci_security/test_sync_crs_contract_views.py`
- `tests/ci_security/test_unified_common_maintenance_workflow.py`
- `tests/ci_security/test_ci_security_contract.py`
- this paired English/German Change Record

## Commands and results

All shell checks use RTK. The commands below are the executed commands with
portable aliases replacing machine-specific paths; the exact mapping remains
in the task-owned execution plan. `FRAMEWORK_PYTHON` denotes the Framework
interpreter, `PR136_ROOT` the isolated checkout, `PR136_TMP_ROOT`,
`PR136_DOC_TMP_ROOT` and `PR136_DOC_BUILD_ROOT` the external task directories
used for each check, `PR136_BUILD_ROOT` the external build directory,
`PR136_EVIDENCE_ROOT` the external task evidence root, and
`ACTIONLINT_BIN` the existing Actionlint executable.

| Command | Exit code | Result | Evidence |
| --- | --- | --- | --- |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_five_connector_with_crs_no_mrts_contract.FiveConnectorWithCrsNoMrtsContractTest.test_canonical_profile_fixture_and_schema_are_closed -v` | 1 → 0 | Original stale commit reproduced; corrected canonical test passed. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md; runs 37312711723, 37312711744` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_sync_crs_contract_views.SyncCrsContractViewsTests.test_next_crs_release_preserves_portable_contract_and_rejects_drift -v` | 0 | Future CRS update and stale fixture/schema controls passed. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_five_connector_with_crs_no_mrts_contract tests.ci_security.test_sync_crs_contract_views tests.ci_security.test_unified_common_maintenance_workflow -q` | 0 | 54 tests passed. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_unified_common_maintenance_workflow tests.security_regression.test_common_version_descriptor_series tests.security_regression.test_runtime_component_lock tests.ci_security.test_five_connector_with_crs_no_mrts_contract -v` | 0 | 61 candidate tests passed. | `$PR136_EVIDENCE_ROOT/maintenance-gate-validation.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_ci_security_contract tests.ci_security.test_framework_ci_security_contract tests.ci_security.test_update_workflow_tools.WorkflowToolUpdaterTests.test_proposed_tree_validation_accepts_a_tool_only_candidate tests.ci_security.test_unified_common_maintenance_workflow` | 0 | 64 security and publisher tests passed. | `$PR136_EVIDENCE_ROOT/maintenance-gate-validation.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_canonical_maintenance tests.ci_security.test_unified_common_maintenance_workflow tests.ci_security.test_ci_security_contract tests.ci_security.test_framework_ci_security_contract tests.ci_security.test_update_workflow_tools.WorkflowToolUpdaterTests.test_proposed_tree_validation_accepts_a_tool_only_candidate` | 0 | 77 catalog, rollback, security and publisher tests passed. | `$PR136_EVIDENCE_ROOT/maintenance-gate-validation.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_ci_security_contract.CiSecurityContractTest.test_unified_common_maintenance_rejects_catalog_publication_scope_regressions` | 0 | Subsequent publication-scope negative regression passed. | `$PR136_EVIDENCE_ROOT/maintenance-gate-validation.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$FRAMEWORK_PYTHON" ci/tools/generate-framework-contract-catalog.py` | 0 | Generated catalog corrected through its source contract; only CRS tag and commit changed. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 make test-contract-api PYTHON="$FRAMEWORK_PYTHON" FRAMEWORK_ROOT="$PR136_ROOT" BUILD_ROOT="$PR136_BUILD_ROOT" TMP_ROOT="$PR136_TMP_ROOT"` | 0 | Freshness check and all 23 package API tests passed. | `$PR136_EVIDENCE_ROOT/contract-api.log` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 make test-ci-security-contract PYTHON="$FRAMEWORK_PYTHON" FRAMEWORK_ROOT="$PR136_ROOT" BUILD_ROOT="$PR136_BUILD_ROOT" TMP_ROOT="$PR136_TMP_ROOT"` | 0 | Final native CI-security target: 313 tests passed. | `$PR136_EVIDENCE_ROOT/ci-security-final.log` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHON="$FRAMEWORK_PYTHON" FRAMEWORK_ROOT="$PR136_ROOT" CONNECTOR_ROOT="$PR136_ROOT" OUTPUT_ROOT="$PR136_EVIDENCE_ROOT" BUILD_ROOT="$PR136_BUILD_ROOT" TMP_ROOT="$PR136_TMP_ROOT" bash "$PR136_EVIDENCE_ROOT/lint-remainder.sh"` | 1 | Dependency, YAML, Python/workflow contracts and 9 workflow-security tests passed; harness used an unsupported output root for the next evidence check. | `$PR136_EVIDENCE_ROOT/lint-remainder.sh; lint-remainder.log` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHON="$FRAMEWORK_PYTHON" FRAMEWORK_ROOT="$PR136_ROOT" CONNECTOR_ROOT="$PR136_ROOT" OUTPUT_ROOT="$PR136_ROOT" BUILD_ROOT="$PR136_BUILD_ROOT" TMP_ROOT="$PR136_TMP_ROOT" bash "$PR136_EVIDENCE_ROOT/lint-remainder-final.sh"` | 0 | Corrected read-only evidence root; remaining native guards, catalogs, documentation and whitespace checks passed. | `$PR136_EVIDENCE_ROOT/lint-remainder-final.sh; lint-remainder-final.log` |
| `rtk proxy "$PR136_EVIDENCE_ROOT/tools/ruff" check --no-cache ci/tools/canonical_maintenance.py ci/checks/security/check-ci-security-contract.py tests/ci_security` | 0 | Lint passed. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy "$PR136_EVIDENCE_ROOT/tools/ruff" format --check ci/tools/canonical_maintenance.py ci/checks/security/check-ci-security-contract.py tests/ci_security` | 0 | 25 files passed formatting. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy "$ACTIONLINT_BIN" .github/workflows/check-common-versions.yml` | 0 | Workflow passed. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy env TMPDIR="$PR136_TMP_ROOT" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 make check-documentation PYTHON="$FRAMEWORK_PYTHON" FRAMEWORK_ROOT="$PR136_ROOT" BUILD_ROOT="$PR136_DOC_BUILD_ROOT" TMP_ROOT="$PR136_DOC_TMP_ROOT"` | 0 | Four documentation checks passed. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy git ls-remote --tags https://github.com/coreruleset/coreruleset.git 'refs/tags/v4.30.0' 'refs/tags/v4.30.0^{}'` | 0 | Tag peeled to approved CRS commit. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy git ls-remote --tags https://github.com/aws/aws-lc.git 'refs/tags/v5.11.0' 'refs/tags/v5.11.0^{}'` | 0 | Tag matches approved AWS-LC commit. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |
| `rtk proxy curl -fsSL --max-time 30 -o "$PR136_EVIDENCE_ROOT/crs-rule.conf" https://raw.githubusercontent.com/coreruleset/coreruleset/e03a4f6dabc7a30ebd8c52c97d28a154f590a48f/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf` | 0 | Exact-commit rule downloaded. | `$PR136_EVIDENCE_ROOT/crs-rule.conf` |
| `rtk proxy sha256sum "$PR136_EVIDENCE_ROOT/crs-rule.conf"` | 0 | Expected 8dadc742af2bb6b7e5b48570cb0201930cd9cfe9e3de94776e736605ea7be228 verified. | `$PR136_EVIDENCE_ROOT/crs-rule.conf` |
| `rtk proxy git diff --check` | 0 | Whitespace review passed. | `$PR136_ROOT/.codex/plans/pr136-ci-repair.md` |

## Security impact

No security remediation; existing controls remain active. The additional gate
prevents publication of an invalid candidate.

## Documentation and runtime evidence

This paired record documents the correction. No new connector or lifecycle
runtime evidence is collected or inferred.

## Checks not run

Local Pyright cannot run because Node.js is unavailable. CI runs Pyright using
canonical Node.js. Local Python is 3.14.7; CI checks independently with canonical
Python 3.14.8.

## Limitations and residual risk

The full native lint run exposed the missing catalog after passing its earlier
targets. After regeneration, the API target and the resumed native checks pass;
the affected CI-security target also passes all 313 tests against the final correction.
New PR-head CI remains pending at commit preparation. The maintenance allowlist
adds only the derived catalog. Manual
test/record edits remain outside it. No merge or Parent gitlink update is
authorized.

## Final diff and review status

The final scoped diff and exact reviewed workflow hashes were independently
reviewed without material findings. Whitespace, documentation and relevant local
checks pass. The correction is prepared as a normal follow-up commit for PR #136;
fresh head-bound CI evidence will be reconciled in the PR and execution plan.
No secrets or raw sensitive material were recorded in this Change Record.
