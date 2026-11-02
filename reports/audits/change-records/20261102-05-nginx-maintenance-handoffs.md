# NGINX maintenance handoffs

[Deutsch](20261102-05-nginx-maintenance-handoffs.de.md)

## Identity

| Change ID | `20261102-05-nginx-maintenance-handoffs` |
| --- | --- |
| UTC date | 2026-11-02 |
| Framework base | `1b0885a2aa9b91b3faad76de6df8250bf8147eef` |
| PR | Created separately after commit; no merge authorized. |

## Motivation and problem statement

Canonical common.sh selected NGINX 1.31.8 while ordinary handoffs still required 1.31.6, blocking candidate validation and current runtime consumers.

## Affected components and security boundaries

Framework exact-head composite, runtime provisioning/readiness and current exact-head evidence/broker consumers. Preserve immutable historical root-broker 1.31.4 and historical I12 evidence. Parent changes and gitlink updates remain separate; MRTS unchanged.

## Acceptance criteria

Ordinary consumers agree with canonical 1.31.8 and archive digest `0652b760b3b772d2ec17b47c2fc15d9a95e6fe35cd5b877eadc1a62d9bc75af1`; generation is idempotent and preserves file modes; raw-wrapper verification covers both checkout/selection directions and rejects wrong pins/missing blobs.

## Alternatives considered

Hand-editing every future version projection was rejected because maintenance could recreate the conflict. Disabling provenance checks was rejected.

## Implementation decision

Extend the existing static runtime synchronizer with a closed set of current NGINX handoff outputs and include these views in canonical maintenance. Preserve existing mode on atomic output replacement. Candidate data remains non-executable in verifier regression fixtures; trusted parser comes from the Parent committed gitlink.

## Changed files and tests

Changed `ci/tools/sync-runtime-components.py`, `ci/tools/canonical_maintenance.py`, seven current handoff outputs, current pin fixture tests and focused synchronizer/Git-context regressions. Regenerated inventory source digests and the on-demand archive through their native generator. Added this EN/DE record; default selection unchanged.

## Commands and results

Framework cwd: `/var/tmp/codex/ModSecurity-conector/worktrees/fix-framework-nginx-maintenance-pins`.
Interpreter: `/var/tmp/codex/ModSecurity-test-Framework/venv/bin/python`.
All commands use `rtk bypass`; `PYTHONDONTWRITEBYTECODE=1`.

- `python ci/tools/sync-runtime-components.py --check`: initially exit 1, identified stale ordinary handoffs; after generation exit 0.
- `python ci/tools/sync-runtime-components.py --write`: exit 0; repeated generation byte-idempotent.
- `python -m unittest tests.security_regression.test_runtime_component_sync -v`: exit 0, 20 tests; mode-preservation assertion rerun after review, exit 0.
- `python -m unittest tests.ci_security.test_canonical_maintenance.CanonicalMaintenanceTests.test_maintenance_test_views_follow_catalog_after_crs_views_in_both_modes -v`: exit 0, 1 test.
- `python ci/tools/generate-framework-contract-catalog.py --check`: exit 0.
- `python ci/tools/sync-maintenance-test-views.py --write --root /var/tmp/codex/ModSecurity-conector/worktrees/fix-framework-nginx-maintenance-pins`: exit 0; source bindings and archive regenerated without adding default cases.

- `python ci/tools/sync-maintenance-test-views.py --check --root /var/tmp/codex/ModSecurity-conector/worktrees/fix-framework-nginx-maintenance-pins`: exit 0.
- `python ci/checks/documentation/check-change-records.py`: exit 0.
- `python ci/checks/documentation/check-doc-links.py`: exit 0.
- `python ci/checks/documentation/check-variable-documentation.py`: exit 0, 374 pairs.
- `git diff --check`: exit 0.

Connector tests use explicit `CONNECTOR_ROOT=/var/tmp/codex/ModSecurity-conector/worktrees/fix-submodule-candidate-context`, `CONNECTOR_REVISION=a18ffca3b5bb54887c0b8859ece95478e83cf262`, `TEST_ROOT` and `FRAMEWORK_ROOT` equal to the Framework cwd, `PYTHONPATH` equal to that cwd plus its `/connector_suite`, and `ON_DEMAND_TESTS=1`.

- `python -m unittest modsecurity_connector_tests.test_verify_framework_candidate_contract.VerifyFrameworkCandidateGitContextTests modsecurity_connector_tests.test_verify_framework_candidate_contract.VerifyFrameworkCandidateContractTests.test_checked_out_framework_common_passes_the_data_contract -v`: exit 0, 5 tests against the separate Parent verifier repair.
- `python -m unittest modsecurity_connector_tests.test_nginx_functional_evidence -v`: exit 0, 11 tests. Initial run exposed a stale job-level env lookup; corrected to inspect the single source-owned composite step handoff.
- `python -m unittest modsecurity_connector_tests.test_nginx_exact_head_result_collector.CollectorPinContractTests modsecurity_connector_tests.test_nginx_exact_head_result_collector.CollectorTests.test_rejects_previous_release_and_crossed_runtime_pins modsecurity_connector_tests.test_nginx_exact_head_root_launcher.RootLauncherContractTests.test_rejects_previous_release_and_crossed_candidate_pins -v`: exit 0, 3 tests.


## Security impact

Existing source repository, archive digest, provenance flags and failure behavior remain enforced. Negative tests preserve rejection of crossed pins, wrong revisions, missing Git blobs, duplicate assignments and candidate Python execution. No new CI permissions or historical broker authority.

## Documentation and runtime evidence

Only this record pair is new reader-facing documentation. No host-runtime or lifecycle execution evidence was produced.

## Checks not run

Full test discovery, connector builds, host runtime, I12/matrices and remote Quality Gate were not run locally: outside focused repair scope. Ruff unavailable in the Framework venv (`python -m ruff --version`, exit 1); no package installed.

## Limitations and residual risk

Parent integration requires its separate repair and pin update. Git-object tests validate the verifier data boundary, not hosted runtime readiness. GitHub current-head checks remain delivery evidence to inspect after push.

Hosted lint and action-version checks on initial head585bf6e identified the exact-head action whole-source migration digest and a redundant copied canonical URL. Authenticated the previous single source entry against the base commit, renewed exactly that action digest in `ci/tooling/connector-actions.lock.json` and its aggregate in `ci/checks/security/connector_action_pins.py`; preserved registry, action records and authority. This maintained snapshot has no checked-in generator. Replaced the duplicate URL literal with a SHA-256 trust anchor. `rtk bypass env PYTHONDONTWRITEBYTECODE=1 /var/tmp/codex/ModSecurity-test-Framework/venv/bin/python ci/tools/check-common-versions.py --validate-canonical` passed; `python -m unittest tests.ci_security.test_connector_action_pins -v` passed6 tests;2 focused synchronizer cases passed. The immutable snapshot gate still requires separate review when future maintenance changes composite source bytes.

Current-head CI authority tests rejected automatic publication of the integration composite. Kept its existing read-only publisher boundary: generator/rollback still cover the action, but native automatic publication excludes it. Explicit reviewed maintenance must renew the source snapshot as above. `python -m unittest tests.ci_security.test_canonical_maintenance.CanonicalMaintenanceTests.test_native_workflow_publisher_outputs_have_exact_transaction_authority -v` passed after correction.

## Final diff and review status

Final scoped diff reviewed; no secrets or raw sensitive logs recorded. Review caught atomic mode loss and the focused regression now covers mode preservation. No Parent/MRTS edits or merge.
