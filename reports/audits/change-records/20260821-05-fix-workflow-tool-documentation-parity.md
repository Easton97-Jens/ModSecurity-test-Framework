# Change record

**Language:** English | [Deutsch](20260821-05-fix-workflow-tool-documentation-parity.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260821-05-fix-workflow-tool-documentation-parity` |
| UTC date | 2026-08-21 |
| Framework base revision | `473d2adad32e2db19e24e2339d9eb392040ab226` |
| Issue or pull request | `FND-FRAMEWORK-0110`; Framework PR #105 |

## Motivation and problem statement

The trusted canonical maintenance candidate reached its native updater check,
but the two generators serialized Action-table version and immutable-commit
cells differently. Canonical maintenance used plain Markdown cells while the
native helper emitted backticks. The fail-closed byte comparison correctly
stopped the candidate before publication at the German generated view.

## Affected components and security boundaries

- `ci/tools/update-workflow-tools.py`: native serialization of Action-table
  cells, including compatibility with historical backticked cells.
- `tests/ci_security/test_update_workflow_tools.py`: native/canonical parity
  and deliberate German-view mismatch coverage.
- `docs/github-actions-workflow-security.md` and `.de.md`: remove stale claims
  about a retired standalone publisher without editing generated pin rows.

The candidate SHA binding, isolated `RUNNER_TEMP` proposed tree, byte-for-byte
comparison, publisher allowlist, App-token boundary, and Draft-PR checks are
security-relevant and remain unchanged.

## Acceptance criteria

1. Canonical and native derivations emit byte-identical English and German
   Action-table views for the same valid Action candidate.
2. A changed German view still fails closed with its exact path before any
   publisher action.
3. Historical backticked cells are accepted as input and normalized to the
   canonical plain-cell output.
4. Repository-native updater, contract, workflow, pin, documentation, and
   diff checks pass before delivery.
5. Current-head hosted PR checks, including the SonarQube Cloud Quality Gate,
   are observed; the resulting-master dispatch is then observed separately
   after explicitly authorized integration.

## Alternatives considered

- Removing or relaxing the byte comparison was rejected because it would allow
  canonical and native generators to diverge before a privileged publisher.
- Changing canonical output to backticks was rejected because canonical output
  is the established generated representation.
- Normalizing only one documentation language was rejected because both views
  are part of the same constrained output surface.

## Implementation decision

The native updater now writes the canonical plain-cell representation. It still
recognizes historical backticked cells and converts only a matched Action row
to that same representation. No mutable path inventory, validation input,
release provenance rule, or publishing behavior changes.

## Changed files and tests

- `ci/tools/update-workflow-tools.py`
- `tests/ci_security/test_update_workflow_tools.py`
- `docs/github-actions-workflow-security.md`
- `docs/github-actions-workflow-security.de.md`
- this paired Change Record

The new regression first generated canonical output from an updated
`ci/lib/common.sh`, then required exact native/canonical equality for both
documentation views. It also changes only the German generated row and proves
that the exact comparison still rejects it. The existing paired-documentation
test additionally exercises historical backticked input.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy …python -m unittest …test_canonical_generated_candidate_matches_native_documentation_views` | 1 | Pre-fix regression reproduced the expected German-view byte mismatch. | Local task worktree; original hosted failure `32517027013` |
| `rtk proxy …python -m unittest …test_canonical_generated_candidate_matches_native_documentation_views` | 0 | Post-fix parity and deliberate German mismatch control passed. | Local task worktree |
| `rtk proxy …python -m unittest tests.ci_security.test_update_workflow_tools` | 0 | 41 updater tests passed, including paired plain/backtick compatibility. | Local task worktree |
| `rtk proxy …python -m unittest tests.ci_security.test_sync_canonical_workflow_pins` | 0 | 12 canonical-generator tests passed. | Local task worktree |
| `rtk proxy …python -m unittest tests.ci_security.test_unified_common_maintenance_workflow tests.ci_security.test_ci_security_contract` | 0 | 47 workflow-topology and CI-security-contract tests passed. | Local task worktree |
| `rtk proxy …python -m unittest discover -s tests/ci_security -q` | 0 | Final full CI-security suite: 287 tests passed. | Local task worktree |
| `rtk proxy …python ci/tools/sync-canonical-workflow-pins.py --check --root .` | 0 | Canonical generated views have no drift. | Local task worktree |
| `rtk proxy …python ci/checks/security/check-github-actions-workflows.py --check all` | 0 | All 16 workflow metadata, pin, and permission checks passed. | Local task worktree |
| `rtk proxy …python ci/checks/security/check-workflow-action-pins.py` | 0 | Every external workflow Action is SHA-pinned. | Local task worktree |
| `rtk proxy …python ci/checks/security/check-ci-security-contract.py --root .` | 0 | CI-security contract passed. | Local task worktree |
| `rtk proxy …python ci/checks/documentation/check-{doc-links,variable-documentation,repository-path-references,change-records}.py` | 0 | All four documentation and Change-Record checks passed. | Local task worktree |
| `rtk proxy …python -m py_compile ci/tools/update-workflow-tools.py tests/ci_security/test_update_workflow_tools.py` | 0 | Changed Python files compiled. | Local task worktree |
| `rtk proxy …/ruff check` and `…/ruff format --check` | 0 | Hash-locked Ruff lint and format checks passed for the updater and CI-security tests. | Task-owned external tool root |
| `rtk proxy git diff --cached --check` | 0 | Staged six-file diff has no whitespace errors. | Local task worktree |
| GitHub Actions and SonarQube Cloud on Framework PR #105 | 0 | Required current-head CI checks passed; the Quality Gate reported 0 new issues, 0 security hotspots, and 0.0% duplication on new code. | PR #105 at `459c2a25aee0908748055efb86a5cd7cc459ea2d` |

The staged diff was manually reviewed for scope and secrets; the independent
security-diff review found no publisher/control regression. The hosted
current-head checks recorded above are retained with the PR; a follow-up
documentation-only commit repeats the full current-head CI cycle before merge.

## Security impact

This is a CI-maintenance availability repair, not a bypass. The original path
was reproduced and the post-fix legitimate path passes in the focused test. A
deliberately modified German generated row remains rejected by the unchanged
byte comparison. No publisher credential, permission, checkout, or allowed
write surface was expanded.

## Documentation and runtime evidence

The English and German workflow-security guides now describe the single
canonical publisher accurately. No connector runtime behavior was changed or
tested. PR #105 hosted validation passed for its initial repair head; run
`32517027013` is retained only as the pre-fix failed-candidate evidence. The
authorized master dispatch is an additional, post-merge runtime proof.

## Checks not run

Local Pyright did not run because `node` is unavailable in this execution
environment. The documentation-only follow-up requires a fresh current-head
hosted CI/SonarQube Cloud round. The resulting-master manual dispatch cannot
run until the explicitly authorized PR integration has completed.

## Limitations and residual risk

The fix cannot by itself prove GitHub-hosted credentials, actions, or
publisher behavior. Those controls require fresh current-head hosted checks,
followed by the explicitly authorized master integration and dispatch.

## Final diff and review status

The repair PR initially contained exactly the six listed files and passed
whitespace, scope, secret, CI, SonarQube Cloud, and review checks at
`459c2a25aee0908748055efb86a5cd7cc459ea2d`. This paired documentation-only
follow-up records that evidence and requires the same exact-head verification
cycle before its protected squash merge.
