# Change record

**Language:** English | [Deutsch](20260821-05-fix-workflow-tool-documentation-parity.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260821-05-fix-workflow-tool-documentation-parity` |
| UTC date | 2026-08-21 |
| Framework base revision | `473d2adad32e2db19e24e2339d9eb392040ab226` |
| Issue or pull request | `FND-FRAMEWORK-0110`; Draft PR pending |

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
5. A current-head hosted candidate run is observed after the Draft PR; a
   resulting-master dispatch remains separate from this record until explicitly
   authorized and merged.

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

The staged diff was manually reviewed for scope and secrets; the independent
security-diff review found no publisher/control regression. Hosted current-head
evidence is recorded only after the Draft PR exists.

## Security impact

This is a CI-maintenance availability repair, not a bypass. The original path
was reproduced and the post-fix legitimate path passes in the focused test. A
deliberately modified German generated row remains rejected by the unchanged
byte comparison. No publisher credential, permission, checkout, or allowed
write surface was expanded.

## Documentation and runtime evidence

The English and German workflow-security guides now describe the single
canonical publisher accurately. No connector runtime behavior was changed or
tested. Hosted runtime evidence after this new branch is pending; run
`32517027013` is retained only as the pre-fix failed-candidate evidence.

## Checks not run

Local Pyright did not run because `node` is unavailable in this execution
environment. Hosted PR checks, SonarQube Cloud, review threads, and a
workflow-dispatch smoke run remain pending until the Draft PR exists. A
resulting-master manual dispatch cannot run until a current explicit
master-integration authorization exists and the PR is merged.

## Limitations and residual risk

The fix cannot by itself prove GitHub-hosted credentials, actions, or
publisher behavior. Those controls require current-head hosted checks, followed
by a separately authorized master integration and dispatch.

## Final diff and review status

At staging, exactly the six files listed above are included, with no unstaged
task files. Whitespace, scope, and secret review passed; the normal task-branch
commit, Draft PR, and hosted checks remain the next delivery steps.
