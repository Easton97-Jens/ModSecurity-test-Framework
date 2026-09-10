# Change record

**Language:** English | [Deutsch](20260910-01-consolidate-canonical-action-updates.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260910-01-consolidate-canonical-action-updates` |
| UTC date | 2026-09-10 |
| Framework base revision | `86451b45ae7bb7953baf9f81f2c2dad07395a808` |
| Issue or pull request | Draft PR [#116](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/116); no existing PR was modified. |

## Motivation and problem statement

Framework PRs #113 and #114 split one CodeQL release into separate generated
workflow-only Dependabot PRs. Both fail the canonical pin contract because the
source of truth is `ci/lib/common.sh`, not the generated workflow views. The
existing canonical single-Draft-PR publisher was also blocked: its proposed
tree did not regenerate a Node-derived workflow value before exact output
comparison.

## Affected components and security boundaries

- `ci/tools/update-workflow-tools.py` regenerates only the isolated proposed
  tree from the trusted canonical source before byte comparison.
- `.github/dependabot.yml` disables only routine `github-actions` version PRs;
  security updates remain outside that Dependabot version limit.
- The canonical trusted-default publisher, immutable SHA pins, fixed Draft PR,
  scoped App token, `pull_request` boundaries, and no-merge/no-force posture
  remain unchanged.

Parent and MRTS source, Gitlinks, branches, and delivery states are unchanged.

## Acceptance criteria

1. A combined Action/tool and Node runtime candidate passes the canonical
   generated-candidate validation.
2. A stale or malformed generated view remains fail-closed.
3. Routine Action releases use only the existing fixed canonical Draft-PR
   publisher, while the unrelated `pip` configuration is unchanged.
4. Workflow metadata, immutable pin, and CI-security contracts pass.
5. PRs #113 and #114 are neither merged, closed, nor otherwise mutated.

## Alternatives considered

- A Dependabot group for `github/codeql-action/**` would make one larger PR,
  but still changes generated views without `common.sh` or the lock and remains
  invalid.
- One wildcard Dependabot group would unnecessarily couple unrelated Actions
  and retains the same canonical-source defect.
- Ignoring all Dependabot updates would risk suppressing security updates.

The selected approach fixes the existing canonical publisher and suppresses
only routine Dependabot version updates with the documented zero limit.

## Implementation decision

After applying a constrained Action/tool candidate to its `RUNNER_TEMP`
proposed tree, the native helper invokes the trusted canonical synchronizer on
that tree before comparing every managed output byte-for-byte. Regression tests
now model both an Action-plus-Node plan and the canonical pre-apply snapshot.
The Dependabot configuration sets `github-actions` version concurrency to zero;
the canonical workflow remains the single fixed Draft-PR publisher. Bilingual
security/tooling documentation records the boundary.

## Changed files and tests

- `.github/dependabot.yml`
- `ci/tools/update-workflow-tools.py`
- `tests/ci_security/test_update_workflow_tools.py`
- `tests/ci_security/test_unified_common_maintenance_workflow.py`
- `docs/security/ci-security-tooling.{md,de.md}`
- `docs/github-actions-workflow-security.{md,de.md}`
- this paired Change Record

The updater regression covers canonical Action/runtime generated views; the
workflow contract test proves the routine Action publisher boundary and leaves
the `pip` limit unchanged.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `python -m unittest tests.ci_security.test_update_workflow_tools -v` | 0 | 41 updater and negative-control tests passed. | Isolated Framework worktree |
| `python -m unittest tests.ci_security.test_unified_common_maintenance_workflow -v` | 0 | 15 unified publisher/contract tests passed. | Isolated Framework worktree |
| `python ci/tools/sync-canonical-workflow-pins.py --check --root .` | 0 | Canonical generated views are current. | Isolated Framework worktree |
| `python ci/checks/security/check-github-actions-workflows.py --check all` | 0 | All 16 workflows passed static metadata/security validation. | Isolated Framework worktree |
| `python ci/checks/security/check-workflow-action-pins.py --workflow-root .github/workflows` | 0 | All external Actions remain full immutable SHAs. | Isolated Framework worktree |
| `python ci/checks/security/check-ci-security-contract.py --root .` | 0 | CI security contract passed. | Isolated Framework worktree |
| `python -m unittest tests.ci_security.test_ci_security_contract -v` | 0 | 34 CI-security-contract tests passed. | Isolated Framework worktree |
| `python -m unittest discover -s tests/security_regression -p test_workflow_action_pins.py -v` | 0 | 25 Action-pin regression tests passed. | Isolated Framework worktree |
| `python -m unittest discover -s tests/security_regression -p test_workflow_security_contract.py -v` | 0 | 9 workflow-security-contract regressions passed. | Isolated Framework worktree |
| `actionlint -color=false .github/workflows/*.yml` | 0 | All workflow syntax and expressions passed. | Isolated Framework worktree |
| `zizmor --offline .github` | 0 | No findings; 35 repository-managed suppressions. | Isolated Framework worktree |
| Native documentation link, variable, path-reference, and Change Record checks | 0 | Bilingual and traceability checks passed. | Isolated Framework worktree |
| `git diff --check` | 0 | No whitespace errors in the final local diff. | Isolated Framework worktree |

## Security impact

This is a correctness repair for a fail-closed validation path, not a security
control relaxation. The proposed tree remains private and bounded; the
synchronizer uses the trusted checked-in source and writes only inside that
tree. The byte-for-byte comparison, pinned Action requirement, token scope,
and trusted-default publishing boundary remain active. The alternate path of a
generated-view-only Dependabot PR remains rejected by canonical checks.

## Documentation and runtime evidence

English and German CI-tooling and workflow-security documentation now describe
the single routine publisher and the separate Dependabot security-update path.
Hosted run `34440400760` supplies the original failure evidence. No new hosted
execution is dispatched: before a merge, the trusted workflow deliberately
checks out `master`, so a dispatch would not test this task branch.

## Checks not run

Exact-branch hosted PR checks are pending on Draft PR #116. A later trusted
canonical maintenance run is also pending because it must use the delivered
default-branch source. `ruff` is unavailable locally and was not installed; the
full product lint suite was not completed. Historical lint run `34391779761`
concerns unrelated product files, not this workflow/updater change.

## Limitations and residual risk

Dependabot security updates are deliberately not grouped with routine version
updates and the canonical updater does not consume Dependabot security alerts.
They remain a separate alert/review path. No guarantee is made that the two
already-open external Dependabot PRs disappear; their mutation requires a
separate user authorization.

## Final diff and review status

The isolated worktree has passed the listed local checks and `git diff --check`.
Independent security-diff review found no new security finding, and
documentation checks and final scope review passed. Commit and normal Draft-PR
delivery to #116 are complete; exact-head hosted checks remain pending. No
merge, default-branch write, force push, or Parent Gitlink update is authorized.
