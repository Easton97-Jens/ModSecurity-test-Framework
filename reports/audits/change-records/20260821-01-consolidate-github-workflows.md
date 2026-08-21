# Change record

**Language:** English | [Deutsch](20260821-01-consolidate-github-workflows.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260821-01-consolidate-github-workflows` |
| UTC date | 2026-08-21 |
| Framework base revision | `bd69ee96e0e7082317d4afe1232bee625665eb9a` |
| Issue or pull request | [Framework Draft PR #101](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/101) to `master`; hosted rerun pending the follow-up repair |

## Motivation and problem statement

Seventeen Framework workflows contained repeated hash-locked CI dependency
bootstrap steps, while their workflow semantics are intentionally distinct.
This change removes only the exact shared bootstrap implementation and retains
the surrounding workflow wrappers. A static review also found two maintenance
availability hardening gaps: public GitHub issue data was accumulated without
explicit byte budgets, and an existing MRTS maintenance PR was matched without
an explicit first-party head-repository identity check.

## Affected components and security boundaries

- `.github/workflows/`: untrusted PR boundaries, trusted maintenance jobs,
  immutable action pins, permissions, event filters, and stable check names.
- `ci/tools/install-hash-locked-ci-dependencies.sh`: shared locked CI package
  installation and `pip check` boundary.
- `ci/tools/reconcile-common-version-review-issues.py`: public GitHub issue
  metadata to trusted reconciliation boundary.
- `.github/workflows/update-submodules.yml`: GitHub PR metadata to trusted
  first-party maintenance-branch reuse boundary.
- `ci/checks/security/check-ci-security-contract.py` and
  `tests/ci_security/`: executable regression controls for both changes.

Parent source and gitlink are unchanged. MRTS source, revision, branch, and
gitlink are read-only and unchanged.

## Acceptance criteria

1. All 17 source workflows are audited and retain their intended behavior.
2. Only exact, behavior-compatible dependency-bootstrap duplication is shared;
   no whole workflow is deleted or merged.
3. The helper remains hash-locked, fails on unexpected arguments, and is bound
   by the CI security contract.
4. Public issue reconciliation has explicit per-response, aggregate-byte, and
   retained-item bounds with failure before unsafe aggregation.
5. Existing MRTS maintenance PR matching requires the fixed branch and the
   exact first-party `GITHUB_REPOSITORY` identity.
6. Relevant local checks pass, and unavailable hosted validation remains
   explicit rather than represented as a pass.

## Alternatives considered

- Merge or delete similar workflows: rejected. The 17 workflows differ in
  event/trust model, permissions, artifacts, publishing gates, or required
  checks. In particular, CodeQL PR analysis and trusted security upload remain
  separate.
- Extract maintenance publisher bodies: rejected. Their reviewed job profiles,
  token scope, and contract hashes are intentionally strict and nonidentical.
- Add a token to `update-workflow-tools.yml` to avoid a historical rate limit:
  rejected. The standalone resolver is deliberately credential-free; this is
  an operational limitation requiring a separate security review, not a safe
  opportunistic workflow change.
- Match PRs only by owner-qualified CLI query: not sufficient alone. The chosen
  solution requests and validates first-party head metadata explicitly and
  fails closed when it is absent or mismatched.

## Implementation decision

Added `ci/tools/install-hash-locked-ci-dependencies.sh`, which resolves the
Framework root, accepts no arguments, runs the existing
`requirements-ci.lock` installation with `--require-hashes`, and runs
`python3 -m pip check`. Eight ordinary/read-only workflows now call it, keeping
their previous visible step names and adding it to relevant path filters.
Strict maintenance publisher workflows retain their inline bootstrap because
their full reviewed profiles are intentionally distinct.

The `ci-security-osv.yml` trusted `pull-request-head` job also deliberately
retains its reviewed inline bootstrap: it checks out the trusted PR **base**
revision, where a helper introduced only by the PR head is unavailable and
must not be fetched into that job. Its current-default-branch advisory job
uses the helper. Hosted PR #101 run `32436667389` proved this availability
constraint with an initial exit 127; the follow-up contract regression guard
now rejects helper use in the trusted-base job.

The security contract binds the helper by SHA-256 and requires the expected
per-workflow invocation counts. It also binds the submodule publisher profile
after adding an explicit `headRefName`, `headRepository`, and
`headRepositoryOwner` filter.

Issue reconciliation now caps one GitHub response at 1,000,000 bytes,
accumulated issue payloads at 16,000,000 bytes, and retained issues at 25,600;
all limits fail closed. No token, permission, trigger, branch filter,
artifact, retention, check name, CodeQL separation, Parent gitlink, or MRTS
source was changed.

## Changed files and tests

| Workflow | Decision | Preserved behavior / validation |
| --- | --- | --- |
| `check-action-versions.yml` | helper-only | PR/push filters and action/version contract checks remain. |
| `check-common-versions.yml` | audited, unchanged | Unique trusted maintenance/reconciliation/publisher profile remains inline. |
| `check-python-version.yml` | audited, unchanged | Unique candidate and draft-PR publisher profile remains inline. |
| `ci-security-codeql-pr.yml` | audited, unchanged | Untrusted PR analysis remains separate from trusted upload. |
| `ci-security-codeql.yml` | audited, unchanged | Trusted push/schedule security upload remains separate. |
| `ci-security-dependency-review.yml` | audited, unchanged | Unique dependency-review action behavior remains. |
| `ci-security-osv.yml` | helper + trusted-base inline | The trusted PR-base job retains its inline bootstrap; the default-branch advisory job uses the helper. |
| `ci-security-quality.yml` | helper-only | Ruff and hosted Pyright quality gate remain. |
| `ci-security-scorecard.yml` | helper-only | PR/current-head and advisory behavior remain. |
| `ci-security-secrets.yml` | helper-only | PR-diff and full-history Gitleaks behavior remain. |
| `ci-security-workflow-lint.yml` | helper-only | actionlint, ShellCheck, zizmor, and CI-security test gates remain. |
| `cleanup-artifacts.yml` | audited, unchanged | Its unique `actions: write` cleanup permission remains scoped. |
| `five-connectors-with-crs-no-mrts-contract.yml` | helper-only | Portable no-MRTS contract remains read-only. |
| `lint.yml` | helper-only | Framework lint target and check name remain. |
| `test-common.yml` | audited, unchanged | Case materialization and runner outputs remain independent. |
| `update-submodules.yml` | hardened | First-party PR head identity is now explicit; only `tools/MRTS` gitlink maintenance semantics remain. |
| `update-workflow-tools.yml` | audited, unchanged | Credential-free standalone resolver remains; historical API rate limiting is documented. |

Added or updated tests:

- `tests/ci_security/test_ci_security_contract.py`: helper digest/reference,
  trusted-base OSV inline-bootstrap, and first-party PR identity negative
  controls.
- `tests/ci_security/test_common_version_review_reconciler.py`: oversized
  response, aggregate-byte/count, and ordinary-page controls.
- `tests/ci_security/test_five_connector_with_crs_no_mrts_contract.py`: shared
  helper lock and `pip check` assertions.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Locked `pip install --require-hashes -r requirements-ci.lock` | 0 | Existing locked `PyYAML==6.0.3` satisfied. | Task evidence archive `workflow-consolidation-20260820` (retained outside this repository). |
| `python -m pip check` | 0 | No broken requirements. | Same retained task-evidence archive. |
| `actionlint -shellcheck=… .github/workflows/*.yml` | 0 | All workflow YAML and shell steps pass. | Same retained task-evidence archive. |
| `zizmor --offline .github` | 0 | No reportable findings; configured suppressions retained. | Same retained task-evidence archive. |
| Unsafe zizmor fixture | 14 (expected) | Dangerous-trigger/template-injection control was rejected. | Same retained task-evidence archive. |
| Ruff check and format check for CI scope | 0 | Clean after formatting the touched Python files. | Same retained task-evidence archive. |
| `python -m unittest discover -s tests/ci_security -q` | 0 | 286 tests passed. | Same retained task-evidence archive. |
| `ci/checks/security/check-ci-security-contract.py --root .` | 0 | CI security contract passed. | Same retained task-evidence archive. |
| `ci/checks/security/check-github-actions-workflows.py --check all` | 0 | All 17 source workflows pass pins and permissions checks. | Same retained task-evidence archive. |
| `ci/checks/security/check-workflow-action-pins.py` | 0 | All external actions use full commit SHAs. | Same retained task-evidence archive. |
| `ci/tools/safe-make.sh lint` | 0 | Full Framework lint and its broader regression/documentation checks passed. | Same retained task-evidence archive. |
| `bash ci/tools/install-hash-locked-ci-dependencies.sh unexpected-argument` | 2 (expected) | Helper rejected arguments before package work. | Same retained task-evidence archive. |
| Hosted PR #101 OSV `pull-request-head` initial run | 127 | Trusted-base checkout could not see the PR-head helper; the narrow inline-bootstrap repair is pending a new exact-head run. | [Run 32436667389](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/32436667389) |

## Security impact

The reconciliation remediation has a confirmed source-to-sink resource-boundary
gap: public issue bodies and page results reached in-memory aggregation for a
trusted maintenance job without explicit byte limits. The original unsafe
boundary is covered by targeted oversized-response and aggregate controls; a
normal one-page control remains accepted. The source fix, focused tests,
complete CI-security suite, and Framework lint pass locally. It remains
`fixed` locally pending exact-PR-head hosted evidence and resulting-master
reproduction.

The PR-head identity repair is security hardening for a plausible
availability/correctness collision. Source and contract mutation tests prove
the new control; no live fork-query reproduction was claimed. An independent
read-only final-diff security review found no high, critical, or
release-blocking defect.

The hosted OSV regression confirms that a trusted-base job must not acquire a
PR-head helper merely to share setup. The repair preserves the original
reviewed inline bootstrap and fails the security contract if that job invokes
the helper; no token, checkout expansion, or trust-boundary change is used.

## Documentation and runtime evidence

This English Change Record and its complete German companion document the
workflow matrix, security boundary, validation, limitation, and rollback.
The sealed prompt-only Codex Security scan is retained outside this repository
as task-evidence artifact `workflow-consolidation-20260820-security-scan`.
Its sealed snapshot predates one warning-only `CDPATH=''` ShellCheck portability
clarification in the shared helper and the matching contract-digest update; it
was not retroactively rewritten. The final source snapshot and its focused
post-scan controls are retained as task-evidence artifact
`workflow-consolidation-20260820-post-security-scan-validation`
(SHA-256 `7494c2b5b1b7fd785a5e60b72917172aaae9e5c5c928fd3873ccc1dff403a1ae`).
`bash -n`, ShellCheck, CI-contract/workflow/pin checks, focused Ruff, and the
286-test CI-security suite passed on that final source snapshot. The broader
`safe-make.sh lint` pass preceded this syntax-only correction and is reported
at that exact scope rather than as a final-snapshot claim.
No connector runtime, production service, Parent change, or MRTS runtime claim
is made.

## Checks not run

- Local Pyright was not run because Node.js is unavailable (`node --version`
  exited 1). The locked hosted quality workflow remains required for PR
  readiness.
- Hosted PR #101 checks started on the initial exact head. Its OSV
  `pull-request-head` job failed exit 127 because the trusted-base checkout
  lacked the PR-head helper; a narrow local repair is complete. A replacement
  exact-head hosted rerun remains required after the original Change Record
  used non-portable task-local evidence paths that Framework lint rejected.
  SonarQube Cloud and a live fork-collision scenario also remain pending/not
  run.
- No maintenance workflow was manually dispatched because PR-triggered checks
  cover the changed read-only paths and no token-bearing maintenance action is
  needed for local validation.

## Limitations and residual risk

The standalone workflow-tool resolver can still be rate-limited by GitHub's
unauthenticated API quota. Exposing a token would change its reviewed
credential boundary and is intentionally outside this change. The new
first-party PR filter prevents a metadata collision conservatively; hosted
GitHub behavior still needs current-head validation. The helper's hash binding
is a post-execution contract control under the existing pull-request workflow
trust model, not an independent review-before-execution mechanism.

## Final diff and review status

The initial Framework-only diff was reviewed with `git diff --check`, exact-
path staging preparation, and a secret-candidate review. The hosted OSV
failure requires a separately reviewed follow-up commit and full current-head
validation. The Parent worktree, Parent gitlink, and MRTS state remain
unchanged. Delivery remains one Draft PR to `master`; no merge, force push,
settings change, or default-branch change is authorized.
