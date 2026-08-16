# Change record: 20260816-06-fix-codeql-action-release-resolution

**Language:** English | [Deutsch](20260816-06-fix-codeql-action-release-resolution.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260816-06-fix-codeql-action-release-resolution` |
| UTC date | `2026-08-16` |
| Framework base revision | `f583bbfd74f8e0e76f0a65378702cbbaad77e7d8` |
| Issue or pull request | Resulting-master workflow run `31975000540`; no pull-request or commit result is established by this record. |

## Motivation and problem statement

The resulting-master `Check common.sh versions` run failed in the canonical
maintenance resolver with exit code 2. The observed CodeQL source was
`github/codeql-action/releases/latest`, whose response identified a CodeQL
bundle (`codeql-bundle-v2.26.3`) rather than a numeric Action release tag. The
generic stable-Action parser consequently could not produce a supported
`latest_upstream` Action release and the fail-closed resolver stopped the
maintenance plan.

## Affected components and security boundaries

The affected Framework components are the canonical maintenance resolver and
the lock-aware workflow-tool updater. The relevant boundary is trusted CI
maintenance consuming official GitHub release metadata and resolving an
automatically selected same-major Action tag to an immutable commit. Parent,
connector runtime, and
the read-only `tools/MRTS` checkout are outside scope.

## Acceptance criteria

1. CodeQL `latest_upstream` is sourced from one bounded official release page,
   not from the bundle-prone `releases/latest` endpoint.
2. Only published, non-prerelease, numeric Action tags are selectable.
3. Same-major CodeQL updates remain automatic when the compatible tag is
   valid; a newer major is reported for manual review only.
4. An automatically selected same-major tag is resolved through the Git API
   and its immutable commit identity remains validated; a cross-major result
   is review metadata only.
5. Non-CodeQL Action resolution and fail-closed behavior remain unchanged.

## Alternatives considered

- Continuing to parse `releases/latest` was rejected because the observed
  response is a CodeQL bundle, not an Action release.
- Treating a bundle tag as an Action version was rejected because it would
  weaken the Action provenance and immutable-pin contract.
- Automatically applying a new major was rejected; the existing policy
  requires manual review for a major transition.
- Removing CodeQL from canonical maintenance was rejected because every
  canonical CI pin must remain in the shared maintenance plan.

## Implementation decision

The updater adds a bounded release-page selection for the newest stable
numeric Action tag across majors. Canonical maintenance uses that selection
only for CodeQL's upstream comparison, while retaining the existing
same-major release selection for automatic compatible updates. Only an
automatically selected same-major tag continues through the existing Git API
tag-to-commit and immutable-commit validation; the cross-major result is
recorded for manual review and is not applied. Bundle tags, malformed or
prerelease tags, and a new major remain excluded from automatic application.
Runtime validation also binds `github/codeql-action` to
`same-major-release` and rejects a malformed `latest-release` lock.

## Changed files and tests

This task changes the canonical resolver, updater, focused regression tests,
paired security guide, and paired Change Record:

- `ci/tools/canonical_maintenance.py`;
- `ci/tools/update-workflow-tools.py`;
- `tests/ci_security/test_canonical_maintenance.py`; and
- `tests/ci_security/test_update_workflow_tools.py`;
- `docs/security/ci-security-tooling.md`;
- `docs/security/ci-security-tooling.de.md`;
- `reports/audits/change-records/20260816-06-fix-codeql-action-release-resolution.md`; and
- `reports/audits/change-records/20260816-06-fix-codeql-action-release-resolution.de.md`.

The focused tests cover rejection of bundle and malformed/non-numeric release
tags, selection of a newer numeric major for review, continued same-major
automatic updates, immutable commit confirmation, and rejection of a malformed
CodeQL `latest-release` lock.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `gh run view 31975000540 --repo Easton97-Jens/ModSecurity-test-Framework --json headSha,jobs,conclusion` | `0` | The resulting-master run at `f583bbfd74f8e0e76f0a65378702cbbaad77e7d8` failed in `canonical-maintenance` while resolving mandatory scopes with exit code 2. | [Run 31975000540](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31975000540) |
| `env PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.ci_security.test_update_workflow_tools tests.ci_security.test_canonical_maintenance` | `0` | 43 focused updater and canonical-maintenance tests passed in the hash-locked task environment. | Framework task worktree |
| `env PYTHONDONTWRITEBYTECODE=1 ./ci/tools/safe-make.sh check-documentation` | `0` | Documentation links, bilingual variable/path references, and Change Record contracts passed. | Framework task worktree |
| `env PYTHONDONTWRITEBYTECODE=1 ./ci/tools/safe-make.sh lint` | `0` | Full lint passed with canonical, workflow, documentation, provenance, and CI-security/contract coverage. | Task-owned external validation root |
| `git diff --check -- docs/security/ci-security-tooling.md docs/security/ci-security-tooling.de.md reports/audits/change-records/20260816-06-fix-codeql-action-release-resolution.md reports/audits/change-records/20260816-06-fix-codeql-action-release-resolution.de.md` | `0` | No whitespace errors in the changed documentation and record files. | Framework task worktree |

## Security impact

The change preserves the supply-chain boundary: only official numeric Action
tags are candidates, and an automatically selected same-major tag is bound to
its immutable commit. A cross-major tag is review metadata only. No new GitHub
permission or credential is introduced. A malformed, bundled, or unverifiable
release remains a fatal or manual-review outcome. No security control is
weakened.

## Documentation and runtime evidence

The English and German security guides now document the observed bundle-valued
endpoint response, the bounded release-page source, the same-major automatic
path, immutable commit validation, manual review for a new major, and the
runtime binding to `same-major-release`. Run `31975000540` is observed
runtime/lifecycle failure evidence only; it does not
prove a successful corrective hosted run, a pull-request result, a merge, or
any SonarQube Cloud result.

## Checks not run

- Hosted pull-request checks and SonarQube Cloud analysis remain pending for
  the task's delivery phase; the full Framework lint and scoped security
  review passed locally.
- No new master dispatch was performed after the corrective working-tree
  change.

## Limitations and residual risk

The correction remains unverified until the owning implementation validation
and a fresh hosted run demonstrate that the canonical maintenance workflow
completes successfully. SonarQube Cloud must independently report Quality Gate
passed with 0 new issues and 0.0% duplication on new code before any merge.

## Final diff and review status

The final diff includes only the eight Framework-owned paths listed above. No
secrets, tokens, raw response bodies, or complete logs are recorded. The
working-tree changes are unstaged and uncommitted at this record update; no
push, pull request, merge, Parent gitlink update, or MRTS action has occurred.
