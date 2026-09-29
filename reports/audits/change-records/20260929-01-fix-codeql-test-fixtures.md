# Change record: isolate CodeQL release test fixtures

**Language:** English | [Deutsch](20260929-01-fix-codeql-test-fixtures.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260929-01-fix-codeql-test-fixtures |
| UTC date | 2026-09-29 |
| Framework base revision | 6df30cc261b6033c1498f9d035fe4e7771c14a4a |
| Issue or pull request | [PR #122](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/122) |

## Motivation and problem statement

PR #122 updates the production CodeQL Action pin to v4.38.1. Four resolver
tests use fixed release pages around v4.38.0 while reading their baseline
from the moving production lock. Three of those tests consequently reach
the stale-release guard instead of their intended validation branch.

## Affected components and security boundaries

The change is confined to `tests/ci_security/test_update_workflow_tools.py`
and this paired record. No production resolver, workflow, dependency pin,
permission, publisher allowlist, or connector behavior changes.

## Acceptance criteria

The four synthetic release-page tests use a coherent, test-owned baseline.
The baseline helper does not mutate the loaded lock and remains independent
of simulated production versions v4.38.1, v4.99.0, and v5.0.0. A release page
older than the fixture is still rejected before release confirmation.
Full-suite and PR-check success remain to be demonstrated by CI.

## Alternatives considered

Downgrading the production pin or weakening the stale-release guard would
hide the test defect. Repeatedly raising hard-coded release-page versions
would break again after future maintenance updates. A copied fixture keeps
the existing production policy fields without sharing mutable test state.

## Implementation decision

Add `codeql_release_fixture`, which copies the loaded CodeQL record and
sets its version, commit, and release URL together through the existing
`changed_action` helper. Use the fixture only in the four synthetic
release-page tests. Preserve all existing assertions and production guards.

## Changed files and tests

`tests/ci_security/test_update_workflow_tools.py` adds the fixture and two
regression tests: `test_codeql_release_fixture_is_independent_and_does_not_mutate_lock`
and `test_codeql_resolver_still_rejects_a_stale_release_page`. Four existing
tests now obtain their baseline from the fixture. This record and its
German partner document the same scope and verification limits.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Python `compile` and `ast.parse` on the three added methods | 0 | Syntax accepted; two added regression tests identified; not a test-suite run | Not applicable |
| `git apply --numstat` on the prepared fix patch | 0 | Test-file patch has 62 additions and 8 deletions; no applicability claim | Not applicable |
| `git ls-remote` for the PR branch | 128 | Local network could not resolve github.com; repository reads and publication use the GitHub connector | Not applicable |

## Security impact

No security remediation was performed. The stale-page, same-major,
immutable-release, draft, and tag-consistency checks are not weakened.
The new negative regression test covers rejection before confirmation;
its execution is not claimed by the syntax check.

## Documentation and runtime evidence

The English and German change records are added together. No generated
report, runtime evidence, host build, or connector lifecycle result is
changed or claimed.

## Checks not run

`make test-ci-security-contract`, `make lint`, `make check-change-records`,
`make check-documentation`, `make check-bilingual-docs`, `make check-doc-links`,
and full-worktree `git diff --check` were not run locally because a complete
checkout was unavailable after the GitHub DNS failure. CI results must be
read for the new PR head rather than inferred from the prepared patch.

## Limitations and residual risk

This commit implements only the prepared CodeQL test fix. AWS-LC automatic
maintenance remains a separate, unimplemented task. The PR remains a draft;
no merge or auto-merge is authorized. The automated publisher's existing
scope checks remain intact and may reject reusing a manually extended
maintenance branch; no bypass is introduced.

## Final diff and review status

The intended delta is the prepared test-file patch plus this paired record.
Publication must preserve the current PR history and use a non-forced
fast-forward. There is no full local staged or unstaged diff. The added
methods were inspected for whitespace and secrets; no credentials or raw
runtime data are included. GitHub commit-diff and PR-head readback are the
publication checks; full CI success is not asserted in this record.
