# Change record: Common-version Draft-PR publisher

**Language:** English | [Deutsch](20260727-01-add-common-version-draft-publisher.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260727-01-add-common-version-draft-publisher` |
| UTC date | 2026-07-27 |
| Framework base revision | `47e50e7bc43ba7a3b5bad1a9448111794f664cc0` |
| Issue or pull request | Framework Draft PR [#53](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/53), task branch `agent/common-version-native-publisher`; no merge or auto-merge is authorized. |

## Motivation and problem statement

The scheduled Common-version workflow could safely create an ephemeral candidate
but could neither publish a reviewable Draft PR nor pass its own Common-version
ShellCheck step. It needs a narrow update path that remains useful without a
separately configured secret or GitHub App credential.

## Affected components and security boundaries

The Framework workflow, its CI-security contract, `common.sh` and APXS-list
consumers are affected. This touches the CI write-authority boundary: candidate
resolution must remain read-only, while a trusted publisher may only create a
Draft PR for `ci/lib/common.sh`. Parent, MRTS source, and both Gitlinks are
outside this change.

## Acceptance criteria

- Resolver and candidate validator are token-free in source and use only
  `contents: read`.
- The publisher is schedule/manual/default-branch gated, has only
  `contents`/`pull-requests` write permission, and creates or updates one
  fixed-branch Draft PR.
- The publisher independently re-resolves a 64-character SHA-256 candidate and
  accepts only a `ci/lib/common.sh` working-tree diff.
- ShellCheck blockers are corrected without suppressions; Parent and MRTS stay
  unchanged.

## Alternatives considered

Keeping the workflow read-only cannot maintain versions through a PR. Reusing
the workflow-tool publisher's GitHub App is not an equivalent option because
the App configuration is externally missing and that publisher changes workflow
files. A PAT, direct push, broad staging, or an auto-merge would widen the
authority boundary and was rejected.

## Implementation decision

The workflow now has `resolve`, `candidate-validate`, and `publish` jobs.
Readers work only on temporary copies. The publisher re-resolves and SHA-256
binds the candidate, validates it again, restricts the path, and supplies the
short-lived native `github.token` only to the existing full-SHA-pinned
`peter-evans/create-pull-request` Action. It remains a Draft-only path.

## Changed files and tests

- `.github/workflows/check-common-versions.yml` adds the three-job topology.
- `ci/checks/security/check-ci-security-contract.py` and
  `tests/ci_security/test_ci_security_contract.py` define and mutate-test the
  least-privilege workflow contract.
- `ci/lib/common.sh`, `ci/tools/doctor.sh`, and
  `ci/runtime/smoke-installed.sh` use a POSIX APXS candidate-list helper;
  `tests/no_crs/test_apxs_cache_selection.py` covers literal glob handling and
  fallback selection.
- The action-lock purpose and paired workflow-security documentation describe
  the newly reviewed use of the existing pinned PR action.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `sh -n` on changed shell files | 0 | Shell syntax passed. | Task evidence retained under `/var/tmp/codex/ModSecurity-conector/runs/20260727-common-version-native-publisher/` |
| APXS literal-glob/fallback control | 0 | A literal `*` was not expanded and the later `sh` candidate was selected. | Same task evidence root |
| `shellcheck -x ci/lib/common.sh ci/checks/catalog/check-common-helpers.sh` | 0 | Exact Common-version workflow ShellCheck scope passed locally. | Same task evidence root |
| Locked Ruff check and format check | 0 | All CI-security Python targets pass lint and format validation. | Same task evidence root |
| Locked actionlint with ShellCheck | 0 | The amended Common-version workflow passes GitHub Actions linting. | Same task evidence root |
| `python3 ci/checks/documentation/check-change-records.py` | 0 | Paired Change Record headings and reciprocal links pass the contract. | Same task evidence root |
| `git diff --check` and staged equivalent | 0 | No whitespace errors. | Commit `7d369ed2a7be5a72d1ebccafb626db76f4c70f57` |
| Initial PR #53 hosted checks | non-zero | CI remediation required for workflow Body ShellCheck, Ruff formatting, and Change Record template headings. | GitHub Actions runs `30299159464`, `30299159306`, `30299140782`, `30299159376` |

## Security impact

This is CI-authority hardening, not a product security remediation. The
original unsafe paths are retested structurally: reader token exposure,
write permission, stale checkout, short candidate hash, direct push, token
substitution, and path expansion are all rejected by the contract test.
The alternate bypass class of changing workflow files remains excluded from
this native-token design.

## Documentation and runtime evidence

English and German workflow-security documentation and this paired record were
updated. No connector or MRTS runtime lifecycle was run because this is a
Framework CI-maintenance change. PR #53 is the delivery evidence; a later
scheduled or manual default-branch run is required to observe actual automated
Draft-PR publication.

## Checks not run

The isolated Framework task worktree has no approved Framework virtual
environment, and policy forbids creating or substituting one incidentally.
Python unit tests, the full CI-security contract test, and `make lint` were not
run locally. The narrowly scoped Change Record check
used the available system Python only because it has no third-party dependency;
the locked standalone Ruff and actionlint binaries were fetched into the
task-owned external evidence root. Exact-head hosted checks remain required
delivery evidence.

## Limitations and residual risk

The native token cannot safely replace the GitHub App needed for
`update-workflow-tools.yml`; that workflow remains unchanged. No credential
value, secret, direct push, Parent change, MRTS change, or Gitlink change is
introduced. Hosted remediation evidence for the amended PR head remains
pending at this record's revision.

## Final diff and review status

The scoped staged diff and whitespace diff were reviewed before commit
`7d369ed2a7be5a72d1ebccafb626db76f4c70f57`; the task worktree was clean and
local/remote/PR heads matched that commit. Draft PR #53 is open. This record's
follow-up amendment addresses the observed CI-only formatting and template
defects; it authorizes neither merge nor auto-merge.
