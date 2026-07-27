# Change record: Add the common-version Draft-PR publisher

**Language:** English | [Deutsch](20260727-01-add-common-version-draft-publisher.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260727-01-add-common-version-draft-publisher` |
| UTC date | 2026-07-27 |
| Framework base revision | `47e50e7bc43ba7a3b5bad1a9448111794f664cc0` |
| Issue or pull request | Task branch `agent/common-version-native-publisher`; Draft PR pending at record creation. No merge or auto-merge is authorized. |

## Motivation and decision

The scheduled Common-version workflow safely created an ephemeral candidate but
could neither publish a Draft PR nor pass its own ShellCheck step. The new
three-job topology uses the short-lived native GitHub job token model already
used by the Framework Python-version publisher, because its maintenance scope
is only `ci/lib/common.sh`, not a workflow file.

`resolve` and `candidate-validate` remain `contents: read`, token-free in
source, and operate only on a temporary copy. `publish` runs only for a
scheduled/manual default-branch event in the authoritative repository. It has
only `contents`/`pull-requests` write permission, re-resolves the candidate,
compares its SHA-256 to the read-only validation result, and rejects every
working-tree diff outside `ci/lib/common.sh`. The sole explicit token consumer
is the full-SHA-pinned `peter-evans/create-pull-request` action, which creates
or updates one fixed-branch Draft PR and cannot merge it.

## Scope and security boundary

- Changed: the Common-version workflow, its CI-security contract and tests,
  `common.sh` ShellCheck fixes, APXS-list consumers, the existing action-lock
  purpose, bilingual workflow-security documentation, and this paired record.
- No PAT, repository secret, GitHub-App credential, direct push, broad staging,
  auto-merge, Parent change, MRTS source change, or Gitlink change is added.
- `update-workflow-tools.yml` remains unchanged: hosted evidence proves the
  native token lacks the workflow-file authority required there.
- Negative contract mutations reject reader write permission or token exposure,
  a stale checkout, direct push, unreviewed token input, and path expansion.

## Verification

| Command | Exit code | Result |
| --- | --- | --- |
| `sh -n` on `ci/lib/common.sh`, `check-common-helpers.sh`, `doctor.sh`, and `smoke-installed.sh` | 0 | Changed shell files passed syntax validation. |
| `sh -eu -c '. ci/lib/common.sh; … ci_find_bin_list …'` | 0 | The APXS-list helper selected a later valid candidate and rejected an invalid list. |
| `shellcheck -x ci/lib/common.sh ci/checks/catalog/check-common-helpers.sh` | 0 | The exact ShellCheck scope used by the Common-version workflow passed. |
| `git diff --check` | 0 | No whitespace errors in the current task diff. |

The isolated Framework task worktree has no Framework virtual environment. The
local policy prohibits incidental creation or substitution of one, so Python
tests, CI-security/workflow-contract execution, documentation checks, `make
lint`, actionlint, zizmor, and Ruff are `not_run` locally. Hosted
PR checks and SonarQube Cloud remain exact-head evidence pending delivery.

A broader local ShellCheck invocation reports pre-existing findings in the
unrelated `doctor.sh` and `smoke-installed.sh` scripts. Their existing
diagnostic and source-following findings are outside the workflow's exact
ShellCheck scope; this change only replaces their unsafe APXS candidate-list
word splitting and does not suppress any lint control.

## Residual risk and review

No credential value, secret, raw hosted log, Parent change, or MRTS change is
recorded. The focused review covers the authority boundary: upstream data is
handled read-only until the publisher independently validates, hash-binds, and
path-binds it. A post-merge scheduled/manual publisher run remains required to
prove Draft-PR creation. This record does not authorize a merge.
