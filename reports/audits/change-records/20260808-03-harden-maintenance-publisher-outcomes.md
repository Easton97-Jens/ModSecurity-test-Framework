# Change record: Harden maintenance publisher outcomes

**Language:** English | [Deutsch](20260808-03-harden-maintenance-publisher-outcomes.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260808-03-harden-maintenance-publisher-outcomes |
| UTC date | 2026-08-08 |
| Framework base revision | da28e6da58fa8b1135d3631612a78e73ff98584b |
| Issue or pull request | Task branch `fix/maintenance-publisher-outcomes`. Draft PR pending; no merge or auto-merge is authorized. |

## Motivation and problem statement

The two scheduled/manual maintenance workflows lacked one unambiguous terminal
outcome. A workflow-tool publisher failure could be hidden behind skipped
downstream work, and the CPython publisher still used the native job token.
Observed hosted receipts for the requested source revisions show the
workflow-tool publisher failed while minting its App token and the CPython
publisher failed while creating or updating its Draft PR. The hosted log body
was unavailable to this task, so no unobserved error text is recorded here.

## Affected components and security boundaries

- `.github/workflows/update-workflow-tools.yml` now binds the resolver's
  canonical Base64 candidate and SHA-256 identity through validator and
  publisher, preflights the configured App identifiers without displaying
  values, and ends in a read-only terminal outcome job.
- `.github/workflows/check-python-version.yml` now uses the same
  repository-limited App configuration, permits only `Contents` and `Pull
  requests` App writes, verifies one constrained Draft branch/PR, and ends in
  a read-only terminal outcome job.
- `ci/tools/update-workflow-tools.py`, the static CI-security contract, and
  focused tests bind the source behavior. The paired English/German guide
  documents it.
- Parent source, Parent/Framework Gitlinks, MRTS source, and MRTS Gitlinks are
  outside this Framework-only change.

## Acceptance criteria

- Only the exact no-update state is green; missing, malformed, unknown, or
  failed resolver/validator/publisher/App states fail closed.
- No-update creates or modifies no branch, commit, or pull request.
- Workflow-tool consumers validate the resolver candidate's exact SHA-256
  identity and require a non-empty update before applying it.
- Both publishers use the configured GitHub App without a native-token, PAT,
  or secret fallback; configuration failures are red and do not disclose
  values.
- CPython uses only the required App scopes, preserves a fixed branch/title/
  Draft/marker/path contract, and never merges.
- The static contract, negative tests, paired documentation, and this Change
  Record capture the final source behavior.

## Alternatives considered

- Treating any skipped publisher as a green no-update result was rejected:
  resolver-output and publishing failures would become ambiguous.
- Giving the native job token wider permissions or retaining `github.token` as
  a fallback was rejected because it broadens the credential boundary.
- Creating a PR, branch, or commit for a no-update result was rejected because
  it creates unnecessary maintenance state.

## Implementation decision

Each publisher keeps its built-in token at `contents: read`. The publisher
preflight checks only whether
`WORKFLOW_UPDATER_APP_CLIENT_ID` and `WORKFLOW_UPDATER_APP_PRIVATE_KEY` are
present; it prints neither value. The pinned App-token action is the sole
publishing credential source. The CPython token requests `contents` and
`pull-requests` write only; the workflow-tool token additionally requests
`workflows` write because it may update workflow files.

The new `outcome` jobs run with `always()` and empty permissions. They validate
all preceding job results and their outputs before writing bilingual summaries.
They explicitly reject unrecognized output and failed publishing rather than
masking it as a no-op. Existing strict workflow-tool Draft-PR controls remain;
CPython receives equivalent fixed branch, title, marker, Draft, base, and
approved-path checks.

## Changed files and tests

- `.github/workflows/check-python-version.yml`
- `.github/workflows/update-workflow-tools.yml`
- `ci/tools/update-workflow-tools.py`
- `ci/checks/security/check-ci-security-contract.py`
- `ci/checks/security/check-github-actions-workflows.py`
- `tests/ci_security/test_update_workflow_tools.py`
- `tests/ci_security/test_update_python_version.py`
- `tests/ci_security/test_ci_security_contract.py`
- `tests/ci_security/test_framework_ci_security_contract.py`
- `tests/security_regression/test_workflow_security_contract.py`
- `docs/github-actions-workflow-security.md` and
  `docs/github-actions-workflow-security.de.md`
- This paired Change Record.

Positive coverage proves the real workflow profiles; negative mutations reject
missing outcome jobs, non-empty outcome permissions, token exposure, unknown
terminal conditions, removed candidate identity binding, removed App
preflight, native-token fallback, broadened App scope, weakened Draft controls,
force-style cleanup masking, green publisher-error paths, workflow-level
CPython read scope, and a missing CPython reader-job permission.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused updater/contract unit suites | 0 | Workflow-tool updater (26), CPython updater (12), and CI-security contract (33) tests passed. | Local Framework task worktree. |
| Explicit four-module unit command | 0 | 80 updater/contract tests passed. | Local Framework task worktree. |
| `make test-ci-security-contract` | 0 | 141 CI-security contract and regression tests passed. | Local Framework task worktree. |
| `make test-workflow-action-pins` | 0 | 25 immutable Action-pin tests passed. | Local Framework task worktree. |
| `make test-workflow-security-contract` | 0 | 9 workflow-security contract tests passed. | Local Framework task worktree. |
| `make check-github-actions-workflows` | 0 | Source-controlled workflow pin and permission checks passed. | Local Framework task worktree. |
| `make check-documentation` | 0 | Documentation, bilingual parity, and Change-Record checks passed before final record reconciliation. | Local Framework task worktree. |
| `make lint` | 0 | Complete repository-defined local lint/CI-security aggregate passed. | Local Framework task worktree. |
| Locked Ruff `0.15.22` lint and format checks | 0 | The exact hosted file set passed after the narrowly scoped format remediation. | Checksum-verified task-local tool retrieval. |
| SonarCloud Quality Gate | 1 | PR #67 current head `72b2904` reported only the concrete task-owned static-analysis annotations remediated by this follow-up. | GitHub check run `93130371506`; no raw hosted log retained. |
| `ci/checks/security/check-ci-security-contract.py --root .` and YAML parse | 0 | The reviewed workflow contracts and both changed workflow YAML documents passed. | Local Framework task worktree. |
| Codex Security working-tree diff scan | 0 | All 14 changed files received full-file receipts; no reportable finding survived discovery. | Sealed task-local scan evidence (not versioned). |

## Security impact

This is a CI credential-boundary and outcome-integrity hardening. The original
workflow-tool credential-mint failure remains red; the CPython publisher no
longer uses the native job token for publishing and starts with no workflow-
level built-in token. Its resolver, candidate-validator, and publisher receive
only their individual `contents: read` built-in token, while the outcome stays
empty. The contracts pin preflight behavior, App scope, candidate identity,
strict Draft-PR state, job-scoped read access, and terminal report bodies.
Focused alternate-bypass mutations were rerun through the static contract tests
and were rejected. The legitimate controls are the unmodified local workflows
and their focused test suites.

## Documentation and runtime evidence

The English and German workflow-security guides now describe the shared App
configuration names, no-value preflight, different App scopes, no-fallback
rule, exact no-update states, strict Draft-PR state, job-scoped CPython reader
permissions, and ordinary PR checks. No credential values, repository setting
changes, hosted App-installation proof, or connector/MRTS runtime evidence was
collected.

## Checks not run

- A hosted no-update and update-present run of both workflows is not yet run.
  App installation/permission verification requires a repository owner and is
  not proven by the available command response.
- Hosted PR checks, review state, branch protection, and SonarQube Cloud are
  exact-Draft-PR-head controls. The already pushed head was inspected; this
  follow-up's exact head must be pushed and rechecked before any merge review.
- `actionlint`, `zizmor`, and `pyright` are not locally installed and were not
  downloaded. After the initial Draft-PR check identified six Ruff-format-only
  changes, the repository's checksum-verified fetcher supplied locked Ruff
  `0.15.22` in task-local storage; its exact lint and format checks passed.
  The installed ShellCheck is the reviewed `0.11.0`, but the repository-native
  workflow invocation requires actionlint integration, so no non-equivalent
  standalone extraction check was substituted.

## Limitations and residual risk

Source and local tests cannot prove that the GitHub App is installed only on
this repository or has the requested permissions. The hosted publisher path
remains externally dependent on that configuration. No direct `master` push,
merge, auto-merge, PAT fallback, Parent change, or MRTS change is included.

## Final diff and review status

The original task commit was pushed and exactly one Draft PR was opened. Its
initial `python-ci-security-quality` failure was confined to Ruff formatting;
the exact pinned formatter produced a narrow six-file follow-up that passed
local lint/format and the full local aggregate. That follow-up's security-
quality, actionlint/contract, zizmor, CodeQL, action-version, secret-scanning,
Scorecard, OSV, and common-structure checks passed; SonarCloud instead reported
the concrete task-owned annotations recorded above. This follow-up remediates
them before one normal push and a new exact-head check. The sealed scoped
security-diff scan found no reportable regression. This record contains no
credential value or raw hosted log.
