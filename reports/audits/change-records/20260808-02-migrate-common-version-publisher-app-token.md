# Change record: Migrate the Common-version publisher to a GitHub App token

**Language:** English | [Deutsch](20260808-02-migrate-common-version-publisher-app-token.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260808-02-migrate-common-version-publisher-app-token` |
| UTC date | 2026-08-08 |
| Framework base revision | `da28e6da58fa8b1135d3631612a78e73ff98584b` |
| Issue or pull request | Framework PR [#65](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/65) targets `master`. This record tracks its source finalization; it never authorizes a merge. |

## Motivation and problem statement

`check-common-versions.yml` already resolved and independently validated a
bounded `ci/lib/common.sh` candidate, but its publisher used the native
GitHub-token path. That path does not prove the requested repository-limited
GitHub App authority or reliable ordinary pull-request event delivery. Hosted
run `31254801083` further showed that the candidate validator stopped before
publisher execution because the directly invoked CRS provenance test could not
import its local test helper.

During PR #65 finalization, review also found that an `unknown` resolver result
could be treated like a harmless no-update outcome and that no terminal job
proved the skipped/no-update state or published an operator-facing summary.
Both conditions required a source fix before this PR could be eligible for
delivery.

The first normal source push cleared those three recorded Sonar findings, but
the fresh PR analysis reported two new open `python:S3776` findings in the
same static security-contract checker. Although the Sonar Quality Gate stayed
`OK`, that does not meet this task's zero-open-issue policy. The follow-up
therefore decomposes only the affected validation functions into bounded
helpers without changing their reviewed errors or fail-closed decisions.

## Affected components and security boundaries

This Framework-only change covers the Common-version GitHub Actions publisher,
its CI-security contract and mutation suite, the CRS provenance regression
test import boundary, action-use metadata, paired workflow-security guidance,
and this record. The security boundary is the transition from a validated
default-branch candidate to a narrowly scoped Draft pull request. Parent,
MRTS, Gitlinks, runtime connectors, and a merge are outside scope.

## Acceptance criteria

- Resolver and validator remain credential-free, `contents: read`, independent,
  and bound through an exact 64-character SHA-256 candidate digest.
- The native publisher token remains `contents: read`; exactly one pinned App
  token is limited to the current owner/repository with only `contents` and
  `pull-requests`: write.
- The App configuration gate, state check, fixed maintenance identity, body
  marker, and `ci/lib/common.sh` path restriction fail closed on deviation.
- Only current update-eligible sources may produce `update_available=false`;
  `unknown`, `blocked`, and `error` outcomes fail before a no-update decision.
  A credential-free `always()` result job must prove the terminal state and
  publish the reviewed English/German outcome.
- No native-token, PAT, SSH, direct-default-branch-push, force-push, broad
  staging, PR takeover, merge, or auto-merge path is introduced.
- The required tests, paired documentation, action-pin contract, Change Record
  contract, and final PR delivery evidence are recorded truthfully.

## Alternatives considered

Keeping the native token would retain an insufficient publishing/event-boundary
claim. A PAT, deploy key, long-lived secret, or runner-driven push would widen
authority. Reimplementing the publisher with custom Git pushes was unnecessary
because the existing full-SHA-pinned `peter-evans/create-pull-request` Action
can use the scoped App token after a fail-closed state check. All alternatives
that permit a direct `master` update, token fallback, or a synthetic candidate
were rejected.

## Implementation decision

The publisher now revalidates the candidate on the trusted default revision,
checks its SHA-256 and exact diff, preserves the validated JSON/Markdown
output, and creates an English/German Draft body from that data only. It stops
with a clear configuration error for an available update when
`WORKFLOW_UPDATER_APP_CLIENT_ID` or `WORKFLOW_UPDATER_APP_PRIVATE_KEY` is
unavailable. The configuration gate derives only a non-secret Boolean because
GitHub Actions does not support a direct secret reference in `if:`. The secret
value is supplied only to the pinned App-token Action;
the resulting short-lived token is supplied only to a read-only GitHub API
state check and the pinned pull-request Action. State A has no branch or open
matching PR; state B has exactly one same-repository, correctly identified
Draft PR whose diff is only `ci/lib/common.sh`. Every other state fails closed.
The trusted default-revision SHA reaches `github-script` through a named action
environment variable rather than template interpolation into JavaScript.

The resolver now marks deliberately tracked local-policy entries without an
automated updater contract as `not_applicable`, while `unknown`, `blocked`, and
`error` remain fail-closed. Its terminal result job always checks the actual
job outcomes. It permits `false` only after a successful resolver and skipped
candidate/publisher jobs, emits the exact bilingual no-update summary, and
permits `true` only after all three prior jobs succeed. The update outcome
reports the constrained Draft PR URL or number, with a factual fallback when
the Action does not return either output; every other state fails.

## Changed files and tests

- `.github/workflows/check-common-versions.yml` uses the constrained App token,
  state check, fixed Draft identity, validated body, default-branch drift
  check, and a credential-free terminal result job.
- `ci/checks/security/check-ci-security-contract.py` defines an exact
  Common-version publisher/result profile and rejects native-token/permission/
  scope, state, path, SHA, write-path, and terminal-state drift. Its
  publisher-step and result-job checks are decomposed into bounded helpers to
  remediate the two current Sonar cognitive-complexity findings without
  weakening the contract.
- `ci/tools/check-common-versions.py` fails closed for `unknown` results and
  distinguishes deliberately non-updatable local-policy entries from unsafe
  upstream resolution failures.
- `tests/ci_security/test_ci_security_contract.py` mutation-tests the App
  token, configuration names, permissions, repository/owner scope, branch,
  draft, marker, staging, direct/force pushes, SHA binding, artifact reuse,
  publisher gate, PR takeover bypasses, and directly executes terminal result
  states and bilingual summaries.
- `tests/security_regression/test_common_versions_sonar_provenance.py` proves
  that unknown provenance fails closed while non-updatable local policy does
  not create a false error.
- `tests/security_regression/test_crs_git_ref_provenance.py` makes its local
  provenance helper importable when the test is invoked by its fully qualified
  module name.
- `ci/tooling/security-tools.lock.yml` records the additional use of the
  already pinned App-token Action; no Action version changes.
- `docs/github-actions-workflow-security.md` and its German companion document
  the App-token contract, no-update/configuration behavior, fixed Draft state,
  and normal PR-check expectation.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy gh run view 31254801083 --log` | 0 | Resolver passed; candidate validation failed with `ModuleNotFoundError: git_provenance_test_support`; publisher was skipped. | [Run #14](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31254801083) |
| `make test-ci-security-contract` | 0 | 138 CI-security, Change Record, evidence, updater, and security-contract tests passed, including direct terminal-result execution. | Task-owned external Framework worktree |
| `make test-workflow-action-pins` | 0 | 25 action-pin regression tests passed. | Same task worktree |
| `make test-workflow-security-contract` | 0 | 7 workflow-security contract tests passed. | Same task worktree |
| `make check-github-actions-workflows` | 0 | Python-version, pin, and permission checks accepted every checked-in workflow. | Same task worktree |
| `make check-documentation` | 0 | Links, bilingual parity, path references, and Change Record contract passed. | Same task worktree |
| `make lint` | 0 | Full local lint and regression matrix passed, including the workflow-security and provenance suites. | Same task worktree |
| SonarCloud PR #65 analysis at `0ba1e39d64baaa34cb9f2ae51b875609749f724e` | 0 | Quality Gate `OK` and no open hotspots, but two new OPEN `python:S3776` findings remained; this is the source of the current bounded follow-up, not zero-policy success. | [PR analysis](https://sonarcloud.io/dashboard?id=Easton97-Jens_ModSecurity-test-Framework&pullRequest=65) |
| `<locked-tools>/actionlint -shellcheck=<locked-tools>/shellcheck` | 0 | All checked-in workflows and embedded shell blocks passed. | SHA-256-locked local tools |
| `<locked-tools>/zizmor --offline .github` | 0 | No findings; 33 repository-configured suppressions were reported. | SHA-256-locked local tool |
| `<locked-tools>/ruff check …` and `ruff format --check …` | 0 | Ruff lint and format checks accepted the relevant CI-security scope (20 files). | SHA-256-locked local tool |
| Focused `unittest` updater/NGINX/CRS module trio | 0 | 37 tests passed; the focused Common-version provenance/terminal-state suite also passed. | Same task worktree |
| `check-common-versions.py --check --json --timeout 10` | 2 | Correct fail-closed preflight: a ModSecurity v3 release needs separate immutable-provenance review and a newer HAProxy tuple is available; no file was modified. | Task-owned external Framework worktree |
| `git diff --check` | 0 | No whitespace errors in the final uncommitted review. | Same task worktree |

## Security impact

This is a CI-authority hardening and CI-validation repair. The original
native-token publisher path is rejected structurally, while the legitimate
control remains a trusted-default-branch candidate with a matching SHA-256,
safe App configuration, allowable state A/B, and exactly one permitted changed
path. The alternate-bypass mutations cover token fallback, App scope/permission
drift, private-key name drift, branch/PR hijacking, broad staging, direct and
force pushes, a short or missing digest, resolver-artifact reuse, and an
untrusted publisher gate. No credential value is recorded.

## Documentation and runtime evidence

The English/German workflow-security pair is updated. No connector or MRTS
runtime was needed. Run #14 is hosted failure evidence for the test import
defect, not proof of the App publisher: its publisher was correctly skipped.
The repository metadata check confirmed that the required App-variable and
App-secret names are present without reading either value. The standard CLI
OAuth credential cannot prove App-installation metadata through the App JWT
endpoint, so installation and effective App permissions remain unverified
until a real post-merge publisher run mints and uses the scoped token. That run
must use real upstream results rather than a fabricated candidate.

A no-write resolver preflight correctly returned exit code 2 rather than a
false no-update result: ModSecurity v3 now has a newer release whose tag and
immutable commit require a separate provenance review, and HAProxy has a newer
official tarball/checksum tuple. This is source-control evidence for the
fail-closed behavior, not an App-publisher end-to-end result and not authority
to update either pin in this PR.

## Checks not run

The repository-local Node runtime required by the hash-locked Pyright package
is unavailable (`node` and `nodejs` are absent), so Pyright is blocked rather
than installed globally. The first pushed PR head completed its hosted checks,
but its two open Sonar findings require this new source amendment; exact-head
hosted/Sonar evidence for that amendment and post-merge publisher evidence
remain pending. No unavailable or unrun check is presented as passed.

## Limitations and residual risk

Required App configuration names are present, but the installation and its
effective permissions have not yet been proven by a successful short-lived
token mint. The normal event/check behavior of an App-created Draft PR remains
unobserved until the source-fix PR is merged with separate authorization. The
current resolver preflight also means a post-merge manual run would fail before
either the authorized update or no-update terminal case unless a separately
reviewed provenance decision is made. The state check reduces branch/PR
takeover and default-branch-drift risk but does not authorize a merge,
branch-protection bypass, or a change outside `ci/lib/common.sh`.

## Final diff and review status

The source-fix worktree is isolated on
`fix/common-version-draft-publisher-app-token`; no Framework `master`, Parent,
MRTS, or Gitlink change is authorized. The final source review includes a
clean `git diff --check`, exact static publisher/result-profile checks, no
native-token fallback, no `workflows` write request, no direct/force push, and
no unreviewed App-token consumer. PR #65 already exists; the first normal
source push at `0ba1e39d64baaa34cb9f2ae51b875609749f724e` exposed the two new
Sonar findings, so this bounded amendment still requires a normal push,
current-head hosted checks, zero-open-issue Sonar evidence, and all required
delivery gates before it can become ready for review. It must not be merged
while the known post-merge resolver preflight cannot reach either permitted
terminal outcome without a separate approved provenance decision.
