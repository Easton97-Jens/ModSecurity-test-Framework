# Change record: 20260816-05-preserve-fatal-maintenance-summary

**Language:** English | [Deutsch](20260816-05-preserve-fatal-maintenance-summary.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260816-05-preserve-fatal-maintenance-summary` |
| UTC date | `2026-08-16` |
| Framework base revision | `5115281e6ba5245ab90ab4cddc926944cab88aba` |
| Issue or pull request | Master dispatch `31972254226`; follow-up repair PR status and merge are not established by this record. |

## Motivation and problem statement

The follow-up master dispatch failed again in the canonical resolver after the
hash-locked dependency bootstrap. The hosted job exposed the resolver failure
but did not retain the generated plan in its job summary because the shell
exited before the summary append. The remediation must preserve useful plan
evidence while keeping fatal resolver outcomes non-zero and fail-closed.

## Affected components and security boundaries

The affected boundary is the Framework canonical-maintenance resolver and its
trusted GitHub Actions job. The resolver may use the existing read-only
job-scoped token only for exact HTTPS `api.github.com` requests. Redirects are
rejected and secrets are never disclosed. The standalone workflow-tool reader
remains token-free, and the repository-limited publisher App-token boundary is
unchanged. Parent, connector runtime, and MRTS are outside scope.

## Acceptance criteria

1. The generated JSON and Markdown plans are checked for existence even when
   the resolver returns a fatal non-zero code.
2. The Markdown plan is appended to `GITHUB_STEP_SUMMARY` before that same
   resolver code is returned, so the hosted job remains failed but diagnosable.
3. API authentication remains exact-authority-only (`https://api.github.com`),
   with no redirects and no token disclosure.
4. No publisher, permission, auto-merge, or direct-master boundary is widened.
5. Fresh PR/hosted evidence proves the final head and resulting master; the
   required SonarQube Cloud metrics are zero new issues and zero duplication
   on new code.

## Alternatives considered

- Returning success after a fatal resolver result was rejected because it would
  make an incomplete maintenance plan publishable.
- Dropping the plan summary on failure was rejected because it removes the
  evidence needed to diagnose mandatory global-scope failures.
- Sending the read-only token to all network requests or following redirects
  was rejected because it crosses the API credential trust boundary.
- Changing the standalone workflow's token permissions was rejected because
  that workflow is intentionally a token-free reader.

## Implementation decision

The canonical-maintenance shell records the resolver exit code, allows the
resolver to finish writing its generated plan, verifies both plan files,
appends the Markdown plan to the hosted job summary, and then exits with the
original non-zero code. The resolver's API client remains restricted to exact
HTTPS `api.github.com` use of the existing read-only token, rejects redirects,
and never prints the credential. This record documents the design and
observed failure; resulting-master proof remains pending.

## Changed files and tests

The integrated follow-up PR scope includes the canonical maintenance workflow
and resolver, their security contract, focused resolver/HTTP regression tests,
and the paired English/German reader documentation and Change Record. In the
current worktree that includes `.github/workflows/check-common-versions.yml`,
`ci/tools/check-common-versions.py`,
`ci/checks/security/check-ci-security-contract.py`,
`tests/ci_security/test_unified_common_maintenance_workflow.py`, and
`tests/security_regression/test_common_version_http_client.py`, together with
the four guide files and this paired record. The source, workflow, and test
changes are concurrent implementation work in the same PR; this documentation
slice itself changed only the guide and Change Record files.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `gh run view 31972254226 --json ...` | `0` | Master run failed in `canonical-maintenance` during resolution with exit 2 after dependency installation and `pip check`; head `5115281`. | [run 31972254226](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31972254226) |
| `gh run view 31972254226 --log-failed` | `0` | Hosted log confirms the resolver was invoked with the read-only token and ended with exit 2; the plan-summary remediation was not yet proven by this run. | [run 31972254226](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31972254226) |
| Documentation/Change Record validation | `0` | Link, bilingual-pair, path-reference, and Change Record contracts passed. | Task worktree |
| `git diff --check` | `0` | No whitespace errors in the documentation slice. | Task worktree |

## Security impact

The remediation preserves failure semantics while improving failure evidence.
It does not broaden the API token's authority, permit redirects, expose a
secret, or alter publisher capabilities. Hosted validation of the final repair
and SonarQube Cloud zero metrics is still required.

## Documentation and runtime evidence

The reader-facing English/German guides record the observed run and the
planned behavior. Run `31972254226` is failure evidence only; it does not prove
the follow-up repair, a PR merge, resulting master, or SonarQube Cloud's zero
new-issue and zero-duplication requirements.

## Checks not run

- Fresh exact-head hosted checks, SonarQube Cloud, protected-branch merge, and
  resulting-master dispatches were not available at this record update.
- Source regression tests are outside this documentation-only slice.

## Limitations and residual risk

Until a fresh hosted run proves the behavior, a fatal resolver result remains
a release/integration blocker. The plan summary must be visible while the
workflow still fails, and SonarQube Cloud must independently report zero new
issues and zero duplication on new code before integration.

## Final diff and review status

The integrated PR contains the source, workflow, regression-test, guide, and
Change Record scope listed above. This agent changed only the guide and Change
Record files; no code, workflow, or test file was changed here. Nothing was
staged, committed, pushed, merged, or dispatched by this documentation slice.
Hosted verification, SonarQube Cloud results, and delivery remain owned by the
parent agent and are not claimed by this record.
