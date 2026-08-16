# Change record: 20260816-04-harden-github-api-auth-boundary

**Language:** English | [Deutsch](20260816-04-harden-github-api-auth-boundary.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260816-04-harden-github-api-auth-boundary` |
| UTC date | `2026-08-16` |
| Framework base revision | `a5cbfff185cad3810fcafad534dc334be92a0df8` |
| Issue or pull request | Master dispatches `31968050889` and `31968224482`; repair branch pending publication. |

## Motivation and problem statement

The canonical maintenance resolver failed on the hosted master runs while
resolving the mandatory global inventory. The repair must make the existing
read-only GitHub token useful for the API calls that need authentication while
preserving the Framework's supply-chain boundary: no token on non-API hosts,
no credential disclosure, no redirect to another authority, and no expansion
of publisher permissions.

## Affected components and security boundaries

The affected boundary is the Framework CI maintenance resolver and its
GitHub API client. The standalone `update-workflow-tools.yml` reader remains
token-free. The canonical maintenance workflow may receive the existing
job-scoped read-only `GITHUB_TOKEN` only in its explicitly reviewed resolver,
reconciliation, and re-resolution steps. The publisher's short-lived
repository-limited App token and its Draft-only boundary are unchanged. Parent,
connector runtime, and MRTS are outside scope.

## Acceptance criteria

1. A bearer token is sent only to the exact HTTPS `api.github.com` authority.
2. Redirects are rejected before or at response validation, without copying
   the token to a redirected host.
3. Tokens never appear in plans, summaries, diagnostics, or errors.
4. Unexpected HTTP responses, including 403/429, remain fail-closed, and
   existing publisher permissions are unchanged.
5. Fresh hosted checks prove the repair, the resulting master state, and
   SonarQube Cloud `0` new issues and `0.0%` duplication on new code.

## Alternatives considered

- Making the standalone workflow token-aware was rejected because it would
  widen an unrelated reader boundary.
- Sending the token to every HTTPS request was rejected because release and
  download hosts are not the GitHub API authority.
- Following redirects was rejected because a valid API token could cross an
  untrusted authority boundary.
- Suppressing or weakening the resolver failure was rejected because the
  mandatory global inventory must remain fail-closed.

## Implementation decision

`github_payload()` constructs only fixed, repository-scoped HTTPS GitHub API
URLs, accepts only the reviewed release-page query, and attaches the existing
read-only credential only when `GITHUB_TOKEN` is present. It refuses malformed
token control characters before a request is built, disables redirects before
they can forward request headers, and rejects a changed final URL before
reading a response. The standalone workflow remains token-free and the
publisher/App-token contract is unchanged. Hosted PR, SonarQube Cloud, merge,
and resulting-master evidence remain pending until freshly observed.

## Changed files and tests

- `ci/tools/update-workflow-tools.py` uses the existing optional read-only
  credential only for a fixed GitHub API request, rejects malformed API paths,
  token control characters, redirects, and final-URL changes.
- `tests/ci_security/test_update_workflow_tools.py` covers absent/present
  credentials, origin/path restrictions, redirect refusal, and redacted
  malformed-token rejection.
- `docs/github-actions-workflow-security.md` and its German companion document
  the API credential, redirect, rate-limit, and hosted-evidence boundary.
- `docs/security/ci-security-tooling.md` and its German companion distinguish
  the token-free standalone reader from the canonical maintenance caller.
- This English/German Change Record pair records observed failure, local repair
  evidence, and outstanding hosted evidence.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `gh run view 31968050889 --json ...` | `0` | Master run failed in `canonical-maintenance` at resolver exit 2 after dependency bootstrap and `pip check`; head `a5cbfff`. | [run 31968050889](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31968050889) |
| `gh run view 31968224482 --json ...` | `0` | Same observed failure on the same master head; result job succeeded only because it summarized the failed resolver. | [run 31968224482](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31968224482) |
| `python -m unittest -v tests.ci_security.test_update_workflow_tools` | `0` | 33 updater tests passed, including optional token, no redirect, invalid path, and token-control-character controls. | Task worktree |
| `python ci/checks/security/check-ci-security-contract.py` | `0` | Existing CI security contract passed without permission or publisher-boundary changes. | Task worktree |

## Security impact

The implemented change narrows credential exposure, rejects malformed token
values without echoing them, and prevents credential forwarding across
redirects. It does not alter runtime connector behavior or add publisher
authority. The security controls have not yet been proven by a fresh hosted
run at this record update.

## Documentation and runtime evidence

The English/German workflow-security guide now records the exact API authority,
read-only token use, redirect rejection, token non-disclosure, unchanged
publisher boundary, and the two observed master failures. The source-level
regressions establish the local repair controls. The observed runs remain
failure evidence only; they do not prove a successful hosted repair, merge,
resulting master state, or SonarQube Cloud zero metrics.

## Checks not run

- Fresh PR checks, SonarQube Cloud, protected-branch merge, and post-merge
  master dispatches are not yet available at this record update.

## Limitations and residual risk

Until the repair is published and rerun, the hosted resolver failure remains
open. SonarQube Cloud must independently report zero new issues and zero
duplication on new code before integration is considered verified.

## Final diff and review status

The task diff contains the API client and focused tests, paired English/German
security documentation, and this Change Record pair. No files are staged or
committed, no branch is pushed, and no PR or master write has yet been
performed. The parent agent owns hosted verification and delivery decisions.
