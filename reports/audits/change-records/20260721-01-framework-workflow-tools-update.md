# Change record: Framework workflow tooling update

**Language:** English | [Deutsch](20260721-01-framework-workflow-tools-update.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260721-01-framework-workflow-tools-update |
| UTC date | 2026-07-21 |
| Framework base revision | 9dab40c2b8799dc1e4597cb2a2c223ec3f6cd72b |
| Issue or pull request | Draft pull request pending when this record was written; no merge or auto-merge is authorized. |

## Motivation and problem statement

The Framework needed current immutable GitHub Action provenance and a repository-native way to propose later Action or checksum-locked CI-tool updates without allowing metadata, reused branches, or downloaded assets to write the default branch. The prior pins used checkout v7.0.0 and setup-python v6.3.0; there was no dedicated Framework Action/tool updater.

## Affected components and security boundaries

- .github/workflows receives checkout v7.0.1 and setup-python v7.0.0 full-commit pins, plus the constrained updater workflow.
- The former common-version PR delivery path is now read-only: it applies its check only to a runner-temporary copy of `common.sh`; the force-capable third-party PR action and all branch/PR delivery steps are removed.
- The tool lock, updater, fetcher, and CI-security contract bind official release URLs, tags, commits, tool assets, SHA-256 digests, and safe redirect hosts.
- Resolver and validator are token-free/read-only. The default-branch-gated publisher has only contents: write and pull-requests: write, creates or updates one Draft PR, and has no force-push, auto-merge, or direct default-branch path.
- tools/MRTS was not initialized or modified; its gitlink remains 13aa91291adea12d5c607fdd165d010fcfb1da78. No Parent file is in this record's scope.

## Acceptance criteria

- All Framework Action references remain full SHA-pins with matching lock records and release comments.
- The updater rejects unstable releases, foreign redirects, out-of-root temporary paths, mutable or ambiguous metadata, and changes outside its exact allowlist.
- A proposed candidate is validated in an isolated tree and changed tool assets are checksum-validated without execution before publication.
- Reused maintenance branches must be reconstructible byte-for-byte from the trusted default revision plus a verified candidate.
- The common-version check must retain its candidate validation while having no write permission, publishing token, branch operation, or pull-request delivery path.
- English/German documentation and this paired record describe the final boundaries without claiming unobserved hosted CI or runtime evidence.

## Alternatives considered

- Extending the former common.sh PR publisher was rejected because its third-party delivery action has a force-update implementation. Its useful candidate check is retained as a read-only runner-temporary operation instead.
- Tag-based Action references, floating tool URLs, unrestricted HTTPS redirects, and one write-capable updater job were rejected because they do not preserve immutable provenance or least privilege.
- Reusing a matching branch based only on paths was rejected; trusted-base reconstruction prevents an allowed file from carrying injected publisher code.

## Implementation decision

Checkout is updated to v7.0.1 at 3d3c42e5aac5ba805825da76410c181273ba90b1 and setup-python to v7.0.0 at 5fda3b95a4ea91299a34e894583c3862153e4b97. The Action/tool lock remains the canonical provenance source; unrelated locked tool versions are unchanged.

The updater separates resolver, validator, and publisher. The contract parses the workflow and pins the write-capable publisher's reviewed step profile, including command/script bodies, rather than relying on loose text markers. The updater uses official GitHub release metadata, validates annotated-tag identities and release-asset digests, and accepts only explicit GitHub release-asset redirect hosts before SHA-256 verification.

`check-common-versions.yml` no longer publishes a maintenance branch or PR. It checks and ShellChecks an ephemeral copy under `RUNNER_TEMP` with read-only permissions, so the new constrained workflow/tool updater is the only Framework path that can create or update a Draft maintenance PR.

## Changed files and tests

- Affected .github/workflows pins, lock records, the new update-workflow-tools workflow, and the now read-only common-version candidate check.
- ci/tools/update-workflow-tools.py, ci/tools/fetch-security-tool.py, and ci/checks/security/check-ci-security-contract.py.
- Focused updater, fetcher, and contract tests, including unsafe mutations for permissions, triggers, PR creation, force/default pushes, redirects, stale candidates, and branch reuse.
- English/German workflow-security and CI-tooling guides, plus this paired record and index entries.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| python3 -m unittest discover -s tests/ci_security -v | 0 | 106 focused CI-security tests passed. | Local task validation; no payload retained. |
| python3 -m unittest tests.security_regression.test_workflow_security_contract -v | 0 | 7 workflow-security regression tests passed. | Local task validation. |
| CI workflow, Action-pin, and CI-security contract checkers | 0 | 14 workflows, immutable pins, and constrained publisher profile passed. | Local task validation. |
| git diff --check | 0 | No whitespace errors. | Framework task worktree. |

## Security impact

This is CI supply-chain hardening. Mutable pins, broad redirect acceptance, token exposure in read-only jobs, unvalidated candidate trees, force/default pushes, auto-merge, duplicate PRs, and injected reusable-branch content are covered by explicit negative tests. Removing the third-party common-version PR publisher also removes its force-capable branch update/delete behavior. The updater does not run a changed downloaded tool before validating its checksum and archive layout.

## Documentation and runtime evidence

English/German workflow-security and CI-tooling documentation describes immutable pins, release provenance, the redirect boundary, and the resolver/validator/publisher model. No connector, MRTS, or runtime/lifecycle evidence was collected: this is a Framework CI configuration change.

## Checks not run

- Local Ruff was not run because its executable/module is unavailable.
- Hosted Actionlint/ShellCheck/Zizmor execution, CodeQL, dependency review, OSV, Scorecard, Gitleaks, and any Sonar check remain exact-Draft-PR-head evidence to be observed after publication.
- PR #39 was not modified. Its independent Python-updater work can overlap in workflow/docs files and may require later maintainer conflict resolution.

## Limitations and residual risk

The updater deliberately supports only reviewed lock records and explicit paths. New Action/tool types, release-asset layouts, or workflow files require an intentional contract/profile update. GitHub-hosted checks and review are still required for the exact published commit.

## Final diff and review status

The source diff received an independent read-only security review, focused tests, workflow/pin/contract checks, and whitespace review before this record. At this record's creation it remains uncommitted and unpushed; the final Draft PR number, exact-head CI evidence, and review state must be added only after they are observed.
