# Change record — expand Framework CI security

**Language:** English | [Deutsch](20260718-01-expand-framework-ci-security.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260718-01-expand-framework-ci-security |
| UTC date | 2026-07-18 |
| Framework base revision | `9954b99a31fab0006cdf903ab477c8158c50fea8` |
| Pre-reconciliation PR history | `66d90872cfc0125536267d574b776d2e88d26b23`; earlier commits listed below are retained as historical context only. |
| Issue or pull request | [Framework Draft PR #27](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/27) |
| Current remote Draft PR head | `66d90872cfc0125536267d574b776d2e88d26b23` before the normal master reconciliation candidate is committed and pushed. |
| Reconciliation state | Current Framework `master` was merged normally and non-rewriting into the task worktree; the resulting candidate remains local until its final scope review, commit, normal push, and exact-head verification. |
| Delivery state | Draft PR only; local reconciliation validation is recorded below, while fresh remote checks, SonarCloud, reviews, threads, and exact-head equality remain required. `verified_pr` has not been reached. |

## Motivation and problem statement

The Framework used mutable Action tags and had no Framework-owned CI security
scanner/provenance contract. The initial scanner-action design also exposed a
task-owned transitive mutable-container path. This change replaces that path
with checksum-verified CLIs and adds Framework controls without changing the
Parent repository, its gitlink, or MRTS. Independently governed common-
structure and Action-pin controls from Framework `master` are retained
additively; this reconciliation does not replace them.

## Affected components and security boundaries

- Workflows and Dependabot: untrusted PR tokens, checkout, scanner, SARIF,
  dependency, cancellation, and maintenance boundaries.
- CI tooling, downloader, and contract checker: remote Action/tool provenance,
  archive extraction, and source-level policy validation.
- Tests, fixtures, Makefile, and Python tooling: positive and negative control
  coverage.
- Security documentation: paired English/German guidance.

tools/MRTS is not initialized or modified. Scanner checkouts use
submodules false; CodeQL additionally ignores tools/MRTS.

## Acceptance criteria

1. Every remote Action is pinned to a reviewed 40-character SHA with an exact
   version comment and lock record.
2. PR workflows avoid pull_request_target, persisted credentials, broad
   default permissions, unsafe cache/artifact behavior, and unbounded jobs.
3. Gitleaks, OSV, CodeQL, Scorecard, dependency review, actionlint, ShellCheck,
   zizmor, Ruff, Pyright, and dependency hygiene have truthful Framework scope
   and no automatic remediation.
4. The security contract has positive and negative fixture evidence; it covers
   Action pinning, permission declarations, triggers, checkout, timeouts,
   concurrency, and tool-lock structure without changing the common-structure
   product assertion.
5. Before this work can be reported as `verified_pr`, documentation, this
   record, focused checks, a finalized source-diff security review, a committed
   candidate, and exact remote PR-head evidence must be complete. An open Draft
   PR may predate the final candidate and is not that evidence.

## Alternatives considered

- Mutable major tags or unverified package installation: rejected because the
  CI security boundary needs immutable provenance.
- Unbounded or generic scanner artifact upload: rejected. CodeQL uses the
  narrower code-scanning SARIF channel, Gitleaks findings require redaction,
  and OSV/Scorecard retain only validated bounded JSON evidence for one day.
- Go or JavaScript/TypeScript CodeQL: rejected because current Framework source
  evidence supports Actions, Python, and C/C++ only.
- Changing the independently governed test-common catalog invariant: rejected
  as out of scope for this CI/security expansion.

## Implementation decision

A Framework-native YAML lock records Action and CLI provenance. A Python
downloader verifies direct HTTPS GitHub release assets before atomically
publishing a raw executable or safely extracting an archive to runner-owned
directories. OSV Scanner and Scorecard run as checksum-verified CLIs rather
than container-backed Actions. Workflow and test contracts reject mutable pins,
unsafe triggers, unexpected write permissions, unsafe checkout settings,
non-exact Python selection, unprovisioned downloader dependencies, and missing
timeouts/concurrency. CI dependency installation is limited to the hash-locked
PyYAML wheel; standalone security CLIs remain outside the checkout.

The task-owned security follow-up commit adds a semantic workflow-evidence checker rather
than relying only on textual matches. It verifies executable PR checkout
references, CodeQL's exact PR head and language/build configuration, and
Gitleaks' exact PR head, Git-object/range checks, and mandatory redaction. It
also rejects cache use and unapproved artifact/SARIF channels in the affected
workflows. The OSV report schema now rejects structurally incomplete or
overlapping vulnerability groups and requires every listed vulnerability ID to
be represented by exactly one group. Evidence readers and comparator outputs
are contained under the runner-temporary root. The CRS version-pinning helper
uses private `mktemp` files under a validated runner-temporary root rather
than a predictable `/tmp` path.

The scheduled common-version and artifact-cleanup workflows retain their
necessary write capabilities but use non-persisted checkout, narrow
permissions, exact Action pins, explicit timeouts, and non-cancelling
maintenance concurrency.

## Changed files and tests

- Hardened the tracked Framework workflows in the CI-security scope; added CI
  security, quality, secrets, OSV, CodeQL, Scorecard, and dependency-review
  workflows.
- Added a CI dependency lock, tool lock/downloader, security and bounded-JSON
  evidence checkers, positive/negative zizmor fixtures, Ruff configuration,
  and Pyright configuration.
- The task-owned security follow-up adds the semantic workflow-evidence
  checker, strict OSV group-schema validation, runner-root containment,
  exact-head CodeQL and Gitleaks controls, and the CRS private-`mktemp` repair.
- Replaced task-owned mutable-container OSV/Scorecard Action internals with
  checksum-verified release CLIs; selected exact CPython 3.12.13 with
  `check-latest: false`; and bound CodeQL to its linked tool bundle.
- Added English/German CI-security documentation and documentation-index links.
- Hardened the `test-common.yml` execution envelope while retaining the
  dynamic, non-empty corpus and Apache-common-selection contract already on
  `master`; no fixed catalog count is reintroduced.
- The current local CI-security suite contains sixty-four positive and negative
  tests. They cover the original contracts plus semantic workflow controls,
  strict OSV evidence/group coverage, downloader containment, and the CRS
  temporary-path regression.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Current reconciliation: `make test-ci-security-contract test-change-record-contract test-workflow-action-pins test-workflow-contract` with external roots | 0 | 65 CI-security tests, 4 Change-Record tests, 21 immutable Action-pin tests, and 2 dynamic common-structure tests passed against the reconciled candidate. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0/build/pr27-reconciliation.iwDakV` |
| Current reconciliation: NGINX and PCRE2 archive/provenance regression modules | 0 | All 15 missing/malformed/mismatch/legitimate-control archive tests passed; the master release tag, exact asset, and required SHA-256 contract remains intact. | Same approved run |
| Current reconciliation: direct Action-pin, CI-security, CI-security-evidence, Change-Record checks and Python compile | 0 | All four contracts passed; compile used the registered external pycache after a protected-worktree write attempt was rejected by the environment. | Same approved run |
| Current reconciliation: `make lint` with explicit Framework and external roots | 0 | Shell/Python checks, 65 CI-security, Action-pin, dynamic workflow, documentation, catalog, and diff checks passed. | Same approved run |
| Historical candidate evidence below | n/a | The following earlier rows are retained for traceability only and are not exact-head merge evidence for the reconciled candidate. | Earlier retained task evidence |
| Focused Framework CI-security suite | 0 | All sixty-four local positive/negative contract, semantic-workflow, strict-OSV-evidence, downloader-containment, lock-path, and CRS-temp-path tests passed. | `20260718T084030Z-expand-framework-ci-security-be8fb24d` |
| `make test-ci-security-contract` | 0 | The same sixty-four CI-security tests passed through the Framework target. | Same task run |
| Semantic workflow-evidence checker | 0 | The task-owned source commit satisfies exact-head, artifact/channel, cache, reachability, and OSV evidence constraints. | Same run |
| `make check-documentation` | 0 | Documentation links, variable docs, path references, and Change-Record contract passed for the local candidate at that point. | Same run |
| `make lint` | 0 | Framework lint completed, including Python compilation, CI-security tests, workflow YAML, security data-flow, CRS, and documentation checks. | Same run |
| actionlint with locked ShellCheck | 0 | All 12 tracked workflows passed. | Same run |
| zizmor over `.github` | 0 | No reportable findings; zizmor reported 19 offline-tool suppressions. | Same run |
| zizmor unsafe fixture | 14 expected | Rejected dangerous trigger and PR-title interpolation. | Same run |
| Ruff lint and format check | 0 | Task-owned CI-security Python scope passed with a task-owned cache directory. | Same run |
| Locked tool downloader and scanner smoke controls | 0 | Locked release assets and the OSV/Scorecard smoke controls passed without checkout writes. | Earlier retained task evidence; not a substitute for final-head remote evidence. |

## Security impact

This is CI/security hardening, not a connector-runtime remediation. The
original mutable Action path is replaced by a lock-enforced immutable SHA
contract. The discovered mutable Docker images inside the OSV and Scorecard
Actions are not retained: both scanners run only after their independently
verified release binary is fetched to runner-temporary storage. Positive
controls cover current workflows and the safe zizmor fixture; the negative
control proves that a dangerous trigger plus untrusted interpolation is
rejected. Direct download validation covered raw-binary and archive policies.
The PR OSV control compares exact-base and exact-head reports and fails only
for newly introduced vulnerability groups; its retained evidence is size-,
regular-file-, and JSON-validated. The local follow-up adds semantic
exact-head enforcement for CodeQL and Gitleaks, strict OSV group coverage, and
runner-root evidence containment. The finalized focused source-diff assessment
confirmed no High or Critical finding; it remediated three Medium/P2 semantic
reachability and OSV-base-availability defects with regression coverage.

## Documentation and runtime evidence

Added the paired CI-security guide and linked it from both documentation
indexes. No connector runtime or lifecycle evidence was collected or claimed;
the observed evidence is static CI/source validation.

## Checks not run

- Local Pyright: pending remediation or an available local Node.js runtime; the
  observed local `node --version` result was unavailable. Declaring pinned CI
  setup does not substitute for observing the final remote check.
- Final-candidate remote evidence: task-owned source commit
  `768a06b5b734547f8213cc6918c26ef4a8ef9f67` and this documentation
  reconciliation require an intentional normal task-branch push, after which
  GitHub-hosted PR workflows (including CodeQL, Dependency Review, Gitleaks,
  OSV, Scorecard, and workflow/quality checks) must be tied to that exact head.
  Current remote PR evidence applies only to `5b2a26a...`.
- External governance: the applicable dependency graph/Dependabot result and
  SonarQube Cloud quality gate require their normal external evidence on the
  final PR head. The separately tracked SonarQube limitation is not resolved
  by these local documentation or source checks.

## Limitations and residual risk

GitHub repository-level Actions defaults, SHA-enforcement settings, branch
protection, Dependabot alerts, and SonarQube Cloud configuration are external
governance controls and are not changed by this Framework-only task. The
current SonarQube Cloud failure remains separately tracked. Full-history
Gitleaks and scheduled OSV scans are intentionally advisory until findings are
triaged.

## Final diff and review status

The published remote history on `agent/expand-framework-ci-security` currently
ends at `66d90872cfc0125536267d574b776d2e88d26b23`. A normal, non-rewriting
merge of Framework master `9954b99a31fab0006cdf903ab477c8158c50fea8` is under
local reconciliation. Its additive resolution retains the current NGINX
release-tag/asset/required-SHA-256 tuple, PCRE2 digest enforcement, the
independent full-SHA Action-pin checker, and the dynamic common-structure
contract; #27 adds its scanner/evidence controls rather than replacing them.
The candidate still requires an explicit scoped diff review, normal commit and
push, local/remote/PR-head equality, fresh remote CI and SonarCloud evidence,
reviews, and review-thread verification. There is no Framework merge, Parent
gitlink update, Parent product/workflow change, or MRTS change. This remains a
Draft PR and is not a `verified_pr` delivery state.
