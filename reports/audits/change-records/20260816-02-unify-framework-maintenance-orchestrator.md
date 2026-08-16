# Change record: 20260816-02-unify-framework-maintenance-orchestrator

**Language:** English | [Deutsch](20260816-02-unify-framework-maintenance-orchestrator.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260816-02-unify-framework-maintenance-orchestrator` |
| UTC date | `2026-08-16` |
| Framework base revision | `bd0dbdbd0a28e0705c123963209d6e5e410bacad` |
| Issue or pull request | Task-owned [Framework Draft PR #83](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/83). No merge or master write is authorized by this record. |

## Motivation and problem statement

The common-version maintenance flow could apply a component selector to the
whole registry. A scheduled or manually dispatched run therefore risked
omitting go-ftw, Albedo, and canonical CI pins when a runtime/source component
was selected. Review-only observations also had no single typed plan shared by
the resolver, validator, publisher, and issue lifecycle.

## Affected components and security boundaries

The Framework-only documentation describes the common-version orchestrator,
canonical runtime series, generated views, typed review plans, and trusted
issue reconciliation. It covers `ci/tools/resolve-canonical-maintenance.py`,
the common-version workflow, and the related CI/security contracts without
granting documentation any independent pin authority. The relevant boundary is
the transition from official upstream metadata to generated files and the
trusted default-branch issue writer; pull-request jobs remain read-only. Parent,
connector-runtime, and MRTS behavior are outside this record.

## Acceptance criteria

1. English and German variable documentation says that go-ftw, Albedo, and all
   canonical CI pins are checked in every scheduled, dispatched, full, and
   component-scoped run.
2. The documentation states that `--component` filters only additional
   runtime and source components and that runtime series, release-root, and
   base tuples are
   explicit, including the separate HAProxy HTX line.
3. The workflow-security guide documents the deterministic shared plan,
   generated-view checks, trusted issue reconciliation, fail-closed hash and
   completeness checks, and no auto-merge behavior in both languages.
4. This Change Record has an equivalent German companion and both files remain
   free of credentials or transient runner data.

## Alternatives considered

- Keeping separate go-ftw, Albedo, and CI-pin workflows was rejected because a
  component-scoped common run would still produce an incomplete maintenance
  decision.
- Letting documentation retain the old `not_applicable` descriptions was
  rejected because it would contradict the mandatory global resolver scope.
- Giving pull-request jobs issue-write permission was rejected; reconciliation
  belongs only to a trusted default-branch job consuming the validated plan.

## Implementation decision

The paired reference pages now describe one orchestrator and one deterministic
plan. They distinguish canonical `common.sh` values from generated runtime,
Python, workflow, and CRS views; describe explicit Lighttpd/HAProxy series and
the independent HTX tuple; and record the fixed Draft-PR/no-auto-merge
boundary. Manual-review issues are described as a trusted default-branch
reconciliation step, not as a side effect of resolver or pull-request jobs.

## Changed files and tests

- `docs/reference/variables.md` and `.de.md` document the unified scope,
  explicit series, artifact/platform identity, and generated-plan behavior.
- `docs/github-actions-workflow-security.md` and `.de.md` document the shared
  planner, plan revalidation, issue writer boundary, and terminal fail-closed
  states.
- This English/German Change Record pair documents the Framework-only change.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `python -m unittest -v` (11 unified-maintenance, pin, resolver, reconciler, and fetcher modules) | `0` | 119 tests passed. | Hash-locked task virtual environment |
| `python -m unittest -v tests.ci_security.test_ci_security_contract tests.ci_security.test_framework_ci_security_contract` | `0` | 50 CI-security contract tests passed. | Hash-locked task virtual environment |
| `python -m unittest -v` (seven runtime/component provenance, sync, lock, download, and Traefik modules) | `0` | 88 regression tests passed. | Hash-locked task virtual environment |
| `python -m unittest` (six historical provenance modules, including ModSecurity v3 and Sonar contracts) | `0` | 108 tests passed; one intentionally skipped. | Hash-locked task virtual environment |
| `ci/tools/check-common-versions.py --validate-canonical`, `sync-runtime-components.py --check`, canonical Python/Workflow pin checks, and CI-security-contract check | `0` | Canonical inputs, generated views, runtime inventory, and CI contract passed. | Hash-locked task virtual environment |
| Documentation link, variable, workflow-YAML, and Change Record checks | `0` | All checked documentation contracts passed. | Hash-locked task virtual environment |
| Checksum-locked `actionlint` with `shellcheck`, plus `zizmor --offline .github` | `0` | Actionlint passed; Zizmor reported no findings (41 documented suppressions). | Task evidence directory |
| Checksum-locked `ruff check` and `ruff format --check` for the CI-security quality target set | `0` | Lint and formatting passed after mechanical remediation. | Task evidence directory |
| `git diff --check` and `bash -n ci/lib/common.sh` | `0` | Whitespace and shell syntax passed. | Task worktree |

## Security impact

The documentation records a security-relevant scope correction: mandatory
global checks cannot be bypassed with a runtime/source component selector, and
issue writes are confined to a trusted default-branch job consuming a typed,
hash-bound plan. No credentials, permissions, auto-merge capability, or
untrusted write path is introduced by the documentation.

The final provenance review also bound ModSecurity v3's upstream repository
identity before any network lookup: the candidate URL is canonicalized and
must match an immutable digest anchor for the fixed official identity. The
foreign-repository/no-network and malformed-anchor controls pass locally.

The follow-up remediation bounds canonical Python platform validation,
confines `--common-sh`, review-plan, and runtime-root reads to their approved
trust boundaries, and requires the exact official HTTPS HAProxy source root
before requests. Independent review found no remaining high, critical, or
medium issue in this delta; exact-head hosted evidence remains required.

## Documentation and runtime evidence

The English and German reference pages and workflow-security guides are updated
as a synchronized pair. Local orchestration, pin-generation, runtime,
documentation, and CI-security-contract validation has passed in the
hash-locked task virtual environment. The trusted hosted issue writer remains
confined to its default-branch workflow path and is intentionally not invoked
locally.

## Checks not run

- The original Draft-PR head
  `387722449e3b95dd81b11cad5cd4a665a7d6971b` ran hosted checks and did not
  qualify: actionlint, zizmor, immutable-action, and Ruff checks failed, and
  SonarQube Cloud reported Quality Gate `ERROR` with 68 New Issues. Those
  results are retained as remediation evidence and are not reused for the
  follow-up head.
- The follow-up remediation head created after this record requires its own
  exact-head GitHub Actions and SonarQube Cloud checks before the PR can be
  considered verified.
- A local read-only full upstream plan cannot currently establish the same
  GitHub API evidence because unauthenticated API requests were rate-limited;
  the workflow passes its least-privileged `github.token` only to its four
  resolver steps. No local token was copied or persisted.
- No GitHub issue, merge, Parent gitlink, or MRTS action has been performed.

## Limitations and residual risk

The hosted App token, default-branch protection, GitHub API behavior, and
SonarQube Cloud analysis still require the exact follow-up-head trusted CI run
and human review. Those controls are not weakened or simulated locally.

## Final diff and review status

The follow-up task diff covers the shared maintenance workflow, canonical pin
authority and generated views, runtime series projections, security contracts,
regressions, paired documentation, and this Change Record. Local whitespace,
link, bilingual, Change Record, runtime, CI-security-contract, Actionlint,
Zizmor, and Ruff checks pass after remediation. An independent security-diff
review found no reportable high, critical, or medium issue. The historical
provenance suite passed with 108 tests (one intentionally skipped), including
the ModSecurity v3 foreign-repository/no-network regression. No credentials,
tokens, raw logs, or sensitive payloads are recorded; hosted verification of
the follow-up exact head remains pending.
