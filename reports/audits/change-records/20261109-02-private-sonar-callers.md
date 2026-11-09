# Immutable private Sonar callers

**Language:** English | [Deutsch](20261109-02-private-sonar-callers.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261109-02-private-sonar-callers |
| UTC | 2026-11-09 |

## Motivation and problem statement

Hosted full-scope scans expose parser omissions without adequate causal details. The reviewed private diagnostic action must run from a previous published immutable source commit. The existing action-source checker also incorrectly sends its Node metadata through a composite-only renderer.

## Affected components and security boundaries

Framework owns its scanner caller, dedicated native data role, generated lock, source inspectors and regression tests. Parent owns its separate scanner caller and non-executing projection logic. The Parent protected five-source closure imports no Framework executable code. MRTS remains unchanged.

## Acceptance criteria

Freeze the published action at `0f3889fd2f9d6f8d4fc6c3ec82d44f6859ed32f3`. Preserve upstream scanner identity/version, signature verification, complete analysis scope, Framework cfd5 fixture, Parent standards/projects/Gate semantics and all 23 integration projections. Preserve all composite source linting and reject unreviewed Node/Docker actions or metadata aliases.

## Alternatives considered

PR-head local token execution, broad same-owner exceptions, fabricated release tags, raw public DEBUG, scope reduction and executable imports into the Parent protected publisher are rejected.

## Implementation decision

The dedicated source role is separate from release-managed action repositories. Two complete approved scanner mappings permit staged migration: the original official action or the exact reviewed remote wrapper with the same inputs. The source expander preserves only the frozen Parent scanner role. The Parent publisher validates its exact data block locally and leaves its SHA unchanged while projecting the integration revision. Node metadata and main bytes must match the independently reviewed hashes; every other action still receives actual composite actionlint/ShellCheck validation. Parent summaries retain analysis outcomes and use the wrapper's bounded identity facts instead of exporting report URLs.

The separate Parent security-tools updater accounts for the governed official upstream only after validating the complete frozen caller. Checkout and tool updates preserve its exact bytes. Changes to the currently fixed Sonar upstream are intentionally rejected before any write and require a separate reviewed contract change; the central SonarSource lock and resolver governance remain in place.

## Changed files and tests

Scanner workflows, Framework native data/lock producer, whole-call contract module, workflow/source checkers, Parent projection/fixtures and focused regressions. The previously published action implementation and its 23 offline tests are unchanged by this caller integration. Standard case inventory is unchanged.

The native lock producer admits only the exact previous reviewed role for migration directly to the newly frozen role. Diagnostic YAML duplicates, merge keys, non-scalar fields and altered shapes fail before loading or replacement. Both independent CI contract passes validate the whole canonical scanner step; ordinary release and repository checks remain active. Genuine proposed-tree fixtures copy the required package closure.

Two inert main-source Shell fixtures differ only in spacing after the read/write redirection operator. One behavioral regression runs both with sh and bash against fresh regular files and verifies output, exit and descriptor closure. The maintained scheduler receives the same single whitespace change. Hosted analysis must establish whether spacing changes parser behavior; syntax validity alone does not establish that cause.

## Commands and results

For the current frozen-role update, all 14 native canonical-producer tests passed, including migration, idempotence and malformed-role controls; native canonical generation exited 0. Earlier results below describe their original source revisions. Current complete validation and maintenance-view freshness are pending. The preceding full native lint completed 703 methods without test failures or errors but exited 2 because its output-root invocation violated the native output contract; it is not a successful full lint run.

Native canonical generation and freshness checks exited 0. Focused checks passed 4 caller, 25 source/Node-admission, 14 canonical pin, 20 Sonar boundary and 9 workflow security tests. Actual installed actionlint v1.7.12 and ShellCheck v0.11.0, matching the native pins, validated all 20 composite sources; the exact reviewed Node source was separately accounted. Native workflow, Change Record, link and bilingual checks passed. Genuine immutable Git-object fixtures fixed three stale projection tests. The complete Parent cohort ran 59 methods: 42 passed and 17 rejected the current unmatched Parent/Framework integration pins. Those 17 require the synchronized committed-target cycle and are not passes.

The complete updater cohort passed all 56 methods, including all five new role/atomicity controls and the real proposed-tree integration. The native maintenance-view producer refreshed ten existing source-binding digests and the generated archive; its freshness check passed. All 100 default cases and 80 execution selectors remain unchanged. The archive retains every existing definition and adds 16 authentic regression methods, increasing its on-demand definition count from 8292 to 8308. Native extraction identity and retained native definitions are unchanged. Parent-owned Python 3.14.4 independently passed actual workflow/upstream inventory and frozen-change denial without Framework executable imports. One existing HTTPError test fixture emitted a ResourceWarning; it was not suppressed.

## Security impact

Token access remains confined to a remote immutable action. Wrong pins, metadata hashes, implementations, owner profiles, scanner inputs, aliases, symlink sources and extra role occurrences fail closed. No hook, permission, compiler warning, test, analysis profile or Gate is disabled or weakened. Raw scanner output remains private under the separately reviewed action contract.

## Documentation and runtime evidence

This paired record describes preparation and offline validation. Hosted diagnostics and current-head quality checks remain independent evidence; no connector runtime or deployment is claimed.

## Checks not run

Synchronized committed-target Parent/Framework checks, current-source full validation, current private diagnostics and exact-head quality/readback remain pending. An earlier hosted private Framework report remained incomplete and did not close the parser omissions. Local syntax/lint evidence does not replace the later hosted checks.

## Limitations and residual risk

The action's private diagnostic facts may still report unknown causes. Passing a Gate does not establish parser completeness, and similar Parent/Framework counters do not prove shared causes. The two repositories require separate publication and integration verification.

## Final diff and review status

Focused offline validation and independent source review are complete. Publication, committed-target integration checks and hosted diagnostic verification remain pending. Analyzer gap closure is not claimed.
