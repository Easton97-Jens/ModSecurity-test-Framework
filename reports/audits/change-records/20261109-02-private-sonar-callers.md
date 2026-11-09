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

Hosted candidate validation exposed three missing-package errors that an ambient local Python path had masked. Framework now launches the same trusted checkers and canonical producer in isolated child interpreters, binding imports to the private proposed tree. Both copied package inputs must remain regular and byte-identical to trusted read-only sources; missing or altered copies fail before execution. Inherited Python paths are removed, bytecode writing is disabled, and the publisher write allowlist is unchanged. The existing closure regression now executes the real native boundaries and tests missing and altered copies; current clean-context validation remains required.

## Changed files and tests

Scanner workflows, Framework native data/lock producer, whole-call contract module, workflow/source checkers, Parent projection/fixtures and focused regressions. The previously published action implementation and its 23 offline tests are unchanged by this caller integration. Standard case inventory is unchanged.

The native lock producer admits only the exact previous reviewed role for migration directly to the newly frozen role. Diagnostic YAML duplicates, merge keys, non-scalar fields and altered shapes fail before loading or replacement. Both independent CI contract passes validate the whole canonical scanner step; ordinary release and repository checks remain active. Genuine proposed-tree fixtures copy the required package closure.

Two inert main-source Shell fixtures differ only in spacing after the read/write redirection operator. One behavioral regression runs both with sh and bash against fresh regular files and verifies output, exit and descriptor closure. The maintained scheduler receives the same single whitespace change. Hosted analysis must establish whether spacing changes parser behavior; syntax validity alone does not establish that cause.

## Commands and results

Hosted revision `ce1039a90f5f2fa0fb7c06634157b3fbcf6c5639` completed scanner and server processing with the expected project, fixture and actual verbose mode. Its Gate passed all five conditions and had no hotspots; all seven preceding Python findings closed as fixed. Two new complexity findings in the canonical common-source checker required the helper extractions. Its separate workflow-security job still failed three isolated candidate imports; the clean local reproduction confirmed those three errors before the import-boundary fix. Four genuine clean-context methods then passed. The affected matrix below preceded the committed follow-up evidence recorded next.

Committed follow-up `d521ea718149e6b5fc719a0dc4fecf07eb733e7f` passed the complete native lint target: 19 cohorts and 703 methods, with no failures, errors, skips or ResourceWarnings. The outer PYTHONPATH was removed; the native Makefile supplied its explicit Framework package bindings. Hosted checks finished with 19 successes and three conditional skips. Server readback confirmed the same revision, verbose mode, all five Gate conditions passing, no hotspots, both complexity findings closed as fixed, one open S5906 assertion-style finding and no accepted findings. The assertion-only follow-up replaces the equivalent negated membership assertion with assertNotIn, preserving both operands and its failure message without adding a test method. Its exact-head hosted confirmation remains pending; the full-native evidence belongs to the committed revision above.

The same hosted diagnostic report remains incomplete: nine warnings and seven unclassified occurrences of the word token ERROR, with scanner exit 0. Those token occurrences do not establish seven fatal analysis errors. The report records 85 full translation units, 60 of 1120 functions and 443 of 19635 statements with parser errors. Both adjacent and spaced minimal Shell fixtures and the maintained scheduler still report parsing failures, so the whitespace change is not a parser fix. The migration baseline is directly identified as unparseable, but its codepoint-limit signal remains unbound. These facts establish narrower reproductions without closing the analyzer gaps.

The current follow-up passed the complete 401-method workflow-security cohort without an ambient PYTHONPATH, all 56 Parent-updater methods and 19 focused producer/caller/Shell methods, with no skips. Actual composite and Node admission, primary CI contracts, canonical and maintenance freshness, documentation checks, the 44-file hosted Ruff scope and pinned Pyright all passed; Pyright reported no errors or warnings. The existing Parent HTTPError fixture still emitted one ResourceWarning, without suppression. The native maintenance producer preserved the inventory, all 100 default cases and 80 selectors, every archived definition and the count of 8316; it added or removed no methods. Earlier results below describe their original source revisions.

The earlier local full-native run for the hosted revision used the correct output root and exited 0: 19 cohorts, 703 methods, no test failures, errors, skips or ResourceWarnings. Its inherited Python path nevertheless masked the three isolated import failures observed in hosted CI. A still older run completed 703 method summaries but exited 2 because its output-root invocation violated the native output contract; that historical run remains a failure. The later committed follow-up result above is separate from both historical runs.

Native canonical generation and freshness checks exited 0. Focused checks passed 4 caller, 25 source/Node-admission, 14 canonical pin, 20 Sonar boundary and 9 workflow security tests. Actual installed actionlint v1.7.12 and ShellCheck v0.11.0, matching the native pins, validated all 20 composite sources; the exact reviewed Node source was separately accounted. Native workflow, Change Record, link and bilingual checks passed. Genuine immutable Git-object fixtures fixed three stale projection tests. The complete Parent cohort ran 59 methods: 42 passed and 17 rejected the current unmatched Parent/Framework integration pins. Those 17 require the synchronized committed-target cycle and are not passes.

The complete updater cohort passed all 56 methods, including all five new role/atomicity controls and the real proposed-tree integration. The native maintenance-view producer refreshed ten existing source-binding digests and the generated archive; its freshness check passed. All 100 default cases and 80 execution selectors remain unchanged. The archive retains every existing definition and adds 16 authentic regression methods, increasing its on-demand definition count from 8292 to 8308. Native extraction identity and retained native definitions are unchanged. Parent-owned Python 3.14.4 independently passed actual workflow/upstream inventory and frozen-change denial without Framework executable imports. One existing HTTPError test fixture emitted a ResourceWarning; it was not suppressed.

## Security impact

Token access remains confined to a remote immutable action. Wrong pins, metadata hashes, implementations, owner profiles, scanner inputs, aliases, symlink sources and extra role occurrences fail closed. No hook, permission, compiler warning, test, analysis profile or Gate is disabled or weakened. Raw scanner output remains private under the separately reviewed action contract.

## Documentation and runtime evidence

This paired record describes preparation and offline validation. Hosted diagnostics and current-head quality checks remain independent evidence; no connector runtime or deployment is claimed.

## Checks not run

Synchronized committed-target Parent/Framework checks and hosted quality/readback of the assertion-only follow-up remain pending. The committed follow-up's private diagnostic report remains incomplete and does not close the parser omissions. Local syntax/lint evidence does not replace later hosted checks.

## Limitations and residual risk

The action's private diagnostic facts may still report unknown causes. Passing a Gate does not establish parser completeness, and similar Parent/Framework counters do not prove shared causes. The two repositories require separate publication and integration verification.

## Final diff and review status

Committed full-native and hosted follow-up evidence is recorded above. Publication of the assertion-only follow-up, committed-target integration checks and its exact-head hosted verification remain pending. Analyzer gap closure is not claimed.
