# Private Sonar cache comparison and diagnostic visibility

**Language:** English | [Deutsch](20261109-05-private-sonar-cache-visibility.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261109-05-private-sonar-cache-visibility |
| UTC date | 2026-11-09 |
| Framework base revision | d521ea718149e6b5fc719a0dc4fecf07eb733e7f |
| Issue or pull request | Framework PR #169 |

## Motivation and problem statement

The hosted analysis retains unresolved parsing gaps despite verbose logging and a passing Gate. An overlong physical log line currently retains severity and parser-marker counts while skipping location and signal extraction. These observations do not identify a cache cause or bind an unassociated document limit to a source.

## Affected components and security boundaries

The Framework owns the private action executable, offline tests and this paired record. The candidate leaves existing callers, source-hash admission, generated views, Parent and MRTS unchanged. Raw scanner data remains private to the runner and is deleted.

## Acceptance criteria

Use a new empty private filesystem analysis cache for each invocation without restoring it. Preserve all four validated analysis profiles and the original 23 controls. Publish only bounded numeric or enum facts; unsupported event formats and causal translation-unit identities remain unknown.

## Alternatives considered

Project settings, paid profile edits, analysis-depth changes, exclusions, caller-provided cache paths, larger unbounded log buffers and association by adjacent path mentions were rejected. Changing cache storage tests a hypothesis; it does not establish the cause of earlier gaps.

## Implementation decision

After exact caller-argument validation, the wrapper creates a new private cache directory and appends fixed `sonar.cfamily.analysisCache.mode=fs` and `sonar.cfamily.analysisCache.path` settings. The path must be safe for the pinned action's argument tokenizer. Existing entries and aliases are rejected. The cache survives the scanner invocation and is removed with the existing private-run cleanup, including failure paths. The scanner download cache remains separate. The settings follow the [Cloud CFamily cache documentation](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/languages/c-family/customizing-the-analysis#analysis-cache).

CFamily version extraction accepts a complete recognized logger payload with four bounded decimal components. Missing or conflicting observations remain explicit. Fixed-memory tracking reports literal markers and decoder loss on overlong lines without publishing their contents or creating source bindings. Two existing SnakeYAML class literals map to fixed library enums; these do not identify JSON or IaC sensor ownership. Separate context-reset counts and document-binding reason counts explain recognized boundaries without reusing an expired association. Existing ROOT/CAUSE, inventory, line and byte limits remain enforced.

## Changed files and tests

The candidate changes `.github/actions/sonar-private/main.cjs`, its diagnostics regression test and this paired record. Five new groups cover real cache lifecycle, cache/path denial, numeric version observations, late overlong markers and exception/binding visibility. Existing profile tests deny cache overrides, and existing timeout/overflow tests create a cache before exercising cleanup. The real-Git regression can select an explicit source root when the test copy is outside a Git checkout.

## Commands and results

Node 24 syntax checks passed for both JavaScript files. The full offline candidate suite passed 28 tests with zero failures or skips. All original 23 groups remain, including the 10,000-identity and 50,000-repeat subprocess with its hard 2500 ms deadline. The first measured suite completed in approximately 1.59 seconds; its adversarial group completed in approximately 586 ms. No canary appeared in the test output. Exact candidate JavaScript postimages passed Secrets qualification.

## Security impact

The official action and scanner pins, signature verification, token allowlist, sequential bootstrap, process-group cleanup and cumulative 128 MiB raw-capture limit remain unchanged. Source scope, native inputs, language standards, analysis depth and Gate requirements are preserved. Configured empty-cache and verbose facts are distinguished from observed analyzer facts. No raw snippets, unknown paths or exception bodies are emitted; `diagnosis_complete` remains false.

## Documentation and runtime evidence

This record describes a private candidate and offline evidence. Tests ran zero scanner quality analyses and collected no connector runtime evidence. Publication and exact immutable commit/main-hash identity are pending. A separate later caller migration must freeze the actually published action through normal admission and generation contracts.

## Checks not run

The candidate has not run in hosted CI. Current-head Cloud readback, observed cache reuse, exact deployed CFamily version and causal closure of Shell, JSON and CFamily gaps remain unverified. No project or quality-profile setting was changed.

## Limitations and residual risk

Empty private cache storage can increase runtime and disk use. Literal overlong markers indicate discarded evidence, not parser causes or source ownership. No new causal translation-unit grammar is introduced. The current document limit remains unbound unless the original strict event grammar directly establishes a source. Offline success does not prove a hosted zero-issue result.

## Final diff and review status

The candidate is prepared for local diff and independent review. It has not been copied into the Framework checkout, published or selected by callers. Overall integration remains pending.
