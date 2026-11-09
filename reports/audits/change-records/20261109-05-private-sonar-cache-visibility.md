# Private Sonar cache comparison and diagnostic visibility

**Language:** English | [Deutsch](20261109-05-private-sonar-cache-visibility.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261109-05-private-sonar-cache-visibility |
| UTC date | 2026-11-09 |
| Framework base revision | d521ea718149e6b5fc719a0dc4fecf07eb733e7f |
| Published action revision | 5181cedba82af8d83de4b123080fb80ff414de15 |
| Issue or pull request | Framework PR #169 |

## Motivation and problem statement

The hosted analysis retains unresolved parsing gaps despite verbose logging and a passing Gate. An overlong physical log line currently retains severity and parser-marker counts while skipping location and signal extraction. These observations do not identify a cache cause or bind an unassociated document limit to a source.

## Affected components and security boundaries

The Framework owns the private action executable, offline tests and this paired record. The published payload preserved existing callers and generated views. The separate reviewed caller migration now binds only its published identity and exact implementation hash. Parent retains its own data-only contract; MRTS is unchanged. Raw scanner data remains private to the runner and is deleted.

## Acceptance criteria

Use a new empty private filesystem analysis cache for each invocation without restoring it. Preserve all four validated analysis profiles and the original 23 controls. Publish only bounded numeric or enum facts; unsupported event formats and causal translation-unit identities remain unknown.

## Alternatives considered

Project settings, paid profile edits, analysis-depth changes, exclusions, caller-provided cache paths, larger unbounded log buffers and association by adjacent path mentions were rejected. Changing cache storage tests a hypothesis; it does not establish the cause of earlier gaps.

## Implementation decision

After exact caller-argument validation, the wrapper creates a new private cache directory and appends fixed `sonar.cfamily.analysisCache.mode=fs` and `sonar.cfamily.analysisCache.path` settings. The path must be safe for the pinned action's argument tokenizer. Existing entries and aliases are rejected. The cache survives the scanner invocation and is removed with the existing private-run cleanup, including failure paths. The scanner download cache remains separate. The settings follow the [Cloud CFamily cache documentation](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/languages/c-family/customizing-the-analysis#analysis-cache).

CFamily version extraction accepts a complete recognized logger payload with four bounded decimal components. Missing or conflicting observations remain explicit. Fixed-memory tracking reports literal markers and decoder loss on overlong lines without publishing their contents or creating source bindings. Two existing SnakeYAML class literals map to fixed library enums; these do not identify JSON or IaC sensor ownership. Separate context-reset counts and document-binding reason counts explain recognized boundaries without reusing an expired association. Existing ROOT/CAUSE, inventory, line and byte limits remain enforced.

## Changed files and tests

The published payload changes `.github/actions/sonar-private/main.cjs`, its diagnostics regression test and this paired record. Five new groups cover real cache lifecycle, cache/path denial, numeric version observations, late overlong markers and exception/binding visibility. Existing profile tests deny cache overrides, and existing timeout/overflow tests create a cache before exercising cleanup. The real-Git regression can select an explicit source root when the test copy is outside a Git checkout; actual integrated validation left that override unset.

## Commands and results

Hosted caller revision `4e7f359ace6a8fed9bbe7e692fe86d3c7dd8472c` completed CI and server analysis; all five Gate conditions passed and no hotspots remained. The preceding S5906 finding closed as fixed. One new S7780 finding requested String.raw for an escaped backslash in the cache-path denial test. This source correction uses the equivalent raw suffix with the same seven codepoints and preserves every assertion and all 28 test groups. The action implementation, metadata and caller pin are unchanged; exact-head hosted confirmation of this style correction remains pending.

Node 24 syntax checks passed for both JavaScript files. Actual integrated validation passed 28 tests with zero failures or skips in 1631.655 ms; the adversarial group completed in 619.873 ms within its hard 2500 ms deadline. All original 23 groups remain, including the 10,000-identity and 50,000-repeat subprocess. No canary appeared in the test output. Exact integrated JavaScript postimages passed Secrets qualification. The separate full-native result of 19 cohorts and 703 methods belongs to the earlier committed `d521ea718149e6b5fc719a0dc4fecf07eb733e7f` and does not establish this payload's hosted behavior.

## Security impact

The official action and scanner pins, signature verification, token allowlist, sequential bootstrap, process-group cleanup and cumulative 128 MiB raw-capture limit remain unchanged. Source scope, native inputs, language standards, analysis depth and Gate requirements are preserved. Configured empty-cache and verbose facts are distinguished from observed analyzer facts. No raw snippets, unknown paths or exception bodies are emitted; `diagnosis_complete` remains false.

## Documentation and runtime evidence

Normal commit and push published `5181cedba82af8d83de4b123080fb80ff414de15` on retained ref `refs/heads/codex/preparation-private-sonar-cache-20261109`. This published ref is a runtime dependency of pinned callers and must survive later squash and task-branch cleanup. The reviewed main SHA-256 is `a13995cf0b52e3ccc1bb0476ed3dad290e8a9e1bf88d8397cc77afaf1ee06084`; action metadata is unchanged. The separately reviewed caller migration freezes that published identity through normal admission and native generation contracts. Offline tests ran zero scanner quality analyses and collected no connector runtime evidence.

## Checks not run

Exact-head hosted confirmation of the S7780 source correction and causal closure of Shell, JSON and CFamily gaps remain pending. Offline checks and a passing Gate do not establish cache reuse or parser completeness. No project or quality-profile setting was changed.

## Limitations and residual risk

Empty private cache storage can increase runtime and disk use. Literal overlong markers indicate discarded evidence, not parser causes or source ownership. No new causal translation-unit grammar is introduced. The current document limit remains unbound unless the original strict event grammar directly establishes a source. Offline success does not prove a hosted zero-issue result.

## Final diff and review status

The payload and caller migration were independently reviewed and normally published. Publication and hosted confirmation of this test-style follow-up, the matching Parent target and remaining causal diagnostic verification are pending. Overall integration and analyzer-gap closure are not claimed.
