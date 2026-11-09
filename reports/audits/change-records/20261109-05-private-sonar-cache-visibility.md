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


The follow-up adds at most eight document-limit association facts from a strict native three-event sequence: inventory-bound parse WARN, immediately following DEBUG limit details, and immediately following DEBUG ParseException stack naming the identical canonical file. The stack must include both expected IaC conversion/analyzer frames and stay within 32 lines and 16 KiB. Missing, reordered, unrelated, conflicting, truncated, decoder-loss or over-budget input resets the sequence; read failure never finalizes it. Explicit logger/thread identities must match and are discarded. Absent identities yield only `SEQUENCE_CORRELATED`; matched identities yield `LOGGER_THREAD_MATCHED`. Existing `UNBOUND` observations, severity counts and `diagnosis_complete=false` remain unchanged. The public [IaC logging implementation](https://github.com/SonarSource/sonar-iac/blob/9ab7daea8377cb59a27c89cabb223916263c3480/iac-common/src/main/java/org/sonar/iac/common/extension/analyzer/AbstractAnalyzer.java#L122) motivates this prospective sequence; it does not identify the deployed build.

The numeric CFamily parser now optionally accepts exactly one space and a parenthesized 40-character lowercase hexadecimal build suffix, discarding that suffix. All other tails remain rejected. The shape appears in [firsthand scanner logs](https://community.sonarsource.com/t/random-failure-of-sonarqube-throwing-java-lang-nullpointerexception-exception/141145); it is not a current-host version claim.

## Changed files and tests

The historical published cache payload added five groups for cache lifecycle, cache/path denial, numeric versions, overlong markers and exception visibility. The present follow-up changes only the action executable, its diagnostics test and this paired record. Five further groups preserve all preceding 28 groups and cover the three-event sequence, missing/reordered/conflicting context, bounded input, privacy and the strict version suffix. The real-Git test retains its native repository root for integrated validation; the explicit source-root override is confined to private candidate tests.

## Commands and results

Hosted revision `9a9c1b6e95950f6afc50537ee586db4470907dff` completed 19 CI checks successfully with three conditional skips. All five Gate conditions passed; no OPEN or ACCEPTED issues or hotspots remained. The server reported 167 FIXED findings and the existing 26 false-positive classifications. S5906 and S7780 both closed as fixed through source corrections. These hosted results describe that preceding revision, not this diagnostic follow-up.

The reviewed private candidate passed 33 Node tests without failures or skips in 1847.302 ms; its 10,000-identity/50,000-repeat adversarial group completed in 841.365 ms within the hard 2500 ms deadline. Actual integrated syntax checks passed for both JavaScript files; Node passed all 33 groups without failures or skips in 1683.006 ms, with the source-root override unset. Its adversarial group completed in 726.114 ms within 2500 ms. Canonical freshness, maintenance freshness and the main security contract passed. The 29 admission methods produced 27 passes and two errors: both rejected the changed implementation against the still-frozen historical role hash. Actual composite admission rejected the same mismatch; this is a current transitional failure, not a completed 20-composite/one-Node pass. No role or test expectation was weakened. The historical 28-group integrated cache validation and the separate full-native result of 19 cohorts and 703 methods at `d521ea718149e6b5fc719a0dc4fecf07eb733e7f` remain scoped to their earlier source revisions.

## Security impact

The official action and scanner pins, signature verification, token allowlist, sequential bootstrap, process-group cleanup and cumulative 128 MiB raw-capture limit remain unchanged. Source scope, native inputs, language standards, analysis depth and Gate requirements are preserved. Configured empty-cache and verbose facts are distinguished from observed analyzer facts. No raw snippets, unknown paths or exception bodies are emitted; `diagnosis_complete` remains false.

## Documentation and runtime evidence

Normal commit and push published `5181cedba82af8d83de4b123080fb80ff414de15` on retained ref `refs/heads/codex/preparation-private-sonar-cache-20261109`. This published ref is a runtime dependency of pinned callers and must survive later squash and task-branch cleanup. The historical published main SHA-256 is `a13995cf0b52e3ccc1bb0476ed3dad290e8a9e1bf88d8397cc77afaf1ee06084`; action metadata is unchanged. The separately reviewed caller migration freezes that published identity through normal admission and native generation contracts. Offline tests ran zero scanner quality analyses and collected no connector runtime evidence.

## Checks not run

Publication of this follow-up as a new immutable wrapper, caller rebinding and exact-head hosted verification remain pending. The current role still names the earlier published payload; whole-source checks that compare its frozen implementation hash can reject this transitional source. The role is not relaxed in this change. Matching-target full-native verification and causal closure of Shell, JSON and CFamily gaps remain pending. No project or quality-profile setting was changed.

## Limitations and residual risk

Empty private cache storage can increase runtime and disk use. Literal overlong markers indicate discarded evidence, not parser causes or source ownership. The existing document-limit signal remains unbound; additional sequence correlation is not causal certainty. No mapping from the public `2.27-SNAPSHOT` source to deployed `2.27.0.24646` is established. The strict optional version suffix is supported by public scanner logs, not an observed current-host version. Offline success and a passing Gate do not prove parser completeness.

## Final diff and review status

The historical payload and caller migration were independently reviewed and normally published. The new private candidate was independently reviewed before integration. Local follow-up validation is recorded above with its current transitional admission failures. New immutable publication, caller rebinding, passing whole-source admission and hosted causal verification remain pending. Overall integration and analyzer-gap closure are not claimed.
