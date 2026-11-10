# Private Sonar cache comparison and diagnostic visibility

**Language:** English | [Deutsch](20261109-05-private-sonar-cache-visibility.de.md)


The current caller change binds only the separately published revision `9ae8ecc4f686e9cc70413e5494bc098a24eb18d7`, with main SHA-256 `3865be06f1ccfaf2c2757b0fc29bfd0ae0c0a0374aec9f09342292402d592a1b` and unchanged action metadata. The preceding role `865e4ec4fd0a745d1d125b3f43b3dd8d56b3ca7a` is admitted only for exact native lock migration; the older 5181 role remains rejected. Retain all three published runtime refs, including `refs/heads/codex/preparation-private-sonar-cfamily-attribution-20261110`. The already validated 44 integrated Node groups describe the unchanged implementation; the current binding passed 97 contract methods (including 14 producer and 29 admission methods), 11 projection methods and all 56 physical updater methods without skips. Actual source lint admitted 20 composites and the reviewed Node action. Parent-owned Python proof, primary security/native CI contracts, canonical and maintenance freshness, Ruff check/format over the 44-file scope and pinned Pyright passed; Pyright reported no errors or warnings. The updater fixture emitted one ResourceWarning (two textual occurrences), without suppression. Native generation changed exactly seven existing scalar slots, preserving all memberships and order, 100 default cases, 80 selectors and 8316 archive definitions. Earlier passing binding paragraphs describe the preceding 865 migration. Current delivery, fresh hosted caller verification and the matching committed Parent pair remain pending. Neither the Parent gitlink nor its index changes here; the matching committed Parent pair remains pending.

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261109-05-private-sonar-cache-visibility |
| UTC date | 2026-11-09 |
| Framework base revision | d521ea718149e6b5fc719a0dc4fecf07eb733e7f |
| Published action revision | 9ae8ecc4f686e9cc70413e5494bc098a24eb18d7 |
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

This follow-up replaces the ambiguous native-event separator regex with a linear single-character search, uses equivalent optional-chain guards and combines the two consecutive test pushes without changing either array. Additive CFamily attribution recognizes exact published IR-failure headers and inventory-bound paths, unbound dropped-function counts, and trusted TU/header diagnostic pairs with three fixed categories. A strict new TU or IR header resets the previous context as NEW_KNOWN_CONTEXT and starts independently on that same line. Unknown messages, envelopes, conflicts, malformed paths and capture loss remain fail-closed. Each context stays within 32 lines and 16 KiB; each fact list retains at most 128 records. Raw messages, identifiers, external paths and logger identities are discarded. Document-reset shapes contain only fixed severity, payload-class and logger-presence counters. Existing warning/error counts, UNBOUND observations and diagnosis_complete=false remain unchanged.

The prospective layouts come from [firsthand Cloud IR logs](https://community.sonarsource.com/t/c-c-taint-analysis-llvm-ir-generation-fails-with-invalid-size-request-on-a-scalable-vector-win/190312) and [TU/header diagnostics](https://community.sonarsource.com/t/cfamily-6-77-cannot-resolve-the-c-standard-library-in-the-macos-26-5-sdk/187896). The dropped-function excerpt does not establish the following path layout, so those counts remain UNBOUND. These sources do not establish that deployed 6.86.0.113840 emits the same layouts or explain this project's losses.

## Changed files and tests

Historical additions: The historical published cache payload added five groups for cache lifecycle, cache/path denial, numeric versions, overlong markers and exception visibility. The present follow-up changes only the action executable, its diagnostics test and this paired record. Five further groups preserve all preceding 28 groups and cover the three-event sequence, missing/reordered/conflicting context, bounded input, privacy and the strict version suffix. The real-Git test retains its native repository root for integrated validation; the explicit source-root override is confined to private candidate tests.

The current follow-up owns only the action executable, its native test and this paired record. The integrated 44 groups retain all prior assertions; private path adapters were reversed before integration. Metadata, caller roles, workflows, native views, 100 default cases, 80 selectors and 8316 archived definitions remain unchanged.

## Commands and results

The preceding payload integration passed both syntax checks and all 44 Node groups without failures, skips or cancellations in 3518.107122 ms, with the source-root override unset and native test paths restored. All preceding 33 groups remain; eleven additional groups cover the prospective parser, privacy, bounds, consecutive TU/IR contexts and linear rejection. The original 10,000-identity/50,000-repeat group completed in 981.77789 ms; the unchanged 500 long-space/newline pairs completed in 1475.98501 ms. Both hard 2500 ms child deadlines remain unchanged. Main CI security, canonical freshness and maintenance freshness passed. Before the current 9ae binding, the actual 29 admission methods produced 27 passes and two errors rejecting the new implementation against the unchanged published 865 role; actual composite admission exited 1 for that same frozen-body mismatch. That was a transitional failure, not a completed 20-composite/one-Node pass. No role, expectation or guard was weakened. Native documentation checks and their observed results accompany the current-source validation receipt.

The preceding hosted caller at `2fcaea1e36532c40366aab0cb41e88fd7ab335b7` passed scanner execution and all five Gate conditions and observed CFamily 6.86.0.113840. Four JavaScript findings remained OPEN there: S8786, two S6582 findings and S7778. This source follow-up addresses those expressions; no new-head hosted closure is claimed. Recovered parsing and IR losses, Shell failures and the unbound document-limit observation remain unresolved.

Historical results below describe their original source revisions, not this unpublished follow-up.

Hosted revision `9a9c1b6e95950f6afc50537ee586db4470907dff` completed 19 CI checks successfully with three conditional skips. All five Gate conditions passed; no OPEN or ACCEPTED issues or hotspots remained. The server reported 167 FIXED findings and the existing 26 false-positive classifications. S5906 and S7780 both closed as fixed through source corrections. These hosted results describe that preceding revision, not this diagnostic follow-up.

The reviewed private candidate passed 33 Node tests without failures or skips in 1847.302 ms; its 10,000-identity/50,000-repeat adversarial group completed in 841.365 ms within the hard 2500 ms deadline. Actual integrated syntax checks passed for both JavaScript files; Node passed all 33 groups without failures or skips in 1683.006 ms, with the source-root override unset. Its adversarial group completed in 726.114 ms within 2500 ms. Canonical freshness, maintenance freshness and the main security contract passed. The 29 admission methods produced 27 passes and two errors: both rejected the changed implementation against the still-frozen historical role hash. Actual composite admission rejected the same mismatch; this was the preceding transitional failure, not a completed 20-composite/one-Node pass. No role or test expectation was weakened. The historical 28-group integrated cache validation and the separate full-native result of 19 cohorts and 703 methods at `d521ea718149e6b5fc719a0dc4fecf07eb733e7f` remain scoped to their earlier source revisions.

The preceding 865 caller migration passed 97 contract methods, including 14 native-producer and 29 admission methods; 11 genuine projection methods and all 56 physical updater methods also passed. Actual source lint admitted 20 composites and the one reviewed Node action. Both JavaScript syntax checks and all 33 Node tests passed without a source-root override (0 failures, 0 skips; 1786.674 ms). Parent-owned Python independently passed its native proof. Canonical and maintenance freshness, primary security/native CI contracts, Ruff check/format over 44 files and pinned Pyright passed. The initial projection invocation failed because RUNNER_TEMP was absent; the corrected external-directory invocation passed all 11 methods without a source change. Native generation changed only one lock commit, two inventory digests and four archive scalar slots; all memberships, 100 default cases, 80 selectors and 8316 archived definitions remain unchanged. Hosted verification and the synchronized committed Parent target remain pending.

## Security impact

The official action and scanner pins, signature verification, token allowlist, sequential bootstrap, process-group cleanup and cumulative 128 MiB raw-capture limit remain unchanged. Source scope, native inputs, language standards, analysis depth and Gate requirements are preserved. Configured empty-cache and verbose facts are distinguished from observed analyzer facts. No raw snippets, unknown paths or exception bodies are emitted; `diagnosis_complete` remains false.

## Documentation and runtime evidence

The historical cache payload `5181cedba82af8d83de4b123080fb80ff414de15` with main SHA-256 `a13995cf0b52e3ccc1bb0476ed3dad290e8a9e1bf88d8397cc77afaf1ee06084` remains retained on `refs/heads/codex/preparation-private-sonar-cache-20261109`. Normal commit and push published the reviewed three-event follow-up at `865e4ec4fd0a745d1d125b3f43b3dd8d56b3ca7a` on `refs/heads/codex/preparation-private-sonar-three-event-20261109`; its main SHA-256 is `234bb01ea1a24e03ea374bd37dbf65a6c04dc2a80d4f98ecec14e8afe6ea8fe8` and action metadata is unchanged. Retain both published refs through later squash and task cleanup. The new ref protects the immutable runtime dependency of callers rebound here. Offline tests ran zero scanner quality analyses and collected no connector runtime evidence.

## Checks not run

Before publication at `9ae8ecc4f686e9cc70413e5494bc098a24eb18d7`, strict whole-source admission rejected the difference from the 865 role. That observed transitional failure remains historical evidence. The implementation is now immutably published, and its current exact source binding passed all 29 admission methods and actual 20-composite/one-Node source lint without weakening a guard. Caller delivery, fresh hosted quality verification, full-native verification of the matching committed Parent pair and causal closure of Shell, JSON and CFamily gaps remain pending. No project or quality-profile setting was changed.

## Limitations and residual risk

Empty private cache storage can increase runtime and disk use. Literal overlong markers indicate discarded evidence, not parser causes or source ownership. The existing document-limit signal remains unbound; additional sequence correlation is not causal certainty. No mapping from the public `2.27-SNAPSHOT` source to deployed `2.27.0.24646` is established. The strict optional version suffix is supported by public scanner logs, not an observed current-host version. Offline success and a passing Gate do not prove parser completeness.

## Final diff and review status

Historical payloads and caller migrations were independently reviewed and normally published. The 9ae successor was independently reviewed and integrated with native test paths; its existing 44-group source-bound offline receipt is reused unchanged here. The current source binds the published immutable revision and passes exact admission. Caller delivery and fresh hosted verification remain pending. Overall integration and analyzer-gap closure are not claimed.