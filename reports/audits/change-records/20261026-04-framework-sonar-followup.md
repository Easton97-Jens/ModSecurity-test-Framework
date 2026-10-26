# Framework Sonar follow-up

**Language:** English | [Deutsch](20261026-04-framework-sonar-followup.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261026-04-framework-sonar-followup |
| UTC date | 2026-10-26 |
| Framework base revision | 5ef4dc3c |
| Issue or pull request | [PR #138](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/138) |

## Motivation and problem statement

The first complete CLI scan exposed Git binary metadata warnings, focused quality findings and four source-context-dependent compiler-recorder security reports.

## Affected components and security boundaries

Framework Sonar helper, scanner properties, strict workflow checker and offline regressions. Parent gitlink unchanged; MRTS read-only. All 31 Ubuntu runner fields remain 26.04.

## Acceptance criteria

Exclude Git metadata from MAIN and TEST without excluding maintained files; preserve strict validation and compiler behavior; retain exact-head analysis and source-supported issue dispositions.

## Alternatives considered

Broad source exclusions, rule suppression and gate changes would hide evidence. Necessary Path grouping and valid shell arithmetic must not be rewritten solely for analyzer warnings.

## Implementation decision

Add only .git/** metadata exclusions, split coherent helper responsibilities, reuse one explicit Ubuntu runner constant and separate the composite loader assertion. Four reports were individually resolved FALSE-POSITIVE after independent source review: fixed private evidence destinations, same-privilege local executable selection, list argv and JSON content cross no HTTP or added privilege boundary. No rules or gates changed.

## Changed files and tests

Native capture helper, sonar-project.properties, security contract checker, readiness/native analysis regressions and paired security guide. Compiler recorder and main behavior, exact publisher digests, permissions and action pins remain unchanged.

## Commands and results

77 affected security/updater methods passed; nine native-analysis methods covering ten cases passed, including causal missing-.git rejection before correction and success afterwards. Helper reconstruction preserved AST semantics and execution order. Hosted head 5ef4dc3c completed approved SDK build, one real C compilation, CLI 8.2.0.6438 upload and CE analysis eb2599ca-c449-4e33-8cb3-e643eb0b593d. Eleven other workflow runs passed. Four issue dispositions were freshly read back as RESOLVED/FALSE-POSITIVE.

## Security impact

CFamily executed eight taint rules without resulting issues; Python enabled 32 taint rules. Gate readback for the completed analysis became OK with security rating A after the four reviewed dispositions; coverage was absent from gate conditions. This is no complete-security or vulnerability-free claim.

## Documentation and runtime evidence

The pre-correction scan indexed 764 files with C/Python/shell/YAML/JSON profiles, no analyzed C++ or Go unit. Standard logs provide no complete indexed-path inventory. Shell warning common.sh:2617 was not reproduced by static bash -n and sh -n checks; expression retained. No connector runtime evidence.

## Checks not run

The original hosted job retains its earlier failed-gate conclusion. Fresh hosted SDK/CLI/server and gate verification is required for the follow-up head. No runtime, E2E, I12 or updater publication campaign.

## Limitations and residual risk

False-positive dispositions are specific to the current local CLI trust boundary. New service callers or privilege transitions require renewed review. Static shell parsing does not establish runtime behavior.

## Final diff and review status

Prepared for coordinator review and a normal PR #138 follow-up; no merge. Exact follow-up-head hosted verification remains pending.
