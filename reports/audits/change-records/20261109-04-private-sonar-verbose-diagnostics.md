# Private verbose Sonar diagnostics

**Language:** English | [Deutsch](20261109-04-private-sonar-verbose-diagnostics.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261109-04-private-sonar-verbose-diagnostics |
| UTC date | 2026-11-09 |
| Framework base revision | b36565af8f401ce381cd4bca396f30bfef420944 |
| Issue or pull request | Framework PR #169 |

## Motivation and problem statement

The private wrapper appended DEBUG logging together with an explicit `sonar.verbose=false`. This prevented the intended verbose diagnostic configuration. File-only parse warnings also lacked a separate inventory-bound representation, and document limits were grouped solely by their numeric limit.

## Affected components and security boundaries

Framework owns the private action executable, offline Node tests and this paired record. Existing callers retain their previously frozen action commit until a separate caller change selects the newly published immutable action. This change does not update Parent or MRTS sources, pins or gitlinks.

## Acceptance criteria

Force DEBUG plus `sonar.verbose=true` after validating the original exact caller inputs for Framework and all three Parent profiles. Reject additional caller verbosity overrides. Retain the existing 17 offline controls and inventory, privacy, capture, cleanup and analysis contracts. Never infer a source from an ambiguous or interrupted exception event.

## Alternatives considered

Passing inherited runner debug settings, publishing raw DEBUG output, expanding generic error classifiers, reducing analysis scope and assigning file warnings a synthetic line zero were rejected. A document limit without sufficient contiguous evidence remains `UNBOUND`.

## Implementation decision

The validated private argument suffix now sets verbose true explicitly. File-only warnings require a complete timestamped, single-quoted warning envelope and a source accepted by the existing inventory validator. Only repository-relative inventory facts, fixed categories and occurrence counts are emitted as `file_failures`. A private per-result weak index points to at most 10,000 retained occurrence entries; repeated warnings update the existing entry without scanning the public array. Overflow identities are not indexed, and separate results remain independent.

A private streaming context permits prospective Java exception headers for the upstream [SnakeYAML Engine root exception](https://github.com/snakeyaml/snakeyaml-engine/blob/master/src/main/java/org/snakeyaml/engine/v2/exceptions/YamlEngineException.java) and [classic SnakeYAML root exception](https://github.com/snakeyaml/snakeyaml/blob/master/src/main/java/org/yaml/snakeyaml/error/YAMLException.java), plus narrowly recognized Java stack continuations. These class definitions justify the prospective whitelist; they do not prove the format of a hosted scanner event. The context expires after at most 32 total event lines or 16 KiB and resets on unknown/interleaved lines, other logger events, truncation, decoding loss or end of input. Limits are grouped by numeric limit and bound repository/path identity, with unbound limits kept separate. No earlier exception is retroactively bound.

The first recognized exception must be a root header. Subsequent recognized headers must be explicit `Caused by` continuations. An initial cause header or a second bare root header clears association instead of inheriting a previous file identity.

## Changed files and tests

Changed `.github/actions/sonar-private/main.cjs`, `tests/security_regression/sonar-private-diagnostics.test.cjs` and this paired record. Six additional test groups cover prospective binding, distinct and repeated files, unbound-first ordering, unsafe paths and quote ambiguity, context reset and lifetime, root/cause ordering, CRLF, read-chunk boundaries and actual UTF-8 decoding loss. Existing argument tests now cover verbose true and override rejection for all four profiles; GPG warning accounting and the adversarial deadline test are strengthened. The real deadline workload retains 10,000 file identities, repeats the last identity 50,000 times through exported `acceptLine` without stream state, and verifies ordering, exact occurrence counts, overflow accounting and result isolation.

## Commands and results

Node 24 syntax checks passed for both JavaScript files. The focused Node test run passed all 23 tests with zero failures or skips. The original 17 controls remain covered, including private output, token isolation during bootstrap, capture permissions, cumulative overflow, timeout, descendant cleanup and fixed system Git. The adversarial child retains its hard 2500 ms deadline. Exact-file Secrets checks passed for the qualified postimages. No private canary appeared in test output.

## Security impact

The official upstream action, scanner version, signature verification, exact source revisions, complete analysis scope, native arguments, include paths, language standards and Quality Gate wait remain unchanged. Raw captures stay private and bounded; inherited runner debug remains excluded. The parser publishes no raw exception text, source body or fabricated location. `diagnosis_complete` remains false.

## Documentation and runtime evidence

This English/German record describes source changes and offline qualification. The tests performed zero scanner quality analyses and collected no connector runtime evidence. The new immutable action commit identity remains pending publication; it must be frozen by a later, separate caller change.

## Checks not run

Fresh hosted verbose execution, exact-head Cloud issue and Gate verification, and causal closure of Shell/JSON/CFamily diagnostics remain pending. Existing caller/source digest admission must be reconciled through its normal producer and publication sequence before integration.

## Limitations and residual risk

The exception envelope is prospective. Unsupported future scanner formatting stays unbound, including timestamp-prefixed continuation lines. Source binding identifies a contiguous accepted event; it does not prove analyzer completeness or close historical parsing gaps. Offline success proves no hosted zero-issue result.

## Final diff and review status

The JavaScript diff and whitespace checks passed local review. Source qualification is ready for independent review; publication, caller freezing, hosted validation and overall integration remain pending.
