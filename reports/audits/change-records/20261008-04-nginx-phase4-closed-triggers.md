# Change record

**Language:** English | [Deutsch](20261008-04-nginx-phase4-closed-triggers.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-04-nginx-phase4-closed-triggers |
| UTC date | 2026-10-08 |
| Framework base revision | `11e1d20990d4ecbbcf18641782b04f0bb6369c69` |

## Motivation and problem statement

Eight selected Required Phase-4 records have no scheduled native operation. Declarative future fixtures cannot prove split ingestion, EOS, Engine limit outcomes, or bounded native metadata.

## Affected components and security boundaries

Framework closed input helper, NGINX fixtures and focused unit tests. Actual Parent host operations and native product observations remain separate boundaries.

## Acceptance criteria

Closed inputs retain all eight identities, bounded response chunks, explicit Engine-owned limits, and deterministic reuse sources. Unknown identities fail. Input specifications contain no observed status or fabricated events.

## Alternatives considered

Reusing off evidence for safe, assigning observed outcomes from inputs, and accepting an arbitrary native event would not prove the exact contract. Closed inputs plus separate real observations preserve these distinctions.

## Implementation decision

`tests/runners/nginx_phase4_contracts.py` returns fresh bounded specifications and eight unique NGINX fixtures. A marker spans 16- and 11-byte chunks; neither chunk individually matches. Limit operations use 64/65-byte bodies and explicit `SecResponseBodyLimitAction` values `ProcessPartial` or `Reject`. The existing Required identity `phase4_deny_after_commit_log_only_minimal` uses the existing `safe` mode by the latest explicit user decision, "minimal muss in safe rein". No `minimal` parser mode or alias is introduced and the existing off legacy behavior is preserved. EOS reuses only the exact split operation; bounded metadata reuses only the exact over-limit operation.

## Changed files and tests

New helper, `tests/runners/test_nginx_phase4_contracts.py`, eight fixtures under `tests/cases/connector-specific/nginx/`, and this EN/DE pair. Shared catalog/schema/normalizer integration remains coordinator-owned.

## Commands and results

RTK-wrapped Framework Python unittest discovery: initial missing-helper regression failed; implementation runs nine tests, exit 0. A subsequent MIME-scope negative failed before removing same-load `SecResponseBodyMimeTypesClear`, which the pinned Engine's merge path clears together with newly added types. Inputs retain existing defaults and explicit `text/plain`. YAML input fixtures parse. `make check-documentation` and whitespace checks pass. Full native lint remains integration work.

## Security impact

No selection reduction, validator weakening, payload events, synthetic native observations, or MRTS writes. Engine response-inspection policy remains Engine-owned; no connector cumulative budget is introduced.

## Documentation and runtime evidence

Input fixtures are not evidence. Native chunk delivery, rule/EOS observations, actual Engine inspection length/action, Root/nobody, client result, cleanup, and strict canonical mapping remain required. External development focus `stream-c-r1` actually invoked all eight identities with existing baseline artifacts before the final safe migration decision: split/EOS returned HTTP 200 with native rule/EOS; Engine Reject and the then-selected off-after-commit operation produced client exit 18 and native failure/abort observations. Those two results are not contract PASS and off data cannot prove the newly selected safe operation. A fresh safe invocation remains required. In particular the Reject fixture remains future until the actual native operation contract is validated; it invents no HTTP success expectation. These changes do not establish final Exact-Head coverage or Protected acceptance.

## Checks not run

Complete Framework lint and final integrated host/CI/Sonar validation remain coordinator-owned; input tests do not substitute for them.

## Limitations and residual risk

Actual Engine retained-byte length and native limit outcome are not established by fixture size or bytes handed to append. Dedicated native observation and strict mapping remain mandatory.

## Final diff and review status

Exclusive worktree implementation; no publication or Parent Gitlink update by this workstream.
