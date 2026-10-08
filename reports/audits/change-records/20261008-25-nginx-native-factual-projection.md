# Change record

**Language:** English | [Deutsch](20261008-25-nginx-native-factual-projection.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-25-nginx-native-factual-projection |
| UTC date | 2026-10-08 |
| Framework base revision | `f14b2cf0744fe30f3d64ccb421b98adaf1dfd863` |

## Motivation and problem statement

Verified native operation receipts must be mapped without turning receipt measurements or connector-specific expectations into fabricated native event fields. Logging cleanup allow must never become request-header allow.

## Affected components and security boundaries

New Framework factual projection, focused tests and this paired record only. Current standalone native descriptor registry and phase-one override dependencies were replayed normally. Generic validator, catalog, schemas, Root integration, MRTS and Gitlinks are not changed by the projection slice.

## Acceptance criteria

Require strict reader layer proof and exact case/run/operation/original invocation identity. Validate the declared native descriptor against current CaseSchema and all42 closed routes. Keep genuine flat native events unchanged; select actual phases and Rules, expose cleanup separately, and reject terminal-operation, deny-action and cleanup-order contradictions. Preserve generic case expectations and expose immutable connector-specific overrides. No status or canonical_status decision.

## Alternatives considered

Populating observed_event_fields from expected names or guessing event metadata from a receipt would invent evidence. Selecting logging cleanup as request-header allow would cross a lifecycle boundary.

## Implementation decision

`project_native_operation(case, proof)` returns copied factual observations and read-only native descriptors/overrides. It reuses the repository CaseSchema validator without changing it. `observed_event_fields` contains only genuine selected native keys. Receipt measurements, parsed numeric reason fields, exact original JSONL line sizes/digests and decoded socket framing measurements are explicitly separated into `mappingEvidenceFacts`; response bodies are not copied there. Full native events and cleanup_native_events retain their actual phases and fields.

Raw malformed requests retain actual HTTP400 with no admitted fault transaction/event. Finish failure retains visible200 and native logging HTTP0. Budget cases retain actual504 before commit or visible200 after commit with the real timeout/timing pair. Clean shutdown retains actual200. MIME/body-limit/event-boundary observations and legacy safe-mode expectations remain explicit; no missing expected event key is synthesized.

Integration correction: the request-header intervention source structure uses `phase1_intervention` / `MSCONN_EVENT_REQUEST_BLOCKED`, but the actual Common JSONL protocol view serializes this unobserved host action as `engine_decision` / `MSCONN_EVENT_ENGINE_DECISION`. Native HTTP403, empty `actual_action` and visible HTTP0 remain unchanged. Non-disruptive matches serialize as `rule_match` with allow actions. Reader, projection and event-boundary helper require these actual written fields, not an unsent source structure or invented sent deny action.

## Changed files and tests

`tests/runners/nginx_native_operation_projection.py`, `tests/no_crs/test_nginx_native_operation_projection.py` and this record pair. Pure fixtures exercise all42 descriptors plus null/case/phase/Rule/run/schema/mutation controls, cleanup scope, actual deny-action/status, terminal contradictions, budget/finish distinction and raw framing facts. Fixtures are not native runtime evidence.

## Commands and results

Test-first module absence was observed as RED. The owning Framework Python passed eight focused projection tests and 56 broader reader/registry/Phase4/projection tests. Repository-native `make test-no-crs-contract` passed all300 tests; `make check-documentation` and staged whitespace checks passed. Exact commands and external logs are retained in the task handoff. RTK wrapped all shell execution.

Root integration observed the source-accurate callback fixture as RED, then passed 34 combined projection/strict-reader tests after the exact callback correction. This remains controlled fixture validation, not runtime evidence.

The subsequent full-source caller test used the real Common writer and exposed the protocol-view discrepancy. Written-byte fixtures were red before the reader/helper correction; 44 integrated native reader/projection/event-boundary/canonical-binding controls then passed. Original native files are never rewritten to satisfy this vocabulary.

## Security impact

Projection cannot confer source/build authority. It requires a strict-reader proof and preserves actual phase/TX/Rule boundaries, but final Source/digest/rerun/retention authority remains coordinator-owned. Wrong native event order, foreign operations after pointer rejection, deny actual_action allow or HTTP200 and mutated descriptors are rejected. Immutable overrides cannot migrate generic expectations for other connectors.

## Documentation and runtime evidence

This is a factual mapping seam, not a canonical acceptance gate. No PASS/status/canonical_status is returned. Selected events deliberately exclude cleanup from request-operation observations; separately returned actual logging cleanup remains available for coordinator-selected cleanup contracts.

## Checks not run

No native runtime or full build. Ruff unavailable and not installed; no remote SonarQube closure claim.

## Limitations and residual risk

A dictionary claiming layer_verified is not cryptographic authentication; callers must pass the actual strict reader result under controlled source authority. Generic request events absent from the native source remain absent, not fabricated. Read-only descriptor mappings require deliberate copying if a caller chooses to serialize or merge connector-local expectations.

## Final diff and review status

Focused four-file projection slice only. Generic expectations, native events, Required scope and canonical policy remain unchanged.
