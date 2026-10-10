# Change record

**Language:** English | [Deutsch](20261008-27-nginx-native-fact-contract.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-27-nginx-native-fact-contract |
| UTC date | 2026-10-08 |
| Framework base revision | `160079c7d4fdccb32371fa2fb8871a1be1ee8125` |
| Issue or pull request | Coordinator-owned NGINX all-required integration; no new PR |

## Motivation and problem statement

Catalog expectations such as connection reuse, MIME scope or split/EOS evaluation are not Common event keys. Canonical consumers need transparent mappings from actual authenticated operation evidence, not expected-field padding or synthetic events.

## Affected components and security boundaries

Only the new Framework fact contract, focused tests and this record pair. Source/run authority and original retained-file authentication remain the strict bundle reader's responsibility. Central normalizer, generic validators, schemas, catalog, Parent source, MRTS and Gitlinks are outside this slice.

## Acceptance criteria

Recognize exactly42 declared native operations without shrinking Required scope. Preserve all genuine selected native event keys and separate LOGGING cleanup. Bind native mappings to unchanged original JSONL lines and host mappings to sealed receipts, original observation JSON or raw H1 wire. Reject missing or contradictory phase, Rule, status and expected-field evidence. Return no status, canonical_status or PASS.

## Alternatives considered

Copying expected names into observed_event_fields fabricates evidence. Treating access-log HTTP200 or cleanup allow as a request-header event conflates different producer and lifecycle boundaries. Generic validator bypass is not an integration substitute.

## Implementation decision

`derive_native_operation_contract(case, strict_reader_proof)` calls the existing factual projector. It returns its actual facts plus observed_rule_ids, mapped_evidence_fields, per-field mapped_evidence_origins, native_event_origins, native_cause, semanticValues and semantic_evidence_origins. Native event fields remain unchanged. Mapping origins identify actual invocation, original artifact SHA256 and source pointer; native origins additionally identify original line digest/index, event index and TX.

The closed case-result table describes operation-layer semantics only after the strict reader's proof and actual mapping checks. Engine limits are mapped from retained native supplied/retained lengths and actual rules.conf directives. MIME scope uses genuine content type and actual engine retention. H1 framing uses original downstream bytes. Connection reuse uses actual native access counters. Phase1 keepalive client completion/EOS is explicitly a separate host mapping; native pre-send EOS/transport fields retain their original values. Write results use closed payload-free actual fault/resume ledgers. Rule, event, message and phase mappings cannot be supplied by host metadata.

Native cause and visible HTTP status are separate. Preconnector H1 rejection has no invented Engine event/TX. Missing genuine request-header completion remains an error. An actual request_headers_complete row must have the exact Source-shaped completion tuple and reason native_return=1;common_completed=1. Cleanup remains LOGGING, not Phase1 allow. Dependencies include the coordinator's approved native-only clean-shutdown HTTP200 override (`c9e9b3fd246ded97040dc1253e530934b8e4bf71`), preserving generic status0, and the real Common serialized vocabulary correction (`9f3f95d2f30be37799ad2bf654253bfa847c7783`): pre-send request denial is engine_decision/MSCONN_EVENT_ENGINE_DECISION; event-boundary callbacks are rule_match/allow. Source struct names are not invented serialized keys.

## Changed files and tests

`tests/runners/nginx_native_operation_contract.py`, `tests/no_crs/test_nginx_native_operation_contract.py` and this EN/DE pair. Controlled fixtures cover strict-reader pointer proof, all12 Phase4/MIME operations, original-line binding, absent/foreign/mutated facts, event/cleanup scope, expected-result/field mismatches, status distinction, H1 framing, connection counters and exact P1 completion. The existing lightweight safe-mode fixture omits original_http_status/headers_sent: this gap is explicitly rejected before a separate unit fixture adds source-assigned fields. Neither fixture is runtime evidence.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy env PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python -m unittest tests.no_crs.test_nginx_native_operation_contract -v` | 1 | Initial RED: new module absent | Controlled unit invocation |
| `rtk proxy env TMPDIR=<external-task-runs> PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python -m unittest tests.no_crs.test_nginx_native_operation_contract -v` | 0 | 12 focused tests; Framework-owned interpreter | Controlled unit invocation |
| `rtk proxy env TMPDIR=<external-task-runs> PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python -m unittest tests.no_crs.test_nginx_native_operation_contract tests.no_crs.test_nginx_native_operation_projection tests.no_crs.test_nginx_native_operation_bundle -v` | 0 | 46 tests after both coordinator corrections; repeated after final client-EOS mapping | Controlled unit invocation |
| `rtk proxy env TMPDIR=<external-task-runs> PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 make test-no-crs-contract PYTHON=<framework-python> BUILD_ROOT=<external-build-root>` | 0 | 342 tests after dependency corrections, before final focused client-EOS refinement | Task analysis: stream-a-native-fact-contract-final.log |
| `rtk proxy env PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 make check-documentation PYTHON=<framework-python>` | 0 | Links, bilingual variables, paths and change-record contract | Framework documentation checks |
| `rtk proxy git diff --check` | 0 | No whitespace errors | Owned worktree |

## Security impact

No product security remediation or authentication change. This seam strengthens evidence separation: actual native fields cannot be invented from expectations, LOGGING cannot impersonate Phase1, and host mappings require original authenticated observations. A dictionary claiming layer_verified is not authentication; the caller must invoke the strict reader under explicit authority before this seam and revalidate original bytes offline.

## Documentation and runtime evidence

Paired English/German record. All validations are pure controlled fixtures. No current native runtime, build, full E2E or all-required PASS is claimed. The original97 Required selection remains coordinator-owned and unchanged.

## Checks not run

No native runtime/build/full E2E: serialized coordinator slot and integrated module are prerequisites. Ruff unavailable; no tool installation or remote scan performed.

## Limitations and residual risk

Unproved expected fields fail closed even on a recognized route. Root integration must preserve strict-reader source authority, exact offline regeneration and central canonical policy. Immutable projected descriptors require deliberate copying for serialization. Host H1 facts prove no H2/H3 behavior.

## Final diff and review status

Only four new owned files. Dependency commits are existing coordinator-owned work, not part of this delivery. Staged diff, original-byte boundaries and whitespace reviewed; no central/source/Gitlink changes. Broader validation and final focused rerun passed; normal scoped commit is handed off to the coordinator.
