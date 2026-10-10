# Change record

**Language:** English | [Deutsch](20261008-25-nginx-native-bundle-terminal-proofs.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-25-nginx-native-bundle-terminal-proofs |
| UTC date | 2026-10-08 |
| Framework base revision | `b184389621e81d1d7ef1bd320140731900b1f8ae` |

## Motivation and problem statement

Independent public-reader controls reproduced three accepted wrong-proof forms: a non-disruptive/allowed event standing in for denial, later source work after transaction cleanup, and a P4 technical event attached to a terminal P1 mapper failure. Digest resealing alone does not make those contradictory observations valid.

## Affected components and security boundaries

Only the native operation bundle reader, its existing unit tests and this record pair. Authorized closed helper dependencies were imported into the owned worktree before this slice. Catalog, projection, canonical normalization, Parent product sources, build/runtime, Gitlinks and MRTS remain unchanged.

## Acceptance criteria

Require current source-native P1 denial fields, not a future host action or pass callback. Require cleanup to be the final event for its transaction. A terminal mapper failure contains exactly its real P1 protocol error followed by preserved successful cleanup. Enforce flat bounded source scalar types without coercion. Retain positive routes, source/artifact authority and existing payload/type/digest negatives.

## Alternatives considered

Selecting a denial by blocked/action/rule fields alone admits contradictory event types and delivery facts. Checking cleanup classification without chronology admits after-free native work. Filtering only P1 protocol errors discards conflicting later phases. Weakening helpers or treating resealed bytes as canonical PASS does not solve these defects.

## Implementation decision

sequence_denials requires phase1_intervention / MSCONN_EVENT_REQUEST_BLOCKED, request_headers, blocked/deny/deny, rule1100001, native403 and visible0. Current access.c emits actual_action empty before core sends headers; neither allow nor an invented future deny is admissible. Controlled positive fixtures now use that exact actual source vocabulary, not the old engine_decision substitute.

cleanup_events rejects every later same-transaction row, while preserving interleaved other-transaction events. The Common pointer operation accepts only its source-bound P1 protocol error then cleanup; later/foreign phase or error rows fail rather than being filtered out. native_event_shape checks the actual Common flat field vocabulary, required identity/phase/status scalars, 255-byte UTF-8 string bounds/no NUL, real booleans, bounded unsigned counters and integer status fields. JSON duplicate/nonfinite, nested metadata, payload/secret and unsafe file controls remain intact.

## Changed files and tests

tests/runners/nginx_native_operation_bundle.py; tests/no_crs/test_nginx_native_operation_bundle.py; this EN/DE pair. Negative controls rewrite original retained unit bytes and recompute all relevant child, parent and envelope seals; the public reader executes actual closed helpers without validator mocks. Synthetic unit fixtures are not runtime evidence.

## Commands and results

The final controls against original Reader54f96ad produced exactly20 expected failures in26 tests. The corrected reader passes all26 focused tests. The operation-helper regression set passes88 tests; make test-no-crs-contract passes303 tests. RTK-wrapped execution uses external TMPDIR/PYTHONPYCACHEPREFIX and logs stream-c-bundle-fix-red-final.log, stream-c-bundle-fix-green.log, stream-c-bundle-fix-cross.log and stream-c-bundle-fix-broad.log. Catalog166, documentation links, variables and path checks pass. The new record pair passes the actual record_errors checker; diff whitespace is clean.

The full check-documentation target stops at the imported record20261008-04 EN/DE heading mismatch: its retained transport/finish dependency descriptions add an extra subsection. That older pair is outside this four-file fix and remains unchanged. Details are retained in stream-c-bundle-fix-docs.log.

## Security impact

The reader no longer accepts cleanup allow as a substitute for a native denial, non-disruptive callbacks as blocked proof, impossible post-cleanup native work or hidden foreign-phase errors in terminal mapper receipts. Source scalar coercion and unbounded strings cannot invent actual observations.

## Documentation and runtime evidence

Read-only source authority: current Parent access.c request_intervention_log_event, Common status/phase/event serializer contracts and native cleanup producer order. Returned facts remain layer_verified only; no canonical status or event is manufactured.

## Checks not run

No native build, runtime, E2E or remote CI/Sonar was run. The coordinator owns fresh integrated evidence and source/build administrative trust.

## Limitations and residual risk

These checks establish observation-layer consistency, not trusted build provenance, global cross-bundle run/projection uniqueness or authenticated native execution. Source-admission authority and canonical integration remain separately owned.

## Final diff and review status

Focused four-file fix only. The original three accepted-wrong-proof cases are now rejected after complete resealing; positive actual-source routes remain accepted as unit observation layers. No Root worktree/source mutation or publication.
