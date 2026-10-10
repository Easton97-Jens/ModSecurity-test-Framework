# Change record

**Language:** English | [Deutsch](20261008-24-nginx-native-operation-bundles.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-24-nginx-native-operation-bundles |
| UTC date | 2026-10-08 |
| Framework base revision | `3435e0aa131034dd56b022adbaeda04cda4ae8e1` |

## Motivation and problem statement

An operation receipt or HTTP status alone does not authenticate retained native observations. Forty-two closed native NGINX operations need a common fail-closed reader before the separately owned canonical normalizer can consume their evidence.

## Affected components and security boundaries

New Framework reader, focused tests and this paired record only. Existing standalone operation helpers are reused. Parent producers, catalog, schemas, canonical status mapping, sealed retention, MRTS and Gitlinks are not changed by this slice.

## Acceptance criteria

Reopen original receipts and raw artifacts beneath explicit artifact authority. Reject unsafe paths, symlinks at every component, hard links, foreign ownership, writable directories/files, nonregular or oversized files, digest/source/run/role/operation mismatches and H2/H3 substitution. Require actual configuration, build snapshots, native transaction/error/cleanup facts and closed helper validation. Never manufacture an event or promote a status.

## Alternatives considered

Receipt-selected source whitelists, inferred framing, unsealed original receipts and HTTP-only acceptance cannot establish the selected observation layer. A local success must not be represented as trusted build provenance or remote quality closure.

## Implementation decision

`validate_native_operation_bundle(record, authority, sources, canonical=False)` returns verified layer facts or raises `ValueError`. Caller authority supplies exact Parent/Framework/MRTS revisions, source roots and expected binary/module/selected fault-library digests. `required_source_paths(case_id)` exports the closed namespaced source whitelist for the producer wrapper. Original receipt bytes are unchanged; the returned file manifest seals reopened bytes for subsequent verified copying.

Routing covers raw H1 rejection, Common pointer faults, Phase 4/MIME, lifecycle/framing/soft-budget sequences and event boundaries. Event boundaries bind the original parent and distinct child receipts. Actual native events remain flat and unchanged; genuine technical errors require an empty Rule. Before-admission mapping failure has no Engine transaction or cleanup. Native allocation failure requires the scoped NULL-return ledger and Common cleanup with native completion zero. Raw H1 rejection has no admitted fault transaction; its valid control must have an actual native transaction and cleanup.

## Changed files and tests

`tests/runners/nginx_native_operation_bundle.py`, `tests/no_crs/test_nginx_native_operation_bundle.py` and this record pair. Focused tests exercise all route groups using retained unit bytes and the real closed helper implementations, including resealed negative controls. Unit fixtures are explicitly synthetic and are not new native runtime evidence.

## Commands and results

The owning Framework Python passed 23 focused bundle tests plus 17 explicit Phase 4 helper tests (40 total). Repository-native `make test-no-crs-contract` passed all 284 tests; `make check-documentation` and the staged whitespace check also passed. RTK wrapped execution, with caches, temporary data and logs under the external project roots. Exact commands and logs are retained in the task handoff.

## Security impact

Every artifact is read through no-follow file descriptors with ownership, link, permission, size and stable metadata checks. Actual build and compiled fixture bytes must match explicit caller digests. Duplicate JSON keys, nonfinite numbers, nested native metadata and payload/secret fields are rejected. Source helpers execute only after current bytes match the caller-authorized closed source seal, which is rechecked after validation. No arbitrary receipt-provided source is imported.

## Documentation and runtime evidence

This record covers local source and unit validation only. The returned proof has `layer_verified` and raw facts, not canonical PASS. The coordinator owns integration, run uniqueness, final provenance authority and sealed retained copying.

## Checks not run

No new native NGINX runtime or full build was run. Ruff is unavailable in the owning environment and was not installed. No remote SonarQube closure is claimed.

## Limitations and residual risk

Projection freshness relies on the authenticated producer's direct-child creation contract and exact run/case naming; this reader does not stat arbitrary receipt-selected external paths or establish global run uniqueness. UID rejection is tested through real file descriptors with controlled `fstat` metadata because changing ownership is unsupported by the managed test filesystem. Missing producer fields fail closed and require integration work, not invented observations.

## Final diff and review status

The final review is restricted to the new reader, tests and record pair. Required scope, native semantics, schemas and canonical policy remain unchanged.
