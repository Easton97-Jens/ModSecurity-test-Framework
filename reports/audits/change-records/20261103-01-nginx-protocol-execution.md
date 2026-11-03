# Native NGINX protocol executors and source-context fixtures

[Deutsch](20261103-01-nginx-protocol-execution.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261103-01-nginx-protocol-execution |
| UTC date | 2026-11-03 |
| Framework base revision | bb6c7580208a05c17d6d6674571731b6a71028cb |
| Issue or pull request | Task branch codex/runtime-protocols-20261103; delivery coordinated separately |

## Motivation and problem statement

The existing H2/H3 catalog cases lacked executable native NGINX descriptors.
Two wiring regressions failed earlier at an invalid non-Git product fixture.
Rendered TLS/QUIC listeners and a non-promoting optional probe could not qualify
actual allow/block behavior or eliminate HTTP/1 fallback.

## Affected components and security boundaries

Framework selection, native protocol dispatch, source collection, canonical
retention and independent evidence validation. The ordinary hosted runtime
uses fresh preflight and existing owned-process cleanup. Protected broker
admission and connector product capabilities remain separate boundaries.

## Acceptance criteria

Existing supported modern cases select real executors. A valid transfer with
wrong HTTP version, absent/mismatched ALPN, absent stream identity, unobserved
QUIC, mismatched native transaction or failed cleanup cannot pass. Raw native
events stay unchanged. The standard 100-case inventory does not grow.

## Alternatives considered

Promoting compile flags, using an optional unrelated probe, inserting client
facts into native events or marking unsupported resets/multiplexing successful
would not establish the requested runtime contract.

## Implementation decision

Closed executors send independent allow and contract requests through real
TLS/H2 or QUIC/H3 listeners. A common reader verifies original hashed bytes,
exact source identities, native access/rule correlation, forced-client
negotiation and metadata-only bidirectional QUIC observation. Canonical records
name independent host facts explicitly and reopen their evidence on validation.
H1-only operations remain unexecuted in modern invocations; their denominator
is preserved. Product resets, multiplexing, h2c and modern first-byte remain
explicit unsupported/unimplemented work.

Independent review reproduced contradictory native decisions, pre-commit Safe evidence and missing allow events being accepted. The corrected reader requires original clean-allow completion, actual deny intent/intervention status, exact committed Safe semantics, and observed outcomes. Library validation now precedes backend acquisition. No expected-result field supplies an observed result.

## Changed files and tests

New `tests/runners/nginx_protocol.py`, native single/selected protocol runners,
focused on-demand regression module and paired protocol documentation. Updated
canonical collector/selection/retention and case-result schema, selected-host
dispatch and the wiring fixture. Source-context fixtures now create a genuine
Git checkout with current product version contracts.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| RTK, original two wiring methods, Framework-owned Python3.14.4 | 1 | Both reproduce exact invalid source-context failure before selection | runtime-readiness/protocols baseline tool receipt |
| RTK, Framework-owned Python3.15.2, protocol regression module | 0 | 15 tests; protocol/ALPN/stream facts, fallback, semantic intervention, clean allow, packet metadata, canonical reopen/retention/exact pair, aliases, cleanup and unsupported operations | runtime-readiness/protocols |
| RTK, Framework-owned Python3.15.2, full protocol wiring module | 0 | Ten real Make selection/init tests; no host launched | runtime-readiness/protocols |
| RTK, five neighboring selection/authority modules | 1 | 37/40 pass; three separate old non-Git authority-fixture failures | runtime-readiness/protocols |

## Security impact

Missing provenance is rejected. QUIC capture persists no packet payload or raw
connection identifier. Ephemeral TLS material is removed during owned cleanup.
No scanner, preflight, native capability or repository protection is weakened.

## Documentation and runtime evidence

The paired protocol guide states prerequisites, operations and evidence limits.
Selftests establish source contracts and failure detection only. A fresh
admitted-artifact runtime run and exact source-pair record are separate
coordinator-owned evidence; this record does not claim comprehensive acceptance.

## Checks not run

No full profile/protocol campaign or protected broker operation is run by this
change. Local Sonar is expressly suspended by the current user instruction;
GitHub Sonar/CodeQL remain unchanged. Fresh host evidence and delivery are
reported by the integration coordinator, independently of these selftests.

## Limitations and residual risk

H3 needs an HTTP3-capable curl and approved packet-observation permission.
New reset/multiplex product features require separate implementation. Existing
authority-fixture context failures are separate regressions, not protocol PASS.

## Final diff and review status

Reviewable Framework-only worktree changes; no Parent source, gitlink or MRTS
write. The integration coordinator owns final combined validation, inventory
source bindings, commit/PR delivery and actual runtime readiness claims.
