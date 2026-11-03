# Traefik capture source preparation

**Language:** English | [Deutsch](20261103-traefik-capture-source-contract.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261103-traefik-capture-source-contract |
| Repository | Framework |
| Delivery | Reviewable task branch; integration pending |

## Motivation and problem statement

The full forwardAuth preparation stopped at its sealed profile check. Its
historical live-repository object references had also drifted, and migrated
Framework helpers were absent from the complete Parent export. Historical
observer variants would have removed newer snapshot/finalize and ABI guards.

## Affected components and security boundaries

Framework Traefik source preparation and the shared I12 object registry. Parent
product files and MRTS remain outside this change.

## Acceptance criteria

Complete request/companion preparation, strict seals, current product preservation,
reproducible generation and focused positive/negative regressions must pass.

## Alternatives considered

Digest-only updates, disabling registry verification and replaying historical
product snapshots would hide drift or remove current guards; all were rejected.

## Implementation decision

The Framework now supplies a reviewed recipe and reproducible generator with
`--check`, current contextual product observation deltas, current helper bindings,
and a sealed generated adapter contract. The generator checks separately pinned
input and output bytes and retains hashes/offsets of untouched spans. Native
instrumentation preserves every product byte after removing only its observation
lines. Historical objects retain exactly their original identities as inert
lossless line data with original Git provenance. Global registry verification
and all source, destination and output checks remain active. Source-only receipts
record the actual Framework revision and separate helper hashes.

## Changed files and tests

`current_capture.py`, `regenerate_capture.py`, the recipe/generated contract,
central manifest and inert objects/deltas, Auth/native preparation, existing
CurrentCapture/Auth tests and paired Auth README. New regressions are on demand;
the shared 100-case default inventory is unchanged by this change.

## Commands and results

Focused source-preparation, positive/negative adapter and generic source-copy
controls passed with Framework CPython 3.15.2. Full request and companion CLI
preparation passed separately. The regenerated 169-object/10-profile registry
verified, and generator `--check` passed. Commands use RTK and explicit
`CONNECTOR_ROOT`, `CONNECTOR_REVISION`, `TEST_ROOT`, `PYTHONPATH` and external
output roots. Exact wrapped calls and exit codes are retained in the task evidence.

## Security impact

Fail-closed admission remains mandatory; unknown product/helper bytes, modified
seals/deltas and destination escapes are rejected before source writes.

## Documentation and runtime evidence

Paired Auth README documents regeneration and its byte/source boundary. No new
runtime evidence is claimed.

## Checks not run

No host execution, full campaign, local Sonar or remote delivery checks were run
by this scoped implementation worker. Existing remote gates remain required.

## Limitations and residual risk

This is Framework-owned source/test infrastructure. The selected Parent baseline
is an external dependency, `11fab78a5447f75cb254ddf963eca770fa04ba04`; no Parent
product or MRTS files change. Parent pin adoption requires separate delivery and
integration. Native source application passed, but full native host preparation
still requires its historical artifact/private toolchain inputs and independent
admission. No host was started and no protocol, P1–P4, EOS, first-byte, current
method-inspection or metadata acceptance is claimed. Existing historical failures
remain separate. Local Sonar was explicitly suspended for this task; existing
remote checks remain required.

## Final diff and review status

Focused checks and diff whitespace validation passed; independent integration
review, remote checks and separate Parent pin adoption remain pending.
