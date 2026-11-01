# Protocol integrity integration after test migration

**Language:** English | [Deutsch](20261101-02-protocol-test-integration.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261101-02-protocol-test-integration |
| UTC date | 2026-11-01 |
| Framework base revision | `d503ddbea1a3b6df7766edc247b0a9886ff10668` |
| Issue or pull request | Framework integration for Parent Draft #348; publication pending |

## Motivation and problem statement

The completed migration moved all connector tests into Framework. Thirteen
Parent #348 checker/test deltas remained at deleted paths. Dropping them loses
24 definitions and Common protocol assertions; restoring them breaks ownership.
The user also selected the verified artifact/QUIC fixes from Drafts #143/#144.

## Affected components and security boundaries

Framework Common/Apache/NGINX checkers, seven Python test modules, three Go test
sources and fixture admission. A mutation checker must inspect its actual copied
fixture, not an inherited real Parent root. Parent source is an explicit external
validation dependency; no Product source, MRTS or unrelated host-context work is
changed here.

## Acceptance criteria

Preserve all13 mapped deltas and24 definitions; retain100 standard cases/
80 executions and all selectors. Regenerate bindings/archive/map natively.
Positive controls pass; mutated inputs reach and fail the real checkers.
Verify this integration before the separately authorized Framework-master merge
and exact dependent Parent pin. No Parent-master merge or broad qualification.

## Alternatives considered

No resurrected Parent tests, copied old-schema hashes, mocked checker behavior,
weakened context/gates/warnings or unverified pointer. Cwd-only fixture selection
was insufficient. A genuine isolated fixture Git snapshot preserves the existing
context contract without a production bypass.

## Implementation decision

Normally merge verified #143 `b7d643f` and #144 `9e49913`, then port Parent
`db431efa` deltas through the current source map. Retain the default selection.
Each checker child selects its isolated fixture's post-mutation Git HEAD, with
sanitized Git overrides, isolated configuration and disabled hooks/templates/
signing. Framework code/context remains real and unchanged. Register idempotent
Close cleanup after Open in the new incomplete-response UDS test.

## Changed files and tests

The13 mapped sources preserve19 Go and five Python definitions plus existing
test extensions/Common assertions. A shared test-only fixture-repository helper
corrects Apache/NGINX mutation inputs. Update four generated inventory/archive/
migration-map views, paired ownership docs and this record. #143/#144 retain
their own records and16 newly authorized on-demand methods. No standard cases
are added or hidden in collectors.

## Commands and results

RTK, Framework Python and explicit source/output roots; external Product input
`b43faa78d403afd492c007e8f4a740ad21da1ac9` plus documentation-only edits.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Old Apache/NGINX adoption targets | 2 each | Obsolete exact expectations reproduced | External command record |
| Same targets with integrated checkers | 0 | Negotiated protocol/const/authority contracts pass | External command record |
| Native bindings/archive/map generation and checks | 0 |100/80 standard,2551/1133 optional and1993 baseline IDs preserved | External command record |
| Public inventory admission `--check` | 0 | Complete100-case cap admitted; not an execution | External command record |
| Initial12 Python methods | 1 | Nine mutation failures exposed inherited real-Parent context | External command record |
| Five focused methods after fixture correction | 0 | Positive controls and actual mutation rejection pass | External command record |
| Same12 selected Python methods after fixture correction | 0 | All12 pass, including the previously missed mutations | External command record |
| Integrated protocol-client suite and four QUIC helper methods | 0 |43 methods plus four helper methods pass | External command record |
| Explicit Framework-root documentation/pin checks | 0 | Links,344 EN/DE pair checks, path references, records and pins pass | External command record |
| `make check-common-helpers-c17 ON_DEMAND_TESTS=1` | 0 | Common protocol/late-policy assertions; warnings-as-errors | `pr348-test-migration-20261101.GnuEMR/common-build` |
| Envoy admitted Go overlay `-race -json` | 0 | Eight packages;392 pass terminals,0 failure/skip | `pr348-test-migration-20261101.GnuEMR/go/validation.md` |
| Traefik admitted native Go overlay `-race -json` | 0 |173 pass terminals; one explicit real-service-dependent skip | Same Go validation record |
| `go mod verify`, module diff and `gofmt -l` | 0 | Pinned modules verified; declarations/formatting unchanged | Same Go validation record |

Offline dependency misses and overlong AF_UNIX paths remain recorded setup
failures. Existing locked modules were materialized/verified; short task-owned
temporary paths resolved the socket prerequisite. One documentation invocation
inherited the main Parent CONNECTOR_ROOT and hit an unrelated local policy link;
the corrected command selects this Framework root explicitly and passes.
New-head hosted checks remain pending at preparation.

## Security impact

Restores mutation-input provenance and preserves fail-closed protocol/phase/EOS
contracts. No authentication, isolation, warnings, gates or production context
validation is weakened. Integrity/regression maintenance, not a new validated
connector vulnerability or authenticated external-attestation claim.

## Documentation and runtime evidence

Updated EN/DE ownership guide and record. Unit/race/Common results do not prove
real host/TLS/H2/H3 traffic or lifecycle/stream isolation. Skipped
`TestUDSEngineNativeBodyPolicy` requires a private Common/libModSecurity UDS
service; its real-service behavior remains unverified.

## Checks not run

No full historical/default-suite campaign, live host/TLS/H2/H3 qualification,
new module/toolchain version or MRTS execution. Local Go1.27.3 is not exact pinned
production Go1.26.9 evidence. Unpublished-head hosted PR/master checks and Sonar
remain pending.

## Limitations and residual risk

Protocol-aware checker expectations bind the explicitly selected Parent parity
source. Framework-master integration and exact Parent lock/workflow pin remain
separate required delivery steps; broader original qualification stays open.

## Final diff and review status

Task-owned Framework preparation only. Independent bounded fixture security
review found no blocker and no environment/secret dumping. Scoped diff/whitespace
and independent EN-DE review passed. Current-head CI/Sonar and exact-head merge remain
required. No secrets/raw sensitive payloads/full environments or actual PR merge
are claimed in this preparation record.
