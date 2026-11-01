# Traefik native informational-response regression

**Language:** English | [Deutsch](20261101-01-traefik-native-informational.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261101-01-traefik-native-informational |
| UTC date | 2026-11-01 |
| Framework base revision | `d503ddbea1a3b6df7766edc247b0a9886ff10668` |
| Issue or pull request | External Connector finding `SEC-TRAEFIK-NATIVE-001`; separate Framework delivery |

## Motivation and problem statement

An informational response must not consume final response-header inspection.
The Framework supplies the regression and real-host adapter for this external
Connector defect; the product fix belongs to the Connector repository.

## Affected components and security boundaries

Native Traefik package tests, the dedicated host adapter, reviewed inventory
bindings, exact source mappings and their generated registration. MRTS and the
general protocol matrix are unchanged. No tests return to the product tree.

## Acceptance criteria

Explicitly observe 100/102/103 on HTTP transport; inspect final-only protection
headers and final status once; retain deny/redirect, request EOS, bounded P4,
streaming, keepalive and exactly-once cleanup. Keep the standard 100-case limit.
Real pinned Traefik/plugin/UDS/libmodsecurity evidence remains a separate gate.

## Alternatives considered

ResponseRecorder alone cannot establish informational response semantics.
Full response buffering would violate the streaming contract. Adding all
specialists to the automatic selection would exceed its fixed 100-case budget.

## Implementation decision

Six explicit specialist Go selectors expand to 31 leaves. Real HTTP tests use
`httptrace.Got1xxResponse`; synchronized completion makes transaction observation
safe under the race detector. Four host scenarios use one keepalive connection.
The inventory admits only these exact specialist identities/selectors/groups;
all existing source, expansion, provenance and path checks remain. Migration
registration records the four new mapped Framework sources as post-migration
additions while retaining strict immutable-source lookup for historical files.

## Changed files and tests

The new `informational_response_test.go` covers final decisions (13), request EOS
(3), implicit final paths (10), streaming (1), Upgrade/Hijack (1), and header
bounds (3). The host adapter separately covers 103-deny, no-103 deny, 103-allow
and legitimate followup. Source map, inventory, archive and test map register
the additional cases. The paired testing guide documents invocation and scope.

## Commands and results

All shell commands use RTK; Python is Framework-owned. The coordinating task
retains exact invocations, source digests and run output outside both checkouts.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Framework specialist overlay, then `go test -run '^TestInformationalResponse' -v ./...` on unchanged Connector base `a6001a09210bc9516256d28af5da45d73f0fe2f2` | 1 | 10 informational final-response leaves and 3 request-EOS leaves failed; 3 no-information controls passed | `unit-red/observed-red.json` under the external task root |
| Public Framework entrypoint with six exact Go selectors and `--on-demand --strict-skips` | 0 | All 31 expanded Go leaves passed against the candidate product delta | `unit-green/active-tests-5pnrf4rn/summary.json` under the external task root |

## Security impact

The reproducer confirmed P3 inspected 103 instead of final 201 and missed the
final-only marker; intended deny returned 200 with protected upstream test
bytes. The fixed-pair Go run withheld those bytes and distinguished the own
rejection body. The bounded-header negative tests retain validation failures.
This record does not claim an independent Framework vulnerability fix.

## Documentation and runtime evidence

See the paired [testing guide](../../../docs/testing/traefik-native-informational.md).
Real host results, exact committed pair, race/vet and final scan evidence are
owned by the coordinating task and its external delivery report. A Go package
PASS alone does not establish host runtime support.

## Checks not run

This bounded subtask did not run the general protocol matrix, MRTS or a full
repository test campaign. Final integrated race/vet, secret scanning and three
real host repetitions belong to the coordinating task.

## Limitations and residual risk

The initial red stdout was observed through the execution tool; the retained
compact note is an observation record rather than a verbatim log. The base SHAs
plus source delta identify the local pair until delivery produces new commits.
Host prerequisites and identity checks must pass without weakened isolation.

## Final diff and review status

Changes are handed to the coordinating task for final diff, whitespace and
secret review and separate Framework/Connector Draft PRs. Framework integration
must precede a dependent Connector pin update. No merge or direct master push
is authorized.
