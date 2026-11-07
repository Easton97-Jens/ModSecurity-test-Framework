# Protocol acceptance preparation

**Language:** English | [Deutsch](protocol-acceptance-preparation.de.md)

These opt-in preparation adapters cover native NGINX H2/H3/h2c and separate
Apache, HAProxy HTX/SPOP-companion, Envoy ext_proc, Envoy ext_authz-companion,
Traefik ForwardAuth-companion and native Traefik H2 paths without changing
the 100-case standard selection. Comprehensive
acceptance remains **NOT_RUN**. This document does not declare
`READY_FOR_FULL_ACCEPTANCE` or promote a connector capability.

## Scope and registration

The closed registry is `tests/runners/protocol_acceptance_contract.py:CASES`.
It contains 25 stable IDs. For each of `h2` and `h3`, the suffixes are
`parallel_stream_transaction_isolation`, `parallel_cleanup_balanced`,
`first_byte_before_response_end`, `no_full_response_buffering`, `upstream_reset`,
`phase3_deny`, `phase4_safe` and `phase4_strict`. The remaining IDs are:

| H2 | H3 |
| --- | --- |
| `h2_deny_does_not_abort_unrelated_stream` | `h3_deny_does_not_abort_unrelated_stream_preparation` |
| `h2_client_rst_stream` | `h3_client_stream_cancel` |
| `h2_server_rst_stream` | `h3_server_stream_reset` |

The three additional IDs are `h2c_prior_knowledge_preparation`,
`h3_reset_does_not_abort_unrelated_stream` and
`phase4_strict_http2_stream_reset`. Multiple IDs can select the same scenario;
each selected ID still requires its own complete evidence bundle.

[The existing native executor](nginx-native-protocol-execution.md) and its
canonical fixtures/assertions retain their previous scope. The separate entry
point is
`connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-protocol-acceptance.py`.
It is dedicated to `native-nginx-http-module`. Other profiles use their own
adapters and independent native evidence readers. A missing required path is
not resolved by declaring it unsupported. No Framework, Parent or MRTS promotion
follows from a preparation result.

## Independent observations

A source-built libcurl multi client forces the selected protocol and starts an
allow peer before the target. Peer, target and follow-up must use the same
transport connection and distinct streams and native transactions. Native
transaction creation/cleanup and rule/phase events bind each request; a queued
client request alone does not prove active multiplexing. H3 access records bind
streams through the remote transport endpoint because native NGINX
`$connection` is per request there.

Raw client debug observations supply stream identifiers and any client ALPN.
Missing client ALPN remains absent; server `$ssl_alpn_protocol` is recorded as a
separate observation. h2c requires HTTP/2 prior knowledge without TLS/ALPN.
H3 additionally needs bidirectional loopback QUIC packet metadata. Packet
payloads and raw QUIC connection identifiers are not retained. An H1 fallback,
contradictory protocol identity or missing original witness fails validation.

The controlled upstream pauses before EOS. The driver releases its barrier
only after actual client bytes are observed, or the expected blocked target
completes. The reader checks the observed byte count and the paused/not-EOS/not-
finished snapshot; elapsed time alone cannot satisfy streaming. P3 checks a
pre-commit deny; P4 Safe requires the rule witness and log-only behavior. Strict
keeps the original native `abort_connection` action distinct from the client-
observed server stream reset: H2 error `0x2`, H3 error `0x102`. It requires the
exact affected stream, a successful unrelated peer and a successful follow-up
on the same connection. Client cancellation and controlled upstream reset
have separate scenario expectations.

## Execution and evidence

Use the existing admitted host execution context and Framework-owned Python
environment. The driver executes the existing identity/runtime preflight in
that same context, then owns a loopback NGINX host, upstream, ports and client.
It creates no UDS. H3 needs the existing `AF_PACKET` observation permission.
Missing preflight prerequisites produce `BLOCKED`, never PASS. Do not change
global permissions or install dependencies to make a run pass.

Inspect `--help` through RTK and the selected interpreter before execution.
Supply `--case-id`, `--nginx-binary`, `--module`, `--output-root`, `--run-id`,
`--parent-sha`, `--framework-sha`, `--mrts-sha`, `--framework-root`,
`--curl-prefix`, `--client-build-root` and the applicable `--library-dir`.
Use full source SHAs, admitted source-matched binaries, a source-built curl
prefix with the required protocols, and fresh absolute external output/build
paths. Source context must expose both the Framework root and its
`connector_suite` directory on `PYTHONPATH`; set `TEST_ROOT` to the Framework
root and `CONNECTOR_ROOT`/`CONNECTOR_REVISION` to the selected Parent source.
The runner does not install software or escalate privileges.

`receipt.json` binds source revisions, source hashes, copied executable/module
hashes, actual configuration/rules and original client/access/native/upstream/
QUIC/role/cleanup evidence. The independent `validate_bundle` reader reopens
these files and verifies hashes, closed inventories, request completeness,
writer/driver errors, protocol identity, native cleanup and listener release.
Missing requests, incomplete JSONL, zero observations, mutations, mismatched
runs/streams/transactions or failed cleanup cannot yield PASS. Original native
event bytes are preserved. Task-owned keys/certificates and children are
removed; retained evidence remains external to the checkout.

Run `tests.no_crs.test_protocol_acceptance_contract` with the selected Framework
interpreter for positive and negative contract controls. These unit tests do
not substitute for host runs. Keep the existing
`tests.no_crs.test_nginx_protocol_executor` and
`modsecurity_connector_tests.test_nginx_full_lifecycle_protocol_wiring`
regressions. Run-scoped commands, identities, outcomes and outstanding checks
belong in the paired [Change Record](../reports/audits/change-records/20261106-01-protocol-acceptance-preparation.md).
Local Sonar is suspended for this task; existing GitHub Sonar and CodeQL checks
remain required. Preparation evidence and later full acceptance are separate.

## Separate non-NGINX H2 registry

`tests/runners/non_nginx_h2_acceptance.py:CASES` registers **56** additional
opt-in IDs, separately from the 25 NGINX IDs and the 100 standard cases.
Each prefix below has eight suffixes: `allow`, `phase1`, `phase2`, `phase3`,
`phase4_safe`, `phase4_strict`, `client_cancel`, `upstream_reset`.

| Prefix | Selected profile | Executable Framework adapter |
| --- | --- | --- |
| `apache_h2_` | Apache native module | `connector_suite/adapters/apache/harness/apache_h2_acceptance.py` |
| `haproxy_htx_h2_` | Local native HTX filter | `connector_suite/adapters/haproxy/harness/haproxy_h2_acceptance.py` |
| `haproxy_spop_htx_h2_` | SPOP request phases plus native HTX response companion | `connector_suite/adapters/haproxy/harness/haproxy_spop_h2_acceptance.py` |
| `envoy_h2_` | Native streamed ext_proc | `connector_suite/adapters/envoy/harness/envoy_h2_acceptance.py` |
| `envoy_ext_authz_h2_` | ext_authz plus response companion | `connector_suite/adapters/composite_harness/companion_h2_acceptance.py --adapter envoy_ext_authz_h2` |
| `traefik_forwardauth_h2_` | ForwardAuth plus response companion | `connector_suite/adapters/composite_harness/companion_h2_acceptance.py --adapter traefik_forwardauth_h2` |
| `traefik_native_h2_` | Native UDS middleware | `connector_suite/adapters/traefik/harness/traefik_native_h2_acceptance.py` |

The original 32 IDs remain selected. The three separate profile paths add
24 IDs; registration does not imply a successful host run. Together with the
25 NGINX IDs and eight existing H2/H3 neighbour checks, the preparation scope
contains 89 requested host executions and 85 distinct bare case IDs, plus three
separately counted Apache H1 regressions. Four NGINX names occur in both driver
catalogs; their driver contracts and traffic variants must be stated explicitly.
Repeated executions are not additional unique cases.

Inspect each adapter's `--help` through RTK in the explicit source context
above. Apache accepts one full `--case-id`; the other adapters accept a scenario
through `--case`. Envoy Strict requires
`--late-action-policy strict --case phase4_strict`; its default selection runs
the seven Safe-policy scenarios. Each adapter requires explicit external
runtime and admitted binary/build inputs. The HAProxy build helpers
`ci/provisioning/prepare-haproxy-h2-test-build.py` and
`ci/provisioning/prepare-haproxy-spop-h2-test-build.py` build logging-only native
observers from verified source copies. Production source bytes remain unchanged.
Their manifests retain historical build identities, exact transformation and
source/archive/library/binary hashes; reused outputs need fresh source admission.

A verified TLS 1.3/ALPN-h2 raw-frame client holds peer stream 1 while target
stream 3 runs, then uses stream 5 for follow-up. It decodes native HPACK status
headers using the admitted libnghttp2 ABI and rejects missing/duplicate status,
H1 fallback and malformed frames. P2 submits an actual bounded POST body.
Native access, Common rule/phase decisions and profile-specific transaction
cleanup remain separate observations. A target must finish cleanup while the
TLS connection is open and the peer is still held; host shutdown cannot supply
that proof. Apache's test module observes actual mod_security request-context
release from an APR pool cleanup. HTX observes its actual detach; SPOP additionally
joins native handoff/claim/close using a SHA-256 handle witness without exporting
the raw response handle. Early SPOP P1/P2 denies require zero phantom claims.
The SPOP fixture sends explicit `Content-Length: 0` for empty H2 requests because
its current NOTIFY ABI does not carry H2 END_STREAM; this is a visible product
boundary, not proof of every possible H2 request-body framing.

Each case checks Allow/Block, applicable request/response phase and exact rule,
client-visible target outcome, active peer isolation, successful follow-up,
readiness and owned cleanup. Safe requires first bytes before upstream EOS plus
the actual log-only decision. Strict requires the real affected-stream reset,
with profile-specific error codes, rather than inferring transport action from
an engine decision or successful gRPC send. Corruption controls reject missing,
duplicate, foreign or mismatched evidence, malformed JSON, unsafe evidence files,
late cleanup and writer failures. The registry's completeness checker rejects
zero results, missing/duplicate/foreign IDs and every non-PASS terminal result;
it supplements the independent host readers.

## Proven H2 reset cause and versioned correction

The retained baseline reproduced all four failures at Parent
`adf75d05ced37ccab066b8608aed1ce297be84e3` / Framework
`b5d8d9442d7751c04ee84f478f594fc84a236e3b`. Independent verified TLS/H2 frame
observations showed target RST_STREAM after about 12 seconds without new input,
but immediately after a controlled PING with a healthy peer/follow-up. This
establishes pending server output rather than delayed libcurl processing.

NGINX queued the reset in `ngx_http_v2_close_stream`, then returned while another
stream was processing, leaving the real connection write event unscheduled.
`ci/provisioning/patches/nginx/h2-close-stream-flush.patch` posts the existing
write event when queued output remains and the connection is not blocked.
The native preparation path applies it to verified pinned source with zero fuzz;
its SHA participates in provenance/cache identity. It neither calls a recursive
flush nor retains a request pointer. Assertions and timeouts are unchanged.

Fresh H2 and H3 native builds passed. The four retained regressions and eight
H2/H3 neighbors passed in focused candidate runs. An independent no-PING frame
probe observed target reset after about 15 ms with healthy peer/follow-up.
Final committed-pair counts and current hosted CI belong in the run-scoped report
and paired Change Record; candidate runs alone do not establish global readiness.
The sealed earlier 21-PASS/4-FAIL observations remain retained as before evidence.

Envoy Strict now sends a late ImmediateResponse through the pinned native host.
Its filter-manager resets an already-committed downstream stream; the service
records the successful send separately from the client-observed reset. Eight
candidate ext_proc H2 cases passed with timely cleanup. This does not promote
ext_authz or a different Envoy version/profile.

## Remaining profile boundaries and readiness

All ten logical profiles keep separate claims. The selected stock and patched
lighttpd contracts remain H1-only. Envoy ext_authz and Traefik ForwardAuth require
their own response companions and cannot inherit direct ext_proc/native results.
The registry now provides separate complete companion and native Traefik H2
paths. Their own final committed-pair execution, source/build admission and
current checks decide qualification; an adapter or diagnostic PASS alone does
not close those obligations. No new unsupported marker or removed case resolves
a missing required path.

The preparation client permits only owned IPv4 loopback origins, verifies CA,
peer and host, sets a checked TLS 1.3 minimum before networking, and intentionally
uses plaintext only for the separately selected h2c fixture. Actual TLS-1.2-only
negative controls require rejected handshakes with no HTTP bytes. Callback ABI,
numeric stream logging and bounded h2c use are reviewed per Sonar occurrence;
local review is distinct from hosted issue disposition and required Gate status.
Local Sonar remains suspended. Comprehensive acceptance remains **NOT_RUN**.
Readiness is declared only in the final reconciled report when every mandatory
preparation criterion and required current-head hosted check is satisfied.
