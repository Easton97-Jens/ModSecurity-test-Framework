# Protocol acceptance preparation

**Language:** English | [Deutsch](protocol-acceptance-preparation.de.md)

This opt-in preparation runner adds executable native NGINX paths for H2, H3
and h2c without changing the 100-case standard selection. Comprehensive
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
It is dedicated to `native-nginx-http-module`. The other nine logical profiles
retain their own capability and runner gaps. A missing required path is not
resolved by declaring it unsupported. No Framework, Parent or MRTS promotion
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

## Observed preparation outcome

The targeted `trial4` host campaign evaluated all 25 registered IDs: **21 PASS,
4 FAIL**. The failing IDs are `h2_phase4_strict`, `h2_server_rst_stream`,
`h2_upstream_reset` and `phase4_strict_http2_stream_reset`. All 25 bundles
verified owned-process and listener cleanup. Original failed observations remain
in external `host/trial4` evidence; expectations and failing regressions remain
unchanged. Preparation is **NOT_READY**; comprehensive acceptance is **NOT_RUN**.

H3 Strict passed with the peer held after headers until an actual target reset,
then a healthy peer and follow-up on the same connection. For H2, the native
abort event appeared immediately, but the client observed reset only about
12 seconds later when the peer barrier timed out; the peer then failed. An
H2-only build without QUIC reproduced both Strict and upstream-reset failures.
The source-level hypothesis is that NGINX HTTP/2 queues RST in `close_stream`
and returns while another peer is processing. This is a hypothesis about the
observed product path, not a completed root-cause proof or remediation. Product
changes are outside this preparation change.

Still-required modern paths include Apache H2, HAProxy HTX H2 and its SPOE
companion H2 stream shutdown, and Envoy ext_proc H2. This NGINX runner does not
close those gaps. The selected stock and patched lighttpd profiles have an
existing H1-only contract; modern protocols are excluded by that contract,
without a new unsupported declaration. All ten logical profiles retain
separate acceptance claims.

The eight adjacent existing real-host cases also passed:
`protocol_h2_negotiated`, `h2_phase2_deny`, `h2_phase3_deny`, `h2_phase4_safe`,
`protocol_h3_negotiated`, `h3_phase2_deny`, `h3_phase3_deny`, `h3_phase4_safe`.
The completed execution receipt is retained externally as
`host/adjacent/executions.json`, with Framework base
`62b411e073551ef0fef22ab3d372e2489f2ae168` and Parent source
`a5f697c35acb5386d2037f91dfed10ad4b469cd9`. These successful adjacent paths do
not close the four failed new H2 cases.
