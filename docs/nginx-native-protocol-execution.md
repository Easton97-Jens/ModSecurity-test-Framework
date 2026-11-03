# Native NGINX H2/H3 execution

**Language:** English | [Deutsch](nginx-native-protocol-execution.de.md)

The selected host accepts only `http1`, `h2` or `h3` downstream values. Unknown
values fail with exit2 before host dispatch; they never silently select H1.
Receipt/source checks, access bindings, native phase semantics and QUIC checks
are separate validation stages with the same mandatory integrity conditions.

The native protocol executor connects the existing TLS H2 and QUIC H3 catalog
contracts to an isolated NGINX master/worker, a loopback upstream and a forced
curl client. `full-lifecycle-nginx` with `NGINX_DOWNSTREAM_PROTOCOL=h2` or `h3`
dispatches the supported protocol cases through this executor. Ordinary H1-only
operations receive no modern-protocol result; they remain unexecuted and the
selection denominator is unchanged. An enhanced build alone still selects H1.

Supported operations are negotiation, no fallback, P1/P2/P3 deny, P4 Safe
log-only, the legacy H2 transport probe and H3 Alt-Svc advertisement. Each case
also sends an independent allow request. Reset, Strict stream termination,
multiplex transaction isolation, modern first-byte and h2c contracts remain
outside the implemented executor. Their product capability states and honest
non-execution remain authoritative; no skip is counted as success.

Use an admitted current NGINX binary/module pair built with `h1-h2` for H2 or
`h1-h2-h3-quic` for H3. Select the Framework-owned interpreter and explicit
product/test checkout identities. The caller supplies the library directory,
an appropriate curl executable, a bounded run ID, all three source revisions
and a fresh private external output directory. The executor runs the existing
runtime preflight in the same launcher before starting the host. H3 additionally
requires permission to observe loopback packets with an `AF_PACKET` socket.
Missing identity or client prerequisites produce `BLOCKED`, never PASS.

For a bounded single case, invoke
`connector_suite/modsecurity_connector_ci/runtime/lifecycle/run-nginx-protocol-cases.py`
through RTK and the selected interpreter. Its `--help` lists the closed case
IDs and required `--nginx-binary`, `--module`, `--output-root`, `--run-id`,
`--parent-sha`, `--framework-sha`, `--mrts-sha`, `--framework-root`, optional
`--library-dir` and `--curl` arguments. No package installation or automatic
privilege escalation occurs in the executor.

H2 uses `--http2-prior-knowledge` over TLS; H3 uses `--http3-only`. A successful
HTTP transfer is insufficient: curl's actual HTTP version and stream-open trace
must agree. Both native access records must independently report the requested
protocol and accepted ALPN through `$ssl_alpn_protocol` and bind the allow and contract requests to different native
transactions. Native rule, phase, URI and transaction witnesses establish each
deny or Safe action. H3 also requires bidirectional, port-scoped loopback
QUIC/UDP long-header observations. Only packet sizes, direction, version and
hashed connection identifiers are retained; packet payloads and raw identifiers
are not written.

Some curl QUIC TLS backends omit an accepted-ALPN trace line. The client parser
preserves that absence; it does not infer ALPN from HTTP/3 or copy the server's
value into a client observation. A completed bundle still requires matching
server ALPN on **both** original access records. An explicit contradictory
client ALPN always fails. `alpn_source=nginx_access_ssl_alpn_protocol` identifies
the independently verified server source; `client_alpn_observed` and
`client_alpn` retain whether the client actually reported ALPN and its value.
Missing or contradictory server ALPN cannot produce PASS even when HTTP/3
transfer, stream and QUIC packet observations succeed.

`tests/runners/nginx_protocol.py` reopens the private evidence bundle, verifies
all original hashes, source contracts, run/revision identities, request/access
correlation, native witness and cleanup. Canonical collection and retention
reuse that reader and independently revalidate PASS records. Original native
event bytes remain unchanged. `protocol_evidence_mapping` distinguishes fields
present in native events from independently observed client/access/QUIC facts;
ALPN and stream IDs are never inserted into Common events.

The executor uses the existing pidfd-bound owned-child cleanup, verifies the
TCP and UDP listener release, stops its upstream and packet observer and removes
its ephemeral TLS key/certificate even on failure. Metadata evidence remains in
the task-owned output. A passing focused run proves only its exact current
source/artifact pair and selected operation. Comprehensive protocol acceptance,
unsupported product features and protected broker authorization are separate.

Run the on-demand regressions with the Framework interpreter using
`python -m unittest tests.no_crs.test_nginx_protocol_executor` and the migrated
`modsecurity_connector_tests.test_nginx_full_lifecycle_protocol_wiring` module.
They test parsing, no fallback, packet metadata, evidence mutation, request/run
mixups, cleanup, canonical revalidation and real Make selection/init. These
selftests do not launch a protocol host or qualify runtime traffic. They do not
increase the 100-case standard selection.
