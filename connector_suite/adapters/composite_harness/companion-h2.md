# Authorization and response companion HTTP/2 preparation

`companion_h2_acceptance.py` runs the complete logical `envoy-ext-authz` or
`traefik-forwardauth` profile. Each has eight explicit opt-in cases: Allow,
P1/P2/P3 deny, late P4 Safe/Strict, client cancellation and upstream reset.
The automatic default inventory remains unchanged.

The host and service arguments must name absolute regular executable files.
Relative executable names are rejected before execution so PATH lookup cannot
select bytes different from the hash-admitted file. This admission does not
make caller-selected binaries or checkout configuration a sandbox.

Select `--adapter envoy_ext_authz_h2` or `--adapter traefik_forwardauth_h2`,
one `--case`, both source roots and full revisions, a fresh external runtime
root, the native host and its independently admitted `--host-sha256`, and
the freshly built native composite `--service` and `--build-receipt`.
`--require-clean` rejects dirty final source pairs. The receipt must preserve
the native builder exit status, exact compiled source hashes before/after,
and the service and libModSecurity hashes. Admission is repeated after traffic.

The client verifies TLS 1.3, the fixture CA and ALPN `h2`; it has no protocol
fallback. Stream 1 remains active while target stream 3 runs and closes its
native retained transaction. Stream 5 then tests the same live connection.
Held response cases require actual DATA before upstream EOS is released.
P2 uses the actual bounded POST entity. Native host access, request hash,
server-issued retained identity, rule and lifecycle records must agree.
Envoy stream UUIDs and Traefik request counters are distinct from wire stream
numbers and are joined through unique request metadata on the same connection.

Both composite modes reuse the Common CGo engine backend identified in raw
Common events as `envoy`/`ext_proc`. The logical profile is independently
established by the native host and the retained authorization/response handoff;
the backend name is not ext_proc qualification of either logical profile.

Safe keeps the complete committed response and records log-only. Explicit
Strict requires matching native runtime policy and requests a host abort;
only independent downstream RST_STREAM observations prove the result.
The request is recorded separately from a Common host-confirmed outcome.
An observed incomplete companion transport records a typed protocol terminal,
never invented response EOS or an attributed client/upstream cancellation.

`--completion-writer-fault` bounds only the selected service's regular-file
writes to inject a real lifecycle writer failure. It is a negative control:
the run must fail and still stop its task-owned host, service and fixture.
Reports require nonzero, complete, unique results and checked cleanup of
processes, ports, private TLS files and the private UDS. Empty traffic,
crossed identities, missing phases or writer failures cannot produce PASS.

Focused reader controls run with:

```sh
python -m unittest connector_suite.adapters.composite_harness.test_companion_h2_acceptance
```

The payload-free metadata fixtures come from actual Allow, Strict and Cancel
preparation runs. They are unit-test inputs, not final-pair runtime evidence.
Fresh committed-pair execution remains required before a preparation claim.
