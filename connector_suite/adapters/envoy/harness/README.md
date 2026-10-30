# Envoy Connector Harness

**Language:** English | [Deutsch](README.de.md)

Status: C17 `ext_authz` service with separated start and runtime smokes.
Connector metadata is `minimal_runtime_smoke` / `connector-gap` for the targeted
request-header 200/403 path only.

## Entrypoints

- `serve_envoy_connector.sh` materializes a concrete connector config and runs
  the built service in the foreground.
- `start_envoy_connector.sh` validates connector and Envoy configs, starts both
  Envoy and the service with the same ephemeral private loopback TLS listener,
  checks both processes, and stops them without requests.
- `run_envoy_connector_runtime.sh` validates a temporary Envoy YAML config,
  starts a local upstream, the connector service, and Envoy, then verifies an
  allowed HTTPS 200 and a rule-backed HTTPS 403 through `ext_authz` over a
  private loopback TLS listener. The `ext_authz` sidecar remains internal
  loopback HTTP.
- `run_envoy_smoke.sh` is the Framework-facing compatibility entrypoint for the
  same real connector runtime path.
- `envoy_smoke_helper.py` provides only the dependency-free upstream and
  certificate-verifying HTTPS probe; it does not make security decisions.

The compatibility entrypoint additionally writes the existing Legacy JSONL
format only after validating fresh private 200/403 client observations, the
matching native rule `1000001`/transaction event and stopped processes. Its
`runtime-result.json` and `targeted-result.json` refer to the same actual
Libmodsecurity two-request observation. Missing, stale or contradictory
evidence fails; previous PASS outputs are cleared before another run. This
entrypoint accepts the targeted pair, without body, CRS or YAML-catalog claims.
The Parent Legacy launcher supplies the centrally prepared host binary and
current shared-build service and response observer.

The runtime smoke requires `ENVOY_BIN` and the separately built connector
service. Missing binaries return Exit 77/BLOCKED. Invalid config, early process
exit, request failure, wrong status, or missing event evidence returns FAIL.
Every started process is stopped on success, error, or signal.

The runtime path creates a one-day self-signed certificate and private key
only beneath its verified private root, uses them solely for its loopback
listener/client pair, and removes both during cleanup. It never stores their
contents in its summary or event evidence.

The smoke records metadata-only decision events and does not log request or
response bodies. `ext_authz` is request-phase only; response-body verification
remains false.

The full-lifecycle dispatcher does not reuse the `ext_authz` runtime entrypoint.
It invokes `runtime-smoke-envoy-ext-proc` through
`full-lifecycle-envoy-ext-proc`, which starts a real Envoy listener, the Go
`ext_proc` CGo/Common service, and a local upstream. The selected service uses
one real Common/libmodsecurity transaction per ext_proc stream and writes raw
Common JSONL under the run root; its completion JSONL remains supplementary.
The smoke verifies bounded HTTP/1.1 P1/P2/P3/P4 rule/action behavior, including
host-confirmed deny, redirect, and safe log-only outcomes after successful gRPC
sends. This connector-local evidence is non-promoted and cannot establish
reset, timeout, HTTP/2, client-byte, canonical-result, or production claims.
