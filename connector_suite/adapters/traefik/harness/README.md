# Traefik Harness

**Language:** English | [Deutsch](README.de.md)

Status: minimal_runtime_smoke for the connector-owned forwardAuth request path
Runtime status: broader connector behavior remains not-verified / connector-gap

`run_traefik_smoke.sh` remains the framework-facing compatibility entrypoint.
The connector-owned service path is exercised directly by
`scripts/runtime-smoke.sh`, which starts the built Common-runtime-backed
forwardAuth service, a minimal upstream, and Traefik with a temporary File
Provider configuration.

Current local self-test:

- `make -C connectors/traefik self-test-decision-service`

The self-test covers only in-memory allow/block decision logic. It does not
prove a Traefik `forwardAuth` deployment, HTTP service behavior, CRS execution,
libmodsecurity integration, or Traefik traffic handling.

Separated real-service stages:

```sh
make -C connectors/traefik build-connector
make -C connectors/traefik check-config
make -C connectors/traefik start-smoke
make -C connectors/traefik runtime-smoke
```

Only `runtime-smoke` sends requests. It requires 200 for the allowed request and
403 for `X-Modsec-Smoke: block`; resolved-runtime failures are FAIL rather than
BLOCKED. Response-body processing remains unsupported by `forwardAuth`.

Framework runtime-smoke entrypoint:

```sh
make smoke-traefik
```

The framework-facing entrypoint does not run decision-service starter self-tests
as runtime evidence. Missing explicitly local runtime dependencies remain
BLOCKED/77.

The full-lifecycle dispatcher does not reuse this `forwardAuth` compatibility
entrypoint. It invokes `runtime-smoke-traefik-native` through
`full-lifecycle-traefik-native`, which stages `native_middleware/` in an
isolated pinned Traefik local-plugin workspace, builds/starts a persistent
private UDS Common/libmodsecurity engine, and verifies target P1--P4-safe
host behavior. It loads `MSCONNECTOR_RULES_FILE` when supplied so the real
events use the Framework rule IDs. This evidence remains non-promoted and
cannot stand in for capability or production verification; P4 strict remains
`NOT EXECUTED`.

Future harness work must document:

- Traefik binary, container, or source-build used by the harness
- Traefik configuration file
- selected ModSecurity integration point
- `forwardAuth`, plugin, middleware, sidecar, or custom-module configuration if
  that path is selected
- decision-service endpoint if an external decision service is selected
- evidence paths written by the harness
- result JSON path
- PASS/FAIL/BLOCKED counts
- No-CRS and With-CRS separation
- RESPONSE_BODY, negative/pass-through, and audit/log evidence when evaluated

No runtime result is claimed until the connector-owned runtime smoke succeeds on
the current commit and its external evidence is retained.
