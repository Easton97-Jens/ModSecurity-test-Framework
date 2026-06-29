# Future Connectors

**Language:** English | [Deutsch](future-connectors.de.md)

No new connector is implemented in this stabilization step. Each future
connector must first provide a real-world harness equivalent to Apache and
NGINX.

## HAProxy

- Expected model: SPOE or native extension path must hand request metadata and
  body data to libmodsecurity at the correct phase.
- Difficult areas: buffering, response inspection, audit-log ownership, and
  mapping ModSecurity interventions to HAProxy actions.
- Likely portable first cases: `REQUEST_HEADERS`, `ARGS`, simple request body.
- Likely connector-specific cases: streaming, backend response handling, SPOE
  error paths.

## Envoy

- Expected model: HTTP filter or external processing flow.
- Difficult areas: async body buffering, filter ordering, header mutation, and
  mapping interventions to Envoy responses.
- Likely portable first cases: headers, query args, raw JSON body.
- Likely connector-specific cases: HTTP/2, gRPC, streaming, filter-chain
  configuration.

## Lighttpd

- Expected model: native plugin hook integration or documented scriptable
  module path.
- Difficult areas: request body availability, response filter hooks, and stable
  module build packaging.
- Likely portable first cases: headers and query args.
- Likely connector-specific cases: plugin lifecycle and server config parsing.

## Traefik

- Expected model: plugin/middleware path must be proven before any connector
  claims.
- Difficult areas: plugin sandbox constraints, request body buffering, response
  mutation, and distributing libmodsecurity.
- Likely portable first cases: headers and query args if the middleware can
  call libmodsecurity safely.
- Likely connector-specific cases: dynamic config reload and provider-specific
  middleware wiring.

## Shared Requirement

Every connector must produce summary JSON with `connector_path:
"real-world"`, `validation_mode: "real-world-connector-path"`, stable
`pass/fail/blocked` semantics, and no generated artifacts outside `BUILD_ROOT`.
