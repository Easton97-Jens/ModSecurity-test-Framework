# Architecture

**Language:** English | [Deutsch](architecture.de.md)

The Framework is a reusable test, normalization, and evidence layer for
ModSecurity connector projects. It is not a server, proxy, or connector
implementation.

## Repository boundary

| Layer | Responsibility |
|---|---|
| Framework | YAML cases, runners, normalizers, catalog checks, report generators, and bounded evidence validation |
| Common connector code | Connector-neutral data shapes only, where the connector repository provides them |
| Host adapter | Host hooks, filters, plugins, directives, configuration merge, and intervention translation |
| Connector evidence | Capability declaration, observed artifacts, and promotion decision |

Shared Framework code must not own host SDK objects, server configuration, or
unreviewed payload data. A connector adapter translates its host state into the
selected test and evidence contracts, then translates observed results back
into host-specific behavior.

## Transaction and lifecycle model

The Framework represents a transaction through case metadata and bounded
artifacts. The host adapter owns the actual ordering and must report only
observed phases.

| Lifecycle area | Framework concern | Connector responsibility |
|---|---|---|
| P1 request start | Case selection and request metadata | Connection, URI, and request-header delivery |
| P2 request body | Body fixture and bounded assertions | Incremental body delivery, limits, and intervention behavior |
| P3 response headers | Response-header fixture and assertions | Header delivery and host response handling |
| P4 response body and logging | Non-promotion and privacy boundaries | Streaming, late intervention, final logging, and host-safe behavior |

P1–P4 names do not turn a declared phase into an implementation claim. In
particular, a Phase-4 log, pass-through response, or post-commit connection
outcome must follow the configured evidence policy and must not be presented as
pre-commit response-body blocking.

## Engine and host separation

libmodsecurity public APIs, rules, and transaction state belong to the engine
side. The host adapter controls when those APIs are called and whether a host
can safely apply an intervention. Connector-specific configuration, body
limits, content-type handling, logging, and connection behavior cannot be
generalized merely because the Framework uses common YAML.

The connector-free v3 API smoke is a bounded engine probe. It is not Apache,
NGINX, HAProxy, Envoy, Traefik, or lighttpd runtime evidence.

## Capability and status model

Capabilities label exercised behavior; they do not automatically skip,
promote, or certify a case. Result status distinguishes observed PASS and FAIL
from BLOCKED, NOT_EXECUTABLE, mapped-only, pending, future, connector-gap, and
runtime-difference states.

`RESPONSE_BODY` remains non-verified and non-promoted until the applicable
connector evidence contract accepts stable proof. First-byte timing,
no-full-response-buffering, body limits, event privacy, and evidence promotion
are likewise validated from explicit artifacts rather than inferred from a
report or an exit status.

## Data, events, and privacy

Canonical result and event inputs use bounded, normalized metadata. They may
contain reviewed identifiers, phase, action or decision, status, HTTP status,
version, size, hash, truncation, and redaction facts allowed by the schema.
They must not contain raw request or response bodies, credentials, or
unreviewed host logs.

Hash-chain data can support smoke-level tamper detection. It does not provide
durable integrity without connector-owned secure key handling and storage.

## Build and cache boundary

Source copies, build outputs, logs, temporary data, and evidence live outside
the Git worktree under explicit paths. The Framework does not silently reuse a
parent workspace or rewrite source checkouts. Cache reuse never replaces
current configuration, start, runtime, or evidence validation.

## Related documents

- [Catalog and cases](catalog-and-cases.md)
- [Testing and evidence](testing-and-evidence.md)
- [Connector integration](connector-integration.md)
- [Development](development.md)
- [Variables and placeholders](reference/variables.md)
