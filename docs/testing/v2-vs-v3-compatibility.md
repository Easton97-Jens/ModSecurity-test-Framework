# v2 vs v3 Compatibility

Status: implemented

## Architecture

v2 is an Apache-centered codebase. Many engine, connector, parser, and request
handling concerns are located under `apache2/`.

v3 is libmodsecurity: a connector-neutral engine with public C and C++ APIs.
Connectors are separate adapters that feed transaction phases into the engine.

Decision: new connector architecture follows v3 only.

## API

v2 internal functions and structs are not a connector API for this repository.
v3 public APIs under `headers/modsecurity/` are the usable connector boundary.

Compatible v3 API concepts:

- engine lifecycle
- ruleset lifecycle
- transaction phase calls
- intervention query
- log callback registration

Incompatible v2 concepts:

- direct use of Apache request records as engine state
- APR-owned transaction structures
- direct calls into v2 internal parser/operator functions
- Apache-specific v2 module hooks as a portable lifecycle

## Logging

v2 regression tests often match Apache-style error/debug/audit log text.
v3 exposes a log callback and has its own audit/debug implementation.

Decision: log tests must be normalized and capability-marked before being
considered portable. Raw v2 log text expectations are not portable by default.

## Transaction Lifecycle

v2 lifecycle is shaped by Apache module phases. v3 lifecycle is shaped by
libmodsecurity transaction APIs:

- connection
- URI
- request headers
- request body
- response headers
- response body
- logging

Connector adapters decide where those calls fit in each server/proxy and must
document missing or late phases.

## Connector Model

v2 does not define a general connector model for this monorepo. v3 connectors
should be thin translators between server/proxy hooks and libmodsecurity public
APIs.

## Test Reuse

| Test kind | Portable to v3 connectors? | Placement |
| --- | --- | --- |
| Operator semantics | Maybe | `tests/common/` only after capability review |
| Transformations | Maybe | `tests/common/` only after v3 parity check |
| Rule parsing | Maybe | `tests/common/` if no connector runtime needed |
| Request body parsing | Partial | Common only if body delivery is engine-only; otherwise connector-specific |
| Response body inspection | Partial | Capability-dependent |
| Audit/error log exact text | Partial/no | Normalized and capability-marked, often connector-specific |
| Apache harness behavior | No | `tests/cases/connector-specific/apache/` or historical docs only |
