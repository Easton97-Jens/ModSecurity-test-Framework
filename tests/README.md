# Tests

Status: scaffolded

## Boundaries

`tests/cases/` contains the YAML runtime case corpus. Cases are organized by
topic, and connector-specific variants live below
`tests/cases/connector-specific/<connector>/`.

`docs/imports/common/` contains reference maps and historical import metadata for
portable engine, rule, and behavior tests.

If a test depends on hook order, buffering, streaming, reload, local ports,
server config, module loading, or server/proxy log format, it is not portable
until proven otherwise.

## Categories

- engine-core tests
- connector-specific tests
- audit-log tests
- request-body tests
- response-body tests
- streaming/buffering tests
- capability-dependent tests

## Status

A minimal shared YAML case materializer and HTTP status assertion runner exists
under `tests/runners/`. The Apache and NGINX PoCs use it for current
topic-organized cases under `tests/cases/`, including blocking, pass-through,
request-body, response-header, and audit-log cases.

XFAIL, pending, future, connector-gap, and runtime-difference are YAML metadata
classes, not directory names. Missing YAML `status` is treated as active for
discovery/reporting without rewriting case content.

Cases that require OWASP Core Rule Set can set `requires_crs: true`. They are
excluded from `MODSECURITY_TEST_VARIANT=no-crs` and included in
`MODSECURITY_TEST_VARIANT=with-crs`.

No full connector regression suite exists yet.
