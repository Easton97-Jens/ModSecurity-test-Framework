# ModSecurity Test Framework

This repository contains the shared ModSecurity connector test framework:
YAML case schemas, shared runners, normalizers, runtime-matrix generation, and
coverage/reporting helpers.

It is not a connector implementation repository. Connector code, connector
harnesses, adapter metadata, connector-specific cases, and generated connector
reports live in the consuming connector project.

## Integration Model

The framework is used through explicit paths:

```sh
FRAMEWORK_ROOT=/path/to/ModSecurity-test-Framework
CONNECTOR_ROOT=/path/to/ModSecurity-conector
```

For the local sibling checkout layout, the connector repository may default
`FRAMEWORK_ROOT` to `../ModSecurity-test-Framework`. That is a relative sibling
convenience, not a hidden absolute workspace fallback.

Common cases are read from this repository:

```text
tests/common/cases/
tests/common/schema/
tests/runners/
tests/normalizers/
```

Connector-specific inventory is read from the connector repository:

```text
$CONNECTOR_ROOT/tests/import-status.json
$CONNECTOR_ROOT/tests/<connector>/cases/
$CONNECTOR_ROOT/connectors/<connector>/harness/
```

Generated reports are written to the connector repository unless another
`--output-root` is provided.

## Core Commands

Run framework-only checks:

```sh
make lint
```

Generate connector reports from the shared framework plus connector inventory:

```sh
CONNECTOR_ROOT=/path/to/ModSecurity-conector make generate-test-matrix
CONNECTOR_ROOT=/path/to/ModSecurity-conector make check-test-matrix
```

Run the connector runtime matrix through the connector project:

```sh
CONNECTOR_ROOT=/path/to/ModSecurity-conector make runtime-matrix-all
```

Runtime smokes still belong to the connector project. This framework records
runtime evidence but never promotes xfail, pending, future, connector-gap, or
RESPONSE_BODY cases automatically.

## Runtime Evidence Policy

- Generated coverage is reporting only.
- Full runtime evidence must come from local connector source-build smokes.
- `RESPONSE_BODY` remains non-verified/non-promoted unless explicitly proven by
  stable full-smoke runtime evidence in the connector project.
- `BUILD_ROOT` is a build/output directory, not a cache contract.
- External Apache/NGINX connector repositories are not default dependencies;
  connector source comes from the consuming connector repository.
