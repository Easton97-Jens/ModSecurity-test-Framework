# ModSecurity Test Framework

**Language:** English | [Deutsch](README.de.md)

This repository provides the shared YAML case corpus, runners, normalizers,
catalog checks, and report generators used by ModSecurity connector projects.
It does not implement a web-server or proxy connector.

## Start here

- [Framework documentation](docs/README.md)
- [Architecture](docs/architecture.md)
- [Catalog and cases](docs/catalog-and-cases.md)
- [Testing and evidence](docs/testing-and-evidence.md)
- [Connector integration](docs/connector-integration.md)
- [Development](docs/development.md)
- [Change traceability](docs/change-traceability.md)
- [Variables and placeholders](docs/reference/variables.md)
- [Glossary](docs/reference/glossary.md)

The generated [coverage summary](TEST-COVERAGE-SUMMARY.md) is a deliberate
Framework-root exception: connector and Framework checks consume it, and its
generator is the only supported writer.

## Quick validation

```sh
make setup-dev
make quick-check
make check-documentation
```

Use explicit `FRAMEWORK_ROOT`, `CONNECTOR_ROOT`, `BUILD_ROOT`, `SOURCE_ROOT`,
`TMP_ROOT`, `LOG_ROOT`, and `EVIDENCE_ROOT` values outside Git when a command
crosses repository or runtime boundaries. The reference documentation defines
their format, defaults, and safety rules.

## Scope boundary

Connector repositories own host adapters, configuration, harnesses, capability
manifests, runtime artifacts, and promotion decisions. The Framework can select
and report cases, but it does not infer host support from a starter check,
generated report, or exit code.
