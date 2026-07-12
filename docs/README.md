# Framework documentation

**Language:** English | [Deutsch](README.de.md)

The Framework maintains six manual documentation pairs. Together with the
reference and generated outputs below, they are the complete current
documentation set.

## Guides

| Guide | Use |
|---|---|
| [Architecture](architecture.md) | Boundaries, lifecycle, data, privacy, and cache model |
| [Catalog and cases](catalog-and-cases.md) | YAML schema, provenance, selection, status, and normalization |
| [Testing and evidence](testing-and-evidence.md) | Validation workflow, No-CRS, reports, promotion, and privacy |
| [Connector integration](connector-integration.md) | Adapter contract, ownership, and source attribution |
| [Development](development.md) | CI layout, contribution workflow, and maintenance rules |
| [Variables and placeholders](reference/variables.md) | Inputs, defaults, examples, scopes, and safety notes |
| [Glossary](reference/glossary.md) | Framework vocabulary and status terms |

## Generated outputs

Current generated coverage and runtime reports remain below
[testing/](testing/test-coverage-overview.md). They are updated only through
their reporting generator. The Framework-root
[coverage summary](../TEST-COVERAGE-SUMMARY.md) is the externally consumed
generated exception.

## Documentation checks

```sh
make check-documentation
make check-test-matrix
```

Do not add a redirect-only Markdown file for a moved topic. Update links and
keep the English and German canonical documents structurally parallel.
