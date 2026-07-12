# Framework documentation

**Language:** English | [Deutsch](README.de.md)

This directory contains maintained Framework design, testing, import, quality,
and reference documentation. Generated reports remain generated: they are
written below [`testing/generated/`](testing/generated/) by the reporting tools
and must be changed through their generator, not by editing Markdown.

## Start here

- [Framework overview](../README.md): scope, runtime boundaries, and entrypoints.
- [Variables and placeholders](reference/variables.md): required/optional inputs,
  defaults, formats, examples, and security notes.
- [Glossary](reference/glossary.md): Framework terminology and status vocabulary.
- [Testing guide](testing/README.md): case corpus, variants, and evidence boundary.
- [Architecture](architecture.md), [catalog/capability model](capability-model.md),
  and [status model](status-model.md): the catalog and normalization model.
- [No-CRS evidence contract](testing/no-crs-baseline.md): selection, validation,
  promotion, and privacy boundaries.
- [Connector adapter interface](connector-adapter-interface.md) and
  [future connectors](future-connectors.md): integration and extension rules.

## Structure and sources of truth

| Area | Purpose and source of truth |
|---|---|
| `testing/` | User-facing test, evidence, compatibility, and local-check guides. YAML cases and runner code remain the executable source of truth. |
| `imports/` | Provenance and import analysis for upstream test material. Historical facts remain attributed to their source. |
| `connectors/` | Connector-focused Framework contracts and investigations. Connector source and runtime evidence remain owned by the connector repository. |
| `quality/` and `roadmap/` | Quality work and explicitly non-current planning records. |
| `reference/` | Bilingual variables/placeholders and glossary reference. |
| `testing/generated/` | Generated coverage/runtime reports; [`generated/`](generated/) explains the canonical output locations. |

Add a maintained English/German pair in the nearest area, link it from that
area's index when it is a user entrypoint, and keep technical names, defaults,
paths, IDs, and examples identical across the pair. Explain an adjustable value
beside a command and link to the central reference for repeated values.

Do not place generated reports, connector implementation notes, runtime logs,
or unreviewed upstream copies in this directory. Use `docs/imports/` for source
analysis and the connector repository for connector-owned artifacts.

## Relevant checks

`make check-documentation` checks Markdown links, bilingual variable/reference
coverage, unsafe replacement markers, local developer paths, and moved CI-path
references. `make lint` includes this target. For a local test workflow, see
[`make quick-check`](testing/fast-checks.md) and the [test README](../tests/README.md).
