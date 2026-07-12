# Import Analysis: ModSecurity v2

**Language:** English | [Deutsch](import-analysis-modsecurity-v2.de.md)

Status: implemented

Local reference: `<workspace>/ModSecurity_V2`
Upstream source: https://github.com/owasp-modsecurity/ModSecurity
Observed ref: `v2/master`, `v2.9.13`

## Role

v2 is not the architecture source for new connectors. It is used for:

- regression-test source
- semantics reference
- compatibility reference
- historical Apache implementation context

## Build System

Observed files:

- `configure.ac`
- `Makefile.am`
- `apache2/Makefile.am`
- `tests/Makefile.am`
- `tests/run-regression-tests.pl.in`

v2 is tightly coupled to Apache in the main tree. The `tests/Makefile.am`
builds a `msc_test` binary from many `apache2/*` sources and standalone helpers.

## Regression Value

v2 regression files under `tests/regression/`, `tests/op/`, and `tests/tfn/`
remain useful for rule semantics, transformations, operators, phase behavior,
and compatibility expectations.

## Non-portable Architecture

The following are historical or connector-specific and must not be transferred
directly into new connectors:

- Apache module internals under `apache2/`
- APR pool and Apache request lifecycle assumptions
- v2 request record structures
- v2 parser/internal function calls not exposed by libmodsecurity v3 public API
- Apache server-root Perl test harness behavior

## Reuse Classification

| Component | Source | Scope | Compatibility | Decision |
| --- | --- | --- | --- | --- |
| `tests/op/*.t` | v2 | engine-specific | partial | Candidate for portable mapping after v3 API review |
| `tests/tfn/*.t` | v2 | engine-specific | partial | Candidate for portable transformation tests |
| `tests/regression/*/*.t` | v2 | mixed | partial | Map each case by required phase/capability |
| `apache2/*` | v2 | connector-specific | incompatible | Historical reference only |
| `tests/run-regression-tests.pl.in` | v2 | connector-specific | incompatible | Harness reference only |

## Open Work

Tracked in `docs/roadmap/todo-inventory.md`:

- Build a per-test map from v2 Perl structures to v3 JSON-style cases.
- Mark cases requiring Apache-only config, filesystem layout, or log format as
  connector-specific.
