# Connector test orchestration

**Language:** English | [Deutsch](README.de.md)

## Scope and interface

This package owns the migrated Connector test orchestration, inventory
admission, provisioning, cache preparation, runtime harnesses, collection,
normalization, validation and report generators. Its unique import namespace is
`modsecurity_connector_ci`. It is Framework test code, including checks of
Connector Makefiles/workflows and repository contracts.

[The public interface](../../docs/connector-test-suite.md) requires explicit
`TEST_ROOT`, `CONNECTOR_ROOT`, exact `CONNECTOR_REVISION`, profile and an
existing external output parent. Framework-only unit fixtures may run without
a product checkout. Product builds/configuration/deployment remain Connector
code. Never infer the product checkout from this package's ancestry.

## Layout

| Path | Responsibility |
| --- | --- |
| `checks/` | Source, configuration, documentation and evidence contracts |
| `lib/` | Shared test selection, source binding and orchestration helpers |
| `runtime/` | Host test lifecycle and protected test integrations |
| `evidence/` | Run-scoped collection, normalization and validation |
| `provisioning/` | Test component preparation |
| `testtools/` | Explicit test tool entrypoints |

The selection authority is [active-cases.json](../config/testing/active-cases.json).
Schema 4 separates fixed Framework test-source hashes from snapshotted product
inputs. The original baseline is 100 standard cases / 80 executions and 1893
on-demand cases / 839 executions; new migration regressions remain on demand.
The standard cap stays 100, and missing sources or drift fail admission.

## Evidence and safety

Bind live observations to run, case, request, actual transaction and source
revision. Never borrow another request's logs or replace observed HTTP status
with intervention status. Persist executed traffic before assertions. Missing
mandatory rows, failed writes or empty required result sets fail the run.
Retries preserve attempts without increasing distinct-case totals; mixed runs
or revisions cannot be restamped into one successful summary.

Protected brokers authenticate the protected Parent base and its pinned
Framework source. Candidate Framework files must not become privileged code.
Missing installed gate or host prerequisites remain `BLOCKED`. Keep outputs,
logs, build/cache data and downloads outside source checkouts; never commit
bodies, credentials or private environment values.

A successful validator establishes its evidence contract, not a new host run.
Build, static, native and hosted-runtime results retain their separate meaning.
The source-checkout adapter is not a claim that all migrated modules are included
in the installable Framework package.
