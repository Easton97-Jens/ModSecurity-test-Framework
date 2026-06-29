# Import Analysis: ModSecurity NGINX Connector

**Language:** English | [Deutsch](import-analysis-nginx.de.md)

Status: implemented

Local reference: `/root/conecter/ModSecurity-nginx`
Upstream source: https://github.com/owasp-modsecurity/ModSecurity-nginx
Observed ref: `master`, `v1.0.4-14-g9eb44fd`

## Role

This repository is an NGINX connector for libmodsecurity v3. It is now a
controlled adapter-owned source import under `connectors/nginx/`, with module
`config` at the connector root and productive sources under `connectors/nginx/src/`. The
former `connectors/nginx/upstream/` tree was removed in Phase 10 after durable
attribution was retained under `licenses/nginx/`, `connectors/nginx/ORIGIN.md`,
and `connectors/nginx/SOURCE_MAP.json`. Imported and migrated files are
kept NGINX-specific.

## Build System

Observed files:

- `config`
- `README.md`

Build follows NGINX third-party module conventions with `--add-module` or
`--add-dynamic-module` as documented by the source README.

## Test System

Observed tests:

- `tests/README.md`
- `tests/modsecurity-*.t`
- `tests/nginx-tests-cvt.pl`

The tests are NGINX-specific and depend on the nginx test harness and `prove`.

## libmodsecurity v3 Use

Observed public C API calls include engine/ruleset setup, transaction creation,
request/response phase calls, logging, intervention handling, and cleanup.

## NGINX Hooks

Observed concepts:

- HTTP access phase handler
- HTTP log phase handler
- header filter
- body filter
- location/main config creation and merge
- dynamic/static module ordering considerations

These are `connector-specific` and belong only under `connectors/nginx/`.

## Reuse Classification

| Concept | Source | Scope | Compatibility | Decision |
| --- | --- | --- | --- | --- |
| v3 C API phase sequence | v3 via connector | engine-specific | compatible | Document and adapt |
| NGINX phase/filter registration | connector | connector-specific | compatible only for NGINX | Tracked in `docs/roadmap/todo-inventory.md` |
| nginx-tests cases | connector | connector-specific | partial | Map to `tests/cases/connector-specific/nginx/` |
| Source code files | connector | connector-specific | compatible only for NGINX | Migrated to adapter-owned `connectors/nginx/src/` |

## Import Decision

The import is intentionally separated from `common/`. NGINX phase handlers,
header/body filters, configuration merge logic, and NGINX module build metadata
stay under `connectors/nginx/`. Future common extraction requires separate proof
via real-world Apache and NGINX smoke tests.

## Phase 9 Source Status

The NGINX module `config` now lives at `connectors/nginx/config`; productive
source files live under `connectors/nginx/src/`. The adapter-owned source includes selected
ModSecurity-nginx PR #377 source changes from
`3d72b004ff27a78ea19c6b945870e2cae62a97ac`; this is not a `RESPONSE_BODY`
promotion.
