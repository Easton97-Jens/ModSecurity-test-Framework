# Import Analysis: ModSecurity v3 / libmodsecurity

**Language:** English | [Deutsch](import-analysis-modsecurity-v3.de.md)

Status: implemented

Local reference: `<workspace>/ModSecurity_V3`
Upstream source: https://github.com/owasp-modsecurity/ModSecurity
Observed ref: `v3/master`, `v3.0.15`

## Role

This is the primary architecture and API reference for new connector work.
It provides the connector-neutral libmodsecurity engine and public C/C++ APIs.

## Build System

Observed files:

- `configure.ac`
- `Makefile.am`
- `src/Makefile.am`
- `test/Makefile.am`
- `modsecurity.pc.in`

The v3 tree builds a library and test binaries through Autotools. Windows build
files exist under `build/win32/`, but this scaffold does not consume them.

## Connector-Neutral Components

Reusable concepts from v3:

| Component | Source | Scope | Compatibility | Notes |
| --- | --- | --- | --- | --- |
| `ModSecurity` instance lifecycle | v3 | engine-specific | compatible | Public C API: `msc_init`, `msc_cleanup` |
| Rules set lifecycle | v3 | engine-specific | compatible | `msc_create_rules_set`, `msc_rules_add*`, `msc_rules_cleanup` |
| Transaction lifecycle | v3 | engine-specific | compatible | `msc_new_transaction*`, phase calls, cleanup |
| Intervention model | v3 | engine-specific | compatible | `ModSecurityIntervention`, `msc_intervention` |
| Log callback | v3 | engine-specific | compatible | `msc_set_log_cb`; callback payload depends on log property |
| Regression JSON cases | v3 | engine-specific | partially compatible | Good portable candidates after capability review |

## Relevant Public APIs

Future connector adapters should be built around the public C API:

- engine: `msc_init`, `msc_set_connector_info`, `msc_set_log_cb`, `msc_cleanup`
- rules: `msc_create_rules_set`, `msc_rules_add`, `msc_rules_add_file`,
  `msc_rules_add_remote`, `msc_rules_merge`, `msc_rules_cleanup`
- transaction: `msc_new_transaction`, `msc_new_transaction_with_id`,
  `msc_transaction_cleanup`
- request phases: `msc_process_connection`, `msc_process_uri`,
  `msc_add_n_request_header`, `msc_process_request_headers`,
  `msc_append_request_body`, `msc_process_request_body`
- response phases: `msc_add_n_response_header`,
  `msc_process_response_headers`, `msc_append_response_body`,
  `msc_process_response_body`
- finalization: `msc_update_status_code`, `msc_process_logging`,
  `msc_intervention`, `msc_intervention_cleanup`

## Transaction Lifecycle

v3 separates connector hooks from engine phases. A connector is responsible for
calling the public API in the order its runtime can support. Missing phases must
be documented as capability gaps rather than hidden.

## Logging

v3 exposes a server log callback through `msc_set_log_cb`. Audit/debug log
behavior still depends on rules/configuration and engine internals. This repo
does not implement log collection yet; it only defines normalizer skeletons and
artifact collection hooks in the runner interface.

## Tests

Observed v3 tests include JSON regression cases under
`test/test-cases/regression/` and C++ runners under `test/regression/`.
Those JSON cases are the preferred portable engine-test source, subject to
capability review.
