# Architecture

Status: scaffolded

## Direction

New connector work targets libmodsecurity v3. The local v3 checkout exposes a
connector-neutral engine with public C and C++ APIs under
`headers/modsecurity/`.

The intended adapter flow is:

1. Connector hook receives server/proxy request state.
2. Connector adapter translates server/proxy state into a neutral request view.
3. Connector adapter calls libmodsecurity v3 public APIs in phase order.
4. Connector adapter translates interventions back to server/proxy behavior.
5. Connector-specific tests prove the hook timing and artifact collection.

## Shared Boundary

`common/` contains neutral data shapes only. It does not own server/proxy
objects and does not include connector SDK headers.

`connectors/<name>/` owns all server/proxy integration:

- hook registration
- module/filter/plugin build glue
- runtime configuration
- server/proxy-specific request and response translation
- connector-specific tests

## v3 Transaction Flow

The local v3 headers and source expose these relevant public C APIs:

- `msc_init`, `msc_set_connector_info`, `msc_set_log_cb`, `msc_cleanup`
- `msc_create_rules_set`, `msc_rules_add`, `msc_rules_add_file`,
  `msc_rules_add_remote`, `msc_rules_merge`, `msc_rules_cleanup`
- `msc_new_transaction`, `msc_new_transaction_with_id`
- `msc_process_connection`, `msc_process_uri`,
  `msc_add_n_request_header`, `msc_process_request_headers`,
  `msc_append_request_body`, `msc_process_request_body`,
  `msc_add_n_response_header`, `msc_process_response_headers`,
  `msc_append_response_body`, `msc_process_response_body`,
  `msc_update_status_code`, `msc_process_logging`
- `msc_intervention`, `msc_intervention_cleanup`,
  `msc_transaction_cleanup`

The connector must call only phases it can actually support and document missing
or partial phases as capability gaps.

## Status Terms

- `implemented`: present and locally checked in this scaffold.
- `scaffolded`: structure or interface exists, behavior is not complete.
- `planned`: intended later work with a known direction.
- `unknown`: facts still need proof from source or documentation.
- `blocked`: work cannot proceed without an external decision, source, or test.
