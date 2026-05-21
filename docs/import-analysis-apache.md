# Import Analysis: ModSecurity Apache Connector

Status: implemented

Local source: `<workspace>/ModSecurity-apache`
Observed ref: `master`, `v0.0.9-beta1-26-g0488c77`

## Role

This repository is an Apache connector for libmodsecurity v3. It is a source of
Apache-specific hook and build concepts, not a source to copy blindly.

## Build System

Observed files:

- `configure.ac`
- `Makefile.am`
- `build/apxs-wrapper.in`
- `build/find_apxs.m4`
- `build/find_libmodsec.m4`

Build uses Autotools and `apxs` to build/install an Apache module.

## Test System

Observed tests:

- `t/TEST`
- `t/load-modsec.t`
- `t/simple-block.t`
- `t/very-simple-test.t`
- `tests/run-regression-tests.pl.in`

These tests are Apache-specific because they depend on Apache::Test and httpd
configuration.

## libmodsecurity v3 Use

Observed public C API calls include:

- `msc_init`, `msc_set_connector_info`, `msc_set_log_cb`, `msc_cleanup`
- `msc_create_rules_set`, `msc_rules_add`, `msc_rules_add_file`,
  `msc_rules_add_remote`
- `msc_new_transaction`, `msc_new_transaction_with_id`
- transaction phase calls and `msc_intervention`

## Apache Hooks

Observed hook concepts:

- pre/post config initialization
- request early/late processing
- input/output filters for bodies
- log transaction hook
- per-directory configuration and merge

These are `connector-specific` and belong only under `connectors/apache/`.

## Reuse Classification

| Concept | Source | Scope | Compatibility | Decision |
| --- | --- | --- | --- | --- |
| v3 C API phase sequence | v3 via connector | engine-specific | compatible | Document and adapt |
| Apache hook registration | connector | connector-specific | compatible only for Apache | Apache docs/TODO |
| Apache::Test files | connector | connector-specific | partial | Map to `tests/apache/` |
| Source code files | connector | connector-specific | unknown | No import without license/proven need |
