# Common Case Reference

Status: scaffolded

The runtime YAML corpus now lives under `tests/cases/` and is organized by
topic. This directory is retained for common-case reference notes and import
history only.

Only portable engine/rule/behavior cases belong in common case metadata.

Do not add cases that require a specific server/proxy runtime.

`tests/cases/phases/phase2/phase2_args_block.yaml` is a portable
rule/request/expectation model.
It becomes a connector pass only when a connector-specific harness executes it
and observes the expected result.

Imported, v2-derived, v3-derived, xfail, pending, future, connector-gap, and
runtime-difference classifications are carried by YAML metadata and
connector-owned `config/testing/import-status.json`, not by status folders.

Supported request shapes are intentionally small: `GET`, `POST`, headers,
plain bodies, and deterministic multipart form bodies. Multipart parser edge
cases, streaming, HTTP/2, and connector-specific server configuration stay out
of common cases until both connector harnesses prove the behavior.

Response-body pass-through can live here when both connectors pass. Response
body blocking is mapped as xfail until Apache and NGINX both return stable HTTP
403 for the same YAML case.
