# Apache vs NGINX PoC

Status: scaffolded

## Shared Behavior

Both connector PoCs use the same portable cases:

```text
tests/cases/*.yaml
tests/cases/*.yaml
tests/cases/*.yaml
tests/cases/*.yaml
```

Shared pieces:

- `tests/runners/case_cli.py materialize` writes connector runtime rule files
  and request variables from the YAML case.
- `tests/runners/case_cli.py assert-status` compares the observed HTTP status
  with `expect.status`.
- The expected proof is the HTTP status encoded in each YAML file, currently
  HTTP `403` for all minimal blocking cases.

The shared case is a rule/request/expectation model. It is not proof of a
connector until that connector's runtime harness observes the expected HTTP
status.

`make smoke-common` runs only these common cases on both Apache and NGINX.
`make smoke-all` also runs connector-specific imported cases on their matching
connector.

The proof mode for both PoCs is `real-world-connector-path`: a real HTTP client
talks to a real server process, the server loads the real connector module, the
module calls libmodsecurity, and the observed HTTP response must match the YAML
expectation. Direct libmodsecurity API smoke results are separate and are not
counted as connector success.

## Connector-Specific Pieces

Apache:

- Build integration uses APXS/Autotools from the local `ModSecurity-apache`
  source copy.
- Runtime loads `mod_security3.so` with `LoadModule security3_module`.
- Configuration enables `modsecurity on` and points `modsecurity_rules_file` at
  the materialized rules file.
- A local source-built Apache httpd smoke has observed the YAML-expected HTTP
  status for all current shared minimal cases.

NGINX:

- Build integration uses the ModSecurity-nginx third-party dynamic module path
  with `--with-compat --add-dynamic-module=...`.
- Runtime loads `ngx_http_modsecurity_module.so` with `load_module`.
- Configuration enables `modsecurity on` and points `modsecurity_rules_file` at
  the materialized rules file.
- A local source-built NGINX smoke has observed the YAML-expected HTTP status
  for all current shared minimal cases.
- NGINX-specific imported cases under `tests/cases/connector-specific/nginx/` currently
  cover redirect and TX scoring behavior from the local NGINX suite. They stay
  NGINX-only until Apache equivalence is explicitly tested.

## Lifecycle Differences

Apache and NGINX expose different hook models. The shared runner intentionally
does not model hooks; it only provides the portable test data.

Observed NGINX local source facts:

- Access handling is registered in `NGX_HTTP_ACCESS_PHASE`.
- Logging is registered in `NGX_HTTP_LOG_PHASE`.
- Header and body filters are installed separately.
- Response body processing depends on NGINX filter ordering.

Apache hook details remain connector-specific and are documented in
`docs/import-analysis-apache.md` and `docs/apache-poc.md`.

## Build Differences

Apache source-build mode downloads and builds httpd, APR, and APR-util under
`BUILD_ROOT`. NGINX source-build mode downloads the official GitHub release
archive from `nginx/nginx`, builds NGINX under `BUILD_ROOT`, and writes the
dynamic module under:

```text
$BUILD_ROOT/nginx-runtime/nginx/modules/ngx_http_modsecurity_module.so
```

Neither PoC writes to `/usr`, `/usr/local`, `/etc/apache2`, `/etc/nginx`, or
`<workspace>/*`.

## Current Local Comparison

Observed on 2026-05-15 with `BUILD_ROOT=/src/ModSecurity-test-Framework-build`:

| Shared case | Apache, httpd 2.4.67 | NGINX, nginx 1.31.0 from `release-1.31.0` |
| --- | --- | --- |
| `audit_log_phase1_block.yaml` | HTTP 403 plus audit fields | HTTP 403 plus audit fields |
| `phase1_header_block.yaml` | HTTP 403 | HTTP 403 |
| `phase2_args_block.yaml` | HTTP 403 | HTTP 403 |
| `phase2_args_pass.yaml` | HTTP 200 plus origin body | HTTP 200 plus origin body |
| `request_body_json_block.yaml` | HTTP 403 | HTTP 403 |
| `request_body_urlencoded_block.yaml` | HTTP 403 | HTTP 403 |
| `response_header_basic.yaml` | HTTP 403 | HTTP 403 |

This proves these shared PoC cases for this workspace only. Broader
compatibility still requires connector-specific regression coverage.

Imported common cases add phase action, collection, and request-body coverage.
Their source paths and portability decisions are documented in
`docs/imports/common/shared-case-origin-map.md` and `docs/test-import-plan.md`.
The local `make smoke-all` run on 2026-05-15 after the V2/V3 import pass
reported 30 Apache passes and 33 NGINX passes. The difference is the 3
NGINX-specific imported cases that are not executed on Apache.

V2/V3-derived common cases add semantic and regression coverage without copying
upstream tests:

| Shared group | Apache | NGINX | Notes |
| --- | --- | --- | --- |
| V2 operators/transformations | HTTP 403 | HTTP 403 | Derived from `ModSecurity_V2/tests/op` and `tests/tfn` |
| V3 multipart FILES variables | HTTP 403 | HTTP 403 | Derived from v3 `variable-FILES*` and `variable-MULTIPART_FILENAME` JSON cases |
| V3 XML body processor | HTTP 403 | HTTP 403 | Basic XML collection check only; schema/DTD remains mapped |
| V3 operator/action basics | HTTP 403 | HTTP 403 | Derived from `operator-rx.json`, `transformations.json`, and `secruleengine.json` |

## Body And Multipart Import

The shared runner now materializes deterministic multipart bodies and per-case
response fixtures under each connector runtime directory. The active common
body/filter additions are:

| Shared case | Apache | NGINX | Notes |
| --- | --- | --- | --- |
| `json_request_body_block.yaml` | HTTP 403 | HTTP 403 | Raw `REQUEST_BODY` match; parsed JSON collections remain mapped |
| `multipart_basic_block.yaml` | HTTP 403 | HTTP 403 | Simple multipart text-field match through `ARGS:name` |
| `response_body_pass.yaml` | HTTP 200 | HTTP 200 | Response-body access pass-through only |

`response_body_basic_block` is not an active common PASS. NGINX recognized the
response-body rule in local probing, but the HTTP response was not a stable
403, and the upstream NGINX test marks the block case TODO. It stays documented
as xfail/mapped-only until both connectors return the same stable HTTP 403.

## Summary Metadata

Apache and NGINX summaries under `$BUILD_ROOT/results/` include:

- `connector_path: real-world`
- `validation_mode: real-world-connector-path`
- server binary path
- connector module path
- libmodsecurity shared library path
- `verified_variables` derived only from passing YAML cases

The currently verified real-world variable families are `ARGS`,
`REQUEST_HEADERS`, `REQUEST_BODY`, `FILES`, `XML`, `AUDIT_LOG`, and
`RESPONSE_HEADERS`. `RESPONSE_BODY` remains excluded until a response-body
rule-variable case passes on both connectors.
