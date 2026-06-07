# Runners

Status: scaffolded

The runner layer defines the adapter shape expected by future connector tests.
It does not implement a complete server/proxy adapter suite.

Implemented now:

- `case_cli.py materialize` reads a shared YAML case, writes a connector runtime
  rule file, request headers/body files, deterministic multipart bodies,
  response fixtures, audit-log paths, and shell-safe request/expectation
  variables. An optional `--rules-preamble-file` is written before the local
  case rules for variants such as OWASP CRS.
- `case_cli.py assert-status` compares real connector HTTP status, optional
  response body content, and optional audit-log content with the shared YAML
  case expectation.
- `case_cli.py list-cases` selects applicable common or connector-specific
  YAML cases for a connector scope.
- `case_cli.py case-info` and `summarize-results` write normalized JSON result
  metadata with origin, category, scope, expected status, and observed status.
- `runner_core.py` validates the minimal shared case schema and provides the
  status assertion used by the Apache and NGINX harnesses. The base `expect`
  mapping is used for `MODSECURITY_TEST_VARIANT=no-crs`; a case can provide
  `expect.variants.with-crs` for a minimal With-CRS assertion override.

The Apache and NGINX PoCs use this runner so each YAML file under
`tests/cases/` is the single source for the rule, request, headers, optional
body or multipart body, response fixture, and expected HTTP status.
Imported, pending, future, gap, and former-XFAIL classes are metadata values,
not status directories.
Audit-log cases also use the YAML as the source for stable audit-log field
expectations.

Required adapter methods:

- `prepare()`
- `start()`
- `stop()`
- `reload()`
- `apply_config()`
- `apply_rules()`
- `endpoint()`
- `send_request()`
- `collect_artifacts()`
- `cleanup()`

Unimplemented adapters must raise `NotImplementedError`.

Example:

```sh
python3 tests/runners/case_cli.py materialize \
  --case tests/cases/phases/phase2/phase2_args_block.yaml \
  --rules-file "$BUILD_ROOT/rules.conf" \
  --env-file "$BUILD_ROOT/case.env" \
  --headers-file "$BUILD_ROOT/request-headers.txt" \
  --body-file "$BUILD_ROOT/request-body.bin" \
  --docroot "$BUILD_ROOT/htdocs" \
  --audit-log-file "$BUILD_ROOT/audit.log" \
  --audit-log-dir "$BUILD_ROOT/audit"

python3 tests/runners/case_cli.py assert-status \
  --case tests/cases/phases/phase2/phase2_args_block.yaml \
  --actual-status 403 \
  --response-body-file "$BUILD_ROOT/response-body.txt" \
  --audit-log-file "$BUILD_ROOT/audit.log"
```
