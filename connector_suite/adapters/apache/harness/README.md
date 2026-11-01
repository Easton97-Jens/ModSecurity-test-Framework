# Apache Smoke Harness

**Language:** English | [Deutsch](README.de.md)

Status: adapter-owned source smoke harness

This harness is a connector-specific proof-of-concept runner for the Apache
module built from the adapter-owned `connectors/apache/src` source materialized
under `$BUILD_ROOT/apache-build/connector-src`. It is not a full regression
test suite.

Observed locally on 2026-05-15: source-built Apache httpd `2.4.67` returned
the YAML-expected HTTP status for all current shared minimal cases.

## Boundaries

- Uses only artifacts under `BUILD_ROOT`.
- Does not build or modify any `<external-source-root>/*` repository.
- Does not build or mutate the source checkout; all generated Autotools and
  runtime files stay under `BUILD_ROOT`.
- Reports `pass` only when Apache returns the YAML-expected HTTP status for a
  real local request.
- Defaults to the source-built httpd under
  `$BUILD_ROOT/apache-runtime/httpd/bin/httpd`.
- Reads rule, request, headers, body, multipart body, response fixture, and
  expected status from YAML through `modules/ModSecurity-test-Framework/tests/runners/case_cli.py`.

## Usage

```sh
REFRESH=1 \
BUILD_HTTPD_FROM_SOURCE=1 \
BUILD_ROOT=/src/ModSecurity-conector-build \
make smoke-apache

BUILD_ROOT=/src/ModSecurity-conector-build \
make smoke-apache
```

To use explicit external tools instead of the source-built default:

```sh
APXS=/path/to/apxs \
APACHE_HTTPD=/path/to/httpd \
BUILD_ROOT=/src/ModSecurity-conector-build \
sh connectors/apache/harness/run_apache_smoke.sh
```

If Apache, the module, or `libmodsecurity.so` is missing, the script exits `77`
and marks the result as `blocked`.

## Shared Cases

By default the harness iterates every `*.yaml` file in:

```text
modules/ModSecurity-test-Framework/tests/cases/
modules/ModSecurity-test-Framework/tests/cases/
modules/ModSecurity-test-Framework/tests/cases/connector-specific/apache/
```

To run a subset:

```sh
BUILD_ROOT=/src/ModSecurity-conector-build \
SMOKE_CASES="phase1_header_block phase2_args_block" \
make smoke-apache
```

The harness materializes the Apache rule file, request variables, request
headers, request body, multipart body, and response fixture from each YAML file
at runtime. It uses `/__modsec_smoke_ready` with ModSecurity disabled only for
readiness checks. Do not duplicate the rule, request path, request method,
headers, body, response fixture, or expected HTTP status in the harness.
