# libmodsecurity v3 API Smoke Probe

Status: implemented portable build harness. Local default run observed
`primary_args_phase2` pass after building libmodsecurity in `/src`.

This directory contains a connector-free C smoke probe for the public
libmodsecurity v3 C API. It does not contain Apache, NGINX, HAProxy, Envoy,
Lighttpd, or Traefik integration.

## Build

Default build:

```sh
make -C src/v3-api-smoke
```

Run:

```sh
make -C src/v3-api-smoke run
```

Optional overrides:

```sh
make -C src/v3-api-smoke MODSECURITY_V3_DIR=/tmp/ModSecurity_V3_build
make -C src/v3-api-smoke BUILD_ROOT=/tmp/ModSecurity-test-Framework-build
```

The Makefile checks for:

- `$MODSECURITY_V3_DIR/headers/modsecurity/modsecurity.h`
- `$MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so`

It intentionally does not run `build.sh`, `configure`, or `make` inside
`MODSECURITY_V3_DIR`.

`BUILD_ROOT` and `BUILD_DIR` should be absolute paths outside the Git checkout.
The Makefile blocks relative `BUILD_DIR` values to avoid repo-local artifacts.

Local defaults:

```sh
MODSECURITY_V3_SOURCE_DIR=/root/conecter/ModSecurity_V3
MODSECURITY_V3_DIR=/src/ModSecurity_V3_build
BUILD_ROOT=/src/ModSecurity-test-Framework-build
LOG_DIR=/src/ModSecurity-test-Framework-build/logs
```

GitHub Actions-style paths:

```sh
MODSECURITY_V3_SOURCE_DIR=$GITHUB_WORKSPACE/ModSecurity_V3
MODSECURITY_V3_DIR=$RUNNER_TEMP/ModSecurity_V3_build
BUILD_ROOT=$RUNNER_TEMP/ModSecurity-test-Framework-build
LOG_DIR=$RUNNER_TEMP/ModSecurity-test-Framework-build/logs
```

For automation that needs the blocked exit code `77`, use:

```sh
sh ci/check-v3-api-smoke-prereqs.sh
sh ci/run-v3-api-smoke.sh
```

GNU Make reports failed recipe commands as a make failure; it will print
`Error 77` from the recipe, but the wrapper scripts preserve exit code `77`.

## Result Meanings

- `implemented`: this source file and Makefile exist.
- `blocked`: the configured v3 build copy is missing headers or
  `src/.libs/libmodsecurity.so`.
- `pass`: `primary_args_phase2` produced intervention status `403`.
- `fallback pass`: `fallback_request_uri_phase1` produced status `403` after
  the primary ARGS test failed; this is only a minimal API proof.
- `fail`: the probe built and ran, but the expected primary result was not
  observed.

The fallback must not be documented as ARGS support.

Observed local pass:

```text
primary_args_phase2: pass status=403 phase=request_body
fallback_request_uri_phase1: skipped primary_passed
```
