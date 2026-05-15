# ModSecurity Test Framework

Status: evidence framework

This repository is a focused split of the ModSecurity connector compatibility
work. It keeps the shared YAML cases, runner, build helpers, Apache/NGINX smoke
harnesses, and evidence documentation needed to validate ModSecurity behavior
through real server connector paths.

It is not a connector implementation repository. The unfinished future
connector skeletons from the original monorepo are intentionally not included.

## Evidence Focus

This framework currently supports evidence work for:

- ModSecurity PR #3564: RAW URL-encoded argument collections.
- ModSecurity-nginx PR #377: Phase-4 / `RESPONSE_BODY` handling.
- Real-world connector validation:

```text
Client -> Apache/NGINX -> connector module -> libmodsecurity -> rule variables -> HTTP response
```

The direct libmodsecurity v3 API smoke under `src/v3-api-smoke/` remains
separate. API-only success is not counted as Apache or NGINX connector success.

## Current Status

Active Apache and NGINX smokes use the same source-derived YAML cases. A `pass`
means a real local HTTP request reached a real source-built server, loaded the
real connector module, evaluated rules in libmodsecurity, and returned the
YAML-expected HTTP status.

Current verified variable families from active passing cases are:

- `ARGS`
- `ARGS_NAMES`
- `REQUEST_HEADERS`
- `REQUEST_BODY`
- `REQUEST_COOKIES`
- `REQUEST_URI`
- `FILES`
- `XML`
- `AUDIT_LOG`
- `RESPONSE_HEADERS`

`RESPONSE_BODY` is not verified. The blocking case remains under
`tests/common/cases/xfail/` and is runnable only through the explicit probe.

RAW argument collections from PR #3564 are mapped as unsupported by the current
local `/root/conecter/ModSecurity_V3` checkout unless a configured v3 source
contains the new RAW collection implementation and both connector smokes pass.
Use `sh ci/check-raw-args-support.sh` to inspect the configured
`MODSECURITY_V3_SOURCE_DIR` without modifying it.

## Local Commands

All generated files must stay under `BUILD_ROOT`.

```sh
BUILD_ROOT=/src/ModSecurity-test-Framework-build make lint
BUILD_ROOT=/src/ModSecurity-test-Framework-build make smoke-common
BUILD_ROOT=/src/ModSecurity-test-Framework-build make smoke-all
BUILD_ROOT=/src/ModSecurity-test-Framework-build make probe-response-body || true
```

Useful focused commands:

```sh
BUILD_ROOT=/src/ModSecurity-test-Framework-build make smoke-apache
BUILD_ROOT=/src/ModSecurity-test-Framework-build make smoke-nginx
BUILD_ROOT=/src/ModSecurity-test-Framework-build make summary
BUILD_ROOT=/src/ModSecurity-test-Framework-build make case-matrix
```

`SMOKE_CASES` can restrict a run by case name or file path:

```sh
BUILD_ROOT=/src/ModSecurity-test-Framework-build \
SMOKE_CASES="phase2_args_block request_body_json_block" \
make smoke-all
```

## Source Inputs

The local reference repositories are read-only:

- `/root/conecter/ModSecurity_V2`
- `/root/conecter/ModSecurity_V3`
- `/root/conecter/ModSecurity-apache`
- `/root/conecter/ModSecurity-nginx`

CI and portable runs can fetch equivalent sources under `$RUNNER_TEMP/sources`
or another env-configured source root. Builds, logs, runtime configs, and
results are written under `BUILD_ROOT`.

## Documentation

- `docs/pr-evidence-summary.md`: PR #3564 and PR #377 evidence summary.
- `docs/real-world-connector-validation.md`: connector-path proof model.
- `docs/response-body-blocking-investigation.md`: RESPONSE_BODY xfail probe.
- `docs/test-import-plan.md`: source-derived test import rules and inventory.
- `docs/compatibility.md`: current compatibility and variable status.
- `docs/capability-model.md` and `docs/status-model.md`: schema semantics.
