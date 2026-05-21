# libmodsecurity v3 API Smoke Test

Status: implemented portable build harness. A local explicit-build-root run
observed `primary_args_phase2` pass after building libmodsecurity.

This document describes a minimal connector-free probe for the public
libmodsecurity v3 C API.

## Purpose

The probe checks whether this repository can compile and run a small C program
against a configured libmodsecurity v3 build and load a simple SecRule through
the public C API.

This is not a webserver connector test. It does not use Apache, NGINX, HAProxy,
Envoy, Lighttpd, or Traefik.

The canonical source and build harness live under:

```text
src/v3-api-smoke/
```

`tests/common/v3-api-smoke/` contains only a pointer to that source so the test
tree does not duplicate implementation logic.

## Path Model

Every relevant path is configurable. The current defaults come from
`ci/common.sh` and use a portable local build/output root plus `SOURCE_ROOT`:

```sh
BUILD_ROOT=$HOME/.local/state/ModSecurity-conector-build
SOURCE_ROOT=$BUILD_ROOT/sources
MODSECURITY_SOURCE_DIR=$SOURCE_ROOT/ModSecurity_V3
MODSECURITY_V3_SOURCE_DIR=$SOURCE_ROOT/ModSecurity_V3
MODSECURITY_V3_DIR=$BUILD_ROOT/ModSecurity_V3_build
LOG_DIR=$BUILD_ROOT/logs
```

The local v3 source checkout corresponds to the public ModSecurity repository:

| Repository | Reference role | Upstream | Observed commit | Observed version/tag | License |
| --- | --- | --- | --- | --- | --- |
| ModSecurity v3 | configured engine source checkout | https://github.com/owasp-modsecurity/ModSecurity | `0fb4aff98b4980cf6426697d5605c424e3d5bb60` | `v3.0.15` | Apache-2.0 |

Meaning:

- `MODSECURITY_V3_SOURCE_DIR`: read-only source checkout to copy from.
- `MODSECURITY_V3_DIR`: writable build copy containing the built v3 library.
- `BUILD_ROOT`: writable root for smoke object files, binary, and logs.
- `LOG_DIR`: writable directory for helper logs.

No build step may write generated files into this repository checkout or any
other source checkout.

Generated paths (`MODSECURITY_V3_DIR`, `BUILD_ROOT`, `LOG_DIR`, and
`BUILD_DIR`) should be absolute and outside the Git checkout. The helper and
runner block common unsafe cases instead of creating repo-local artifacts.

## Primary Scenario

Name: `primary_args_phase2`

Rules:

```apache
SecRuleEngine On
SecRule ARGS:test "@streq attack" "id:1001,phase:2,deny,status:403"
```

Simulated request:

```text
GET /?test=attack HTTP/1.1
```

Expected result:

```text
primary_args_phase2: pass status=403
```

If this scenario does not produce a 403 intervention through the pure C API
path, the result must be documented as a primary failure. The implementation
must not infer an explanation without a confirmed source.

## Fallback Scenario

Name: `fallback_request_uri_phase1`

Rules:

```apache
SecRuleEngine On
SecRule REQUEST_URI "@contains test=attack" "id:1002,phase:1,deny,status:403"
```

The fallback is only a minimal proof that the public API can load rules and
produce an intervention for the simulated URI. It does not validate `ARGS:test`
handling.

If the fallback passes while the primary scenario fails, the script exits
non-zero. That result is `fallback pass`, not `pass`, and it must not be
documented as `ARGS:test` support. The expected marker is:

```text
fallback passed, primary failed
```

## Public API Calls

The probe uses these public libmodsecurity v3 C API calls:

- `msc_init`
- `msc_set_connector_info`
- `msc_create_rules_set`
- `msc_rules_add`
- `msc_new_transaction`
- `msc_process_connection`
- `msc_process_uri`
- `msc_process_request_headers`
- `msc_process_request_body`
- `msc_intervention`
- `msc_intervention_cleanup`
- `msc_transaction_cleanup`
- `msc_rules_cleanup`
- `msc_cleanup`

The call order follows the v3 examples and regression harness pattern observed
in the local reference checkout, but the smoke probe runs against
`$MODSECURITY_V3_DIR`.

## Build And Run

Default command:

```sh
sh ci/run-v3-api-smoke.sh
```

Direct Makefile command:

```sh
make -C src/v3-api-smoke run
```

Prerequisite check only:

```sh
sh ci/check-v3-api-smoke-prereqs.sh
```

Optional overrides:

```sh
MODSECURITY_V3_SOURCE_DIR=/path/to/ModSecurity_V3 \
MODSECURITY_V3_DIR=/tmp/ModSecurity_V3_build \
BUILD_ROOT=/tmp/ModSecurity-conector-build \
LOG_DIR=/tmp/ModSecurity-conector-build/logs \
sh ci/run-v3-api-smoke.sh
```

The script and Makefile check for:

- `$MODSECURITY_V3_DIR/headers/modsecurity/modsecurity.h`
- `$MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so`

The smoke runner and Makefile intentionally do not build libmodsecurity. Use
the manual helper if a writable build copy is needed.

For automation, prefer the `ci/` shell scripts. They preserve blocked exit code
`77`. A direct GNU Make invocation prints `Error 77` for the blocked recipe, but
GNU Make itself exits with its own failure code.

## Building The v3 Copy

Default configured build:

```sh
sh ci/build-v3-under-src.sh
```

Portable Linux example:

```sh
MODSECURITY_V3_SOURCE_DIR=/work/ModSecurity_V3 \
MODSECURITY_V3_DIR=/tmp/ModSecurity_V3_build \
BUILD_ROOT=/tmp/ModSecurity-conector-build \
LOG_DIR=/tmp/ModSecurity-conector-build/logs \
sh ci/build-v3-under-src.sh
```

GitHub Actions-style example:

```sh
MODSECURITY_V3_SOURCE_DIR=$GITHUB_WORKSPACE/ModSecurity_V3 \
MODSECURITY_V3_DIR=$RUNNER_TEMP/ModSecurity_V3_build \
BUILD_ROOT=$RUNNER_TEMP/ModSecurity-conector-build \
LOG_DIR=$RUNNER_TEMP/ModSecurity-conector-build/logs \
sh ci/build-v3-under-src.sh
```

The helper copies `MODSECURITY_V3_SOURCE_DIR` to `MODSECURITY_V3_DIR`, then runs
`git submodule update --init --recursive`, `./build.sh`, `./configure`, and
`make` only inside the copy. Logs are written under `LOG_DIR`.

Generated artifacts:

- libmodsecurity build tree: `$MODSECURITY_V3_DIR`
- helper logs: `$LOG_DIR`
- smoke object and binary: `$BUILD_ROOT/v3-api-smoke`
- optional Python cache during checks: `$BUILD_ROOT/pycache` or an explicit
  `PYTHONPYCACHEPREFIX`

If dependencies are missing, document the exact failing command and log path
reported by the helper and keep the status `blocked`.

## Observed Local Result

Observed local build command:

```sh
sh ci/build-v3-under-src.sh
```

Observed generated artifacts, with paths generalized to the configured
variables:

- build copy: `$MODSECURITY_V3_DIR`
- built library: `$MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so`
- helper logs:
  - `$LOG_DIR/copy-source.log`
  - `$LOG_DIR/git-submodule-update.log`
  - `$LOG_DIR/build-sh.log`
  - `$LOG_DIR/configure.log`
  - `$LOG_DIR/make.log`
- smoke build output:
  - `$BUILD_ROOT/v3-api-smoke/v3_api_smoke.o`
  - `$BUILD_ROOT/v3-api-smoke/v3_api_smoke`

Observed on this workspace via `sh ci/check-v3-api-smoke-prereqs.sh`:

```text
v3_api_smoke: MODSECURITY_V3_SOURCE_DIR=<configured ModSecurity source>
v3_api_smoke: MODSECURITY_V3_DIR=<configured build copy>
v3_api_smoke: BUILD_ROOT=<configured build root>
v3_api_smoke: LOG_DIR=<configured log dir>
v3_api_smoke: v3 branch=v3/master
v3_api_smoke: v3 version=v3.0.15
v3_api_smoke: header present: <configured build copy>/headers/modsecurity/modsecurity.h
v3_api_smoke: library present: <configured build copy>/src/.libs/libmodsecurity.so
```

Observed on this workspace via `sh ci/run-v3-api-smoke.sh`:

```text
v3_api_smoke: MODSECURITY_V3_SOURCE_DIR=<configured ModSecurity source>
v3_api_smoke: MODSECURITY_V3_DIR=<configured build copy>
v3_api_smoke: BUILD_ROOT=<configured build root>
v3_api_smoke: LOG_DIR=<configured log dir>
v3_api_smoke: v3 branch=v3/master
v3_api_smoke: v3 version=v3.0.15
v3_api_smoke: header present: <configured build copy>/headers/modsecurity/modsecurity.h
v3_api_smoke: library present: <configured build copy>/src/.libs/libmodsecurity.so
primary_args_phase2: pass status=403 phase=request_body
fallback_request_uri_phase1: skipped primary_passed
```

Interpretation:

- `blocked`: the configured v3 build copy is missing, dependencies are missing,
  or `$MODSECURITY_V3_DIR/src/.libs/libmodsecurity.so` does not exist.
- `implemented`: the connector-free smoke probe source, Makefile, runner, and
  prerequisite checker exist in this repository.
- `pass`: the primary `ARGS:test` scenario produced status `403`.
- `fallback pass`: only the fallback `REQUEST_URI` scenario produced status
  `403`; this is only a minimal API proof.
- `fail`: the probe built and ran, but the primary `ARGS:test` result was not
  status `403`.
- `unknown`: the `primary_args_phase2` runtime result has not been observed
  when the configured v3 library is not built.

Current observed status:

```text
pass
```

## Open Work

Tracked in `docs/roadmap/todo-inventory.md`:

- Keep the `MODSECURITY_V3_DIR` build-copy path reproducible outside source
  checkouts.
- If `primary_args_phase2` fails and `fallback_request_uri_phase1` passes,
  document the exact output without claiming `ARGS:test` support.
- If any public C API call sequence needs adjustment, cite the v3 header,
  example, or regression harness source before changing the probe.
