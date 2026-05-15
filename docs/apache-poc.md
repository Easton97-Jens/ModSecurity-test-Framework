# Apache Connector PoC

Status: scaffolded

## Implemented

- `ci/prepare-apache-build.sh` prepares a connector-specific Apache PoC build
  under `BUILD_ROOT`.
- The helper can build Apache httpd from source under `BUILD_ROOT`; system-wide
  `apxs` and `httpd` are not required.
- `connectors/apache/harness/run_apache_smoke.sh` prepares a local Apache
  runtime under `BUILD_ROOT` and checks for a real HTTP `403`.
- The shared minimal YAML cases under `tests/common/cases/minimal/` define the
  rule/request/expectation model used by Apache and NGINX.
- `tests/runners/case_cli.py` reads each YAML file and materializes the Apache
  rules, request method/path, headers, body, multipart body, response fixture,
  and expected HTTP status for the harness.

Implemented here means build orchestration, runtime harness, and documentation.
It does not mean that Apache has loaded the module successfully in every
environment.

When the smoke passes it is a `real-world-connector-path` validation:

```text
HTTP client -> source-built httpd -> mod_security3.so -> libmodsecurity -> HTTP response
```

The connector-free v3 API smoke under `src/v3-api-smoke/` is separate and is
not counted as Apache connector success.

## Build Flow

Defaults are local conveniences only:

```sh
MODSECURITY_V3_SOURCE_DIR=/root/conecter/ModSecurity_V3
MODSECURITY_APACHE_SOURCE_DIR=/root/conecter/ModSecurity-apache
BUILD_ROOT=/src/ModSecurity-test-Framework-build
LOG_DIR=$BUILD_ROOT/logs/apache
```

All paths are environment-overridable. Generated files must stay outside the
Git checkout and outside `/root/conecter/*`.

## Source-Built httpd Mode

The Apache PoC can build httpd without package installation:

```sh
REFRESH=1 \
BUILD_HTTPD_FROM_SOURCE=1 \
BUILD_ROOT=/src/ModSecurity-test-Framework-build \
sh ci/prepare-apache-build.sh
```

Default source versions:

| Variable | Default |
| --- | --- |
| `HTTPD_VERSION` | `2.4.67` |
| `APR_VERSION` | `1.7.6` |
| `APR_UTIL_VERSION` | `1.6.3` |
| `PCRE2_VERSION` | `10.47` |

Default generated paths:

```text
$BUILD_ROOT/apache-build/downloads/
$BUILD_ROOT/apache-build/httpd-src/
$BUILD_ROOT/apache-build/httpd/
$BUILD_ROOT/apache-runtime/httpd/
$BUILD_ROOT/logs/apache/
```

The helper downloads httpd, APR, and APR-util from Apache distribution URLs,
verifies their SHA256 files, unpacks APR and APR-util into the httpd `srclib`
tree, and configures httpd with:

```text
--prefix=$HTTPD_PREFIX
--with-included-apr
--with-pcre=$PCRE_CONFIG
--enable-so
--enable-mods-shared=most
--enable-mpms-shared=all
--with-mpm=event
```

PCRE handling is explicit:

- `PCRE_CONFIG=/path/to/pcre2-config` or `/path/to/pcre-config` wins.
- `BUILD_PCRE2_FROM_SOURCE=1` builds PCRE2 under
  `$BUILD_ROOT/apache-build/output/pcre2`.
- If no PCRE config tool is available and PCRE2 source build is not enabled,
  the helper exits `77` with `blocked`.

OpenSSL is not enabled for this HTTP-only smoke probe.

The helper copies the read-only sources to:

```text
$BUILD_ROOT/apache-build/ModSecurity_V3
$BUILD_ROOT/apache-build/ModSecurity-apache
```

It then builds only inside those copies. The Apache connector build uses the
observed upstream Autotools/APXS path:

```sh
./autogen.sh
./configure --with-libmodsecurity=$BUILD_ROOT/apache-build/output/modsecurity
make
```

The libmodsecurity staging directory contains copied headers and shared library
artifacts from the v3 build copy:

```text
$BUILD_ROOT/apache-build/output/modsecurity/include/
$BUILD_ROOT/apache-build/output/modsecurity/lib/
```

## Runtime Smoke

The Apache harness renders `connectors/apache/harness/apache_smoke.conf` into a
per-case runtime directory, for example:

```text
$BUILD_ROOT/apache-runtime/phase2_args_block/conf/httpd.conf
```

Rules, request details, and expected statuses are read from:

```text
tests/common/cases/minimal/*.yaml
tests/common/cases/imported/*.yaml
tests/apache/cases/imported/*.yaml
```

The default run executes:

```text
phase1_header_block
phase2_args_block
phase2_args_pass
audit_log_phase1_block
request_body_json_block
request_body_urlencoded_block
response_header_basic
json_request_body_block
multipart_basic_block
response_body_pass
```

Run through the formal target:

```sh
BUILD_ROOT=/src/ModSecurity-test-Framework-build make smoke-apache
```

The harness does not hardcode the rule, request path, request method, headers,
body, response fixture, or expected HTTP status. Readiness uses
`/__modsec_smoke_ready` with ModSecurity disabled so phase and response rules do
not affect startup checks. Status `pass` is only valid when the common runner
checks the observed Apache response against each YAML expectation. A successful
compile alone is not a runtime pass.

The generated `$BUILD_ROOT/results/apache-summary.json` records
`connector_path: real-world`, `validation_mode:
real-world-connector-path`, the httpd binary, `mod_security3.so`,
libmodsecurity, and `verified_variables` derived only from passing cases.

## Current Local Status

Observed in this workspace on 2026-05-15:

- `autoconf`, `automake`, `libtoolize`, `make`, `cc`, `c++`, `curl`, and `perl`
  are present.
- `apxs`, `apxs2`, `apache2`, `httpd`, `apachectl`, and `apache2ctl` were not
  found in `PATH`.
- `REFRESH=1 BUILD_HTTPD_FROM_SOURCE=1
  BUILD_ROOT=/src/ModSecurity-test-Framework-build sh ci/prepare-apache-build.sh`
  built Apache httpd from source, built libmodsecurity v3 in a writable copy,
  and built `mod_security3.so`.
- `BUILD_ROOT=/src/ModSecurity-test-Framework-build make smoke-apache` returned pass
  for all current shared minimal cases and the active common imported cases,
  including raw JSON body, simple multipart text-field, and response-body
  pass-through smokes.

Artifacts generated by the local pass:

```text
/src/ModSecurity-test-Framework-build/apache-build/ModSecurity_V3
/src/ModSecurity-test-Framework-build/apache-build/ModSecurity-apache
/src/ModSecurity-test-Framework-build/apache-build/output/apache/mod_security3.so
/src/ModSecurity-test-Framework-build/apache-build/output/modsecurity/
/src/ModSecurity-test-Framework-build/apache-runtime/httpd/bin/apxs
/src/ModSecurity-test-Framework-build/apache-runtime/httpd/bin/httpd
/src/ModSecurity-test-Framework-build/logs/apache/
/src/ModSecurity-test-Framework-build/logs/apache-runtime/<case>/status.txt
/src/ModSecurity-test-Framework-build/results/apache-summary.txt
/src/ModSecurity-test-Framework-build/results/apache-summary.json
```

Observed tool and version details:

```text
httpd_source_built=1
httpd_version=2.4.67
apxs=/src/ModSecurity-test-Framework-build/apache-runtime/httpd/bin/apxs
apache_httpd=/src/ModSecurity-test-Framework-build/apache-runtime/httpd/bin/httpd
apache_httpd_version=Apache/2.4.67
pcre_config=/usr/bin/pcre2-config
pcre_config_version=10.46
pcre2_source_built=0
apache_smoke_cases=audit_log_phase1_block, phase1_header_block, phase2_args_block, phase2_args_pass, request_body_json_block, request_body_urlencoded_block, response_header_basic, json_request_body_block, multipart_basic_block, response_body_pass
apache_smoke_status=all pass; blocking cases HTTP 403; pass-through case HTTP 200
apache_validation_mode=real-world-connector-path
apache_verified_variables=ARGS,REQUEST_HEADERS,REQUEST_BODY,FILES,XML,AUDIT_LOG,RESPONSE_HEADERS
```

## Status Meanings

- `implemented`: helper scripts, harness template, shared case, and docs exist.
- `blocked`: required source, APXS, Apache, module, or library prerequisite is
  missing; no functionality is claimed.
- `fail`: prerequisites exist but a build, configtest, startup, or HTTP
  expectation fails.
- `pass`: Apache returns the YAML-expected HTTP status for every selected
  shared smoke case.

## Open TODOs

- Verify exact Apache module loading requirements across more distributions.
- Run the source-built httpd mode in CI once the external source checkouts are
  available there.
- If Apache returns non-403, inspect `$BUILD_ROOT/logs/apache-runtime` before
  changing the harness or rule.
- Promote only proven behavior into connector-specific regression tests.

## Public Sources

- Apache httpd install documentation:
  https://httpd.apache.org/docs/current/install.html.en
- Apache httpd distribution index:
  https://downloads.apache.org/httpd/
- Apache APR download page:
  https://apr.apache.org/download.cgi
- PCRE2 build and release documentation:
  https://pcre2project.github.io/pcre2/guide/readme/
