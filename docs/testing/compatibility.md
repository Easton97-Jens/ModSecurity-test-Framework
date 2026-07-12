# Compatibility

**Language:** English | [Deutsch](compatibility.de.md)

Status: scaffolded

## Version Position

The scaffold targets libmodsecurity v3 public APIs. v2 artifacts are not used as
architecture for new connectors.

## Current Compatibility Matrix

| Area | Status | Notes |
| --- | --- | --- |
| Common headers | implemented | Connector-neutral C-compatible data shapes only |
| libmodsecurity v3 API mapping | planned | Public API sequence documented, not wrapped |
| Apache connector | scaffolded | Latest local source-built smoke passed 48/48 active runtime cases |
| NGINX connector | scaffolded | Latest local source-built smoke passed 54/54 active runtime cases after the NGINX harness permission fix |
| Apache real-world connector path | implemented | Smoke summaries record source-built httpd, `mod_security3.so`, libmodsecurity, and verified variables |
| NGINX real-world connector path | implemented | Smoke summaries record source-built NGINX, dynamic module, libmodsecurity, and verified variables |
| HAProxy connector | unknown | SPOE/Lua/native options documented, implementation undecided |
| Envoy connector | unknown | HTTP filter/ext_authz/Wasm options documented, implementation undecided |
| Lighttpd connector | unknown | Native plugin and mod_magnet options documented, implementation undecided |
| Traefik connector | unknown | Yaegi/Wasm plugin options documented, implementation undecided |
| v2 regression reuse | planned | Only portable rule/engine semantics may enter `docs/imports/common/` |
| v2-derived common imports | implemented | Blocking operator/transformation cases and the `t:urlDecode` no-match pass-through case pass locally on Apache and NGINX |
| v3-derived common imports | implemented | Blocking multipart/FILES/XML/operator/action/collection/audit cases and no-match pass-through cases for cookies/header names/ARGS_NAMES pass locally on Apache and NGINX |
| Source-derived Apache/NGINX test import | implemented | Imported YAML cases are derived, not copied; origin and portability are documented |

## Capability Rule

Tests and connector docs must name required capabilities. If a behavior depends
on hook timing, buffering, streaming, log artifacts, reload semantics, or server
configuration, it is connector-specific unless proven portable.

## Shared Minimal Cases

The files under `$FRAMEWORK_ROOT/tests/cases/` are portable
rule/request models supplied by `ModSecurity-test-Framework`.
They are not proof that a connector supports the behavior until that
connector's runtime harness observes the expected HTTP response.

Observed locally on 2026-05-15 with an explicit external `BUILD_ROOT`:

| Case | Capability area | Apache | NGINX |
| --- | --- | --- | --- |
| `audit_log_phase1_block.yaml` | query args, phase 1, audit log | pass, HTTP 403 plus audit fields | pass, HTTP 403 plus audit fields |
| `phase1_header_block.yaml` | request headers, phase 1 | pass, HTTP 403 | pass, HTTP 403 |
| `phase2_args_block.yaml` | query args, phase 2 | pass, HTTP 403 | pass, HTTP 403 |
| `phase2_args_pass.yaml` | query args, phase 2, pass-through | pass, HTTP 200 plus origin body | pass, HTTP 200 plus origin body |
| `request_body_json_block.yaml` | request body, JSON content type, raw body match | pass, HTTP 403 | pass, HTTP 403 |
| `request_body_urlencoded_block.yaml` | form body, `ARGS_POST` | pass, HTTP 403 | pass, HTTP 403 |
| `response_header_basic.yaml` | response headers, phase 3 | pass, HTTP 403 | pass, HTTP 403 |

This proves only these PoC behaviors in this workspace, not full connector
compatibility, CRS support, multipart handling, streaming behavior, HTTP/2, or
complete response-body behavior.

## Imported Case Scopes

| Scope | Location | Compatibility meaning |
| --- | --- | --- |
| common minimal | `$FRAMEWORK_ROOT/tests/cases/` | Already proven locally for both PoCs before the import step |
| common imported | `$FRAMEWORK_ROOT/tests/cases/` | Portable candidates derived from Apache/NGINX tests; compatibility is claimed only after both connector smokes pass |
| v2 imported | `$FRAMEWORK_ROOT/tests/cases/` | Portable v2 semantics candidates adapted to HTTP behavior and proven on both connector PoCs |
| v3 imported | `$FRAMEWORK_ROOT/tests/cases/` | Portable v3 regression candidates adapted to HTTP behavior and proven on both connector PoCs |
| Apache imported | `tests/cases/connector-specific/apache/` | Apache-only until a common equivalent is proven |
| NGINX imported | `tests/cases/connector-specific/nginx/` | NGINX-only until a common equivalent is proven |

Mapped-only categories include HTTP/2, proxy, multipart parser edge cases,
response-body blocking, external-file operators, debug logs, and connector
config inheritance.

Earlier local runs imported common cases after Apache and NGINX evidence. A
2026-05-20 local NGINX run exposed a harness permission blocker where 11
expected-200 pass-through/phase-4 cases returned 403 because NGINX could not
read generated `htdocs/index.html` below a private parent directory. The
2026-05-21 rerun after the harness permission fix passed all 54 active NGINX
cases; see `docs/testing/nginx-runtime-failure-classification.md`.

## Body And Filter Compatibility

| Case or category | Apache | NGINX | Status |
| --- | --- | --- | --- |
| `json_request_body_block.yaml` | pass, HTTP 403 | pass, HTTP 403 | fully-imported-common |
| `multipart_basic_block.yaml` | pass, HTTP 403 | pass, HTTP 403 | fully-imported-common |
| `response_body_pass.yaml` | pass-through, HTTP 200 | pass-through, HTTP 200 evidence | RESPONSE_BODY non-verified/non-promoted |
| `response_body_basic_block` | fail, HTTP 200 | fail, HTTP 200 | former expected-failure/mapped-only |
| PR #377 minimal/safe phase-4 log-only probes | n/a | pass, HTTP 200 in latest NGINX smoke | NGINX-specific log-only evidence; not RESPONSE_BODY promotion |
| PR #377 content-type out-of-scope phase-4 probe | n/a | pass, HTTP 200 in latest NGINX smoke | NGINX-specific log-only evidence; not RESPONSE_BODY promotion |

The response-body block row is intentionally not an active smoke. The NGINX
reference test marks the behavior TODO, and ModSecurity-nginx PR #377 source
changes are treated as source-level evidence only. A local three-repeat probe
did not produce stable HTTP 403 on either connector, so this repository
documents the evidence without claiming connector parity.

## V2/V3-Derived Compatibility

Observed locally on 2026-05-15 with an explicit external `BUILD_ROOT`:

| Case group | Apache | NGINX | Status |
| --- | --- | --- | --- |
| V2 operator semantics (`@streq`, `@contains`, `@beginsWith`, `@endsWith`, `@pm`, `@containsWord`) | pass, HTTP 403 | pass, HTTP 403 | fully-imported-common |
| V2 transformation semantics (`t:lowercase`, `t:trim`, `t:urlDecode`, `t:htmlEntityDecode`) | pass, HTTP 403 | pass, HTTP 403 | fully-imported-common for blocking branches; `t:urlDecode` no-match pass-through now passes in the latest NGINX run |
| V3 multipart FILES variables | pass, HTTP 403 | pass, HTTP 403 | fully-imported-common |
| V3 XML body processor basic case | pass, HTTP 403 | pass, HTTP 403 | fully-imported-common |
| V3 `@rx`, trim, and `SecAction` basics | pass, HTTP 403 | pass, HTTP 403 | fully-imported-common |
| V3 `@pm`, cookies, header names, ARGS_NAMES, and serial audit basics | pass | pass for blocking branches and latest no-match pass-through subset | fully-imported-common for active smoke branches; broader edge cases remain mapped/former expected-failure |
| V3 `nolog,pass` audit absence (`issue-2196`) | pass locally, empty audit log | pass locally, empty audit log | former expected-failure because GitHub Actions observed a non-empty audit log |

The active cases prove only the minimal YAML scenarios. V2 Perl harness
internals, v3 API-only cases, XML schema/DTD validation, malformed multipart,
NUL/binary transformation branches, streaming, HTTP/2, and optional-library
operators remain mapped until dedicated support is added.

## Real-World Connector Path

`real-world-connector-path` is the compatibility proof mode for Apache and
NGINX:

```text
HTTP client -> server process -> connector module -> libmodsecurity -> rule variables -> HTTP response
```

The direct v3 API smoke remains separate and is not connector proof. Connector
summary JSON records `connector_path`, `validation_mode`, `server_binary`,
`module`, `libmodsecurity`, and `verified_variables`. A variable appears there
only if at least one active passing case exercised it through the real server
runtime.

Current active passing cases verify `ARGS`, `ARGS_NAMES`, `REQUEST_COOKIES`,
`REQUEST_HEADERS`, `REQUEST_URI`, `REQUEST_BODY`, `FILES`, `XML`, `AUDIT_LOG`,
and `RESPONSE_HEADERS` through both Apache and NGINX runtime in this workspace.
`RESPONSE_BODY` remains mapped/former expected-failure until an active response-body
variable/blocking case passes on both connectors.

## Latest NGINX Runtime Classification (2026-05-21)

`make smoke-nginx` ran 54 active runtime cases against freshly produced
source-build artifacts: 54 PASS, 0 FAIL, 0 BLOCKED. This rerun used
worker-readable generated runtime files under the NGINX harness work root, so
the previous `htdocs/index.html` permission denial no longer blocks expected-200
pass-through and phase-4 log-only cases.

The 11 previously blocked cases are now current local NGINX runtime PASS
evidence. `response_body_pass` remains pass-through evidence only; it is not
RESPONSE_BODY verification, not response-body blocking proof, and not a full
phase-4 compatibility claim. See
`docs/testing/nginx-runtime-failure-classification.md` for the per-case table.

`v3_action_nolog_pass_no_audit` is also classified as former expected-failure/mapped for now:
local runs in this workspace produced HTTP 200 and empty audit logs, but the
current GitHub Actions run reported `expected audit log to be absent or empty`.
It is not counted as a stable common PASS until local Apache, local NGINX, and
GitHub Actions agree.

## Reproducible Local Setup (Smoke + Lint)

The smoke/lint tooling has explicit prerequisites and reports missing runtime inputs as **BLOCKED**.

Shell helper defaults are centralized in `modules/ModSecurity-test-Framework/ci/lib/common.sh`. Override variables in
the environment rather than editing scripts:

```bash
BUILD_ROOT=$HOME/.local/state/ModSecurity-conector-build
SOURCE_ROOT=$BUILD_ROOT/sources
MODSECURITY_GIT_REF=v3/master
MODSECURITY_SOURCE_DIR=$SOURCE_ROOT/ModSecurity_V3
MODSECURITY_V3_SOURCE_DIR=$SOURCE_ROOT/ModSecurity_V3
MODSECURITY_V3_ROOT=$SOURCE_ROOT/ModSecurity_V3
MODSECURITY_APACHE_SOURCE_DIR=$PWD/connectors/apache
MODSECURITY_NGINX_SOURCE_DIR=$PWD/connectors/nginx
APACHE_BIN=/path/to/apache2
APACHECTL_BIN=/path/to/apachectl
APXS_BIN=/path/to/apxs
NGINX_BIN=/path/to/nginx
MODSECURITY_PKG_CONFIG=modsecurity
MODSECURITY_LIB_DIR=/path/to/lib
MODSECURITY_INCLUDE_DIR=/path/to/include
HTTPD_VERSION=2.4.67
APR_VERSION=1.7.6
APR_UTIL_VERSION=1.6.3
PCRE2_VERSION=10.47
NGINX_SOURCE_REPO_URL=https://github.com/nginx/nginx
NGINX_RELEASE_TAG=latest
```

`modules/ModSecurity-test-Framework/ci/lib/common.sh` is passive and does not run checks, fetch sources, or create
artifacts by itself. Connector source is repo-local by default; external
Apache/NGINX connector repositories require explicit opt-in and are not runtime
defaults.

### Python dependencies

Install dev dependencies before running `make lint`:

```bash
python3 -m pip install -r requirements-dev.txt
```

Currently required for lint helpers:

- `PyYAML>=6,<7` (used by `modules/ModSecurity-test-Framework/ci/checks/documentation/check-workflow-yaml.py`)

If missing, lint prints a clear blocked message and installation hint instead of a Python traceback.


### One-command dev bootstrap

Create an isolated virtualenv and install dev deps:

```bash
make setup-dev
# make now auto-prefers .venv/bin/python when present
source .venv/bin/activate
```

Equivalent target names:

- `make install-dev-deps`
- `make setup-dev`

### Environment doctor

Check Python deps and ModSecurity v3 path detection:

```bash
make doctor
```

The doctor output separates source-build readiness from optional installed
readiness. Source-build readiness uses the configured source aliases from
`modules/ModSecurity-test-Framework/ci/lib/common.sh`; installed Apache/NGINX/libmodsecurity detection is diagnostic
only and does not make system installations a standard prerequisite. If no
ModSecurity v3 source tree is available, doctor exits BLOCKED and prints the
exact export or `make fetch-deps` remediation command.


### Optional GitHub runtime fetch

To bootstrap real external runtime prerequisites explicitly:

```bash
make fetch-deps
```

This uses `modules/ModSecurity-test-Framework/ci/provisioning/fetch-smoke-sources.sh` and fetches the ModSecurity core engine
source from the configured `MODSECURITY_REPO_URL` / `MODSECURITY_GIT_REF` (see
`docs/testing/bootstrap.md`). Apache and NGINX connector source remains
repo-local by default.
No network fetch is triggered automatically by `make setup-dev`, `make lint`, `make doctor`, or `make smoke-all`.

If you only want to run dependency diagnostics first:

```bash
make doctor
```

### Runtime prerequisites for connector smokes

`make smoke-all` requires a ModSecurity v3 source tree path. The portable
source-build default is derived from:

- `SOURCE_ROOT=$BUILD_ROOT/sources`
- `MODSECURITY_SOURCE_DIR=$SOURCE_ROOT/ModSecurity_V3`

Override in portable environments:

```bash
export BUILD_ROOT=/absolute/path/for/build-artifacts
export MODSECURITY_SOURCE_DIR=$BUILD_ROOT/sources/ModSecurity_V3
make smoke-all
```

If prerequisites are missing, smoke scripts now emit explicit blocked guidance that includes:

- missing prerequisite path
- affected env var name
- remediation command/env hint
- explicit statement that result is **BLOCKED**, not **FAIL**

### Status meaning

- **PASS**: expected behavior observed through the real connector path.
- **FAIL**: harness ran and observed unexpected behavior or execution error.
- **BLOCKED**: prerequisites (dependencies, source paths, build/runtime requirements) are missing, so execution could not start reliably.


### Recommended fresh-environment flow

```bash
make setup-dev
make lint
make fetch-deps
make doctor
make smoke-all
```

Use a single consistent `BUILD_ROOT` across `fetch-deps`, `doctor`, and `smoke-all`.


See also: `docs/testing/fast-checks.md` for quick/full check boundaries.


Quick local developer checks can use `make doctor-quick` and `make quick-all`;
these are not full-smoke replacements and may return BLOCKED when runtime
prerequisites are absent. GitHub/Codex CI uses the lighter
`make cloud-quick-check` framework/generator path and intentionally avoids
runtime probes.

## Incremental Coverage Note (2026-05-19)

Added source-derived negative/pass-through common cases for:

- `REQUEST_COOKIES_NAMES` (`v3_request_cookies_names_pass_no_match`)
- `ARGS_NAMES` (`v3_args_names_get_pass_no_match`)
- `REQUEST_URI` with `t:urlDecode` no-match branch (`v2_transformation_url_decode_pass_no_match`)

These additions improve matrix/documented coverage but are not claimed as new stable common PASS evidence until full runtime smoke (`make smoke-all`) runs with all prerequisites.


## Installed runtime detection (non-authoritative)

`make doctor` and `make smoke-installed` / `make installed-readiness` report installed-component readiness using alternative binary names and explicit ModSecurity detection. This is optional diagnostic output, not a required source-build prerequisite.

Supported detection aliases:

- Apache: `apache2` / `httpd` / `apachectl`
- APXS: `apxs` / `apxs2`
- NGINX: `nginx`
- ModSecurity: `pkg-config` (`modsecurity` or `libmodsecurity`) or filesystem evidence (`libmodsecurity.so*` plus `modsecurity/modsecurity.h`)

Supported override variables:

- `APACHE_BIN`, `APXS_BIN`, `NGINX_BIN`
- `APACHECTL_BIN`
- `MODSECURITY_PKG_CONFIG`, `MODSECURITY_LIB_DIR`, `MODSECURITY_INCLUDE_DIR`
- `CI_APACHE_BIN_CANDIDATES`, `CI_APXS_BIN_CANDIDATES`,
  `CI_NGINX_BIN_CANDIDATES`
- `CI_INSTALLED_LIB_SEARCH_DIRS`, `CI_INSTALLED_INCLUDE_SEARCH_DIRS`

This installed-path readiness is informative for quick diagnostics. Full compatibility evidence remains the source-build full-smoke path (`make smoke-all`).


## Cloud/GitHub lightweight path

For Codex Cloud / GitHub Actions, `.github/workflows/quick-framework-check.yml`
runs lightweight framework, lint, generator, and documentation consistency
checks. It does not run connector Runtime-Smokes, source fetches, installed
runtime probes.

This path distinguishes:

- Framework correctness failures (red): lint/schema/python/generated-doc/diff issues.
- Runtime compatibility evidence: local-only via full connector smoke targets.

It does not replace the authoritative local full source-build smoke
(`make smoke-all`).

## Expanded pending compatibility coverage (2026-05-19)

Added a larger source-derived former expected-failure/pending set for connector-gap, runtime-difference, and future-compatibility targets. This extends long-term compatibility tracking without changing current verified PASS semantics.

Notably, RESPONSE_BODY remains non-verified and is not promoted; response-body blocking evidence stays former expected-failure/mapped-only until stable cross-connector HTTP 403 proof exists.

## Pending operator/transformation/phase coverage (2026-05-19)

The compatibility matrix now includes additional source-derived former expected-failure targets for operators, transformations, phase ordering assumptions, and parser/edge behavior. This is roadmap-style coverage, not active verified connector parity.

`RESPONSE_BODY` classification remains unchanged (former expected-failure/mapped-only, non-verified).

## Audit/normalization/parser pending coverage (2026-05-19)

Compatibility tracking now includes additional source-derived former expected-failure targets for audit-log behavior, duplicate/normalization handling, parser partial-body edges, and transformation-chain interactions. These are roadmap probes and not active PASS parity claims.

## Multipart/files/unicode/parser pending coverage (2026-05-19)

Compatibility tracking now includes additional former expected-failure probes for FILES/multipart parsing, Unicode/encoding normalization, deeper JSON/XML structures, and benign XSS-like/SQLi-like transformation interactions. These remain non-verified roadmap coverage.

## Outbound phase (3/4) pending coverage (2026-05-19)

Coverage now includes explicit phase-3 response-header and phase-4 outbound/response-body probes as former expected-failure/connector-gap/runtime-difference/future targets. This improves long-term compatibility tracking while keeping RESPONSE_BODY non-verified.

## Additional outbound follow-up probes (2026-05-19)

A follow-up wave extends phase-3/4 outbound coverage for response-header normalization and outbound audit assumptions. RESPONSE_BODY remains explicitly non-verified and non-promoted.

## Coverage Matrix Reporting

For up-to-date repository coverage reporting, use:

- `docs/testing/test-coverage-overview.md`
- `docs/testing/generated/case-matrix.generated.md`
- `docs/testing/generated/coverage-summary.generated.md`
- `docs/testing/generated/xfail-summary.generated.md`
- `docs/testing/generated/connector-gap-summary.generated.md`
- `docs/testing/generated/phase-coverage.generated.md`

Generation/check workflow:

```sh
make generate-test-matrix
make check-test-matrix
```

These artifacts summarize declared case metadata and import status. They do not
assert full runtime compatibility; `make smoke-all` remains the authoritative
local runtime-evidence path.
