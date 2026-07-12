# Fast Checks vs Full Smoke

**Language:** English | [Deutsch](fast-checks.de.md)

## Purpose

Fast checks provide rapid feedback for Codex/developer iterations without pretending to be full connector validation.

Shared defaults for runtime helper scripts live in
`$FRAMEWORK_ROOT/ci/lib/common.sh`; connector-local `ci/` scripts perform connector-specific checks. The framework path is
configurable with `FRAMEWORK_ROOT` and defaults locally to the module
`modules/ModSecurity-test-Framework`.

## Targets

- `make quick-all`
  - local-preferred orchestration target for fast checks
  - combines lint, doctor-quick, quick-check, smoke-installed, py_compile, diff-check
  - returns QUICK PASS / QUICK BLOCKED / QUICK FAIL
- `make quick-check` / `make codex-check`
  - runs lint, py_compile, and diff checks
  - does **not** run Apache/NGINX full smoke
- `make smoke-installed` / `make installed-readiness`
  - probes installed components and libmodsecurity presence
  - currently acts as installed readiness probe; returns BLOCKED when execution wiring for true installed runtime smoke is not available
- `make smoke-all`
  - full source-build smoke path (authoritative)
- `make runtime-matrix`
  - local source-build Apache/NGINX per-case runtime inventory for the default executable case set
- `make runtime-matrix-all`
  - local source-build Apache/NGINX per-case runtime inventory with `FORCE_ALL_CASES=1`
  - attempts former expected-failure, pending, future, experimental, and connector-gap YAML cases where applicable
  - recorded PASS/FAIL data is evidence only and does not promote YAML status or RESPONSE_BODY support

## Honesty rules

- BLOCKED is not PASS.
- quick checks never replace full smoke for release compatibility evidence.
- no fake green status when prerequisites are missing.

## Recommended flow

```bash
make setup-dev
make quick-all
# if QUICK BLOCKED due to runtime prerequisites:
make fetch-deps
make smoke-all
```


## Installed smoke detection

`make smoke-installed` / `make installed-readiness` is a **detection/readiness** probe for already-installed system components; it is not a replacement for `make smoke-all`.
It is optional diagnostic output only: source-built connector smokes do not
require system Apache, NGINX, APXS, or libmodsecurity installations.

Recognized binary names:

- Apache runtime: `apache2`, `httpd`, `apachectl`
- APXS: `apxs`, `apxs2`
- NGINX runtime: `nginx`

Recognized ModSecurity signals:

- `pkg-config` package: `modsecurity` or `libmodsecurity`
- shared libraries: `libmodsecurity.so` / `libmodsecurity.so.3`
- header: `modsecurity/modsecurity.h`

Optional override environment variables:

- `APACHE_BIN`
- `APACHECTL_BIN`
- `APXS_BIN`
- `NGINX_BIN`
- `MODSECURITY_PKG_CONFIG`
- `MODSECURITY_LIB_DIR`
- `MODSECURITY_INCLUDE_DIR`
- `CI_APACHE_BIN_CANDIDATES`
- `CI_APXS_BIN_CANDIDATES`
- `CI_NGINX_BIN_CANDIDATES`
- `CI_INSTALLED_LIB_SEARCH_DIRS`
- `CI_INSTALLED_INCLUDE_SEARCH_DIRS`

Readiness semantics:

- `READY`: component set is detected.
- `PARTIAL`: only one connector path is detectable.
- `BLOCKED`: required pieces are missing.

Even with `READY`, `smoke-installed` remains non-authoritative until installed-runtime execution wiring exists; `make smoke-all` stays authoritative.


## Cloud/GitHub Actions quick path

Use `make cloud-quick-check` for GitHub/Codex CI environments where checks must
stay lightweight and deterministic.

- Required/pass-fail: `setup-dev`, `lint`, `refresh-framework-reports`,
  `check-test-matrix`, `quick-check`, Python compile, `git diff --check`.
- Runtime probes are intentionally excluded: no `quick-all`, no
  `installed-readiness`, and no full connector smoke.
- This does **not** replace `make smoke-all`; full runtime validation remains
  local and authoritative.

Workflow: `.github/workflows/quick-framework-check.yml` runs the lightweight
framework/generator path on `push` and `pull_request`.

For version and path changes, prefer environment overrides consumed through
`$FRAMEWORK_ROOT/ci/lib/common.sh`, for example `FRAMEWORK_ROOT`, `CONNECTOR_ROOT`,
`BUILD_ROOT`, `SOURCE_ROOT`,
`MODSECURITY_GIT_REF`, `MODSECURITY_SOURCE_DIR`, `MODSECURITY_V3_SOURCE_DIR`,
`APACHE_BIN`, `APACHECTL_BIN`, `APXS_BIN`, and `NGINX_BIN`. Apache and NGINX
connector source is repo-local by default; server source versions are configured
with `HTTPD_VERSION`, `PCRE2_VERSION`, `NGINX_SOURCE_REPO_URL`, and
`NGINX_RELEASE_TAG`. `BUILD_ROOT` is a local build/output location and can be
replaced with any explicit absolute path.
