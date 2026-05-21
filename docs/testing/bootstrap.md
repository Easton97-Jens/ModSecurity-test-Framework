# Runtime Bootstrap (Optional)

This project can optionally fetch real upstream smoke prerequisites from GitHub.
Apache and NGINX connector source is repo-local by default; external connector
repositories are not part of the default runtime bootstrap.

Shared shell defaults for the framework runtime helpers are centralized in
`$FRAMEWORK_ROOT/ci/common.sh`. Connector-local `ci/` scripts are connector-specific checks. The framework `common.sh`
is passive: it only defines variables and helper functions when sourced, and it
does not fetch, install, validate, or create directories by itself.

Set `FRAMEWORK_ROOT` when the framework checkout is not the module
`modules/ModSecurity-test-Framework`.

## Repositories used

- ModSecurity v3: `https://github.com/owasp-modsecurity/ModSecurity.git` (ref: `v3/master` by default)
- Apache connector source: `connectors/apache` in this repository
- NGINX connector source: `connectors/nginx` in this repository
- Shared YAML cases and runner/generator code:
  `$FRAMEWORK_ROOT/docs/imports/common`, `$FRAMEWORK_ROOT/tests/runners`,
  `$FRAMEWORK_ROOT/tests/normalizers`, and `$FRAMEWORK_ROOT/ci`
- Apache/httpd, APR/APR-util, PCRE2, and NGINX server sources are separate
  runtime-build dependencies configured through `modules/ModSecurity-test-Framework/ci/common.sh`.

Central override variables:

- `FRAMEWORK_ROOT`
- `CONNECTOR_ROOT`
- `BUILD_ROOT`
- `SOURCE_ROOT`
- `MODSECURITY_REPO_URL` / `MODSECURITY_GIT_REF`
- compatibility aliases: `MODSECURITY_V3_GIT_URL`, `MODSECURITY_V3_GIT_REF`
- source aliases: `MODSECURITY_SOURCE_DIR`, `MODSECURITY_V3_SOURCE_DIR`,
  `MODSECURITY_V3_ROOT`
- connector source aliases: `MODSECURITY_APACHE_SOURCE_DIR`,
  `MODSECURITY_NGINX_SOURCE_DIR` (repo-local by default)
- optional external connector fetch: `ALLOW_EXTERNAL_CONNECTOR_REPOS=1` plus
  explicit `MODSECURITY_APACHE_REPO_URL` / `MODSECURITY_NGINX_REPO_URL` and
  explicit source destinations under `SOURCE_ROOT`
- server source variables: `HTTPD_VERSION`, `HTTPD_SOURCE_URL`, `APR_VERSION`,
  `APR_SOURCE_URL`, `APR_UTIL_VERSION`, `APR_UTIL_SOURCE_URL`,
  `PCRE2_VERSION`, `PCRE2_SOURCE_URL`, `NGINX_SOURCE_REPO_URL`,
  `NGINX_SOURCE_GIT_REF`, `NGINX_RELEASE_TAG`
- optional installed-runtime hints: `APACHE_BIN`, `APACHECTL_BIN`, `APXS_BIN`,
  `NGINX_BIN`, `MODSECURITY_PKG_CONFIG`, `MODSECURITY_LIB_DIR`,
  `MODSECURITY_INCLUDE_DIR`

Example:

```bash
BUILD_ROOT=$HOME/.local/state/ModSecurity-conector-build \
MODSECURITY_GIT_REF=v3/master \
make fetch-deps
```

## Commands

- Fetch the ModSecurity core source used by smoke dependencies:
  - `make fetch-deps`
- Fetch only ModSecurity core explicitly:
  - `make fetch-modsecurity-v3`

## Behavior and safety

- Fetching is **explicit only** (manual command invocation).
- Existing repositories are **not overwritten**; existing git clones are reused.
- If `git` is missing or network is blocked, command exits BLOCKED/non-zero with clear output.
- No fake runtime artifacts are created.

## Paths

Default fetch root is under build temp:

- `SOURCE_ROOT=$BUILD_ROOT/sources`

You can override destination paths with:

- `MODSECURITY_SOURCE_DIR`
- `MODSECURITY_V3_SOURCE_DIR`

These destination paths must be absolute and under `SOURCE_ROOT` for fetches to
avoid destructive behavior. Connector source paths normally point at
`connectors/apache` and `connectors/nginx` in this repository and are not
fetched.


## BUILD_ROOT consistency

`make fetch-deps`, `make doctor`, and `make smoke-all` are intended to use the same `BUILD_ROOT`.
Fetched sources live under `BUILD_ROOT/sources`.
The default build root is a portable local build/output location, not a promise
that old build artifacts will be reused. If you override `BUILD_ROOT`, use the
same absolute path for all commands in the flow.

Example:

```bash
BUILD_ROOT=/tmp/modsec-build make fetch-deps
BUILD_ROOT=/tmp/modsec-build make doctor
BUILD_ROOT=/tmp/modsec-build make smoke-all
```

NGINX worker-facing runtime files are staged under `NGINX_HARNESS_WORK_ROOT`
by `make smoke-nginx`. In root-run environments the default is a temp directory
such as `/tmp/ModSecurity-conector-nginx-runtime-0`; non-root runs prefer
`RUNNER_TEMP` when available. Permission adjustments stay inside that generated
harness work root. No global NGINX install, system NGINX configuration change,
or broad chmod is required.


## Fast and full targets

- Fast framework checks: `make quick-check`
- Installed runtime probe: `make smoke-installed` / `make installed-readiness`
- Full authoritative connector smoke: `make smoke-all`

Use `REFRESH=1 make smoke-all` to replace existing generated build/output
trees through the guarded cleanup path.

`make smoke-installed` / `make installed-readiness` is optional diagnostic
readiness for already-installed system components. Missing system Apache,
NGINX, APXS, or libmodsecurity packages do not block the source-build smoke
path; `make smoke-all` remains the authoritative local runtime evidence.


## Quick orchestration

Use `make quick-all` for a fast, honest framework/smoke-basis run.
It never triggers full source rebuilds by itself.
If optional runtime diagnostics are incomplete it reports BLOCKED, not PASS.


## Cloud/GitHub lightweight path

GitHub/Codex CI intentionally runs lightweight framework, generator, lint, and
documentation checks only. It does not fetch runtime sources, build Apache or
NGINX, run installed probes, or execute connector smokes. Full runtime evidence
remains local via `make smoke-all`, `make smoke-apache`, and
`make smoke-nginx`.
