# NGINX PoC Plan

**Language:** English | [Deutsch](nginx-poc-plan.de.md)

Status: scaffolded

This document records the NGINX PoC direction and the source facts used for the
scaffolded build/runtime harness.

## Local Source Facts

- Source: `<workspace>/ModSecurity-nginx`
- Observed branch: `master`
- Observed version: `v1.0.4-14-g9eb44fd`
- Build integration is the NGINX third-party module `config` file.
- The `config` file supports explicit libmodsecurity paths through
  `MODSECURITY_INC` and `MODSECURITY_LIB`.

## Build Model

The observed README documents building from an NGINX source tree with:

```sh
./configure --add-module=/path/to/ModSecurity-nginx
```

or dynamic module mode:

```sh
./configure --add-dynamic-module=/path/to/ModSecurity-nginx --with-compat
```

The implemented PoC helper chooses dynamic module mode and builds only under
`BUILD_ROOT`.

Default source mode:

```sh
NGINX_SOURCE_MODE=github-release
NGINX_GITHUB_REPO=https://github.com/nginx/nginx
NGINX_RELEASE_TAG=latest
```

When `NGINX_RELEASE_TAG=latest`, `ci/prepare-nginx-build.sh` resolves the actual
release through the GitHub Releases API and records the resulting tag in
`$BUILD_ROOT/logs/nginx/artifacts.txt`. Explicit tags such as
`release-1.31.0` are also supported. No branch fallback is allowed.

## Request Lifecycle

Observed local source:

- `src/ngx_http_modsecurity_module.c` registers the access handler in
  `NGX_HTTP_ACCESS_PHASE`.
- The same postconfiguration registers a log handler in `NGX_HTTP_LOG_PHASE`.
- Header and body filters are installed through
  `ngx_http_modsecurity_header_filter_init()` and
  `ngx_http_modsecurity_body_filter_init()`.
- `src/ngx_http_modsecurity_access.c` creates request context, processes
  connection data, URI, request headers, and request body through libmodsecurity
  v3 APIs.
- `src/ngx_http_modsecurity_header_filter.c` sends response headers and calls
  `msc_process_response_headers`.
- `src/ngx_http_modsecurity_body_filter.c` appends response body data and calls
  `msc_process_response_body` on the last buffer.
- `src/ngx_http_modsecurity_log.c` calls `msc_process_logging`.

## PoC Target

The NGINX PoC reuses the same portable cases as Apache:

```text
tests/cases/*.yaml
```

Pass criteria remain the same: a real local HTTP response matching each YAML
case expectation. The current minimal cases all expect HTTP `403`.

## Blocked Items

- Fresh environments are blocked until the read-only v3 and ModSecurity-nginx
  source checkouts exist or are provided through environment variables.
- GitHub latest release resolution or explicit tag download can block on
  network/API failures.
- NGINX `pass` is blocked until the dynamic module builds and the runtime
  harness observes HTTP `403`.
