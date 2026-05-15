# NGINX Smoke Harness

Status: scaffolded

This harness is a connector-specific proof-of-concept runner for the dynamic
NGINX module built from the read-only `ModSecurity-nginx` source copy. It is not
a complete regression suite.

Observed locally on 2026-05-15: source-built NGINX `1.31.0` from GitHub tag
`release-1.31.0` returned the YAML-expected HTTP status for all current shared
minimal cases.

## Boundaries

- Uses only artifacts under `BUILD_ROOT`.
- Does not build or modify any `/root/conecter/*` repository.
- Does not import NGINX or ModSecurity-nginx source into this monorepo.
- Reports `pass` only when NGINX returns the YAML-expected HTTP status for a
  real local request.
- Reads rule, request, headers, body, multipart body, response fixture, and
  expected status from YAML through `tests/runners/case_cli.py`.

## Usage

```sh
REFRESH=1 \
BUILD_NGINX_FROM_SOURCE=1 \
BUILD_ROOT=/src/ModSecurity-test-Framework-build \
sh ci/prepare-nginx-build.sh

BUILD_ROOT=/src/ModSecurity-test-Framework-build \
make smoke-nginx
```

The build helper defaults to the official GitHub release source:

```sh
NGINX_SOURCE_MODE=github-release
NGINX_GITHUB_REPO=https://github.com/nginx/nginx
NGINX_RELEASE_TAG=latest
```

When `NGINX_RELEASE_TAG=latest`, the helper queries the GitHub Releases API and
records the actual tag in `$BUILD_ROOT/logs/nginx/artifacts.txt`. To pin a
specific release, set `NGINX_RELEASE_TAG=release-1.31.0` or another exact tag.

If NGINX, the dynamic module, or `libmodsecurity.so` is missing, the script
exits `77` and marks the result as `blocked`.

## Shared Cases

By default the harness iterates every `*.yaml` file in:

```text
tests/common/cases/minimal/
tests/common/cases/imported/
tests/nginx/cases/imported/
```

To run a subset:

```sh
BUILD_ROOT=/src/ModSecurity-test-Framework-build \
SMOKE_CASES="phase1_header_block phase2_args_block" \
make smoke-nginx
```

The harness materializes the NGINX rule file, request variables, request
headers, request body, multipart body, and response fixture from each YAML file
at runtime. It uses `/__modsec_smoke_ready` with ModSecurity disabled only for
readiness checks. Do not duplicate the rule, request path, request method,
headers, body, response fixture, or expected HTTP status in the harness.

Response-body blocking remains mapped as xfail until the NGINX smoke observes a
stable HTTP 403 for the same common YAML case.
