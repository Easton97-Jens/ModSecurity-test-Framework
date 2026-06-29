# CI

**Language:** English | [Deutsch](README.de.md)

Status: scaffolded

CI helper scripts belong here after they are proven to be connector-neutral or
clearly connector-scoped.

`ci/common.sh` is the shared shell config/helper entrypoint. It centralizes
build roots, source roots, ModSecurity core refs/URLs, repo-local connector
source defaults, server source versions/URLs, Python selection, optional
installed-runtime hints, and logging helpers. It is passive: sourcing it
defines variables and functions only.

Important local entrypoints:

- `ci/cloud-quick-check.sh`: framework/generator/lint check for lightweight CI.
- `ci/quick-all.sh`: local-preferred quick orchestration; may return BLOCKED.
- `ci/fetch-smoke-sources.sh`: explicit source fetch helper.
- `ci/fetch-crs.sh`: explicit OWASP CRS fetch helper using the central pin from
  `ci/common.sh`.
- `ci/prepare-crs.sh`: generated CRS setup/preamble helper for the `with-crs`
  test variant.
- `ci/prepare-haproxy-runtime.sh`: local HAProxy source fetch/build helper. It
  uses only the HAProxy URL/version/checksum values from `ci/common.sh`,
  verifies the official checksum, checks `TARGET=linux-glibc` support in the
  downloaded source Makefile, and stages the binary under `BUILD_ROOT`.
- `ci/doctor.sh`: local prerequisite/readiness diagnostics.
- `ci/run-connector-smokes.sh`: local Apache+NGINX smoke orchestration.
- `ci/run-envoy-smoke.sh`, `ci/run-haproxy-smoke.sh`,
  `ci/run-lighttpd-smoke.sh`, and `ci/run-traefik-smoke.sh`: framework-owned
  runtime-smoke entrypoints for the new connector starters. They currently
  write BLOCKED evidence when the connector repository has only a harness
  contract and no executable runtime harness.
- `ci/run-connector-starter-checks.sh`: build/self-test starter evidence for
  Envoy, HAProxy, lighttpd, and Traefik. These results are not runtime-smoke
  evidence.

Full runtime evidence remains local through the Makefile smoke targets.
Apache and NGINX connector code comes from `connectors/apache` and
`connectors/nginx` by default; external connector repository fetches require
explicit opt-in.

Envoy, HAProxy, lighttpd, and Traefik runtime-smoke runners use local roots
only: `SOURCE_ROOT=/src`, `BUILD_ROOT=/src/ModSecurity-conector-build`,
`TMP_ROOT=$BUILD_ROOT/tmp`, `LOG_ROOT=$BUILD_ROOT/logs`, and
`RESULTS_DIR=$BUILD_ROOT/results` unless explicitly overridden to another
allowed path under `/src`. They do not perform global installations.

The HAProxy prepare helper may resolve the local HAProxy binary prerequisite,
but it does not execute SPOE/SPOA traffic and does not produce runtime-smoke
PASS evidence.

CRS runtime validation is variant-based:

- `MODSECURITY_TEST_VARIANT=no-crs` keeps the existing local case-rule behavior.
- `MODSECURITY_TEST_VARIANT=with-crs` injects `MODSECURITY_RULE_PREAMBLE_FILE`
  before generated local case rules.

The CRS repository URL, git ref, source path, and runtime path are defined only
in `ci/common.sh`.
