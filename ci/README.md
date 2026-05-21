# CI

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
- `ci/doctor.sh`: local prerequisite/readiness diagnostics.
- `ci/run-connector-smokes.sh`: local Apache+NGINX smoke orchestration.

Full runtime evidence remains local through the Makefile smoke targets.
Apache and NGINX connector code comes from `connectors/apache` and
`connectors/nginx` by default; external connector repository fetches require
explicit opt-in.
