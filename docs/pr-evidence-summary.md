# PR Evidence Summary

**Language:** English | [Deutsch](pr-evidence-summary.de.md)

Status: implemented

This repository packages the current evidence/validation framework for two
active ModSecurity review topics:

- ModSecurity PR #3564: RAW argument collections for URL-encoded parameters.
- ModSecurity-nginx PR #377: Phase-4 / `RESPONSE_BODY` handling.

The framework is intentionally evidence-first. It records what was observed
through real connector paths and keeps unsupported or unstable behavior mapped
or non-promoted instead of reporting fake PASS results.

## Real-World Connector Path

Connector PASS means the request traveled through this full path:

```text
Client -> Apache/NGINX -> connector module -> libmodsecurity -> rule variables -> HTTP response
```

The connector-free API smoke under `src/v3-api-smoke/` is useful API evidence,
but it is not counted as Apache or NGINX connector proof.

## Evidence-Scoped Variables

Connector summaries may list these variable families in `verified_variables`
when passing real-world Apache and NGINX cases support them:

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

`RESPONSE_BODY` is not verified. The blocking case remains non-promoted/mapped-only because
the dedicated probe has not produced stable HTTP 403 through both connectors.
Default smoke PASS evidence, force-all runtime-matrix evidence, mapped-only
inventory, former expected-failure probes, and API-only smoke evidence remain separate.

## PR #3564: RAW Argument Collections

Public source: https://github.com/owasp-modsecurity/ModSecurity/pull/3564

The PR introduces these RAW URL-encoded argument collections:

- `ARGS_RAW`
- `ARGS_GET_RAW`
- `ARGS_POST_RAW`
- `ARGS_NAMES_RAW`
- `ARGS_GET_NAMES_RAW`
- `ARGS_POST_NAMES_RAW`

The public PR description states that RAW values are captured before
libmodsecurity URL decoding and that existing decoded `ARGS*` behavior remains
unchanged.

Current local evidence:

- `<workspace>/ModSecurity_V3` is still the observed `v3/master` local
  reference.
- A search of that local source found no RAW collection implementation or
  regression files.
- The former `ci/check-raw-args-support.sh` helper performed the same
  read-only check for the configured `MODSECURITY_V3_SOURCE_DIR`; it is no
  longer an active repository command.  Before promoting RAW support, inspect
  the configured source and retain the command and output as run evidence.
- Therefore RAW collections are classified as `mapped-only` /
  `unsupported-local-source` in this repository.

Detailed RAW status is maintained in `docs/raw-args-pr3564.md`.

Promotion rule:

1. A configured `MODSECURITY_V3_SOURCE_DIR` must contain RAW collection support.
2. Source-derived YAML cases may then be added for each RAW collection.
3. Cases count as active PASS only after Apache and NGINX both return the
   expected real HTTP behavior through `make smoke-all`.

## PR #377: RESPONSE_BODY / Phase 4

Public source: https://github.com/owasp-modsecurity/ModSecurity-nginx/pull/377

The PR documents configurable Phase-4 handling modes, late-intervention
constraints after response headers/body may already be sent, and structured
Phase-4 logging. This matches the framework's current decision not to treat a
Phase-4 rule match as connector PASS unless the client observes the expected
HTTP result.

Current local evidence:

- `tests/cases/response/body/response_body_basic_block.yaml` is the explicit
  derived non-promoted probe.
- `make probe-response-body` runs the non-promoted case through Apache and NGINX.
- The last documented probe kept the case non-promoted/mapped-only:
  - Apache returned HTTP 200 without the required audit evidence.
  - NGINX showed Phase-4 match evidence but did not return stable HTTP 403 to
    the client.

`RESPONSE_BODY` must stay out of `verified_variables` until both connectors
produce stable HTTP 403 for an active common case.

## Reproduction

```sh
BUILD_ROOT=/src/ModSecurity-test-Framework-build make lint
BUILD_ROOT=/src/ModSecurity-test-Framework-build make smoke-all
BUILD_ROOT=/src/ModSecurity-test-Framework-build make probe-response-body || true
```

Results are written under:

- `$BUILD_ROOT/logs`
- `$BUILD_ROOT/results`
- `$BUILD_ROOT/apache-runtime`
- `$BUILD_ROOT/nginx-runtime`
- `$BUILD_ROOT/response-body-probe`
