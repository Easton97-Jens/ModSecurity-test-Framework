# Roadmap

Status: current evidence-based framework roadmap snapshot

This framework roadmap tracks reusable YAML cases, runners, normalizers, and
reporting behavior. Connector pass/stability claims belong to connector
repositories and must be backed by real-world connector summaries.

## Current Focus

- Keep YAML case discovery, capability metadata, and generated reporting
  aligned with connector-owned runtime summaries.
- Preserve strict separation between API-only evidence, default connector
  smoke evidence, force-all runtime-matrix evidence, mapped-only inventory,
  xfail probes, and blocked cases.
- Keep `RESPONSE_BODY` non-verified/non-promoted until both Apache and NGINX
  prove stable real HTTP blocking for the same YAML case.
- Keep RAW argument collection cases mapped-only until local ModSecurity v3
  source support for PR #3564 is present and both connectors pass.

## Implemented

- YAML case corpus, runner core, connector-facing CLI, normalizers, and
  generated report scripts.
- Capability validation/normalization for multipart, files, XML, JSON,
  response body, audit log, collections, operators, transformations, actions,
  rule parser, transaction lifecycle, and pass-through metadata.
- Runtime status model that keeps `pass`, `fail`, `blocked`, `xfail`, and
  `skipped` distinct from import/classification status.
- Real-world connector metadata fields for Apache and NGINX summaries:
  `status_model`, `origin_model`, `intervention_model`, `connector_path`,
  `validation_mode`, `audit_behavior`, and `verified_variables`.
- Generated coverage reports for 140 YAML cases, 80 xfail cases, 10 mapped-only
  import inventory entries, 11 connector-gap cases, 13 runtime-difference
  cases, and 24 `RESPONSE_BODY` cases.
- Case matrix, runtime matrix, xfail, connector-gap, phase coverage, and
  coverage summary generation.
- Connector-free libmodsecurity v3 API smoke source and documentation, kept
  separate from connector proof.
- Framework docs for YAML schema shape, shared fixtures, case matrix, fast
  checks, compatibility evidence, response-body blocking, PR #377, and
  PR #3564 RAW argument evidence.

## Next Milestones

- Promote the documented YAML shape into a machine-readable schema after the
  current field set and connector-specific extension rules settle.
- Add portable fixture support for external files, schema/DTD/XML assets,
  file-backed operators, binary/NUL payloads, and larger response fixtures.
- Improve stable audit-log parsing and section-aware assertions while avoiding
  volatile values.
- Keep `make runtime-matrix-all` evidence visible without auto-promoting xfail,
  future, connector-gap, runtime-difference, or response-body pass-through
  cases.
- Add clearer support for connector config-test cases that cannot be expressed
  as plain HTTP smokes.

## Later / Deferred

- HAProxy, Envoy, Lighttpd, and Traefik remain deferred to connector projects
  until Common metadata and harness behavior are stable.
- HTTP/2, streaming, large body/response, CRS comparison, performance, and
  graceful-restart scenarios remain later coverage work.
- Dedicated API-only smoke target expansion remains separate from connector
  proof.

## Blocked / Waiting On

- `RESPONSE_BODY` blocking waits on stable Apache and NGINX real-world HTTP 403
  behavior for the same YAML probe.
- RAW argument collection waits on PR #3564 support in the configured local v3
  source plus Apache and NGINX connector passes.
- XML schema/DTD, malformed multipart, file-backed operator, binary/NUL, HTTP/2,
  and streaming cases wait on explicit fixture and transport support.
- `v3_action_nolog_pass_no_audit` remains xfail while local and GitHub Actions
  audit-log behavior differs.

## Unknowns / Design Decisions

- Whether the machine-readable YAML schema should be JSON Schema, a custom
  validator, or both.
- How to model connector-specific YAML extensions without contaminating common
  cases.
- How to represent empty replies, already-sent headers, and late response-body
  interventions in stable result assertions.
- Which audit-log fields can be made stable across local and GitHub Actions
  environments.

## Recommended Next Actions

- Run connector-owned `make lint`, `make summary`, and `make case-matrix` after
  case or metadata changes.
- Run connector-owned smoke targets before changing PASS/FAIL language in
  connector status docs.
- Keep connector generated reports and the framework-owned root
  `TEST-COVERAGE-SUMMARY.md` refreshed through the connector
  `make generate-test-matrix` / `make check-test-matrix` flow.
- Keep `RESPONSE_BODY`, RAW-ARGS, mapped-only, xfail, blocked, connector-gap,
  and runtime-difference cases visibly separated in summaries.
