# Testing and evidence

**Language:** English | [Deutsch](testing-and-evidence.de.md)

This guide defines the Framework testing workflow and the boundary between a
test result, a generated report, and promotable connector evidence. It does not
claim connector support that has not been observed through the relevant host
path.

## Test layers

| Layer | Purpose | Evidence boundary |
|---|---|---|
| Static checks | Syntax, schemas, links, variables, and local contracts | No runtime support claim |
| Catalog checks | Case selection and No-CRS schema validation | No host execution claim |
| Starter checks | Build or self-test prerequisites | Never a connector-runtime PASS |
| Runtime smoke | Real host request through the connector | Observed host evidence only |
| Generated reports | Reproducible rendering of current inputs | Reporting, not promotion |

`PASS` and `FAIL` describe observed results. `BLOCKED` describes a missing
environment, dependency, harness, or runtime prerequisite. `NOT_EXECUTABLE`
means a case does not apply structurally to that connector or run mode. Neither
state is a PASS.

## Recommended workflow

Run checks from the Framework checkout or through the connector repository with
explicit integration paths:

```sh
make setup-dev
make lint
make check-no-crs-catalog
make check-documentation
make quick-check
make check-test-matrix
```

Use a writable build and temporary location outside Git. The central
[variables and placeholders](reference/variables.md) define `FRAMEWORK_ROOT`,
`CONNECTOR_ROOT`, `BUILD_ROOT`, `SOURCE_ROOT`, `TMP_ROOT`, `LOG_ROOT`, and
`EVIDENCE_ROOT`, including ownership and safety rules.

Full connector validation is explicit:

```sh
make smoke-all
make runtime-matrix
make runtime-matrix-all
make test-no-crs
make test-with-crs
```

Quick checks are useful feedback, but they do not replace a real connector
smoke. A successful source build alone is not a lifecycle, response-body, or
production-readiness claim.

## No-CRS and full-lifecycle evidence

The canonical No-CRS implementation is
`ci/checks/catalog/no_crs_baseline.py`. Its `select`, `init`, `finalize`,
`validate`, and `summarize` operations keep selection, canonical artifacts,
and validation separate.

The evidence path records only reviewed, normalized metadata. It rejects
unbounded request or response payload fields and does not derive a PASS from an
exit code. Capability declarations and generated reports do not substitute for
an observed result. P1–P4, Phase-4-safe handling, first-byte timing, and
no-full-response-buffering assertions remain subject to their explicit
validator inputs and promotion policy.

`RESPONSE_BODY` is intentionally non-verified and non-promoted unless the
required stable connector evidence exists. A pass-through response, a
late-intervention log, an empty reply, or a source-derived upstream test is not
by itself response-body blocking proof.

## Case variants and imports

The `no-crs` variant materializes local rules only. The `with-crs` variant
loads the configured Core Rule Set before local case rules. Optional MRTS input
uses `MODSECURITY_MRTS_VARIANT` and appends generated case roots only for the
selected MRTS run. Feature-demo material remains explicit opt-in and does not
promote a result merely by being present in a report.

See [catalog and cases](catalog-and-cases.md) for schema, provenance, status,
and capability rules.

## Generated reports

The report generator owns the generated outputs below `testing/generated/` and
the Framework root coverage summary. Do not edit any generated file manually.
Refresh through:

```sh
make refresh-framework-reports
make check-test-matrix
```

The current entry report is
[test coverage overview](testing/test-coverage-overview.md). The detailed
[case matrix](testing/generated/coverage/case-matrix.generated.md) and
[runtime matrix](testing/generated/runtime/runtime-matrix.generated.md) retain
the reproducible detail that older manual matrices duplicated.

## Privacy and security

Tests, normalizers, and report writers must keep request and response payloads
out of canonical event and decision metadata. Logs may carry reviewed hashes,
sizes, truncation information, identifiers, phase, status, and host-version
metadata where the schema permits them. Redaction and control-character safety
are required before evidence is promoted.

Hash-chain data is useful smoke tamper detection only. Durable tamper
resistance requires connector-owned key handling, signatures or HMACs, and
appropriate storage controls.

## Historical context

Earlier testing guides, import maps, response-body investigations, and
per-PR plans were consolidated here. Their detailed historical observations
remain in Git; current claims come from the executable catalog and current
generated evidence.
