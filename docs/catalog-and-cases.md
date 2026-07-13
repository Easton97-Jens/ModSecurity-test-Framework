# Catalog and cases

**Language:** English | [Deutsch](catalog-and-cases.de.md)

This is the maintained guide to the Framework case catalog. YAML cases and the
runner implementation are executable sources of truth; this document explains
their shared model without duplicating generated inventories.

## Sources of truth

| Area | Canonical source | Purpose |
|---|---|---|
| Case definitions | `tests/cases/**/*.yaml` | Rules, requests, expectations, metadata, and scope |
| Selection and materialization | `tests/runners/` | Schema validation, filtering, fixtures, and result normalization |
| No-CRS catalog | `ci/checks/catalog/no_crs_baseline.py` | Canonical selection and evidence contract |
| Current inventory | `testing/generated/coverage/case-matrix.generated.md` | Generated case snapshot |
| Current runtime view | `testing/generated/runtime/runtime-matrix.generated.md` | Generated observed-result view |

The repository does not treat a generated report, an upstream test, or a
starter check as a replacement for observed connector evidence.

## Case shape

| Field | Role |
|---|---|
| `name` | Stable case identity; paths may change without changing the identity |
| `metadata` | Scope, status, provenance, capabilities, and promotion boundaries |
| `rules` | Local ModSecurity rules materialized for the case |
| `request` | Method, path, headers, body, multipart data, and fixtures |
| `response` | Optional response fixture used by host harnesses |
| `expect` | Expected status and bounded response or audit assertions |
| `requires_crs` | Limits a case to the With-CRS variant when set |

Use `expect.variants.with-crs` only when the CRS runtime context changes an
assertion. Do not change the base No-CRS expectation to encode a With-CRS
exception.

## Selection, status, and promotion

| Status or property | Meaning |
|---|---|
| `active` / `imported` | Eligible for the relevant case selection; not an automatic PASS |
| `pending`, `future`, `connector-gap`, or `runtime-difference` | Visible in planning and generated reports, not a promotion |
| `mapped-only` | Provenance or design mapping without an executable case claim |
| `runtime_verified` | Evidence metadata; it changes only through the defined evidence path |
| `RESPONSE_BODY` | Non-verified and non-promoted until stable qualifying connector evidence exists |

Case directories organize discovery and reporting. They do not encode a PASS,
FAIL, or promotion state. Connector-specific cases belong below
`tests/cases/connector-specific/<connector>/`; common cases remain portable
only when their assumptions are actually shared.
A connector with no connector-specific YAML cases has no directory; its
absence is intentional and discovery contributes no connector-specific cases.

## Imports and provenance

| Source family | Current use |
|---|---|
| ModSecurity v2 | Semantic and regression reference for derived portable cases |
| ModSecurity v3 | Public API and regression reference for derived portable cases |
| ModSecurity-apache | Apache hook, build, and regression-reference material |
| ModSecurity-nginx | NGINX hook, filter, and regression-reference material |
| MRTS | Optional generated compatibility input; feature-demo remains opt-in |

Imported YAML records its source in metadata. Upstream harnesses, server
configuration, log formats, and files are not copied merely because a related
behavior is useful. A source-derived case becomes a portable assertion only
after its assumptions and observed host behavior are suitable for the selected
scope.

## Capabilities and normalized results

Capabilities describe exercised behavior, not entitlement to skip or promote a
case. The runner normalizes bounded result metadata so connector reports can
distinguish observed PASS, FAIL, BLOCKED, NOT_EXECUTABLE, and non-promoted
states. It does not infer support from an exit code, from a mapped upstream
case, or from a report row.

P1–P4 labels, body limits, phase ordering, first-byte timing, and
no-full-response-buffering claims remain evidence-scoped. Their exact
validation inputs and privacy requirements are described in
[testing and evidence](testing-and-evidence.md).

## Updating the catalog

1. Add or change the YAML case and keep its identity, provenance, scope, and
   expectation explicit.
2. Extend runner or normalizer code only when the case model requires it.
3. Run the catalog and documentation checks before treating a report as current.
4. Regenerate the matrix through its generator; never hand-edit a generated
   inventory.
5. Record a promotion only through observed connector evidence.

## Historical context

Earlier per-source maps, import plans, case matrices, and compatibility notes
were consolidated here. Git history retains their detailed chronology; current
generated reports retain the live, reproducible inventory.
