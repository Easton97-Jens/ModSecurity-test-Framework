# Development and test repairs

**Language:** English | [Deutsch](20261122-01-development-test-repairs.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261122-01-development-test-repairs |
| UTC date | 2026-11-22 |
| Framework base revision | bcf4ab233fcb6394c235ea7069d5cde8c06e34f6 |
| Issue or pull request | Framework branch `codex/devtest-report-repairs-20261122`, follow-up to devtest-20261119T093840Z |

## Motivation and problem statement

The development run exposed missing No-CRS library provisioning, unresolved
smoke-test inputs, and missing HAProxy case-to-event identity. It also exposed
missing local provisioning opt-ins and a shared Apache build output path.

## Affected components and security boundaries

Framework owns the composite action, test harnesses, evidence metadata, and
local prerequisite resolution. Evidence publication still requires the
existing projection and binding policy. Local CI preparation uses the existing
runtime build and download opt-ins and selected component provenance.

## Acceptance criteria

Use a prepared libModSecurity snapshot for every fixed CI row. Resolve the
Envoy launcher from the selected Parent. Give both configuration checks a
usable fixture when no explicit configuration is provided. Bind successful
HAProxy No-CRS results to the observed transaction. Keep compiler output under
the selected build root by default and clearly label blocked optional lint.

## Alternatives considered

The Framework composite owns the provisioning and config stages. A Parent
workflow override would duplicate their runtime context. Changing the
collector allowlist would undermine case-to-event identity validation.

## Implementation decision

The composite selects a connector-specific or shared provisioning target and
exports the engine prefix and its header and library directories. The validator
binds the exact current action bytes to the immutable migration baseline. The HAProxy
harness binds a single observed ID to the completed request window for a
successful No-CRS case. The Envoy and Traefik stages preserve explicit caller
configuration. Optional C17 lint reports BLOCKED for an unavailable SDK.
Automatic local setup requires both existing opt-ins and uses a scoped target.

## Changed files and tests

- No-CRS composite action, exact source amendment and Framework CI common library.
- Envoy and HAProxy harnesses and runtime stage dispatcher.
- Make lint recipes and Apache C-standard check.
- Result identity regression, inventory digests and generated specialist archive.
- This English/German Change Record pair.

## Commands and results

| Command or check | Exit code | Result |
| --- | --- | --- |
| `make check-apache-c17` | 0 twice | Compiler output verified in the default and override locations |
| `sh -n` and `git diff --check` | 0 | Changed shell scripts and patch whitespace checked |
| No-CRS composite offline test with controlled provisioning | 0 | All five rows export the engine inputs. Invalid or missing snapshots block execution |
| Focused result identity unittest | 0 | Captured case bound. Foreign and ambiguous records rejected |
| Config-stage dispatch and native config parsers | 0 | Rule selection and private config checked. Envoy ext_authz, Envoy ext_proc and Traefik accepted the smoke rules with existing binaries |
| `update-inventory-bindings.py --apply` and `update-test-archive.py` | 0 | Seven source digests refreshed and archive regenerated |
| `make check-active-inventory` | 0 | Admitted 100 active cases. The specialist archive matches the source inputs |
| `make check-canonical-common-pins` and three focused action-integrity tests | 0 | Exact action accepted. Wrong baseline and modified checkout/bootstrap checks rejected |

## Security impact

The harness matches only a transaction observed inside the verified case
window. Required evidence and failure gates are preserved. The CI export is
limited to the pinned libModSecurity build paths.

## Documentation and runtime evidence

The linked English and German records describe the changes. The Envoy and
Traefik results prove configuration parsing. The Apache result proves C17 compilation.

## Checks not run

The full connector suite, hosted workflow, and new end-to-end HAProxy and Envoy
runtime checks require their respective authorized runtime context and inputs.

## Limitations and residual risk

The Parent still pins a previously published Framework revision. CI results
for this local repair are pending publication and pin synchronization. APR
and httpd library provenance are separate from supplying libModSecurity.

## Final diff and review status

Reviewed locally in an isolated Framework checkout for Draft PR delivery.
The linked Framework revision in Parent requires separate integration.
