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

## Common-structure CI contract

The `test-common` workflow discovers the shared YAML corpus dynamically. It
requires a non-empty `tests/cases/**/*.yaml` corpus and a non-empty Apache
`common` selection from `case_cli.py list-cases` before materializing and
asserting every selected case. It intentionally does not treat a fixed total
number of YAML files as a contract: case YAML and runner discovery remain the
sources of truth as the catalog evolves.

Catalog-only cases whose metadata excludes them from the default runtime path
are filtered before runtime-only schema validation. Their dedicated catalog or
static checks remain responsible for their own contracts.

`make test-workflow-contract` is the focused local regression check for this
workflow contract. The workflow itself remains the end-to-end control because
it exercises discovery, materialization, fixture creation, and status
assertions with the current catalog.

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

## Protocol target contract

The public targets `make protocol-client`, `make check-protocol-evidence`, and
`make check-transport-hardening-evidence` keep their hyphenated compatibility
names. Their default tools are respectively
`ci/checks/protocol/protocol_client.py`,
`ci/checks/protocol/check_protocol_evidence.py`, and
`ci/checks/evidence/check_transport_hardening_evidence.py`.

`protocol-client` exits `2` when `PROTOCOL_URL` is absent (and strict evidence
also requires `PROTOCOL_FOLLOWUP_URL`). `check-protocol-evidence` exits `2`
when `PROTOCOL_ARTIFACT_DIR` is not a directory, and
`check-transport-hardening-evidence` exits `2` when `CONNECTOR` is absent.
After those guards, the existing runner or checker reports its own evidence
result. `make test-makefile-contract`, also run by `make lint`, statically
requires every Makefile-referenced local Python or shell script to exist.

This contract proves only target-to-tool resolution. H1, H2, and H3 outcomes
still require the applicable client, host, and artifact prerequisites and are
reported separately as runtime evidence.

## CRS source provenance contract

`make test-crs-provenance-contract`, which is also part of `make lint`, runs
the real CRS provisioning boundary against a temporary fake Git executable and
exercises the update decision with a fake GitHub release client. It verifies
that mutable tags, branches, ref namespaces, short hashes, and an unrelated
full hash are rejected before Git use; that the reviewed full commit provisions
only a fresh checkout and a pre-existing source path is rejected before Git
use; and that a mismatch in the fetched, resolved, or final `HEAD` stops before
submodule processing. A newer upstream tag is reported as `unknown`
with no automatic update: changing the release tag and immutable commit remains
a reviewed provenance change. It requires no network or connector runtime and
proves the provisioning identity control only, not a CRS runtime support claim.

## ModSecurity v3 source provenance contract

`make test-modsecurity-v3-provenance-contract`, also run by `make lint`,
executes the real V3 fetch and direct-build boundaries against a temporary fake
Git executable. It verifies that mutable refs and differing non-empty legacy
aliases are rejected, while empty aliases normalize to reviewed metadata; it
also rejects a foreign origin, mismatched fetched/resolved/checked-out commits,
pre-existing fetch paths, `.gitmodules`, and Gitlinks are rejected. It also
proves that Apache, NGINX, and the standalone V3 builder stop an existing
unapproved checkout before copy or build commands run. The legitimate control
uses an approved fake checkout and a minimal local build fixture; it has no
network access, initializes no submodules, and does not make a connector
runtime support claim.

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
