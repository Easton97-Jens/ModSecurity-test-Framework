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

## CI security evidence boundary

[CI security tooling](security/ci-security-tooling.md) validates workflow
provenance, permissions, static source quality, dependency metadata, and
scanner output boundaries. A local pass or a GitHub Actions result is static
CI evidence only: it does not demonstrate connector runtime behavior, protocol
handling, lifecycle promotion, or a host smoke. The SonarQube Cloud quality
gate remains separately observed external evidence for the exact pull-request
head.

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
use; that the exact reviewed release tag is fetched and must peel to that
commit; and that a missing, moved, fetched, resolved, or final `HEAD` mismatch
stops before submodule processing. A newer upstream tag is reported as `unknown`
with no automatic update: changing the release tag and immutable commit remains
a reviewed provenance change. It requires no network or connector runtime and
proves the provisioning identity control only, not a CRS runtime support claim.
The legitimate control accepts an absent manifest and the exact root empty
`.gitmodules` blob `e69de29bb2d1d6434b8b29ae775ad8c2e48c5391` only after
tree, index, worktree, Gitlink, local configuration, and registry checks. It
rejects non-empty, wrong-mode, symlinked, special, mismatched, nested, or
Gitlink-bearing states without invoking `git submodule`.
The same verifier runs in `prepare-crs.sh` immediately before it reads source
templates, rules, or plugins or writes runtime files. Therefore a replacement
after a successful fetch is rejected before source consumption; this remains a
provisioning-boundary result, not connector-runtime evidence.

## ModSecurity v3 source provenance contract

`make test-modsecurity-v3-provenance-contract`, also run by `make lint`,
executes the V3 fetch and direct-build boundaries against a temporary fake Git
executable where the topology decision needs controlled input, plus real-Git
fresh-root fixtures. It verifies that mutable refs and differing non-empty
legacy aliases are rejected, while empty aliases normalize to reviewed
metadata; it also rejects a foreign origin, mismatched
fetched/resolved/checked-out commits, pre-existing fetch paths, and every
missing, extra, origin- or commit-mismatched, symlinked, escaping, dirty, or
non-normal-index member of the approved recursive topology. It proves that
Apache, NGINX, and the standalone V3 builder stop an existing unapproved
checkout before copy or build commands run, and that the standalone build path
reaches the complete guard before it copies source. The legitimate fake control
uses the exact approved root and eight-child graph. Real-Git controls prove
that a fake earlier `PATH` Git is ignored, a symlinked fresh-root parent is
rejected before Git, `core.worktree` cannot redirect checkout writes, an
external attributes/smudge filter is not run, and a local custom
`submodule.*.update` setting is removed before recursion. The contract has no
network access, does not accept generic submodules, and does not make a
connector runtime support claim.

## No-CRS and full-lifecycle evidence

The canonical No-CRS implementation is
`ci/checks/catalog/no_crs_baseline.py`. Its `select`, `init`, `finalize`,
`validate`, and `summarize` operations keep selection, canonical artifacts,
and validation separate.

An NGINX `full_lifecycle` selection and its matching `init` require the
explicit downstream protocol (`http1`, `h2`, `h2c`, or `h3`). A case that
requires another protocol is `NOT_APPLICABLE` to that run; a capable build or
an HTTP/1 request is not H2/H3 execution evidence. The aggregate status uses
the plan's `SELECTED` cases for the missing-evidence gate, while the result
keeps truthful counts for every catalog record. An unexecuted selected case
still prevents PASS; FAIL and BLOCKED retain precedence. A non-selected
`NOT_EXECUTED` record alone does not prevent a scoped PASS.
Both commands take `--downstream-protocol`; this orchestrator-declared run
profile must match the executed host/client protocol and does not itself prove
negotiation. Explicit catalog `request.reuses` mappings may derive narrower
records only from validated live base evidence bound to the current run and,
where required, a uniquely matching canonical event; they do not create
another request or a synthetic runtime event.
Event-backed case claims also require the event phase to match the catalog
phase and any explicit event run ID to match the canonical run. These checks
apply during normalization, manifest binding, and completeness validation.
Native events that omit their optional run ID retain the existing run-local
source-file and transaction provenance contract.

### Configuration operations are not HTTP requests

The phase-0 `invalid_boolean` and `invalid_size` catalog records declare closed
NGINX configuration realizations. `invalid_boolean` uses one concrete NGINX
`configtest` realization: run the retained NGINX binary with `-t` against the
closed configuration containing `modsecurity maybe;`. The expected rejection
requires exit `1`, error class `invalid_boolean`, and both exact diagnostic
fragments `"modsecurity" directive` and `invalid boolean value`. A missing
module, another directive/error, exit `0` or another exit does not satisfy it.
Signed subprocess failures such as `-1` (execution error) and `-9` (termination)
can be retained as failure receipts; they are never expected-rejection PASS.
The stable Required ID `invalid_size` now explicitly tests rejection of the
removed API using its formerly valid input `modsecurity_phase4_body_limit 1048576;`.
It requires exit `1`, error class `removed_directive`, and the exact diagnostic
fragment `unknown directive "modsecurity_phase4_body_limit"`. The old size-parser
rejection, an unrelated error or a different unknown directive cannot fulfill it.
The four Engine response-limit cases and their Required contracts are unchanged.
These distinct contracts
cannot satisfy each other or authorize arbitrary phase-0 receipt-only PASS.

Canonical fulfillment requires the bounded `configtest_receipt` plus its
authorized retained bundle: `nginx-binary`, `nginx-module.so`, `nginx.conf`,
`stdout.log`, and `stderr.log`. Finalization obtains source authority from the
explicit source file's parent, rejects missing/foreign/symlinked artifacts,
and securely retains the five files under
`inventory/configtests/invalid_boolean` or
`inventory/configtests/invalid_size`, separately for each registered case.
Validation rehashes them, checks the
closed nonsecret configuration template and parser diagnostic, and binds the
receipt to the case, directive/value, run, connector/integration mode, source
revisions and binary/module identities. Receipt assertions or unit fixtures
alone do not constitute canonical runtime proof.

This pure configuration test requires neither HTTP nor a fabricated native
event, rule match or transaction ID. It does not prove daemon startup, an open
listener, Root/nobody workers, reload, or a request; those facts remain false
unless separately observed. Request cases retain their existing HTTP/event
requirements, and the global full-lifecycle PASS gate is unchanged.

The public API's connector-scoped `configuration` tagged expectation checks
only a complete bounded operation observation against the declared NGINX
operation. It is not proof that the operation actually ran. Other connector
observations fail that concrete expectation; portable catalog applicability
and selection remain unchanged. The other eight configuration-related required
records have no implemented configuration realization in this slice and are
not converted to PASS or excluded from required coverage.

A retained-build local diagnostic, `nginx-configtest-retained-jaYdBrvH`,
executed the real NGINX binary/module and the actual collector/canonical
finalizer. The positive `invalid_boolean` case became canonical PASS; a
wrong-module control remained FAIL although both NGINX invocations exited `1`.
Both canonical bundles rehashed correctly with zero managed-layout errors.
There were zero events and no HTTP, daemon-start or listener claim. Both
source and canonical aggregates remained FAIL because required requests were
not executed. This is retained-build diagnostic evidence, not a new
Exact-Head full-lifecycle proof.
See the [configuration evidence Change Record](../reports/audits/change-records/20261001-02-nginx-configtest-evidence.md).

The subsequent local diagnostic `nginx-config-size-retained-6si2byjk` ran the
real producer, collector and canonical finalizer for `invalid_size`: the
expected size rejection produced individual PASS; the wrong-module control
remained FAIL although both invocations exited `1`. Both retained five-file
bundles passed all eight canonical validators. Both aggregates remained FAIL,
with no startup, requests or events. This precommit source-dirty diagnostic
uses retained cached C artifacts, not a new Exact-Head build or full E2E.
See the [size contract Change Record](../reports/audits/change-records/20261003-01-nginx-size-configtest.md).

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

## Five-connector With-CRS / No-MRTS evidence contract

`ci/checks/catalog/five_connectors_with_crs_no_mrts.py` defines the separate,
fail-closed profile `five-connectors-with-crs-no-mrts`. Its closed inventory is
exactly Apache, HAProxy, Envoy, Traefik, and lighttpd, in that order. NGINX is
excluded from this profile only; it remains part of the general six-connector
boundary and its other assessment obligations.

The canonical fixture is
`tests/cases/security/crs/crs_sqli_anomaly_block.yaml`. It binds the allow
control (`200`) and SQL-injection block (`403`, intervention `deny`) to the
canonical CRS rule `942270`, using the `CRS_GIT_REF` and
`CRS_APPROVED_COMMIT` tuple from `ci/lib/common.sh` and the pinned
`rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf` digest. The fixture does not
define a local substitute rule. Its fresh source must retain the canonical tag
ref and that tag must peel to `CRS_APPROVED_COMMIT`.

| Connector | Closed adapter identity | Contract mode | Accepted raw evidence |
| --- | --- | --- | --- |
| Apache | `apache-native-httpd-module` | `native-httpd-module` | audit |
| HAProxy | `haproxy-spoe-spop-agent` | `spoe-spop-agent` | event |
| Envoy | `envoy-ext-proc-service` | `ext_proc` | event |
| Traefik | `traefik-native-middleware` | `native-traefik-middleware` | event |
| lighttpd | `lighttpd-patched-native-module` | `patched-native-lighttpd` | audit or event |

These are closed evidence identities. The listed Framework smoke entrypoints
are marked `compatibility-only` and owned by the Parent host contract, so they
cannot be relabelled as native host execution or used to promote this profile.

For HAProxy, the selected Framework entrypoint
`ci/runtime/run-haproxy-smoke.sh` dispatches the connector-owned SPOE/SPOP
smoke harness. Therefore this profile accepts only
`haproxy-spoe-spop-agent` with `spoe-spop-agent`. The genuine separate
full-lifecycle identity `haproxy-native-htx-filter` with
`native-htx-filter` is retained unchanged for its native HTX path, but it has
no Framework smoke entrypoint and is not accepted as evidence for this
profile. A legacy five-connector event carrying the HTX tuple must be
regenerated from the actual SPOE/SPOP path; the native HTX identifier itself
is not renamed or promoted. The profile payload records this as an explicit
`reject-and-regenerate` identity migration, not as a compatibility alias.

The catalog tool has four distinct operations:

```sh
python ci/checks/catalog/five_connectors_with_crs_no_mrts.py profile
python ci/checks/catalog/five_connectors_with_crs_no_mrts.py verify-fixture --source-root <fresh-source-root>
python ci/checks/catalog/five_connectors_with_crs_no_mrts.py validate --evidence-root <private-root> --source-root <fresh-source-root> --connector <fixed-connector> --run-id <id>
python ci/checks/catalog/five_connectors_with_crs_no_mrts.py aggregate --evidence-root <private-root> --source-root <fresh-source-root> --run-id <id>
```

`validate` accepts only one member of the closed set and hash-addressed,
host-provided raw evidence plus non-mutating normalized evidence. It requires
both correlation identities, the pinned CRS identity, an allow control, the
observed `942270` deny result, the closed No-MRTS fields, and completed
cleanup. `aggregate` accepts exactly one validated same-run bundle for each of
the five connectors and refuses a partial, duplicate, or NGINX-containing
inventory. The evidence root must be private and outside the checkout; result
paths are never overwritten.

The four raw inputs have fixed, run-bound locations for host configuration,
the allow request, the block audit, and cleanup. They are parsed as strict
key/value records and are hash-bound to the normalized event. `validate` and
`aggregate` derive the Framework revision from a clean verifier checkout
rather than accepting a caller-supplied commit argument. Their successful
outputs are `CONTRACT_VALIDATED` with `host_runtime_status: UNATTESTED`, never
a connector-host `PASS`.

The focused local regression check exercises fixtures, schemas, closed-set
rejection, provenance binding, receipt validation, and negative cases. Neither
that check nor any catalog command starts a connector host, proves a five-host
runtime success, proves production readiness, or proves a real MRTS process
state. A later connector-owned run must supply its own host and lifecycle
evidence before any runtime claim can be made.

## Case variants and imports

The `empty_header_value` No-CRS runner requires a present `X-No-Crs-Empty`
header with an empty value. Rule `1100503` first checks that exactly one such
header exists, then chains an empty-value match. HTTP `200` alone or an absent
header cannot fulfill the rule/event expectation. Its catalog selection
capabilities remain `request_headers` and `phase1`; no required case is
excluded to reduce coverage. The unchanged normalizer additionally requires
the real phase-1 native event for that rule. Curl-based host drivers must use
the client's explicit empty-header notation rather than its suppression
notation. Host behavior and full exact-head promotion remain Parent-owned.
See the [empty-header runner Change Record](../reports/audits/change-records/20261001-01-empty-header-runner.md).

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
