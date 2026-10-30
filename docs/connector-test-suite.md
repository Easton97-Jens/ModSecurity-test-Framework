# Test ownership and the Framework interface

**Language:** English | [Deutsch](connector-test-suite.de.md)

The Framework owns the complete test implementation: Common and connector
unit, native, compile, integration, regression and E2E tests; fixtures and fault
modules; test adapters; selection and inventories; provisioning, orchestration,
collection, correlation, validation and report generators. This includes tests
of the Connector Makefiles, workflows and repository contracts.

The Connector owns productive Common and connector code, productive modules,
services and response companions, product configuration, build dependencies,
installation, packaging and deployment. Root/component Make targets and small
CI entrypoints call the pinned Framework. Product binaries do not load the
Framework. Productive Envoy launchers are in `connectors/envoy/scripts/`;
productive rule selection requires an explicit rules file.

The one-way dependency remains Connector → Framework. The Framework has no
Connector submodule. The MRTS tool remains pinned and read-only; Framework
package/import corrections have separate followup ownership.

## Source and selection contracts

`TEST_ROOT` selects the Framework checkout. `CONNECTOR_ROOT` selects the
product checkout; `CONNECTOR_REVISION` must match its exact Git HEAD.
`CONNECTOR_TEST_PROFILE` names the selected profile, and
`CONNECTOR_TEST_OUTPUT_ROOT` must already exist outside both checkouts, with
trusted non-symlink ancestry. Connector tests reject missing or invalid product
inputs. Framework-only self-tests do not require a Connector checkout.

The Framework's `connector_suite/config/testing/active-cases.json` is the
selection authority. Migration preserves the baseline **100 standard cases in
80 executions** and **1,893 retained on-demand cases in 839 executions**.
New migration regressions are explicit on-demand entries, separate from these
baseline counts. Inventory admission rejects more than 100 standard cases;
it never truncates selection. Definitions, selected cases, executions and
observed runs are different quantities. A retry is another attempt, not another
unique case. No archived campaign is activated by moving its files.

The final canonical inventory contains **100 standard
cases / 80 executions**, **2250 on-demand cases / 1029 executions**, **463 fixed
Framework test-source bindings** and **232 product-source snapshots**. Its compact
JSON is **2091364 bytes**, below the unchanged **2 MiB** admission limit. These are
selection/source quantities, not executed or passing case counts. The extension
adds 42 explicit on-demand methods: 28 clean-pair methods (including one actual
run still pending) and 14 MRTS-package methods; the original 1993-case baseline
remains unchanged.

The 120 new focused methods passed without skips, including the result-integrity
subset of 56 methods / 131 expanded variants and the closed path-policy subset
of 9 methods / 32 expanded variants. Separately, 136 focused portability methods,
330 native Framework CI methods, 30 public API methods and 3 Makefile methods
passed. The complete native Framework documentation target passed.

Seven repaired default case IDs passed through the public runner. The actual
public CLI foreign-UID/GID control passed both subcases in explicitly authorized
isolated execution. All nine Go executions passed. Seventeen native executions
remain blocked: 13 have validated missing host prerequisites, and 4 have verified
scanner-fixture prerequisites. The pin-sensitive standard Sonar check awaits
the final Connector pin. No prospective aggregate default-run PASS is claimed.

Schema 4 separates fixed Framework test-source hashes from
`connector_source_paths`. Product inputs are snapshotted from the explicitly
selected revision, included in the receipt, and rechecked before and after
execution. Changing a collector still requires a reviewed fixed digest.
Legacy schema-1/2/3 admission fixtures retain their strict hash semantics.
Product updaters do not modify the independent Framework inventory.

`connector_suite/source-map.json`, `migration-baseline.json` and `test-map.tsv`
record legacy source IDs, purposes, selectors, callers and new Framework paths.
The Python namespaces are `modsecurity_connector_tests`,
`modsecurity_connector_ci` and `connector_suite.adapters`. Go tests retain
package-private access through external overlays; product trees are not edited
to install tests. Native test translation units belong to
`connector_native_tests/`.

The migration-map generator now emits schema 3 with a per-Test-ID
`prerequisites` reference to an execution catalog. The TSV retains its original
seven columns and appends machine prerequisites plus readable tool, SDK, host,
profile, privilege, dependency, checkout and external-output columns. Actual
Parent root/component Make, Framework Make and `connector.mk`, CI/action,
Python-discovery, native C/C++, Go and Framework-selftest source routes are
recorded. A discovery candidate or bound source does not establish automatic
selection or observed execution. SDK/tool/host/privilege declarations retain
source locations and conditional or unresolved status; availability is not
inferred. Case-profile metadata is distinct from the runtime `--profile` input.

The same artifact maps five stable requirement IDs to current file ownership:
`migration.test-ownership`, `migration.shared-test-mechanics`,
`migration.mrts-separate-packet`, `migration.connector-thin-integration` and
`migration.clean-pair-integration`. The MRTS package packet belongs to a separate
Framework followup worktree/PR; `tools/MRTS` remains pinned and read-only. Its
nested-definition and validation-source guards, regression preservation and
Framework integration are traced separately from the tool repository. Generated
archive and map outputs match their frozen source inputs: both generator
`--check` runs passed, preserving all 1993 original case IDs. The canonical
inventory counts above describe selection, not successful execution.

## Invocation

This is a source-checkout interface. Its availability does not establish that
all migrated modules are included in the installable Framework package.
Python starts with `-P` and `PYTHONSAFEPATH=1`; only the Framework root and
`connector_suite/` belong in `PYTHONPATH`. Product sources are loaded through
scoped explicit interfaces.

From the Connector checkout, select the task's pinned Framework explicitly
when the environment still exports paths from another worktree:

```sh
FRAMEWORK_ROOT="$PWD/modules/ModSecurity-test-Framework" \
CONNECTOR_TEST_OUTPUT_ROOT="$EXTERNAL_OUTPUT" \
PYTHON="$FRAMEWORK_PYTHON" make check-active-inventory
```

The public source-checkout adapter also supports independent checkouts:

```sh
PYTHONSAFEPATH=1 PYTHONPATH="$FRAMEWORK_ROOT:$FRAMEWORK_ROOT/connector_suite" \
"$FRAMEWORK_PYTHON" -P -m modsecurity_test_framework.connector \
  --connector-root "$CONNECTOR_ROOT" --connector-revision "$CONNECTOR_REVISION" \
  --test-root "$FRAMEWORK_ROOT" --profile h1 \
  --output-root "$EXTERNAL_OUTPUT" --group inventory --check
```

Remove `--check` to execute the selected standard group. Additional inventory
cases require `--on-demand` and an explicit group/case/execution selector.
Named specialist interfaces additionally require `ON_DEMAND_TESTS=1`.
The flag does not authorize a broad historical campaign.

## Result integrity and host-specific contracts

Live case evidence binds run, case, request and source revision; host evidence
additionally requires an unambiguous host transaction. A request-local receipt
bounds log capture; a foreign or ambiguous transaction cannot enrich the case.
A completed request with a valid closed receipt may produce a typed client-only
`request_bound` observation with `transaction_id: null` and
`promotion_allowed: false`. This records the client response without inventing
a host transaction or promoting host capability. Observed client status stays
separate from intervention status. Write failures, missing mandatory rows and
empty required result sets fail the run. Executed Envoy traffic survives
assertion failure, including probes before the first catalog case, without
inventing case PASS.

Apache merges duplicate header occurrences before the adapter observes them.
The explicit `apache-native` rule materializer preserves the original wire
case, HTTP 200, rule `1100504` and its audit assertion, and records adaptation.
It does not weaken historical artifact-pinned overrides.

NGINX's two injected internal pointer faults require HTTP 500,
`phase1_error`, `MSCONN_EVENT_CONNECTOR_ERROR` and `reason=connector_error`.
Malformed client input retains HTTP 400 and its distinct protocol-error type.
This corrects stale test expectations; product fail-closed behavior is retained.

Protected brokers authenticate the protected Parent base and its exact
Framework gitlink before selecting privileged test code. Candidate Framework
content is not trusted code. Gate-required Parent paths remain small
authenticated entrypoints; the gate protocol and host permissions are retained.
Missing protected-host prerequisites remain blockers.

The latest bounded result-integrity run passed 56 methods / 131 expanded
variants. Three actual Apache H1 controls passed with HTTP 200 / 403 / 200
(allow, deny, duplicate header). The allow control used the client-only
`request_bound` observation above; it does not prove a host capability.
The NGINX H1 attempt was blocked with exit 77 because the required existing
runtime was unavailable; this is not a passing host run. These observations do
not qualify a complete H1 lifecycle or an installed protected-host gate.

Upstream [Framework PR #139](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/139)
and [Connector PR #432](https://github.com/Easton97-Jens/ModSecurity-conector/pull/432)
are already merged. The task incorporated Framework upstream base
`1d1e73fb069598e0f0f809d0bf16b5e59047ff88`, preserving task edits and backups
through three-way reconciliation. This upstream integration is separate from
delivery of the migration and MRTS-focused Framework packets.

## Integration and evidence

The clean-pair CLI verifies a committed Connector revision against its recorded
Framework gitlink by default. Both source repositories must contain the selected
Git objects. It creates clean local checkouts from those objects, verifies required
entrypoints and interfaces, invokes the actual Parent Make target
`test-framework-integration-probe`, and validates the exact admitted Common
header test result. The probe requires installed Git, Make, a compatible Python
and `cc`, plus existing private external output storage. Uncommitted source edits
are not copied into the pair. Source wiring and unit controls do not substitute
for a successful real-pair receipt; that positive run remains pending here.

```sh
PYTHONSAFEPATH=1 PYTHONPATH="$FRAMEWORK_ROOT:$FRAMEWORK_ROOT/connector_suite" \
"$FRAMEWORK_PYTHON" -P -m modsecurity_test_framework.connector_integration \
  --connector-source "$CONNECTOR_ROOT" --framework-source "$FRAMEWORK_ROOT" \
  --connector-revision "$CONNECTOR_REVISION" --output-root "$EXTERNAL_OUTPUT" \
  --python "$FRAMEWORK_PYTHON" --profile h1
```

A separately selected development revision uses the following explicit option.
Its receipt records `mode: development` and `standard_combination: false`; it is
separate from verification of the recorded-pin standard combination.

```sh
PYTHONSAFEPATH=1 PYTHONPATH="$FRAMEWORK_ROOT:$FRAMEWORK_ROOT/connector_suite" \
"$FRAMEWORK_PYTHON" -P -m modsecurity_test_framework.connector_integration \
  --connector-source "$CONNECTOR_ROOT" --framework-source "$FRAMEWORK_ROOT" \
  --connector-revision "$CONNECTOR_REVISION" --output-root "$EXTERNAL_OUTPUT" \
  --python "$FRAMEWORK_PYTHON" --profile h1 \
  --development-framework-revision "$(git -C "$FRAMEWORK_ROOT" rev-parse HEAD)"
```

A successful probe establishes repository-interface behavior for the actual Common case.
Hosted H1 and installed-gate qualifications require their own evidence.

Deliver Framework changes first and make their exact commit remotely
available. The dependent Connector PR updates its gitlink and full-SHA CI
references to that commit. Integrate the Framework PR before the Connector PR;
neither repository is merged automatically. HTTP/2, HTTP/3,
Coverage and complete dependency assessment remain outside this migration,
apart from required path/caller adaptations.

The paired change records distinguish executed checks, failures, blockers and
checks not run. A static check, native primitive test or product build does not
establish a hosted H1 lifecycle or a current-head promotion.
