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
cases / 80 executions**, **2307 on-demand cases / 1042 executions**, **492 fixed
Framework test-source bindings** and **234 product-source snapshots**. Its compact
JSON is **2085028 bytes**, below the unchanged **2 MiB** admission limit. These are
selection/source quantities, not executed or passing case counts. The extension
adds 55 explicit on-demand methods: 28 clean-pair methods, 14 MRTS-package
methods, 3 classification guards, 2 prepared/backend helper methods, 4 context
methods, 2 sealed-invocation methods, 1 collector method and 1 SDK method; the original 1993-case baseline remains
unchanged. A closed reviewed set of 155 process-bearing new rows uses the
`migration-integration` group across 12 modules with target-derived ID hashes;
48 pure controls retain the offline-audit group. The original 1993 group
assignments and guard-function ASTs are unchanged; the initial 40 pure controls, both pure helper methods and four guarded context methods passed.

The 120 new focused methods passed without skips, including the result-integrity
subset of 56 methods / 131 expanded variants and the closed path-policy subset
of 9 methods / 32 expanded variants. Earlier scoped runs passed 136 focused portability methods,
30 public API methods and 3 Makefile methods. Current local native Framework CI
passed 330 tests in 163.868 seconds; the exact workflow Ruff lint/format checks
passed all 38 files in 0.104 seconds, and 19 Sonar-contract methods passed in
4.836 seconds. These local results do not establish hosted current-head gates. The complete native Framework documentation target passed.

Seven repaired default case IDs passed through the public runner. The actual
public CLI foreign-UID/GID control passed both subcases in explicitly authorized
isolated execution. All nine Go executions passed. The latest observed ledger
contains 67 passing and 13 blocked standard executions, covering 74 passing and
26 blocked unique cases. The four scanner fixtures and the pin-sensitive Sonar
check passed on targeted reruns; the 13 host/profile prerequisites remain blocked.
These observations span source revisions and do not constitute one complete
standard run on a future final pair.

The authenticated Parent bridge exposes the standalone `connector-context`
CLI through `ci/run-trusted-framework.py --tool connector-context`. It replaces
22 local context-action uses in 9 workflows while retaining authentication and
privilege guards. Four newly registered guarded pure methods cover 15 expanded
cases; source closure follows actual imports and public entrypoints. This adds
no default case and no global Product import path.

The current working bridge delegates raw Git object identity to fixed,
unprivileged `git hash-object --no-filters`; the local Git build was verified
to use SHA1_DC. This does not establish every host's cryptographic build or
SHA-256 Git identity. Immutable byte checks retain SHA-256. A sealed, owned JSON
memfd carries the source filename and exact argv; the fixed interpreter command
contains only owned descriptors. Exact main/exit-status behavior, UID guards and
the cells API remain intact. Two separately registered process methods cover
six exact-argv round trips and eight named invalid-descriptor/envelope cases.
The Product component-basename identity guard and dead-branch specialization
preserve the authentication walk and digest checks. Updater CLI bootstraps use
one fixed eight-name compatibility export registry, and the workflow updater
uses one Framework-path constant.
ASCII JSON escaping preserves valid POSIX surrogate-escaped arguments;
the sixth argv case is separately registered. Collector metadata uses
exact binding pairs separately from payload arguments; one new pure method
declares five cases without adding a snapshot helper.

Fresh native capture compiled all 81 translation units in 35.853 seconds
with actual SDK `ALL_INCS` and mapped header inputs, without drift. Eight
SDK admission controls before recipe import and 19 native Sonar-contract
methods passed; the original 18 method ASTs remain exact. Four new fixed
source bindings have precise physical Framework owners. The closure retains
eight observed, two semantic and two public-entry dependencies; source
bindings were not globally pruned. Fresh canonical security verification passed
69 methods / 257 observed subcases in 10.939 seconds, with no skips or source
drift, against working bridge SHA-256
`1ef4d6fb021605f52c63fef3bf522a325736ceb40457d48c94c091b1e3efc5eb`.
This includes the separately registered sixth surrogate-escaped argv case.
Final public selector reruns remain pending.

CI triage identified three separate migration causes: NGINX's second
`sudo`/`env -i` boundary loses the trusted Run ID; Envoy CRS supplies duplicate
`run_id`; and migrated import-status reads and fingerprints still select an
old Product path. The required repairs preserve the trusted Run ID across the
second boundary, remove the duplicate without changing the strict parser, and
use the selected Framework owner for both import-status operations. Bounded
harness validation passed 42 methods in 9.615 seconds (14 NGINX, 28 Envoy): the
closed second boundary preserves the ID and rejects malformed input; all three
actual Envoy summary blocks contain one ID, and injected duplicates and
mismatches fail closed. Seventeen existing native-generator methods passed in
0.138 seconds. The actual selected Framework manifest reports 80 `former_xfail`
and 10 `mapped_only` entries; read and fingerprint SHA-256 match, and private
Framework/Product-decoy and existing `framework:` resolver controls passed.
These are local boundary and generator proofs, without a live-host run. The
published `5d471`/`a209` pair remains the earlier scoped proof; current working
heads are not yet published and require renewed committed-pair acceptance and
hosted gates. No fresh default-suite run or hosted Sonar PASS is claimed.

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
Framework integration are traced separately from the tool repository. At their recorded source freeze,
archive and map outputs were regenerated in that order and both generator
`--check` runs passed, preserving all 1993 original case IDs. Binding
`--check` and public CLI inventory admission also passed at that freeze. The
latest four-method context-closure registration is a separate source receipt. The canonical
inventory counts above describe selection, not successful execution.


Current integration also incorporates Connector master `ee134` from
[Connector PR #433](https://github.com/Easton97-Jens/ModSecurity-conector/pull/433)
through the ordinary merge `8c7e8c44`. All 1993 latest-master baseline case
objects exactly match their Framework counterparts. Initial immutable baseline
identities remain separate from this later integration.

The separately published MRTS-package correction `197df49` passed 99 methods
in 73.152 seconds; independent definition walking and file-descriptor parity
checks passed. This changes Framework packaging and guards, with `tools/MRTS`
pinned and read-only. The latest native Framework CI run passed 339 methods in
162.706 seconds. Actual bounded runs also passed 54 Common controls, 29 portable
controls, 23 CRS controls and 13 launcher controls. These are separate suites;
their counts are not added to unique inventory case totals.

All native Framework lint recipe stages have passing observations across the
retained full invocation and focused repairs/resumes. The original single full
invocation remains recorded with exit 2; this is not one full green lint run.
Separately, 66 security methods / 238 subcases passed without skips. Runtime-root
ownership, missing run IDs and namespace fixes have a bounded 34-control
HAProxy/Lighttpd PASS. The fresh Envoy suite passed all 28 original methods in 9.446 seconds,
preserving every method ID and assertion count. After the minimal Product
recipe-fallback correction, four actual `make -n` controls passed: default,
`MS` fallback, explicit `RULES` precedence and companion conflicting `RULES`/`MS`. The Product status
Change Record pair now passes the actual Parent whole-archive structural check;
that check does not establish its runtime or CI claims.

The minimal NGINX configure probe passed with checksum-verified existing archives;
the SDK correction uses the actual `BUILD_ROOT` SDK with explicit include/library
paths. C-family source bytes remain identical, so no repeated 81-unit capture
is claimed for that correction.
11 existing context tests and four CLI negative controls also passed. Configure
success establishes this build/configuration layer, not a runtime lifecycle.
The actual C-family capture completed twice after decomposition: 81 translation
units produced 81 unique objects, passing in 38.241 and 37.935 seconds. These are
translation units and objects, not test methods or extra selected case IDs.
The exact standard distribution is 76 C17, 4 C++17 and 1 original smoke C99
translation unit. Every compiler command retains `-Wall -Wextra -Werror` and no
`-Wno` option; the original smoke standard is unchanged. HAProxy/Lighttpd generated includes use the same
maintained original translation units and exact Product extractions in actual
tests and capture. All 28 existing builder test-method ASTs and native function
bodies are preserved; five former comment markers now contain real includes.
The final exact-source-hash capture after AST-identical formatting and admission
repair also passed all 81 units in 36.126 seconds. Independent review passed
eight tests and reviewed all 81 objects.

The Sonar workflow Product analysis input must use compatible published migration
commit `cfd5e49cada3fc793ef50993147e3796a0907443`. Pre-migration `ee134` contains
duplicate test helpers and is unsuitable for this combined analysis. Selection
does not use a Product submodule or a reverse Framework pin. Independent NGINX
wrapper/secret-wiring review passed six tests. The fresh focused run passed all
36 methods in 246.637 seconds. Six namespace-repair modules preserve 71 existing
methods and all 234 assertion ASTs. Their latest per-method outcomes are 71 PASS:
the worker module first had six sandbox UID-mapping skips, then passed all 21
methods in 20.519 seconds outside the Linux sandbox with unchanged guards,
including the six actual Root/nobody descriptor cases. These observations are
not one combined final-head suite run and introduce no case IDs. The named
committed pair passed separately; acceptance after the next pins and hosted
Framework PR #142 / Connector PR #434 gates remain required. Actual Connector `5d471` Sonar failed with four security findings, one code
smell and 5.5% duplication. The working fixes have not yet been server-verified.
Three source-only Framework SDK/Make-owner repairs passed locally; hosted gates
must be renewed. Neither migration PR is merged.

Gitleaks baseline observations and reviewed false-positive classification are
distinct. The current configuration has two `generic-api-key` allowlists, each
requiring both its exact public SHA and its reviewed path to match (AND scope).
The raw receipt retaining 70 public-hash false positives and eight positive/
negative controls remain preserved. Earlier unsuppressed baseline scans do not
mean the current configuration has no allowlists. Actual remote CI verification
of this configuration remains pending; no credentials or customer payloads are
permitted in versioned evidence.

The development attempt using Connector `8c7e8c44` and Framework composition
`1aef2` was correctly rejected because the MRTS package source binding was stale.
It remains a rejected attempt. The final source-binding refresh and later
committed-pair and explicit development-pair probes passed separately. The earlier recorded pair
`cfd5e49` / `e52d7d4` and its three observed Apache controls retain only their
explicitly recorded scope.


The separately selected pure backend-isolation regression is
`offline.migration.prepared-backend-imports-are-isolated-and-reject-tampering`
(`DiagnosticTests.test_prepared_backend_imports_are_isolated_and_reject_tampering`).
It passed one method with five subcases and no skips through the existing offline
hook. The original declared-case method AST was restored exactly; the new logic
has its own five on-demand case IDs and does not extend an old selected loop.

The NGINX Product observability repair in commit `1c1` records only a known
400..599 request-error status, otherwise zero, before the existing timeout 504
override. It preserves unobservable transport, visible status zero and empty
actual action. The real extracted producer and exact consumers passed 28 methods/
156 expanded subtests after six red status variants; the bundle's 26 existing
methods also passed. Canonical internal pointer faults require
`connector_error`, `MSCONN_EVENT_CONNECTOR_ERROR`, typed `request_headers` and
HTTP500; malformed client framing remains HTTP400/protocol error. Three latest
actual H1 drivers passed after a 198.789-second build on Product `1c1`. The
additional existing-helper artifact-reader repair now permits strict reopening
of both fresh fault bundles, followed by projection and contract derivation.
The selected development-chain proof below does not establish a full lifecycle
or a final committed-pair gate PASS.

The user's current merge authorization is conditional on clean Sonar analysis,
no new open findings and every required gate passing. A current-head cloud gate
or migration merge result is not claimed here.


The second explicitly selected pure guard,
`NativeBundleRouterTests.test_worker_self_maps_require_exact_helper_and_paired_ledger`,
passed one method with seven subcases and no skips. The two new pure selectors
therefore declare five and seven subcases separately. Both passed via the public
CLI without skips; selecting either without `--on-demand` was rejected with
exit 2. Removing only the redundant
`Migration regression: ` prefix from 360 new-case purposes preserves the 2 MiB
inventory bound; all 1993 original baseline case dictionaries remain unchanged.

Fresh real NGINX H1 evidence now passes the selected full verification chain:
baseline HTTP 200, both internal pointer faults HTTP 500, identical 34-source
hash sets before launch/in the envelope/after execution, and the public strict
bundle reader, projection and contract derivation. Both fault proofs retain
`layer_verified=true`, `errors=[]`, canonical `connector_error`, typed
`request_headers` and integer HTTP 500. The receipt uses Product
`1c1c71459ce13fc4e2741dd6c30e671cfcbe55a0` and explicit Framework development
working source `1aef2c2268aeb38425aec1da7661baf6c449de25`; the recorded Framework
gitlink remains `e52d7d44c81e997a296b7ffdfb33f12bf85455b9`. This is development
evidence for three selected cases, not final committed-pair acceptance or all
42 native cases. Preserved raw result rows remain `NOT_EXECUTED`; layer proof
does not fabricate canonical result promotion. The 13 blocked standard
executions and their 26 cases remain unchanged in the separate default ledger.

The MRTS followup [Framework PR #141](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/141)
was merged under the conditional user authorization: exact head `197df49` was
squashed as `f5a0940c56edbb94d55d309636ce3d6f501e31a2`. All 16 Actions checks were
terminal (13 success, 3 intentional advisory skips); exact-head Sonar passed all
five conditions with zero OPEN/CONFIRMED issues and zero TO_REVIEW hotspots. The merged master has 9 terminal checks: 8 success and one
existing event-dependent skip.
The published Framework normal master merge
`5a827f3db670588febebd29fa6115142da198c6f` retained the reviewed tree `8037cff4`.
This establishes neither the migration PR's current-head gate nor acceptance
after subsequent pin changes.

Earlier scoped validation also passed 18 Sonar-contract methods in 4.966 seconds
and 39 pin-sensitive methods / 56 expanded variants. Formatting two existing CI
test files preserved their ASTs; all 38 Ruff files passed. Local Pyright remains
blocked by missing Node, with no installation performed; its hosted type gate is
required. The private candidate output cleanup was corrected with an exact private
external temporary root and child `CONNECTOR_TEST_OUTPUT_ROOT`, preserving all
existing assertions and public evidence retention. The postpatch run passed
50 methods / 160 subtests with one stale-source error; after binding refresh,
the remaining integration method passed in 31.859 seconds without skips. All
51 methods / 160 subtests therefore have passing observations across those
runs, rather than one full green run.

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
An earlier NGINX H1 attempt was blocked with exit 77 because the required existing
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
are not copied into the pair. The committed clean pair Connector
`5d47125febe38d18f33cc639bc70942da74fa7d7` / Framework
`a209e5e44be60b578a87a30fc85badcf7bdcab08` passed in 118.763 seconds in recorded-pin mode with
`standard_combination=true`, both checkouts clean before/after, and the actual
Parent Make → Common C1 test passing.

A distinct explicit DEV run passed for the same Connector with selected
Framework `e52d7d44c81e997a296b7ffdfb33f12bf85455b9`, recorded gitlink `a209e5e`,
in 118.865 seconds,
`mode=development` and `standard_combination=false`. Only the expected Connector
gitlink differed before/after; Framework remained clean. The real bridge exposed
11 exports, the private output directory retained mode 0700, and the wrong-pin
control rejected with exit 77. These pair proofs precede the working Sonar fixes;
acceptance of the final committed pair must be renewed. The earlier stale DEV
attempt remains rejected. Earlier Apache H1 controls on `cfd5e49` / `e52d7d4`
retain their scoped 28.625-second proof. Acceptance after the next pins and
current hosted Framework #142 / Connector #434 gates remain required. Evidence
stays in private external output storage; versioned records must not contain
customer payloads or credentials.

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
merge remains governed by the user's conditional authorization and all required gates. HTTP/2, HTTP/3,
Coverage and complete dependency assessment remain outside this migration,
apart from required path/caller adaptations.

The paired change records distinguish executed checks, failures, blockers and
checks not run. A static check, native primitive test or product build does not
establish a hosted H1 lifecycle or a current-head promotion.
