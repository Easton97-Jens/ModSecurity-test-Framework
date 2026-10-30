# Change Record: CR-20261030-test-ownership-migration

**Language:** English | [Deutsch](CR-20261030-test-ownership-migration.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | CR-20261030-test-ownership-migration |
| Date (UTC) | 2026-10-30 |
| Base revision | `3a4f2281568139d94fda6b51dc2e07bb8fc06c67` |

## Motivation and problem statement

All Connector tests and test infrastructure must move into the independent
Framework. Connector retains productive code/build/delivery and small pinned
integration calls. Separate worktrees preserve the original working checkouts.

## Affected components and security boundaries

Explicit `TEST_ROOT` and `CONNECTOR_ROOT` separate test mechanics from the
product under test. The Schema 4 contract, retained by Schema 5, fixes Framework source hashes while binding
product-source snapshots to the selected exact revision. Scoped product-source
imports replace a global Connector import path. Protected execution authenticates
the protected Parent Git object chain and pinned Framework source before code
selection. Required gate checks, host isolation and source authenticity must not
be bypassed. No customer payloads or credentials belong in versioned evidence.

Upstream [Framework PR #139](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/139)
and [Connector PR #432](https://github.com/Easton97-Jens/ModSecurity-conector/pull/432)
are already merged. The task incorporated Framework upstream base
`1d1e73fb069598e0f0f809d0bf16b5e59047ff88`, preserving task edits and backups
through three-way reconciliation. This upstream integration is separate from
delivery of the migration and MRTS-focused Framework packets.

## Acceptance criteria

The retained selection baseline is 100 standard cases / 80 executions and
1893 on-demand cases / 839 executions. New migration regressions remain on
demand; the standard cap stays 100. Test identities, assertions and distinct-case
counting must survive relocation. Product builds must not acquire a Framework
runtime dependency. Framework delivery must precede the dependent Connector pin;
the current user authorization permits merge only after clean Sonar analysis,
no new open findings and all required gates pass.

## Alternatives considered

Leaving connector-specific tests in Parent or adding a reverse Connector
submodule would preserve the unwanted split ownership. Global product import
paths allow candidate files to shadow trusted modules. Explicit source-checkout
interfaces, source-domain admission and external overlays avoid those choices.

## Implementation decision

Framework owns migrated `connector_suite/`, `connector_native_tests/`, shared
public adapter/source interfaces, result correlation and exact-pinned CI actions.
The map preserves legacy source identities while physical package namespaces are
unique. Product code is an explicit revision-bound input, not a Framework runtime
dependency or submodule.

Native/component results above do not establish host request traffic or
product promotion. Apache duplicate headers are adapted explicitly to observed
merged values while retaining HTTP 200, rule `1100504` and audit assertions.
NGINX internal pointer-fault tests require HTTP 500 / `phase1_error` /
`MSCONN_EVENT_CONNECTOR_ERROR` / `reason=connector_error`; malformed client input
retains HTTP 400. These correct stale test contracts without product weakening.

## Changed files and tests

`connector_suite/` contains migrated tests, adapters, fixtures, inventory,
provisioning, evidence/report tooling and path/case maps. `connector_native_tests/`
contains extracted native programs and their source manifest.
`modsecurity_test_framework/`, `tests/runners/`, `tests/normalizers/`, `ci/`,
`.github/actions/` and `.github/workflows/` integrate explicit roots, safe imports,
correlation and authenticated orchestration. New regressions remain on demand.

Documentation pairs: `docs/connector-test-suite`, `docs/connector-integration`,
`connector_suite/modsecurity_connector_ci/README`,
`connector_suite/modsecurity_connector_tests/README` and this record
(`.md` / `.de.md`). The final Git diff is the complete file list.

The requested work is accounted for as follows; pending verification and
delivery remain explicit rather than inferred from file relocation.

| Requested area | Implementation or disposition |
| --- | --- |
| Baseline and mapping | Source/case maps retain original identities, purposes, selectors and old callers alongside current Framework paths and public callers; availability remains distinct from selection and execution. |
| Complete test ownership | Test implementations, fixtures, orchestration, provisioning, collectors and reports moved to Framework; productive code/build/delivery remain in Connector with small pinned entrypoints and two authenticated broker shims. |
| Repository interface | Explicit roots, revision, profile and external output; public unique Python namespaces and scoped imports; one-way Connector → Framework dependency and unchanged protected trust boundaries. |
| Result defects | Request-local identity rejects foreign/ambiguous enrichment; Envoy retains executed traffic after assertion failure; mandatory writes and empty required result sets fail; retries do not add unique cases. |
| Runtime deviations | Apache merged duplicate headers require explicit native rule adaptation, retaining rule `1100504` and audit assertion; injected NGINX internal faults require HTTP 500 and connector-error semantics while malformed client input remains HTTP 400. Actual Apache controls and three selected NGINX development H1 cases passed; final committed-pair and complete lifecycle qualification remain separate. |
| Parallel topics | HTTP/2, HTTP/3, Coverage and full dependency assessment remain outside scope except required path/caller adaptation. MRTS package/import corrections belong to the separate Framework followup packet and shared integration check. |
| Shared mechanics and code size | Native extraction is relocation; repeated loader consolidation removes caller implementation with shared-helper overhead. No equal total code reduction or complete mechanical equivalence is inferred. |
| Verification and delivery | Latest observed defaults: 67 passing / 13 blocked executions, 74 passing / 26 blocked cases across recorded revisions. The recorded 70ce/8ce pair and explicit DEV probe passed before the latest interface/transport/indexing changes, retaining the earlier scoped Apache proof; next-pin pair acceptance, installed-gate proof and hosted final-head gates remain pending. Merge remains conditional on the current user authorization and all required gates. |
| Extension classification and privacy | A closed reviewed process-bearing set uses migration-integration; pure controls retain offline audit, with original baseline groups/guard ASTs preserved. Private external output and exclusion of customer payloads/credentials remain required. |

## Commands and results

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

Renewed real native capture compiled all 81 translation units in 39.790 seconds
with actual SDK `ALL_INCS` and mapped header inputs, without source or SDK/header drift. Eight
SDK admission controls before recipe import and 19 native Sonar-contract
methods passed; the original 18 method ASTs remain exact. Four new fixed
source bindings have precise physical Framework owners. The closure retains
eight observed, two semantic and two public-entry dependencies; source
bindings were not globally pruned. Fresh canonical security verification passed
69 methods / 257 observed subcases in 10.939 seconds, with no skips or source
drift, against working bridge SHA-256
`1ef4d6fb021605f52c63fef3bf522a325736ceb40457d48c94c091b1e3efc5eb`.
This includes the separately registered sixth surrogate-escaped argv case.
The follow-up quality changes cover 66 source files. They replace 23 S1192
literals in 13 files with constants, with 440-function equivalence checks.
Twenty-four unused parameter slots in 23 files changed only declarations;
165 affected methods have passing outcomes across scoped runs. The broader
Ruff result retains its 203 baseline diagnostics unchanged: no full lint PASS
is claimed for those files. Six API complexity refactors preserve guards and
signatures, with 1322 differential paths and 94 methods / 286 subcases passing.
Seven Go helper extractions in five files preserve all 210 original function
ASTs after helper inlining and 112 test definitions; normal/race runs retain
the exact 205 terminal test/subtest identities, all passing without skips.
The 17 YAML guards and actionlint/zizmor contracts remain. The invalid callee
default was later removed while preserving the exact dispatch/call interface. All 41 trusted/Lighttpd methods / 185 subcases
passed, preserving 40 old methods and 114 assertions. Output validation passed
39 methods and 13 filesystem checks. HAProxy ownership checks passed 39 methods,
preserving 25 existing methods and every assertion. Bounded independent review
passed 157 methods in 5.016 seconds without findings. Two C-fixture refinements
passed three existing lifetime/mutation methods in 51.935 seconds; old/new UTF-8
smoke inputs compiled and produced byte-identical stdout. The actual native
evaluator translation unit and Lighttpd's 59 canonical results retain parity
with 40 old contracts. These are local proofs for the follow-up quality changes. The renewed native
run passed 330 tests in 162.202 seconds (outer invocation: 165.353 seconds),
the exact 38-file workflow Ruff lint/format checks passed, and 19 Sonar-contract
methods passed in 4.847 seconds. Indexed-inventory verification passed 61 methods /
21 subcases in 18.843 seconds, plus two actual guarded child controls; the earlier fresh
admission covered all 1149 execution definitions / 2461 cases, not execution of
that whole catalog. All 20 new public methods / 47 expanded cases and 20 implicit-
selection denials passed without skips across the initial 16 successful selectors
and four resumed selectors. The coordinator initially omitted the existing
`ON_DEMAND_TESTS=1` opt-in for those four fixtures; strict skip validation correctly
rejected that attempt. Their corrected CLI calls retain both `--on-demand` and
`ON_DEMAND_TESTS=1`; environment opt-in alone still rejected with exit 2. No source,
test or gate changed to obtain these results. These are source-bound working-
follow-up receipts: the child's Framework-revision environment was unset,
not fabricated as acceptance of a future committed pair. Independent review of
seven source seams found no validated introduced finding within that bounded
scope. New committed-pair and hosted-head acceptance remain required.

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
These are local boundary and generator proofs, without a live-host run.
The published `70ce`/`8ce` recorded pair and separate DEV probe passed;
the older `e77`/`4391` proof retains its historical scope. The earlier 13-file source-owner
repair batch established these local checks: start/remaining/HAP C and Common SDK/security
checks select the actual Framework Make/source owners. Actual Common-helper
C/C++ compilation preserves the three test heredocs and 679 assertions, with
two Framework result helpers; two HAProxy standards helpers compile as C17.
Framework Make restores shell/Python lint scanning over the moved paths and
manifest and exports the selected Framework revision. The C++ collector admits
only the exact tracked regular, revision-bound Framework evaluator; eight
existing methods, actual Bear C++ capture and public Parent Make passed.
NGINX request-window/case-info handling binds the admitted logs root and supports
its sibling layout: 62 existing methods passed in 30.853 seconds with strict
readers unchanged. Later hosted triage on `70ce` / `8ce` found two different
causes: actionlint rejects the required reusable Lighttpd `on_demand` input's
redundant `default: false`, and recursive HAProxy Make resolves a relative Python
path in the component directory. The callee now omits that default; the exact
Parent dispatch default remains false, with explicit same-name forwarding,
required boolean types, permissions, pins and trigger checks retained. Eight
named invalid interfaces reject. The quoted existing `FRAMEWORK_PYTHON` fixes
the recursive boundary: the same selected relative interpreter reproduced
Error 127 before the fix and the actual Parent HTX target passed afterward.
All 22 Framework workflows passed actionlint/ShellCheck. Renewed native/Sonar-
contract checks and the 20 public selectors passed within the scope above.
Renewed capability collection checks the selected source owner: mapped paths
resolve in the Framework, unmapped productive paths in Product, and a missing
mapped target rejects a Product decoy. All 18 module methods passed, including
the new method's three named variants; public collector validation passed for
6 connectors / 60 capability entries. This is source-contract validation,
not a runtime host-capability proof. Renewed actual Apache, NGINX and HAProxy
C17 compiler runs passed; the NGINX/HAProxy run took 8.615 seconds with reviewed
cached header inputs. The earlier five source-owner oracles proved wiring,
not full compilation. The new public capability method separately passed
its 3 variants and 1 implicit-selection denial. The previous 20 methods /
47 variants and 20 denials retain their own source-bound receipts; no combined
21-method run is claimed. N28 hosted acceptance remains pending; the
historical `8ce` analysis still has gate `ERROR` with 120 OPEN issues.

One actual Parent `make quick-check` invocation passed with exit 0 in
576.252 seconds, below its 600-second bound. It completed prerequisite lint,
the canonical installed-actionlint module, lint's diff check, Framework
normalizer/runner/CI Python compilation and the final quick-check diff check.
All 510 source bindings remained unchanged without drift. The log contains
79 passing execution receipts for 18 unique execution IDs; this is not an
80-execution host qualification. The earlier combined-target timeout followed
the coordinator's invocation assumption: Parent's `%` dispatcher starts a
separate submake for each requested target. That timeout was not a source bug
or a guard waiver. The two Make repairs retain quoted relative Framework Python
forwarding and invoke installed workflow lint through
`-m modsecurity_connector_ci.tools.lint_installed_workflows`; 11 focused tests
and the actual CLI passed. This proves the local `70ce`/`8ce` working follow-up,
not acceptance of a future committed pair or hosted head.

Three C++ jobs and the HAProxy native/runtime path encountered network
unreachability. Runtime already made three attempts; no additional runtime retry
is introduced. Native acquisition shares a maximum-three-attempt transient-only
transport: HTTPS/TLS and digests remain mandatory, permanent failures are not
retried and existing destinations are not overwritten. Actual pinned cached
archive parity passed, including the direct verified cache path without network;
this does not prove hosted network recovery. Apache's observed job used merge
revision `054c`, not literal Parent `70ce`.

Four Traefik source-owner repairs preserve all 62 test-method ASTs; the two
standalone modules retain their complete original ASTs apart from restored
imports. Actual bounded native/file tests (9) and private export tests (52)
passed. Five further complexity decompositions passed the same 119 existing
methods before and after, preserving guards and assertions. Native Git object
authentication passed 28 methods in 144.687 seconds, 16 named probes and an
offline-import boundary check, using the exact verified local SHA1_DC backend.
These are scoped local/source proofs, not public host qualification. Fresh
default-suite, next-committed-pair and hosted new-head acceptance remain separate.

Relocating 1295 source paths is distinct from deduplication. The scoped loader
consolidation replaced 326 blocks and removed 1067 net loader lines, with 29
new shared-loader lines recorded separately. These are loader metrics, not a
claim about total repository code reduction.

The registered canonical schema-5 inventory contains **100 standard cases /
80 executions**, **2443 on-demand cases / 1107 executions**, **515 fixed Framework
test-source bindings** and **235 product-source snapshots**. The catalog declares
**1187 execution definitions / 2543 cases**; these are selection quantities,
not executed or passing counts. Its compact JSON is **1112077 bytes** and its expanded UTF-8 source paths occupy
**1086696 bytes**, both below the unchanged **2097152-byte (2 MiB)** bound. All prior binding
identities remain and all 750 ordered source-pool entries are used. The original
1993 case dictionaries and standard IDs remain unchanged. Admission still checks
the expanded UTF-8 source-path bound before materialization.

The extension now contains **120 explicit on-demand methods**, including 37 new
methods / 79 cases in N28: 5 argument-admission methods / 15 cases, 2 native
fixture methods / 6 cases, 12 Go-capture methods / 31 cases and 18 archive-snapshot
methods / 27 cases. Every new method has its own registered selection and
explicit variants. All 37 actual source/effect traces passed with guards active
before imports: 35 pure methods had zero effects; the 2 native methods use the
explicit process boundary. There are 111 pure extension controls and 157
process-bearing rows across 13 explicitly allowlisted modules. Standard selection
remains capped at 100. The actual public runner passed all 37 new methods / 79 cases in 166.939 seconds;
2 mandatory missing-CLI-opt-in controls also passed with `ON_DEMAND_TESTS=1`.
Public admission passed in 6.06 seconds. Final source bindings and all six generator operations passed after the later
import repairs; fresh final admission passed in 5.327 seconds. Paired commit/push
and hosted exact-head CI/Sonar verification remain pending.

The five new source bindings come from observed canonical read closures. Two
existing NGINX rows also gain the actual eager P3-runner import in their closure;
this changes source accounting without adding or concealing independent cases.
No archive is selected automatically and no standard case is added.
The new native fixture module uses the existing full Framework-prefix source
binding form. The historical source map remains byte-identical to `cb129a45`;
no fictional prior Product path is introduced. One new unpublished case ID was
deterministically shortened to the unchanged 128-character bound; original and
standard IDs remain intact.

The earlier 120 focused methods passed without skips, including the result-integrity
subset of 56 methods / 131 expanded variants and the closed path-policy subset
of 9 methods / 32 expanded variants. Earlier scoped runs passed 136 focused portability methods,
30 public API methods and 3 Makefile methods. Earlier local native Framework CI
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

Existing task evidence records 56 result-integrity methods / 131 expanded
variants passing with no failures, errors or skips under Python `-P`,
`PYTHONSAFEPATH=1` and Framework-only `PYTHONPATH`. Source isolation has 3 passing
methods and source-domain admission 4. Six extracted native suites passed;
the SPOP specialist retains one failure reproduced against both original and
migrated code. The native failure is not reported as PASS. These are task-run
results, not a final-head rerun or hosted H1 qualification.

The source-preservation audit examined 5886 baseline Python test method
definitions, including the four upstream MRTS methods, and found no missing
methods or reduced `self.assert*` counts at that audit point. This syntactic audit does not prove semantic equivalence.
The initial native extraction preserved 69 functions / 2011 lines byte-for-byte according
to its source manifest. Loader consolidation replaced 326 repeated blocks and
removed 1067 caller lines; shared helper overhead remains, so this is not a
claim of an equal total code reduction.

A fresh bounded independent source-trust re-review found no findings and
passed 53 methods (20 trusted-bridge, 3 Python-isolation, 30 NGINX contracts),
with no skips/errors, against Connector revision
`ec18f9e92286379a2410e917f76e6a5502675804`. It is not a full security scan,
privileged host run or installed-gate qualification.

Documentation validation actually executed through RTK: a bounded Python
relative-link/heading/code-block inspection passed all 22 owned Markdown files
(11 EN/DE pairs, no broken relative links, equal heading counts and fenced
commands). `rtk bypass git diff --check -- <owned-document-paths>` passed in
both task repositories. The Framework native
`ci/checks/documentation/check-change-records.py --root <framework-root>` passed.
The unchanged original Parent creator/checker API, loaded from the original
checkout with explicit task-root output/check scope, created and validated the
Parent archive because the in-migration creator's old checker path was absent.
No original checkout file was changed. This scoped check does not replace the
full repository bilingual/link Make targets or factual review. The unchanged Parent `ordinary_pair_errors` checks passed
for all ten applicable pairs outside the separate Framework record schema.

Final documentation refresh: all eight migration-guide/record files passed
relative-link, EN/DE structure, fenced-command and technical-literal checks;
both record contracts and scoped `git diff --check` passed. The frozen inventory
counts above describe selection and source admission, not execution claims.

The final reader-link repair repointed 40 links in 32 Connector Markdown
files through the exact migration source map, without changing historical prose.
Explicit Connector- and Framework-root link checks passed. The complete
Connector bilingual check and Framework variable/bilingual check passed after
adding the seven new interface variables to the paired central reference.
The final native Framework repository-path-reference check passed across
2134 files with zero obsolete paths. Two exact historical JSON byte identities
and two exact negative-fixture lines have a closed provenance-bound policy;
changed bytes, stale guards and additional active paths remain errors. Its nine
focused methods / 32 expanded variants passed without skips and admit zero
new default cases. The complete native Framework documentation Make target
passed its link, variable/bilingual, repository-path and Change Record checks.
Historical evidence and negative-input bytes were preserved.

The full 58-method capture-registry specialist run recorded 54 passing
methods and four non-PASS results (3 failures / 1 error), attributable to the
pre-existing SDK hash mismatch. The hash contract is preserved: the reviewed manifest expects
`89ff282b7287ab30a4194bc06c04835f104b8037442e89b35a68fd1253dcfcfc`, while both
the original Connector `ec18f9e92286379a2410e917f76e6a5502675804` bytes and the
byte-identical migrated input hash to
`a220539856ea8164302f7b427fe72c829f035541387aebce620aebae0fa1310e`.
No registry hash or historical object was weakened or rewritten. A separate
broader specialist control rejects loading an external captured controller from
an unselected source; that fail-closed rejection remains a non-PASS positive
control. These results are separate from the 136 passing portability methods.

Checksum-verified Ruff `0.16.10` was fetched as an approved isolated native CI
tool. The actual native CI lint check passed. Formatting seven files preserved
their ASTs; the latest full 38-file Ruff recheck passed.

## Security impact

Explicit `TEST_ROOT` and `CONNECTOR_ROOT` separate test mechanics from the
product under test. The Schema 4 contract, retained by Schema 5, fixes Framework source hashes while binding
product-source snapshots to the selected exact revision. Scoped product-source
imports replace a global Connector import path. Protected execution authenticates
the protected Parent Git object chain and pinned Framework source before code
selection. Required gate checks, host isolation and source authenticity must not
be bypassed. No customer payloads or credentials belong in versioned evidence.

## Documentation and runtime evidence

The latest bounded result-integrity run passed 56 methods / 131 expanded
variants. Three actual Apache H1 controls passed with HTTP 200 / 403 / 200
(allow, deny, duplicate header). The allow control used the client-only
`request_bound` observation; it does not prove a host capability.
An earlier NGINX H1 attempt was blocked with exit 77 because the required existing
runtime was unavailable; this is not a passing host run. These observations do
not qualify a complete H1 lifecycle or an installed protected-host gate.

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

Native/component results above do not establish host request traffic or
product promotion. Apache duplicate headers are adapted explicitly to observed
merged values while retaining HTTP 200, rule `1100504` and audit assertions.
NGINX internal pointer-fault tests require HTTP 500 / `phase1_error` /
`MSCONN_EVENT_CONNECTOR_ERROR` / `reason=connector_error`; malformed client input
retains HTTP 400. These correct stale test contracts without product weakening.

## Checks not run

An earlier NGINX H1 attempt was blocked with exit 77 because the required existing
runtime was unavailable; no NGINX host PASS or installed protected-host gate
proof is recorded here. Current-head CI, final complete-diff review, final source-map /
inventory regeneration and dependent PR delivery require separate observed
results. HTTP/2, HTTP/3, Coverage feature work and a complete
dependency audit are outside scope apart from necessary path changes.
The public adapter is a source-checkout interface; installable package contents
are a separate contract. MRTS remains read-only. No migration merge is claimed.

## Limitations and residual risk

An earlier NGINX H1 attempt was blocked with exit 77 because the required existing
runtime was unavailable; no NGINX host PASS or installed protected-host gate
proof is recorded here. Current-head CI, final complete-diff review, final source-map /
inventory regeneration and dependent PR delivery require separate observed
results. HTTP/2, HTTP/3, Coverage feature work and a complete
dependency audit are outside scope apart from necessary path changes.
The public adapter is a source-checkout interface; installable package contents
are a separate contract. MRTS remains read-only. No migration merge is claimed.

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

The clean-pair CLI verifies a committed Connector revision against its recorded
Framework gitlink by default. Both source repositories must contain the selected
Git objects. It creates clean local checkouts from those objects, verifies required
entrypoints and interfaces, invokes the actual Parent Make target
`test-framework-integration-probe`, and validates the exact admitted Common
header test result. The probe requires installed Git, Make, a compatible Python
and `cc`, plus existing private external output storage. Uncommitted source edits
are not copied into the pair. The committed clean pair Connector
`70cefa5706b1a8339046f3f3d1f77ea9493f3cd0` / Framework
`8ce35c1108d753986b11cb011d24fc99f262f112` passed in 125.528 seconds in recorded-pin
mode with `standard_combination=true`, both checkouts clean before/after, and
the actual Parent Make → Common C1 test passing.

A distinct explicit DEV run passed for the same Connector with selected
Framework `e52d7d44c81e997a296b7ffdfb33f12bf85455b9`, recorded gitlink `8ce35c1`,
in 123.950 seconds, `mode=development` and `standard_combination=false`. Only the
expected Connector gitlink differed before/after; Framework remained clean.
The real UID 1001 bridge exposed 11 exports, retained private output mode 0700
and rejected the wrong pin with exit 77. All 90 updater methods / 216 subcases
passed without skips across 39-method (90.988 seconds) and 51-method (77.711
seconds) runs. These proofs concern that exact published pair, before the latest
interface, transport and indexed-inventory changes. They do not accept the next
committed pair. Earlier `e77` / `4391` recorded/DEV proofs (126.317 / 123.559
seconds), the rejected stale DEV attempt, and Apache H1 on `cfd5e49` / `e52d7d4`
(28.625 seconds) retain their historical scope. Next-pin acceptance and current
hosted Framework #142 / Connector #434 gates remain required. Evidence stays
in private external storage; versioned records contain no customer payloads or credentials.

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
paths. C-family byte-identity statements describe that earlier SDK-only stage.
Initial byte-preservation claims, including the 35 Go files, concern the initial
transfer; later explicit C/Go refinements use the semantic proofs above.
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
Framework PR #142 / Connector PR #434 gates remain required. The historical Connector
`e77c833eef4b23e1252dbcd4c6507ded0b7e2064` Sonar analysis passed all five gate
conditions, with 2.0% duplication, no unresolved issues and no TO_REVIEW hotspots.
That is not a Sonar PASS for Parent `70ce`: the last readback still analyzed
`e77`. Historical Framework `4391` first had 280 issues and later 272 after eight
user-authorized, individually evidenced false positives. The historical Framework
`8ce35c1108d753986b11cb011d24fc99f262f112` analysis at 16:46:21 UTC had reliability
A, maintainability A, 0.0% duplication and no hotspots, but security E and gate
`ERROR`; its initial complete issue inventory contained 178 unresolved findings.
That initial count is not a current remainder. User-authorized issue-specific
comments and server readbacks separately confirm the previous eight, 24 native
and 16 Python false-positive dispositions, plus 16 further native-contract
model errors. Two further lifecycle-model errors bring the individually evidenced
total to 66. The additional 16 native-contract dispositions concern
four controller and twelve ABI claims; eleven actual C17 type probes passed
with three positive and eight const-incompatibility controls. Complete
server readback at 18:38:27 UTC for the `8ce` analysis dated 16:46:21 UTC
shows 120 OPEN issues and no hotspots; gate `ERROR` and security E remain,
with reliability A, maintainability A and 0.0% duplication. The two new individual
readbacks cover `_7KT`'s read-only post-link `TMPDIR` provenance, not precompiler
admission, and `_7MD`'s synchronous `re.subn` callback. All 10 CLI-authority
questions remain open; these dispositions do not admit compiler arguments or tools.
The optional coverage condition reports OK, without establishing a new coverage
quantity. Python `_7Lu` and all other uncertain findings remain open; there is no
blanket disposition, risk acceptance or rule change. Sonar categories are not
independently validated exploits. Both migration PRs remain draft and unmerged;
the next committed pair and actual new-head analyses/gates are still required.

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

## Final diff and review status

Migration delivery uses separate task worktrees and published Framework PR #142 /
Connector PR #434. The named committed pair and explicit DEV probe passed; the
next pins, repeated committed-pair acceptance, hosted current-head checks remain open;
private candidate cleanup now has the separate passing observations above. Ruff passed locally;
Pyright requires its hosted gate. A migration merge result is not claimed.

**N28 source changes and current evidence limits**

N28 extracts bounded helpers for migration-map generation, inventory admission,
maintenance, native capture, observations and result projection while preserving
old selectors and assertions. Argument admission prevents Make-active interpreter
paths and archive response-file/option operands from reaching their downstream
parsers. Existing custom Unicode interpreter paths remain supported.

The private native event fixture holds admitted directory descriptors and cleans
relative to its opened root. Its 2 explicitly process-bearing methods / 6 cases
passed actual strict C17 execution with descriptor delta zero. The repaired
root-owned parent/leaf branch uses a held working-directory descriptor before
dropping identity and fixed relative event paths. The full UID 65534 branch was
**NOT_EXECUTED** locally because the required UID mapping/capabilities were absent;
static review and current-identity path controls do not substitute for that branch.
The process-module allowlist grows explicitly from 12 to 13.

Go capture admits private source/output roots before invoking the compiler,
rejects response files and ambiguous/overriding output arguments, and retains
bytes through owned descriptors. Descriptor ownership also survives stream-wrapper
construction failures. Failure handling does not unlink a replacement namespace
entry; private incomplete artifacts may remain and require explicit inspection.
Consumers must require successful producer status as well as artifact integrity.
The 12 new methods / 31 cases cover this bounded behavior. The separate `_7KV`
question about authority to select the tool remains OPEN; this data-path repair
does not authorize arbitrary compiler selection.

Both NGINX fixture callers now open the source through a trusted nofollow
ancestor-FD walk, copy at most **67108864 bytes (64 MiB)** into a private
`BytesIO`, hash the copied bytes and extract that same object. A source pathname
replacement after hashing cannot change the extracted bytes. The actual pinned
`nginx-1.31.6` archive is **1373124 bytes**. The compressed-input cap is new; it
bounds archive content, not total RAM or extracted/uncompressed size. Python
buffer/copy overhead is additional. No new `O_TMPFILE` or filesystem support is
required. Existing member-count, traversal, link and device checks remain.
Archive admission failure can retain the deterministic task root, so a same-root
retry fails closed; no unsafe automatic cleanup is added. The 18 new methods /
27 cases never execute an untrusted fixture `configure` script.

Six preexisting collector tests also required migration reconciliation. Four
synthetic source rows omitted the transaction ID already present in their event;
the unchanged collector correctly rejected borrowing those events. The fixtures
now supply their matching IDs. The other two tests assert the Framework-owned
artifact-stager path and read selected `connector_suite/connector.mk` for the
existing protocol-client assertions. All 44 methods, 190 assertions and 3 subtest
call sites remain. Copied fixture snapshots changed six RED outcomes to six
GREEN outcomes. Fresh canonical execution now passed the repaired six and two
existing transaction-isolation methods, with zero skips. The first five repairs
and both isolation methods passed pure guards with zero effects; the protocol
script rejection method passed its explicit process boundary with one effect
and no source writes. Its earlier mistaken pure-guard invocation correctly
failed and remains recorded; the method is not claimed pure. No provenance,
runtime or audit/scrubbing guard was weakened.

The current direct existing-contract runs passed 112 inventory/maintenance
methods / 80 subcases and 75 workflow/native-contract methods / 163 subcases.
The separate result-runner group had six reproduced preexisting failures before
the fixture repair and three clean-Framework-prerequisite skips on the dirty
tree. Those skips are not PASS, and no whole-group or full on-demand campaign
PASS is claimed. Separately, the public runner passed the 37 new methods /
79 cases in 166.939 seconds, the 2 missing-CLI-opt-in controls passed even with
`ON_DEMAND_TESTS=1`, and the 2 existing NGINX eager-import selections passed in
15.578 seconds. Admission passed in 6.06 seconds. These receipts bind inventory
`34f3e84ab90e69de85f0b9e042bebc965fde0f34af496f471c74bcde37583ea5`, before
two later unrelated Product-import repairs. Exact reconstruction against final
inventory `dc5980db497faa5ba6885f71552a8555c7bcd96f1ec759a0c4c786e76aec308e`
proves only one old revision-test source SHA changed, outside all 37 selected
closures; every selected source/case field is identical. No repeat of those
37 methods is inferred or required by that unrelated hash refresh. No old
broader-suite skip is converted to PASS.

The actual canonical Go/CGo native producer passed offline in 146.568 seconds,
with 84 compilation units: 62 Product units and 22 context units, plus 73 Product
headers. Captured input hashes remained stable. The 32-byte FIPS transition and
build-ID replay matched the final artifact; this is not FIPS certification.
Validation explicitly records `development_only=true` and `import_eligible=false`.
The native executable was not started; no host runtime or hosted Sonar PASS is
inferred. After the selected Product-import and legacy/migrated-verifier marker
repairs, all 11 old Go-version methods / 25 subcases and 4 old Capture/FIPS methods
passed without skips. The 5 active Go-version row closures have zero gaps.
The current canonical native CI passed 330 tests in 170.503 seconds. The exact
38-file workflow Ruff lint/format selection passed in 0.324 seconds; 19 Sonar-
contract methods passed in 5.139 seconds. Actual compilation of all 81 selected
translation units passed in 40.57 seconds, including object production for all
4 changed Framework C fixtures under C17 with `-Wall -Wextra -Werror`. That run
uses immutable Product input `cfd5e49cada3fc793ef50993147e3796a0907443`, rather
than the whole current Product tree. Comparison of 223 Product inputs found one
delta: the two existing status lines in
`connectors/nginx/src/ngx_http_modsecurity_access.c`. That current translation
unit separately passed strict C17 with `-Wall -Wextra -Werror` in 0.559 seconds
and again in 0.666 seconds after snapshotting all 349 actual inputs. The repeated
object SHA is identical. Its 348 headers remained hash-stable: 6 current Product
headers identical to the immutable input, 24 immutable Product headers,
93 cached SDK/NGINX headers and 225 system headers, with zero context differences.
This separate current-unit proof does not relabel the original 81-unit run.

The two import-only corrections also passed 19 existing revision methods /
51 subcases without skips, plus Report CLI `--help` and import checks. All 25
and 112 original function ASTs in the respective modules remain exact; no report
was generated. No active row is affected; the one indirectly bound test hash
has been refreshed. The 37 public source closures are unchanged by these
unrelated corrections. All six final generator operations passed after that
refresh, and fresh full admission passed in 5.327 seconds. Staging/Gitleaks,
paired commit/push and hosted exact-head CI/Sonar remain pending. These local results do not establish hosted exact-head
gates or merge eligibility.

Published Connector `1f213858ae059d77a84a4bf500b9e90f025e15fe` and Framework
`cb129a45ccfd033fa5aafd08ca0dc7d9ec731e49` have separate real recorded-pin
(151.690 seconds) and explicit DEV (151.493 seconds) acceptance. The recorded
run used clean clones with `standard_combination=true`; DEV selected Framework
`8ce35c1108d753986b11cb011d24fc99f262f112`, recorded
`standard_combination=false` and retained only the expected gitlink difference.
The actual UID 1001 sealed bridge passed with 11 exports/private mode 0700,
and wrong-pin controls returned 77 without exports. All 90 updater methods /
216 subcases passed. These proofs accept that published pair, not the unpublished
N28 follow-up or a final host lifecycle.

The latest complete Framework Sonar analysis at `2026-10-30T19:04:35Z` analyzes
`cb129a45ccfd033fa5aafd08ca0dc7d9ec731e49`. Its last complete issue inventory,
read at `2026-10-30T19:35:24Z`, contained **115 OPEN issues**, gate **ERROR** and
**0 TO_REVIEW hotspots**, before the latest individual disposition. No fresh full
issue count after that disposition is claimed. Parent `1f213858` still has the
stale `e77c833` analysis. The documented individual false-positive dispositions
now total **67**, including the fixed-argv native Git object-identity sink with
complete comment/status readback. Seven other tool-authority questions remain
OPEN; uncertain findings remain open and no rule or Quality Gate is weakened. N28 has
no published new head or hosted exact-head gate yet. Framework PR #142 and
Connector PR #434 remain Draft and unmerged. Conditional master integration
requires clean exact-current-head Sonar, no new open findings and every required
CI/review condition; no merge eligibility is claimed.
