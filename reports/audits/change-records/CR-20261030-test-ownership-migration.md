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
product under test. Schema 4 fixes Framework source hashes while binding
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
no merge or master push is authorized.

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
| Runtime deviations | Apache merged duplicate headers require explicit native rule adaptation, retaining rule `1100504` and audit assertion; injected NGINX internal faults require HTTP 500 and connector-error semantics while malformed client input remains HTTP 400. Actual Apache controls passed; NGINX host verification is blocked. |
| Parallel topics | HTTP/2, HTTP/3, Coverage and full dependency assessment remain outside scope except required path/caller adaptation. MRTS package/import corrections belong to the separate Framework followup packet and shared integration check. |
| Shared mechanics and code size | Native extraction is relocation; repeated loader consolidation removes caller implementation with shared-helper overhead. No equal total code reduction or complete mechanical equivalence is inferred. |
| Verification and delivery | Focused checks and bounded Apache observations are recorded separately from the pending default-run outcomes, installed-gate proof, final-head CI and dependent PR delivery. Framework integration precedes Connector pin integration; no merge is authorized. |

## Commands and results

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
Native extraction preserved 69 functions / 2011 lines byte-for-byte according
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
their ASTs; the final formatting recheck remains pending.

## Security impact

Explicit `TEST_ROOT` and `CONNECTOR_ROOT` separate test mechanics from the
product under test. Schema 4 fixes Framework source hashes while binding
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
The NGINX H1 attempt was blocked with exit 77 because the required existing
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

The NGINX H1 attempt was blocked with exit 77 because the required existing
runtime was unavailable; no NGINX host PASS or installed protected-host gate
proof is recorded here. Current-head CI, final complete-diff review, final source-map /
inventory regeneration and dependent PR delivery require separate observed
results. HTTP/2, HTTP/3, Coverage feature work and a complete
dependency audit are outside scope apart from necessary path changes.
The public adapter is a source-checkout interface; installable package contents
are a separate contract. MRTS remains read-only. No migration merge is claimed.

## Limitations and residual risk

The NGINX H1 attempt was blocked with exit 77 because the required existing
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
Framework integration are traced separately from the tool repository. Generated
archive and map outputs match their frozen source inputs: both generator
`--check` runs passed, preserving all 1993 original case IDs. The canonical
inventory counts above describe selection, not successful execution.

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

## Final diff and review status

Migration implementation and documentation are staged in separate task
worktrees. The final Connector pin, pin-sensitive checks, final formatting
recheck and remote migration PR delivery are pending. Current-head CI,
Quality Gate and migration merge results are not claimed.
