# Change record

**Language:** English | [Deutsch](20261102-01-parent-python-bootstrap-contracts.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261102-01-parent-python-bootstrap-contracts |
| UTC date | 2026-11-02 |
| Framework base revision | `91145b7ba721bdec4e89af754cf40bf496fd2a08` |
| Issue or pull request | Requested repair of Parent runs `41412784227` and `41412832386`; Framework PR #158; initial record preceded PR creation |

## Motivation and problem statement

Current Parent Python updater checks reject Framework composite bootstrap order,
stale job inventories, and unsupported protected/historical workflow composition.
The context binder previously executed Python before setup and interpreter
verification. This Framework change repairs reusable contracts; Parent-native
workflow changes remain a separate delivery.

## Affected components and security boundaries

The 18 `.github/actions/connector-ci/` implementations, Framework-owned Python
workflow checker, and `modsecurity_test_framework/workflow_sources.py` preserve
the boundary between the Parent Gitlink, checked-out Framework code, immutable
remote actions, and authenticated protected execution. MRTS is unchanged.

## Acceptance criteria

Shell-only source proof precedes the checked-out interpreter verifier; setup and
verification precede context binding. Normal inventory matches 47 current jobs.
Protected jobs retain their exact authenticated verifier. Historical composition
accepts only its reviewed immutable shape. Existing bypass negatives pass.

## Alternatives considered

A blanket first-use/context exemption would accept unverified Python. Replacing
the protected wrapper with a direct verifier would lose authentication. Treating
the historical reusable caller as a local ordinary job would invent execution.
Each alternative was rejected.

## Implementation decision

Use shell Gitlink/HEAD equality, exact setup/verifier/context ordering, separate
closed inventory classes, and a closed historical workflow-call mapping. Its six
required string inputs, same-name forwarding, deny-default permissions,
`contents: read`, single immutable nested call at
`8ae707d72f1a8acb25d239e55e28a73cbc7522b1`, and absence of concurrency overrides
are verified. Only two protected broker jobs admit the exact authenticated
`ci/run-trusted-framework.py --tool python-interpreter` verifier.

## Changed files and tests

18 composite action definitions; the connector Python workflow checker and its
`test_python_version_contract.py`; `workflow_sources.py` and
`tests/connector_adapter/test_workflow_sources.py`; paired connector integration
documentation and this record. Tests execute source-gate positive/negative cases,
reject unproven context exemptions, mutate historical grants/pins/inputs/jobs,
and reject direct verifier substitution in protected jobs.

## Commands and results

`FRAMEWORK_PYTHON` denotes the explicit Framework-owned Python 3.14 test venv.
The local execution plan retains complete context/environment command arguments.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk bypass env ON_DEMAND_TESTS=1 PYTHONPATH=.:connector_suite "$FRAMEWORK_PYTHON" -m unittest tests.connector_adapter.test_workflow_sources modsecurity_connector_tests.test_python_version_contract -q` with explicit source/revision context | 0 | 62 tests passed; Parent `430d3194fa04ca4aafcdaef6aeb256d21dc18f0c` callers projected onto feature Framework source | Local scoped verification |
| `rtk bypass git diff --check` | 0 | No whitespace errors in implementation diff | Local scoped verification |

Additional regression work updates `connector_suite/modsecurity_connector_tests/test_framework_workflow_pin_projection.py` and its independent `framework_sha_fixture.py` helper. Against the separate Parent patch, 10 projection tests and 39 updater tests passed: the six early selected-action gate pins remain closed, move with the existing pin synchronizer, reject stale/missing/extra/symbolic identities, and stop a changed Gitlink plus changed checkout before verifier execution. Independent review also passed 24 shell admission cases. Native documentation checks and Ruff lint passed. Whole-file formatter drift in three legacy Python files is present in the base too; those unrelated regions were preserved. The previously formatted `workflow_sources.py` remains formatted.

Hosted scaffold validation identified the immutable connector-source contract as an additional affected owner. Renewed exactly the 18 reviewed composite SHA entries in `ci/tooling/connector-actions.lock.json` and its aggregate in `ci/checks/security/connector_action_pins.py` from a deterministic external script after authenticating the prior contract. This maintained snapshot has no checked-in generator. Action records, source registry, authority and six unaffected sources are unchanged. Native `rtk make check-canonical-common-pins PYTHON="$FRAMEWORK_PYTHON"` and six `tests.ci_security.test_connector_action_pins` tests passed, including tampered early identity/checkout/selector checks across all 18 composites.

Hosted PR #158 Sonar job `125190844829` subsequently failed prerequisite
installation because its index update loaded only the Microsoft Ubuntu 26.04
source. The reviewed repair in `.github/workflows/sonarqube.yml` checks the exact
Ubuntu 26.04/resolute host and existing regular/readable signing key, writes a
fixed root-owned official HTTPS Ubuntu archive/security Deb822 source, and makes
any index-update error fatal. The complete existing package list, signatures,
source/secret confinement, native scope and Quality Gate remain enforced. The
exact `sonar_pr_secret_allowed` program profile is updated; twelve negative
mutations reject foreign origins/suites/keyrings, unsigned options, host/index
bypasses and dropped dependencies. No local APT or system configuration was
changed. The paired tooling guide explains this provisioning boundary.

With the explicit Framework Python 3.15 task venv, `rtk bypass env
TMPDIR=$BUILD_EVIDENCE/contracts/tmp
PYTHONPYCACHEPREFIX=$BUILD_EVIDENCE/contracts/pycache "$FRAMEWORK_PYTHON315" -m
unittest tests.security_regression.test_sonar_analysis_contract -q` passed 20
tests. `$BUILD_EVIDENCE` and `$FRAMEWORK_PYTHON315` are portable aliases recorded
in the local plan. The Sonar workflow passed the full workflow checker,
Actionlint, parsed-run `bash -n`, Ruff lint for the two changed Python files,
and `git diff --check`. These checks did not execute APT or establish a hosted
analysis result; the repaired head still requires a fresh hosted Sonar run.

The Parent follow-up reached interpreter verification successfully on hosted
Python 3.15.1, then failed closed on stale reviewed Framework source digests.
Regenerated `connector_suite/config/testing/active-cases.json` through the
existing `update-inventory-bindings.py --apply` entrypoint. Structural comparison
proves that only ten source SHA-256 values changed; every other field and list
length is identical. The inventory retains 80 execution records, 100 default
cases, 2,686 catalog cases and 2,586 on-demand cases. The generator check and
native connector admission (`--check`, no matrix execution) passed; 72 focused
inventory tests passed with two skips. After five additional Sonar maintenance
fixes, 62 workflow-source/Python-contract tests passed on Python 3.15.2. The
historical broker keeps its exact revision, grants and forwarded inputs.

## Security impact

This repairs bootstrap/source-contract correctness while retaining immutable
references, permissions, authenticated protected entrypoints, and failure gates.
Original ordering failures and alternate unproven-context/direct-protected
verifier bypasses are covered by negative tests. It is not a connector security
assessment.

## Documentation and runtime evidence

`docs/connector-integration.md` and its German companion describe the new
bootstrap and bounded composition contract. Tests provide static source and
local shell evidence. No successful current-head CI, connector-host runtime, merge, or Parent pin
update is established by this record.

## Checks not run

Hosted Sonar on Framework `44d5481cff7c7c75974e9f1f61a10f6eee4a286d`
passed APT provisioning and reached analysis. Its remaining new-code findings
were repaired without suppressions; a fresh analysis must confirm this follow-up. Connector runtime
matrices are outside this workflow-contract change. Full default inventory was
not expanded or weakened.

## Limitations and residual risk

Parent-native ordering repairs and consumption of this Framework revision are
separate prerequisites for combined CI compatibility. The old Parent Framework
pin cannot supply these new contracts. Historical nested workflow contents stay
immutable; composing their interface does not execute them.

## Final diff and review status

Implementation diff and whitespace reviewed; no secrets or raw logs recorded.
Independent review found no open blocker; hosted checks remain pending before final delivery.

The next hosted Parent head passed the inventory digest boundary, then its NGINX setup/quick-check correctly rejected the derived specialist archive. Regenerated `connector_suite/reports/testing/test-selection-archive.generated.json` with the existing `update-test-archive.py`. Its prior inventory and source digests matched the last archive baseline exactly. Changes describe the new inventory digest, 16 existing source records and one new source record, with 35 additional on-demand definitions. Native sources, Framework case catalogues and extracted native definitions are unchanged. This is declarative availability, not extra automatic selection or execution evidence. The complete native `make check-active-inventory` entrypoint passed for both projections on Python 3.15.2.

Durable updater follow-up: a normal Python patch or canonical component update
would otherwise change whole-source-bound `common.sh` without refreshing the
inventory/archive. Added the exact `sync-maintenance-test-views.py` entrypoint,
ordered native derivation and exactly those two generated paths to common
maintenance's candidate, publisher and rollback profiles. Python publication
retains the single assignment and four exact paths; prior to Draft checkout,
trusted code verifies fixed regular Git blobs, unchanged modes, strict ASCII
Python selector and byte-exact base-derived metadata. Oversized blobs are
rejected before capture; foreign Git/context selection and extra metadata
changes are rejected. No full-source derivation is run in the workflow-tool
validator's intentionally minimal snapshot. Standalone writes are fail-closed;
common-maintenance restores its snapshot on a generator failure.

Validation on actual Python 3.15.2: 105 combined publisher/security/Python/
maintenance tests passed (20.373 s), including 12 helper cases and 33 canonical
workflow/rollback cases. Ruff lint/format passed for all seven changed/new Python
files; Actionlint passed all three changed workflows. Exact reviewed program
hashes and the closed metadata path sets changed together. The metadata
projections are regenerated only after these source/test changes settle.

An offline synthetic `3.15.2` to `3.15.3` pin transition exercised the real native
Python-pin and test-view generators: exactly four output files changed, with
only the existing common-source SHA in inventory and its derived SHA in the
archive. No selection changed. All four task file contents were restored byte
for byte; this does not assert an upstream release. Final real metadata write
and read-only checks passed, as did complete native inventory/archive admission.
The final archive retains 8,021 on-demand definitions; this is distinct from
2,686 selectable catalog cases and the unchanged 100 automatic default cases.

Hosted final-head quality checking found three optional-import typing errors in the new test fixture loader. An explicit runtime guard now rejects a missing module specification or loader before import; the 12 helper tests and full-file Ruff lint/format passed again. Local Pyright remains unavailable because Node is absent; the fresh hosted check must establish its result. The archive source digest was regenerated through the same native helper.

The final Sonar review identified a remaining CLI-to-Git argument path in candidate verification. The helper now accepts no CLI revision arguments: candidate mode uses only the fixed `origin/master` and `origin/automation/update-framework-python-315` references. After validating the requested checkout, root selection returns the trusted tool-root constant. Two regression cases verify those fixed references and reject reference overrides before starting a process. Git option boundaries, bounded blobs, mode checks and byte-exact companion checks remain enforced.

The final 107 focused tests passed on Python 3.15.2 (21.222 s), including all 14 helper cases. Ruff lint/format and Actionlint passed. Native regeneration retained the unchanged automatic selection and added only the two new on-demand test definitions, for 8,023 archived definitions.

The current default branch advanced to `ea442cf90861ddc6d555e67352d053d4ad95f731` through the maintenance-import/diagnostic repair. It was integrated into this feature branch, preserving safe diagnostics and retained failure artifacts. The combined resolver run is bound to SHA-256 `99d1d2f4bd3416cdf82dab590c2dee5bdf1937570a2c4a94fdd91e76ce06a98a`. OSV adds one exact current default-branch compatibility tuple with its verified `3.14.10` selector; both earlier exact tuples remain supported.

Newly supplied run `41436076145`, job `125246693705`, failed on that default revision because canonical maintenance omitted the native updater's registered `.github/workflows/ci-findings-regressions.yml` output from its transaction path policy. One explicit filename is added. Three regression tests cover registry completeness, real native workflow projection and apply/rollback with neighboring-path rejection. The unchanged caller-bound plan (internal SHA-256 `9d99bdc3523a4ba69e8280ce031461744d8c8f09b769750c6cb1c8d09a7177db`) was replayed offline against the exact archived failing revision plus this single-path correction: all 43 safe updates succeeded across 22 generated paths. No component updates were published by this replay.

The nested CRS regression runner now preserves an explicitly selected external `PYTHONPYCACHEPREFIX` while keeping bytecode writes disabled and retaining its original closed environment. A cold Python 3.15 test-module import took 2.128 s, exceeding the existing 2 s readiness bound before the FIFO operation. With the normal warmed external cache, the unchanged FIFO test passed in 1.237 s, and the complete 10-test CRS module passed in 58.329 s, including the nested 29-case contract suite. An independent read-only probe passed as well. No FIFO deadline, rejection assertion, reader control or CLI timeout changed.

The user additionally requested the versions listed in the open dependency-review issues: #161 (CPython 3.15.2) is covered by the interpreter migration; #160 is implemented by advancing Ruff from 0.16.10 to 0.17.3. The [official Ruff 0.17.3 release](https://github.com/astral-sh/ruff/releases/tag/0.17.3) is the latest stable release and is neither draft nor prerelease. Its immutable tag commit is `ba65abf8ba7bfbcc059f7fb9712be5ba9cab6abc`; the Linux x64 GNU artifact SHA-256 `2b0890f5a55900af741f133918c2656919bbf18c2ab7741b4ca8403a90e647a9` matches both the official checksum and GitHub asset digest. The existing native checksum-locked fetcher installed the reviewed binary into external task storage. Both exact quality-workflow commands passed with that binary: lint and format checking of 42 files. No rule, formatting configuration or source-style changes were required. Only the three changing Ruff pin fields and their generated lock record are advanced; unrelated compatible updates from the archived 43-update plan are outside this additional issue scope.

The default branch subsequently advanced to `68ca7b411db12ed96ee6208aa792b43e8043470c` through an independent MRTS gitlink update. The unpublished maintenance compatibility tuple now names that exact base with the independently verified `3.14.10` selector. The feature branch integrates the maintenance-code repair from `ea442cf`; it does not change or initialize MRTS. The existing Framework and Parent MRTS revision remains selected in the tested integration.

The intervening non-MRTS default-branch commit `ff7cae78e085e179950c4b871bbf1d5327c69069` (PR #159) is also integrated. Both generated-view merge conflicts were resolved by retaining the incoming generated baselines and running the existing native generators against the combined sources. Relative to that incoming inventory, exactly ten source SHA leaves change; all selection fields and lists are identical. All archive native/extraction/case fields are retained, with 8,034 on-demand definitions after native derivation. Complete inventory/archive admission passed. An independent focused Python 3.15 run passed 43 shared-tooling tests (23 coverage, 19 safe-evidence inputs, one changed FIFO artifact case); it is not connector runtime or historical qualification. The MRTS gitlink is unchanged by this feature branch.
