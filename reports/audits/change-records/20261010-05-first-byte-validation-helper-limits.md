# First-Byte validation: bounded helper responsibilities

**Language:** English | [Deutsch](20261010-05-first-byte-validation-helper-limits.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261010-05-first-byte-validation-helper-limits |
| UTC date | 2026-10-10 |
| Framework base revision | 873e51fbebbedb163a5c75a22a7abe0158861a40 |
| Issue or pull request | Framework PR #137; Parent PR #396 |

## Motivation and problem statement

The exact873 Sonar analysis found two introduced maintainability issues despite GateOK: S3776 reports First-Byte pair resolution complexity16 above15; S107 reports14 pass-error helper parameters above13. Neither requires changing the evidence contract.

## Affected components and security boundaries

Framework catalog normalization and native contract tests. Original sealed-event, transaction/profile/counter/chronology and independent PASS validation boundaries remain unchanged. No Parent, MRTS or connector product change.

## Acceptance criteria

Dedicated structural regressions fail before implementation and pass afterward. Complete normalized records and ordered validator errors remain identical for existing paired/legacy/mismatch/provenance inputs; native NoCRS, documentation and syntax checks pass. Current-source Sonar remains separately required.

## Alternatives considered

Threshold changes, suppressions and evidence-validation reductions were rejected. A larger validation context refactor was unnecessary: provenance errors are solely an ordered prefix at one caller.

## Implementation decision

Extract the unchanged supplied-transaction legacy candidate predicate from the pair resolver. Remove the provenance prefix passthrough parameter from normalized_case_pass_errors and initialize that identical ordered prefix at its only caller before extending unchanged helper errors. Existing status guards, causal checks and error ordering are retained.

## Changed files and tests

`ci/checks/catalog/no_crs_baseline.py`, `tests/no_crs/test_no_crs_baseline.py` and this new EN/DE record pair. Two native structural methods assert focused legacy delegation and the13-parameter limit. The preceding First-Byte Change Record remains unchanged.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| RTK/Python offline first-byte-quality/regression.py | 1 | Two structural tests RED | nginx-full97-followup-20261010T084822Z/first-byte-quality |
| RTK/Python offline regression.py --proposed, initial harness | 1 | Structural GREEN; harness used nonexistent catalog API, corrected externally | Same analysis directory |
| RTK/Python offline regression.py --proposed, corrected | 0 | Two structural tests GREEN;32 complete record/error differential vectors identical, including genuine paired positives | Same analysis directory |
| RTK/Python native two structural tests, tests-only | 1 | Two tests/two failures, 0.006s | first-byte-quality/versioned-red.log |
| RTK/Python native SeparatedNginxFirstByteTest, integrated source | 0 | Eight tests, no skips, 7.312s | first-byte-quality/versioned-green.log |
| RTK/Python regression.py --installed against preserved873 source | 0 | Two structural tests;32 full-output differentials identical, genuine positives PASS | first-byte-quality/versioned-differential.log |
| RTK/make test-no-crs-contract | 0 | 423 tests, no skips, 181.211s | first-byte-quality/versioned-suite.log |
| RTK/make check-documentation test-change-record-contract | 0 | Documentation and four CR tests, 0.087s | first-byte-quality/versioned-docs.log |
| RTK/Python AST parse; RTK/git diff --check | 0 | Both changed Python files valid; whitespace valid | Observed tool receipts |

## Security impact

No security remediation is claimed; no validator, rule, Gate or threshold is weakened. Transaction identity, same-run sealed authority, native-profile restrictions and causal evidence remain identical.

## Documentation and runtime evidence

This EN/DE record documents a behavior-preserving Framework helper refactor. Differential checks reuse immutable genuine AB evidence and in-memory negative inputs. No new runtime evidence was collected; replay is not a new invocation or Full97.

## Checks not run

Full native lint, current-source Sonar, publication and new bounded runtime remain coordinator-owned. No Full97 or protected workflow was run. Structural delegation and parameter checks are not a claim that a new remote Sonar analysis already completed.

## Limitations and residual risk

Structural/differential checks are not a substitute for current-source Sonar analysis or a fresh artifact-bound runtime. Global Required coverage and protected prerequisites remain separate.

## Final diff and review status

Integrated after explicit GO from clean873 and observed native tests-only RED. Exactly two Python files plus this new EN/DE pair are modified/untracked; preceding CR04, catalog, schemas, Required scope, Parent and MRTS unchanged. Original source was retained externally and confirmed byte-identical before editing. Whitespace/scope checks pass. Independent final static review and coordinator diff review found no material contract or scope deviation. Normal separate delivery remains pending.
