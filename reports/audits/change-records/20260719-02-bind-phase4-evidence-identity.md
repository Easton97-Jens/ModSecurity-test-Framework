# Change record

**Language:** English | [Deutsch](20260719-02-bind-phase4-evidence-identity.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260719-02-bind-phase4-evidence-identity` |
| UTC date | 2026-07-19 |
| Framework base revision | `9a729226d2e040d07d7e7a4acebf201faf06ab37` |
| Issue or pull request | FND-CROSS-0006; [Framework PR #34](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/34). This record preserves verified prior-head delivery evidence; its status follow-up requires fresh exact-head verification before merge. |

## Motivation and problem statement

FND-CROSS-0006 showed that the authoritative strict Phase-4 gate could accept a copied rule-1100301 event by matching first-byte fields alone, without binding it to the selected workload.

## Affected components and security boundaries

- `ci/checks/evidence/check_full_lifecycle_evidence.py`
- `tests/no_crs/test_no_crs_baseline.py`

The security boundary is canonical evidence promotion. Event, result, manifest, and the specific selected live Phase-4 PASS record for each claim must agree on connector, non-empty run ID, integration mode, and transaction identity, as well as rule and phase.

## Acceptance criteria

- Foreign or missing event run ID, connector, integration mode, or transaction identity fails closed.
- A result/manifest workload-identity mismatch fails closed.
- An event transaction identity not supplied by the selected live Phase-4 PASS record cannot satisfy that claim.
- The identity-consistent selected control passes the first-byte, no-full-buffering, event-privacy, and promotion checks.
- Parent files, Parent gitlink, and MRTS remain unchanged.

## Alternatives considered

Parent consumer wiring, filename matching, PASS-only selection, and event-only metadata were rejected because they do not repair the independently authoritative Framework predicate. A host-runtime run cannot replace deterministic Framework checker coverage.

## Implementation decision

The strict matcher derives selected identity from result and manifest, requires it on the specific live selected Phase-4 PASS record for the claim, and requires the event transaction ID to belong to that record before comparing first-byte fields. Missing or mismatched identity, including a selected Phase-4 record workload-identity mismatch, fails closed. The unrelated source-fixed FND-FRAMEWORK-0017 CI-parser control is excluded.

## Changed files and tests

- `ci/checks/evidence/check_full_lifecycle_evidence.py`: binds strict event matching to selected workload identity.
- `tests/no_crs/test_no_crs_baseline.py`: adds an identity-consistent control, foreign/missing identity regressions, a result/manifest mismatch regression, and a selected Phase-4 record identity-mismatch regression.
- This English/German Change Record pair records the Framework-only remediation.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused four-method Framework `unittest` with external temporary root | 0 | Selected control passed; foreign/missing event identity, result/manifest mismatch, and a selected Phase-4 record identity mismatch were rejected. | `20260719T224634Z-framework-phase4-blocker-remediation-46e971f1` |
| `python -m py_compile` for the two changed Python files with external bytecode root | 0 | Both files compiled. | `20260719T224634Z-framework-phase4-blocker-remediation-46e971f1` |
| `make -C "$FRAMEWORK_ROOT" ... test-no-crs-contract` with external roots | 0 | 84 No-CRS contract tests passed. | `20260719T224634Z-framework-phase4-blocker-remediation-46e971f1` |
| `make -C "$FRAMEWORK_ROOT" ... lint` with external build and temporary roots | 0 | Repository lint, security/data-flow, documentation, Change-Record, catalog, and whitespace checks passed. | `20260719T224634Z-framework-phase4-blocker-remediation-46e971f1` |
| Framework `git diff --check` | 0 | No whitespace errors in the task diff. | local pre-commit review |
| Focused final security diff review | PASS | No validated residual finding; the cross-case transaction-pooling candidate is fail-closed by claim-specific case binding. | local pre-commit review |

## Security impact

The original missing-run-ID acceptance control was reproduced before the fix. The new regressions retest foreign and missing run ID, connector, integration mode, transaction identity, result/manifest mismatch, and selected Phase-4 record identity mismatch; the legitimate selected control remains accepted. No security control or MRTS boundary was weakened.

## Documentation and runtime evidence

This paired Change Record is the only reader-facing Framework documentation change. No connector host runtime was collected: this is a Framework validator repair, while host runtime evidence is Parent-owned.

## Checks not run

At the prior PR head `d7b9e67bb11435c7bf7ce8a84bc73724dd943ac6`, applicable GitHub Actions passed, SonarQube Cloud reported a passed Quality Gate, and no reviews or review threads existed. This status update changes the PR head, so its exact-head GitHub Actions, SonarQube Cloud, and review/thread verification must be repeated before merge. The local Framework interpreter is CPython 3.14.4 while the checked-in CI contract targets CPython 3.13, so local tests are not CI-parity evidence. MRTS tests are not applicable.

## Limitations and residual risk

The repair establishes only the reusable Framework identity-validation contract; it does not produce or promote connector host artifacts. FND-GITHUB-0006 remains an independent Default Setup/advanced CodeQL uploader issue. No risk is accepted for FND-CROSS-0006; current-head CI/Sonar evidence remains required for `verified_pr`.

## Final diff and review status

Implementation, focused/full No-CRS validation, repository lint, whitespace review, and final security diff review were completed before PR #34 was created. At its prior exact head, applicable GitHub Actions and SonarQube Cloud passed and no review feedback existed. This delivery-status update creates a new head; fresh exact-head CI, Sonar, review, merge, and resulting-master evidence remain required and are retained in task-completion evidence without a self-referential commit loop.
