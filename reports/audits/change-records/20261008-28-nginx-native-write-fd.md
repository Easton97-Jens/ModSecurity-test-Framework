# Change record

**Language:** English | [Deutsch](20261008-28-nginx-native-write-fd.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-28-nginx-native-write-fd |
| UTC date | 2026-10-08 |
| Framework base revision | `41035763109e6f3acf5073d7bff07def3c351fd2` |
| Issue or pull request | Bounded coordinator-approved Source-whitelist audit follow-up |

## Motivation and problem statement

The actual Parent nginx_write_fault.c observation writer emits seven keys, including integer fd. The new fact mapper's six-key contract therefore rejected genuine short-write and would-block rows. Source inspection found the mismatch; no runtime was inferred.

## Affected components and security boundaries

Only the owned native fact-contract write-result branch, its focused tests and this paired record. Parent producer, strict reader, central normalization, schemas, catalog, MRTS and Gitlinks are unchanged.

## Acceptance criteria

Accept exactly the seven actual payload-free Source keys: pid, fd, peer_port, requested_bytes, returned_bytes, errno, fault_triggered. Require fd to be an exact integer in the nonnegative signed32 C-int range. Retain all worker/peer/fault/resume checks; reject boolean, float, string, null, negative, overflow, missing or extra fields.

## Alternatives considered

Dropping fd from retained observations would rewrite native evidence. Permitting arbitrary extra fields would weaken the closed payload-free contract. Neither is used.

## Implementation decision

Add only fd to the exact key set and validate its type/range. Return the same actual resumed outcome and original observation SHA origin; no event or native record is rewritten. Range validation describes the Source writer's descriptor scalar, not proof that a live descriptor remains open.

## Changed files and tests

Existing tests/runners/nginx_native_operation_contract.py and tests/no_crs/test_nginx_native_operation_contract.py plus this pair. Two new controlled tests cover both actual Source-shaped seven-field write variants and malformed/missing/extra fd controls. These fixtures are not native runtime proof.

## Commands and results

Test-first `rtk proxy env PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python -m unittest tests.no_crs.test_nginx_native_operation_contract.NativeContractTests.test_source_shaped_seven_field_write_rows_keep_fd_and_prove_resume tests.no_crs.test_nginx_native_operation_contract.NativeContractTests.test_write_fd_exact_type_range_and_closed_source_fields -v` exited1: both genuine seven-key variants rejected.

After correction, `rtk proxy env TMPDIR=<external-task-runs> PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python -m unittest tests.no_crs.test_nginx_native_operation_contract tests.no_crs.test_nginx_native_operation_projection tests.no_crs.test_nginx_native_operation_bundle -v` passed48 tests with exit0 using the Framework-owned interpreter. `make check-documentation PYTHON=<framework-python>` passed with exit0 through RTK; staged whitespace checks passed. No native producer/build was executed.

## Security impact

No product security remediation. Exact seven-key closure prevents metadata/payload expansion; exact fd type excludes bool-as-int and overflow. Actual worker, peer, fault and subsequent positive resumed-write checks remain required.

## Documentation and runtime evidence

Paired EN/DE record. Pure Source-shaped unit fixtures only; no canonical PASS, current runtime or all-required completion claim.

## Checks not run

Native build/runtime/full E2E and remote scans are outside this bounded follow-up. No tools installed.

## Limitations and residual risk

Root must integrate the separate corrective commit and preserve strict bundle authority/offline revalidation. The previous whole contract-suite run does not prove these newly added fd controls; fresh focused results are reported separately.

## Final diff and review status

Four scoped files; original artifact bytes unchanged, no central edits. Normal commit handed to coordinator after checks.
