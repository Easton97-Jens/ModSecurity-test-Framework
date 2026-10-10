# Change record

**Language:** English | [Deutsch](20261008-35-native-test-assertion-quality.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-35-native-test-assertion-quality |
| UTC date | 2026-10-08 |
| Framework base revision | 4e208ad9b700467f98b9fbef26bfa47295db5e62 |
| Issue or pull request | Framework PR137, six published TEST findings |

## Motivation and problem statement

Published rules S3415, S5778 and S5906 identify inconsistent assertion operand
classification, ambiguous exception targets and non-specific assertions in
four native-evidence test modules. The full published rule descriptions and
issue flows were inspected before changes.

## Affected components and security boundaries

Only four `tests/no_crs/test_nginx_native_*.py` modules and this paired record
change. Production validators, catalog/schema, selection implementation,
canonical proof and connector Source remain unchanged. Tests must retain
their original negative-proof strength.

## Acceptance criteria

Assertions remain actual-first. Exception contexts contain only the target
operation, with setup outside. False means the boolean singleton, not arbitrary
falsiness. Subset comparison retains the same inclusive boundary. Full affected
tests, syntax, diff and all documentation checks must pass.

## Alternatives considered

Reversing the input-invariance oracle or suppressing Sonar would obscure the
test contract. `assertFalse` alone would accept unrelated false-like values.
Central validator changes are neither necessary nor authorized.

## Implementation decision

Name the post-operation input tuple explicitly before comparing it with the
original snapshot. Move namespace construction and strict-reader validation
outside expected-exception contexts. Use `assertIs(actual, False)` and
`assertLessEqual(actual_set, expected_set)` without altering fixtures or cases.

## Changed files and tests

The canonical-binding, operation-contract, operation-projection and native-
selection test modules receive six focused changes. External characterization
of the actual phase1 test rejects `None`, integer zero, empty list/string and
`True` at the strict False assertion. No new runtime cases are introduced.

## Commands and results

Commands were RTK-wrapped with the Framework-owned Python, explicit isolated
`FRAMEWORK_ROOT` and external cache/temp roots supplied through the environment.
Run-scoped logs are identified by basename below; no checkout-specific absolute
paths are published here.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `python -m unittest -v tests.no_crs.test_nginx_native_canonical_binding tests.no_crs.test_nginx_native_operation_contract tests.no_crs.test_nginx_native_operation_projection tests.no_crs.test_nginx_native_selection` before changes | 0 | 47 tests pass; baseline behavior | `stream-c-test-quality-baseline.log` |
| Same command after changes | 0 | 47 tests pass | `stream-c-test-quality-green.log` |
| Controlled actual phase1 test with patched result values | 0 | Five incorrect False-like/boolean values rejected | `stream-c-test-quality-assertion-controls.log` |
| `make check-documentation` | 0 | Links, bilingual variables, repository paths and paired records pass; 892 files, zero obsolete paths | `stream-c-test-quality-docs.log` |
| `python -m py_compile tests/no_crs/test_nginx_native_canonical_binding.py tests/no_crs/test_nginx_native_operation_contract.py tests/no_crs/test_nginx_native_operation_projection.py tests/no_crs/test_nginx_native_selection.py` | 0 | All four modules compile | Task command output |
| `rtk proxy git diff --check` | 0 | Whitespace passes | Task command output |

## Security impact

No security remediation is claimed. Exception tests now exclude setup failures
from target-failure proof; boolean identity becomes stricter rather than weaker.
Existing negative cases and required selection scope are preserved.

## Documentation and runtime evidence

This English/German record documents the test-only change. No native runtime,
build or lifecycle evidence was collected. The 97 required cases and 45 final
native runtime gaps remain unchanged.

## Checks not run

Native builds/runtime, dependency mutation and Sonar publication belong to
Root and were not run. Local tests do not establish published scanner closure.

## Limitations and residual risk

A fresh Root Sonar analysis must confirm all six findings are closed. This
slice does not alter or prove production canonical acceptance.

## Final diff and review status

Scoped four-module diff reviewed for assertion direction, exact boolean type,
exception boundaries and unchanged fixtures. No secrets or raw sensitive
evidence are included. Syntax, all documentation checks and whitespace pass.
The normal atomic Framework commit is supplied at handoff.
