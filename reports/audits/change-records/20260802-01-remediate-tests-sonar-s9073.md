# Change record — remediate Framework test SonarQube Cloud S9073 findings

**Language:** English | [Deutsch](20260802-01-remediate-tests-sonar-s9073.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260802-01-remediate-tests-sonar-s9073` |
| UTC date | 2026-08-02 |
| Framework base revision | `5cb371949ceafec6685cf716ba50a75d0f448bd1` |
| Issue or pull request | SonarQube Cloud Framework `tests/` baseline; Framework PR pending |

## Motivation and problem statement

The current Framework `master` analysis reports seven open `python:S9073`
maintainability findings in `tests/`. Each finding identifies a composite
assertion that combines the existence of an import specification with the
existence of its loader.

## Affected components and security boundaries

The changed paths are Framework test modules only. No connector behavior,
runtime evidence, network, filesystem, subprocess, secret, or MRTS boundary
is changed.

## Acceptance criteria

- Split all seven current `tests/` S9073 composite assertions.
- Preserve the assertion conditions and test behavior.
- Pass focused Framework validation, lint/documentation checks, and current
  PR-head SonarQube Cloud analysis without suppressions or gate changes.

## Alternatives considered

Keeping the composite assertions or suppressing S9073 would leave current
maintainability findings unresolved. A broader test refactor is unnecessary:
separate assertions provide the requested diagnostic clarity without changing
the imported-module contract.

## Implementation decision

Each import-specification and loader prerequisite is asserted independently.
The same boolean conditions are required before `module_from_spec` or
`exec_module` is called, so observable success and failure semantics are
preserved.

## Changed files and tests

- `tests/security_regression/test_no_crs_catalog_maintainability_wave.py`
- `tests/no_crs/test_transport_hardening_evidence.py`
- `tests/protocol_client/test_check_protocol_evidence.py`
- `tests/protocol_client/test_protocol_client.py`
- `tests/no_crs/test_no_crs_baseline.py`
- this paired Change Record

No new test scenario is required because the existing tests exercise exactly
the import paths whose equivalent preconditions were made independent.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused five-module unittest invocation | 0 | 5 tests passed in 0.069 s; each changed module imported and exercised | External task evidence `framework-tests-sonar-20260802` |
| `make lint` with external build and temporary roots | 0 | Shell/Python checks, contracts, security regression tests, documentation, and whitespace check passed | External task evidence `framework-tests-sonar-20260802` |

## Security impact

No security remediation is performed. The change does not alter a security
boundary or weaken a security control.

## Documentation and runtime evidence

This paired Change Record is the only reader-facing documentation change. No
connector runtime or lifecycle evidence is collected because this is a
Framework test maintainability repair.

## Checks not run

The hosted SonarQube Cloud analysis cannot run before a pull request exists.
It remains required for the exact published PR head; no local suppression,
Quality Gate change, or scanner exclusion was introduced.

## Limitations and residual risk

The local repair can prove equivalent Python test preconditions but cannot
itself prove the hosted SonarQube Cloud result; the PR's current-head analysis
remains required.

## Final diff and review status

Local scoped-diff, whitespace, and test/lint review are complete. The final
hosted PR-head review remains pending publication.
