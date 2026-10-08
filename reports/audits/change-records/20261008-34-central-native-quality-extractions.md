# Central native quality extractions

**Language:** English | [Deutsch](20261008-34-central-native-quality-extractions.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-34-central-native-quality-extractions |
| UTC date | 2026-10-08 |
| Framework base revision | 4e208ad9b700467f98b9fbef26bfa47295db5e62 |
| Issue or pull request | Framework PR 137, published-revision Sonar readback r2 |

## Motivation and problem statement

Ten central findings concern repeated literals (S1192), nested conditional expressions (S3358), and cognitive complexity (S3776). The existing configuration-template complexity finding is included, not treated as remotely closed.

## Affected components and security boundaries

Only `ci/checks/catalog/no_crs_baseline.py`, one disjoint characterization test, and this EN/DE pair change. Source authority, retained original bytes, typed provenance, selection and canonical evidence rejection remain strict.

## Acceptance criteria

Keep exact public outcomes and diagnostic precedence, retain all Required cases, pass characterization against both original and refactored implementations, and pass current No-CRS and documentation checks.

## Alternatives considered

Suppressions, reduced validation, and changing catalog expectations were rejected. Broad validator rewrites were unnecessary; small deterministic extractions suffice.

## Implementation decision

Name the first-byte fixture and catalog-schema literals. Extract runner-path checks, the exact native probe predicate, parser diagnostics, native outcome selection, single-record finalization, and generic PASS completeness checks. The native predicate retains the genuine serialized Common engine-decision vocabulary; no event is manufactured or relabeled. Existing call order, exception handling, proof routes and diagnostic strings are retained.

## Changed files and tests

`tests/no_crs/test_central_quality_characterization.py` covers missing/invalid runner paths, identity diagnostic order, closed-contract exceptions, native status/reason combinations, missing authority, configuration-template precedence, specialized early-return routes, generic completeness order, retention order and duplicate same-transaction native observations. Existing raw-artifact and valid-rules tests exercise rehashed foreign identities, rules, phases, payload boundaries and cleanup.

## Commands and results

All commands were RTK-proxied with the Framework virtualenv, bytecode disabled and an externally provided TMPDIR. Evidence basenames refer to the coordinator-approved task analysis directory, not checkout-local output.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `python -m unittest tests.no_crs.test_central_quality_characterization tests.no_crs.test_configtest_artifacts tests.no_crs.test_valid_rules_file_receipt -v` | 0 | 31 baseline and 31 post-refactor tests | `stream-a-central-quality-baseline.log`, `stream-a-central-quality-green.log` |
| In-memory compile of `git show 4e208ad9b700467f98b9fbef26bfa47295db5e62:ci/checks/catalog/no_crs_baseline.py`, followed by the final characterization module | 0 | All 13 tests also pass against original behavior | `stream-a-central-quality-final-characterization-baseline.log` |
| `python -m unittest discover -s tests/no_crs -v` | 0 | 384 tests; current selection included | `stream-a-central-quality-full-no-crs.log` |
| `python -m unittest tests.no_crs.test_central_quality_characterization tests.security_regression.test_no_crs_catalog_maintainability_wave tests.no_crs.test_nginx_native_selection tests.no_crs.test_protocol_selection_scope -v` | 0 | 34 final characterization/selection tests after splitting status and failure test methods | `stream-a-central-quality-final-focus.log` |
| `python ci/checks/documentation/check-change-records.py`, `check-repository-path-references.py`, `check-doc-links.py`, `check-variable-documentation.py` | 0 each | Record structure, repository-local paths, links and EN/DE checks | `stream-a-central-quality-doc-*.log` |
| `python -m ruff check ci/checks/catalog/no_crs_baseline.py tests/no_crs/test_central_quality_characterization.py` | 1 | Ruff unavailable in the existing Framework environment; no installation | `stream-a-central-quality-ruff.log` |

## Security impact

This is behavior-preserving quality work, not a security remediation or a new runtime proof. No authority, identity, validation, cleanup or privacy requirement is relaxed.

## Documentation and runtime evidence

This paired record documents source-level work and controlled fixtures. No native execution, build or host evidence was collected. All 97 selected Required cases remain; the 45 final runtime gaps remain NOT RUN.

## Checks not run

No native build/runtime, dependency installation, remote Sonar rescan, push, Gitlink update or MRTS change. Ruff could not run because the module is absent; coordinator integration lint remains required.

## Limitations and residual risk

Source refactoring does not establish remote issue resolution or a Quality Gate result. Sonar verification remains pending a scan of the integrated revision. Unit fixtures cannot establish host runtime acceptance.

## Final diff and review status

Scoped diff reviewed for exact predicate/call/diagnostic preservation and whitespace. Normal isolated-worktree delivery only; coordinator owns integration and final source/runtime verification.
