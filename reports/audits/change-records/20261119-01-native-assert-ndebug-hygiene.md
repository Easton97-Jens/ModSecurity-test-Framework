# Change record

**Language:** English | [Deutsch](20261119-01-native-assert-ndebug-hygiene.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261119-01-native-assert-ndebug-hygiene |
| UTC date | 2026-11-19 |
| Framework base revision | `95f228936efe17fda24f21323ad87cd698940b48` |
| Issue or pull request | Framework pull request for branch `fix/test-assert-ndebug-hygiene-20261119`; companion Parent change `CR-20261119-verified-cppcheck-findings-connector-hardening` |

## Motivation and problem statement

Native C tests used `assert()` around work the test must perform: fixture file writes,
`fclose()`, path formatting, thread and socket setup and the operation under test. With
`-DNDEBUG`, `assert()` expands to nothing. Such a build skipped that work, could read
uninitialised fixture paths, leaked `FILE` handles, and could print `PASS` without
exercising the code. Reproduction on the base revision: `test_nginx_engine_call_budget.c`
compiled with `-DNDEBUG` and two deliberately broken expectations exited 0; with
`-Werror` it did not even compile, because the whole test body disappeared. Cppcheck
reported these sites as `assertWithSideEffect` and `resourceLeak`.

## Affected components and security boundaries

Framework native test sources under `connector_suite/` and the generated specialist archive.
The boundary is test validity: a vacuous pass hides product regressions. No product code
and no connector runtime behaviour is changed by this record.

## Acceptance criteria

- Every non-I12 Framework C/C++ test source that includes `<assert.h>` undefines `NDEBUG`
  before its first include.
- Every `assertWithSideEffect` site reported by a realistic Cppcheck run of the changed
  non-I12 sources is converted to `TEST_REQUIRE()`, which always evaluates its argument.
- An `-DNDEBUG` build still runs the checks and fails on a broken expectation.
- A regression test for the Parent SPOP `rule_id` formatting fix exists.
- Existing behaviour of the affected tests is unchanged; the specialist archive matches
  its generator and the active inventory stays at 100 cases.

## Alternatives considered

- `#undef NDEBUG` only: guarantees execution, but analyzers still model `assert()` as
  removable and keep reporting leaks; rejected as the only measure.
- Converting every `assert()` (about 1,900): large, unreviewable diff; rejected.
- A shared new header: some sources are compiled from extracted or materialized copies,
  where a new relative include is fragile; a small per-file definition was chosen.

## Implementation decision

- 28 non-I12 sources/headers received an `#undef NDEBUG` guard before the first
  preprocessor include. The 16 sources/headers with side-effect assertions received a
  guarded `TEST_REQUIRE()` definition (`fprintf` to `stderr` and `abort()` on failure).
- 419 assertion sites were converted to `TEST_REQUIRE()`: the sites from the original
  whole-checkout scan plus those found by a realistic scan with real include paths. Only
  the macro name changed; expressions are untouched.
- I12 harness sources (`/i12/` paths and `*_i12_*` probes) remain unchanged under the I12
  work stop; this is enforced by the regression test's exemption and documented.
- New `test_native_assert_ndebug_contract.py` (on-demand): checks the guard order in all
  covered sources and compiles `test_nginx_engine_call_budget.c` with `-DNDEBUG`, requiring
  the control to pass and both a broken `TEST_REQUIRE()` and a broken plain `assert()` to
  fail.
- `test_haproxy_spop_event_sink_failures.py`: new `rule-id=` harness scenario and
  `test_phase4_event_renders_only_positive_signed_rule_ids`.
- `connector_suite/reports/testing/test-selection-archive.generated.json` was regenerated
  with its generator `update-test-archive.py`.

## Changed files and tests

- 26 C test sources and 2 test headers under `connector_suite/` (guard and/or
  `TEST_REQUIRE()`), see the pull-request file list.
- `connector_suite/modsecurity_connector_tests/test_native_assert_ndebug_contract.py` (new)
- `connector_suite/modsecurity_connector_tests/test_haproxy_spop_event_sink_failures.py`
- `connector_suite/reports/testing/test-selection-archive.generated.json` (generated)
- This record pair.

## Commands and results

All commands ran through RTK with the Parent task worktree at
`b79c3d93efbb8330f121caf8fb7c1a7874195e57` as connector root and output in the
task-owned external run root `cppcheck-audit-20261119T095825Z`.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `cc -DNDEBUG` on base `test_nginx_engine_call_budget.c` with broken expectations | 0 | defect reproduced: vacuous pass | `cppcheck-audit-20261119T095825Z` |
| same with this change | 134 | `requirement failed`; unmodified control exits 0 | `cppcheck-audit-20261119T095825Z` |
| `ON_DEMAND_TESTS=1 python3 -m unittest ...test_native_assert_ndebug_contract` (plain `cc` and ASan/UBSan `CC`) | 0 | 2 tests OK | `cppcheck-audit-20261119T095825Z` |
| Cppcheck on the 26 changed C sources, base vs change, same options | 0 | `assertWithSideEffect` 432 to 0, `resourceLeak` 15 to 0 | `cppcheck-audit-20261119T095825Z` |
| `prepare-sonar-cfamily.py` against the clean base Parent | 1 | stops at pre-existing `haproxy_i10_host_caller_test.c` drift; 11 changed units compiled before it | `cppcheck-audit-20261119T095825Z` |
| Recipe compile flags (`-Werror`) for the 14 remaining changed units | 0 | 14 of 14 compile | `cppcheck-audit-20261119T095825Z` |
| `ON_DEMAND_TESTS=1` runners for all changed sources | 1 | all non-passing cases are pre-existing and identical on the base revision (strict-mode, Traefik dispatcher/mutation and HAProxy I10 materializer drift, Apache rules-set IndexError, NGINX contract drift) | `cppcheck-audit-20261119T095825Z` |
| SPOP `rule_id` regression test: base Parent vs fixed Parent | 1 / 0 | `'0' != ''`, `'4294967289' != ''` on base; OK with fix | `cppcheck-audit-20261119T095825Z` |
| `update-test-archive.py`, then `--check` | 0 | archive matches inventory and sources | `cppcheck-audit-20261119T095825Z` |
| Parent `rtk make check-active-inventory` | 0 | `active_case_count` 100, `hard_limit` 100 | `cppcheck-audit-20261119T095825Z` |

## Security impact

Restores the validity of native security and lifecycle tests for builds that define
`NDEBUG`, so a regression can no longer be hidden by a vacuous pass. No security control,
gate, suppression or threshold was weakened.

## Documentation and runtime evidence

This record pair only. No runtime or lifecycle evidence was collected; all results are
compile, unit and static-analysis evidence.

## Checks not run

- Full Framework CI and Sonar analysis: run by the pull request's CI.
- I12 harness sources: intentionally unchanged (I12 work stop).
- `make test` and the full default matrix: outside this scoped fix.

## Limitations and residual risk

- Unconverted `assert()` calls with side effects that Cppcheck cannot recognise remain;
  the `#undef NDEBUG` guard keeps them executing.
- The SPOP `rule_id` regression test expects the companion Parent fix; against an older
  Parent revision it fails by design.
- Five `assertWithSideEffect` sites in I12 sources remain.

## Final diff and review status

Diff reviewed for scope, whitespace (`git diff --check`) and secrets; no credentials or
sensitive payloads are recorded.
