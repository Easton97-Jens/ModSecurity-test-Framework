# Change record

**Language:** English | [Deutsch](20261115-03-connector-c-standard-temp-root.de.md)

**Pre-publication validation snapshot.** This record captures the implemented consumer repair and observed local checks. No hosted CI success, delivery identity, merge or Parent pin change is claimed.

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261115-03-connector-c-standard-temp-root |
| UTC date | 2026-11-15 |
| Framework base revision | `03f50ce2f6854ad9a02227dfc5939ded23e838f6` |
| Issue or pull request | No pull request for this repair at this snapshot; task branch `codex/fix-updater-runner-temp`. |

## Motivation and problem statement

Parent updater run `43723917343` reached the quick check but failed at `check-remaining-connectors-c-standards.sh:93`, which requires `RUNNER_TEMP`. The older trusted namespace helper creates and supplies a private `TMPDIR` without setting `RUNNER_TEMP`. The consumer therefore rejects an explicitly supplied private temporary root.

## Affected components and security boundaries

The change is limited to temporary-root selection in the Framework C-standard check. Namespace helpers, the authenticated bridge, Parent and MRTS remain unchanged. The selected temporary directory must remain explicit; an implicit `/tmp` fallback is outside the contract.

## Acceptance criteria

Keep `RUNNER_TEMP` preferred when supplied. Use explicitly supplied `TMPDIR` only when `RUNNER_TEMP` is unset. A set but empty or nonexistent primary root must not fall back to `TMPDIR`; missing both roots must fail. Do not infer `/tmp`. Preserve the existing C-standard checks, compiler failure status, output cleanup and namespace isolation.

## Alternatives considered

Changing the trusted helper, bridge or Parent would expand the ownership boundary and require a separate delivery chain. Using an implicit system temporary directory would lose the explicit private-root contract. Adapt only the consumer to the private `TMPDIR` already supplied by the trusted namespace.

## Implementation decision

The three-line consumer fix selects `RUNNER_TEMP` first and falls back to explicit `TMPDIR` only when the primary variable is unset. Missing, empty or nonexistent selected roots remain errors. No namespace, bridge, Parent or MRTS implementation is changed. The generated archive was refreshed through its native generator for seven new on-demand tests: its definition count changed from 8469 to 8476, while `inventory_sha256` and the active inventory remained unchanged.

## Changed files and tests

- `check-remaining-connectors-c-standards.sh`: selected consumer temporary-root handling.
- `connector_suite/modsecurity_connector_tests/test_remaining_connectors_c_standard_temp.py`: seven on-demand shell regressions.
- `connector_suite/reports/testing/test-selection-archive.generated.json`: native generated archive refresh for those seven tests.
- `reports/audits/change-records/20261115-03-connector-c-standard-temp-root.md` and `reports/audits/change-records/20261115-03-connector-c-standard-temp-root.de.md`: this paired record.

The seven new tests exercise the real POSIX consumer with a compiler stub, actual `-o` output paths and cleanup checks. Coverage includes primary-root selection, explicit fallback, precedence and negative cases for both roots missing, empty primary, nonexistent primary and compiler status `23`. No native compiler or runtime qualification is inferred. Six existing maintenance tests and one existing namespace-environment test also passed.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Parent updater quick-check / result enforcement | 2 / 1 | Rejected missing `RUNNER_TEMP` at the C-standard consumer although the trusted namespace supplies private `TMPDIR`. | Parent run `43723917343` |
| `"$PYTHON" -B -m unittest -v modsecurity_connector_tests.test_remaining_connectors_c_standard_temp`, before the fix | 1 | Seven tests: five passed, two failed in 7.173 seconds; explicit-`TMPDIR` and compiler-failure cases both stopped with missing-`RUNNER_TEMP` exit 2. | Local Framework validation |
| Same regression command after the fix | 0 | All seven passed in 5.335 seconds. | Local Framework validation |
| `sh -n` on the consumer | 0 | POSIX shell syntax passed. | Local Framework validation |
| `update-inventory-bindings.py --check` | 0 | `INVENTORY_BINDINGS_VERIFIED`; inventory unchanged. | Local Framework validation |
| Native archive generator and `update-test-archive.py --check` | 0 | Archive regenerated and verified; on-demand definitions 8469 to 8476, unchanged `inventory_sha256`. | Local Framework validation |
| Six existing maintenance tests and one existing namespace-environment test | 0 | All seven passed in 0.079 seconds. | Local Framework validation |
| `sonar analyze secrets` on source, tests and archive | 0 | Selected inputs passed; raw scanner output suppressed. | Local Framework validation |

Checks used the Framework-owned virtual environment (`PYTHON`) on existing WSL Python `3.13.7`, Parent revision `ab7a32ab464a3dd8fe119b10d3936acd4b4ae557` and the native Framework base `03f50ce2f6854ad9a02227dfc5939ded23e838f6` plus task changes. `ON_DEMAND_TESTS=1`, explicit `TEST_ROOT`/`PYTHONPATH` and external temporary output storage selected the test context. Independent source review reported no findings. The historical failed run does not establish the result of this repair.

## Security impact

The repair retains an explicitly supplied temporary-root requirement and adds no implicit system-directory fallback. The fallback is unset-only: an empty or nonexistent primary root is not silently replaced. Negative tests retain missing-root rejection, compiler status `23` and cleanup behavior. Namespace isolation, trusted code selection, permissions and MRTS remain unchanged. No security remediation or runtime qualification is claimed.

## Documentation and runtime evidence

This English/German record pair documents the same selected scope and limitations. The failed hosted run is diagnostic evidence only. No successful connector runtime or complete hosted updater execution is claimed for the changed consumer.

## Checks not run

A complete hosted updater rerun, full `quick-check`, native C-compiler/runtime execution and canonical Python `3.15` CI have not run for this snapshot. The focused shell tests use a compiler stub and prove only the stated consumer behavior. Final record-schema, edited-record Secrets and whitespace/diff checks follow the last documentation edit separately.

## Limitations and residual risk

The consumer relies on the caller supplying a suitable explicit private root. This repair does not qualify every namespace lifecycle or connector runtime. Delivery identity and current hosted checks must be assessed separately; no Parent gitlink update or Framework merge is claimed.

## Final diff and review status

Independent source review reported no findings. All seven new shell tests, seven selected existing tests, consumer syntax, inventory validation and generated archive checks passed. Source, tests and archive passed Secrets scans. Final edited-record Secrets scans, paired-record schema validation and whitespace/diff checks follow this last documentation edit. Framework delivery remains separate from Parent and MRTS delivery; no hosted CI or merge result is claimed.
