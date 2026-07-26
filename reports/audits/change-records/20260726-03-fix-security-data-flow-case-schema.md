# Change record: explicit non-materializable security/data-flow descriptors

**Language:** English | [Deutsch](20260726-03-fix-security-data-flow-case-schema.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260726-03-fix-security-data-flow-case-schema |
| UTC date | 2026-07-26 |
| Framework base revision | `a7ebf5a1d9cad2b0a65a7603476a1434fdb16cf6` |
| Issue or pull request | Framework PR pending; unblocks Parent PR #74 exact-head validation |

## Motivation and problem statement

Parent PR #74's hosted runtime matrix built the Apache and NGINX adapters,
then failed while Framework case discovery attempted to treat 15
connector-neutral security/data-flow descriptors as executable YAML tests.
They have no connector-owned ModSecurity rules, and their declared
`security_data_flow` capability was not recognized by the runner schema.

## Affected components and security boundaries

- `tests/cases/security-data-flow/**`: connector-neutral descriptors only.
- `tests/runners/runner_core.py` and `tests/runners/case_cli.py`: the
  selection/materialization boundary.
- `ci/reporting/generate-case-matrix.py`: the generated runtime-inventory
  boundary.

The security boundary prevents an unsupported descriptor from being forced
into a connector runtime, reported as executable, or promoted as a PASS.
This record makes no claim about a connector's body-limit, log-safety, or
transaction-ID behavior.

## Acceptance criteria

1. Each affected descriptor is explicit about being non-materializable and is
   valid under the Framework metadata contract.
2. Force-all discovery excludes only those descriptors, while direct
   materialization rejects them.
3. The contract requires `connector-gap`, `former_xfail: true`, and
   `capabilities.runtime_verified: false`; an active case cannot use it.
4. Reports show the descriptors as non-executable and non-promotable.

## Alternatives considered

- Adding placeholder rules would make the YAML parse but would invent runtime
  behavior and can turn a security gap into a misleading result.
- Reclassifying the cases as mapped-only would discard their intentionally
  visible connector-gap inventory.
- The selected explicit metadata preserves the inventory and blocks execution
  until a connector-owned implementation provides rules and live evidence.

## Implementation decision

`runtime_materializable: false` is a narrow, validated exception to the normal
non-empty `rules` requirement. It is accepted only for former-XFAIL,
connector-gap descriptors with `runtime_verified: false`; the normal rule
requirement remains for all materializable cases. Force-all selection and
direct materialization both enforce this boundary, and the report generator
records the resulting state as `NOT_EXECUTABLE` / non-promotable.

## Changed files and tests

- Runner schema/selection and direct materialization guard.
- Report executable-state calculation.
- The 15 Framework-owned `security-data-flow` descriptors.
- English/German case-catalog documentation.
- Focused runner/CLI coverage plus report-generator regression coverage.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Parent exact PR #74 `report-governance` run `30205593649` | 1 | Reproduced original `case requires rules` after native adapter preparation passed | GitHub Actions run 30205593649 |
| `FORCE_ALL_CASES=1 ... case_cli.py list-cases` before repair | 1 | Reproduced the missing-rules schema rejection | Parent #74 remediation evidence |
| `python3 -m unittest tests.security_regression.test_security_data_flow_case_schema tests.security_regression.test_generate_case_matrix_sonar -v` | 0 | 22 runner, CLI, and report-generator controls passed | Local Framework worktree |
| `FORCE_ALL_CASES=1 ... case_cli.py list-cases` after repair | 0 | Case discovery completed and excluded the 15 descriptors | Local Framework worktree |
| `python3 -m py_compile` for the changed Python modules | 0 | Syntax compilation passed with bytecode directed to the registered external evidence area | Local Framework worktree |
| `make check-security-data-flow-cases` | 0 | All 15 descriptor cases validated | Local Framework worktree |
| `make check-doc-links check-bilingual-docs check-change-records` | 0 | Documentation links, bilingual documentation, and Change Record contract passed | Local Framework worktree |
| `make generate-test-matrix ... MODSECURITY_MRTS_VARIANT=no-mrts` | 0 | Generator smoke completed, but its non-canonical output was deliberately discarded because the no-MRTS input inventory is incomplete | Local Framework worktree |

## Security impact

The original discovery path is retested by the force-all control and now
completes without treating the descriptors as runtime cases. The direct
materialization bypass is explicitly rejected. An attempted active-case
reclassification is rejected by the focused test. No security result is
promoted, and no test or gate is weakened.

## Documentation and runtime evidence

`docs/catalog-and-cases.md` and its German companion document the new field.
The report-generator control proves the metadata is classified
`NOT_EXECUTABLE` / non-promotable even for force-all input. The isolated
no-MRTS generator smoke did not provide canonical report inputs (it lacks the
import-status inventory), so its generated outputs were deliberately restored
instead of being included in this change. The observed hosted evidence proves
native adapter preparation but not full connector runtime success; a fresh
Parent exact-head run remains required after an independently reviewed
Framework integration.

## Checks not run

- Full Framework connector matrix: not run locally because it requires
  external native components and is independently exercised by the Parent
  exact-head producer after Framework integration.
- Ruff/Pyright: not run because neither executable is available locally; no
  tooling was installed.
- Hosted Framework CI, SonarQube Cloud, reviews, and threads: pending the
  separate Draft Framework PR.

## Limitations and residual risk

The 15 cases remain connector-gap inventory; this repair does not implement
their intended security behavior. Parent PR #74 remains blocked until the
Framework PR is merged and its exact revision is deliberately adopted.

## Final diff and review status

Implementation is uncommitted at this record revision. Focused tests,
syntax compilation, descriptor validation, and documentation checks pass;
final scoped diff, whitespace, secret, and staged review remain pending before
commit.
