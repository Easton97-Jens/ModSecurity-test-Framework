# Change record

**Language:** English | [Deutsch](20260718-01-fix-framework-common-structure.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260718-01-fix-framework-common-structure` |
| UTC date | `2026-07-18` |
| Framework base revision | `cdc91a398d6c156eaff927d742b23018a3817fb6` |
| Issue or pull request | None at record creation; a Draft PR follows this record's commit. |

## Motivation and problem statement

`test-common / common-structure` required exactly 141 YAML files while the current Framework catalog contains 179. Removing that stale guard exposed a second defect: runtime discovery validated a `former_xfail` / `connector-gap` security-data-flow catalog case before eligibility filtering, although that catalog-only description intentionally lacks runtime `rules`.

## Affected components and security boundaries

- `.github/workflows/test-common.yml`: CI corpus and materialization contract.
- `tests/runners/runner_core.py`: repository YAML discovery and runtime schema validation boundary.
- `tests/workflow_contract/test_common_structure_workflow.py`: focused regression coverage.
- `Makefile` and `docs/testing-and-evidence{,.de}.md`: local test target and documented contract.

The change preserves YAML parsing, case validation, shell quoting, and task-owned temporary-output boundaries. It is not a security remediation and does not alter Sonar rules, exclusions, scanner configuration, Parent content, or MRTS.

## Acceptance criteria

- No fixed YAML corpus count blocks a valid catalog expansion.
- An empty corpus and an empty Apache common selection fail explicitly.
- Non-runtime catalog cases are excluded before runtime-only schema validation.
- Every selected runtime case is still validated, materialized, and asserted.
- The focused regression and literal common-structure control pass.
- English/German documentation and this paired Change Record agree.

## Alternatives considered

- Updating `141` to `179` would create another stale inventory contract.
- A global manifest would duplicate the documented YAML/runner source of truth.
- Synthetic runtime `rules` would misrepresent connector-neutral catalog-only evidence descriptions.

## Implementation decision

The workflow checks only that the YAML corpus and dynamic Apache common selection are non-empty. The runner reads case metadata, applies existing applicability logic, and fully validates only selected runtime cases. Dedicated static checks remain responsible for catalog-only cases; the existing materialization and status-assertion loop remains for runtime cases.

## Changed files and tests

- `.github/workflows/test-common.yml`
- `Makefile`
- `tests/runners/runner_core.py`
- `tests/workflow_contract/test_common_structure_workflow.py`
- `docs/testing-and-evidence.md`
- `docs/testing-and-evidence.de.md`
- this English/German Change Record pair

The focused test runs dynamic `case_cli.py list-cases` and proves that a non-runtime security-data-flow catalog description is not materialized. The literal workflow control provides the positive materialization/status path.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `make test-workflow-contract` with external `BUILD_ROOT` | `0` | Two focused workflow-contract tests passed. | `20260718T081746Z-framework-common-structure-d6ee7cec` / `evidence/common-structure-current.md` |
| Literal `common-structure` materialization/assertion block with external `RUNNER_TEMP` | `0` | Current Apache common cases materialized and asserted successfully. | `20260718T081746Z-framework-common-structure-d6ee7cec` / `evidence/common-structure-current.md` |
| `python -m compileall -q tests/runners tests/workflow_contract` with external pycache | `0` | Changed Python and focused test compiled. | Task-owned temporary path |
| `make lint` with external pycache/build root | `0` | Project checks completed; see limitations for the fixed `/tmp` subcheck warning. | Task-owned temporary path |
| `git diff --check` | `0` | No whitespace error. | Framework worktree |

## Security impact

No security remediation was performed. Focused review found no new RCE, path-traversal, YAML, `case.env`, subprocess, or temporary-output weakness in the changed discovery path. A separate protocol URL evidence-redaction candidate was recorded for later focused validation and is not part of this change.

## Documentation and runtime evidence

`docs/testing-and-evidence.md` and its German companion document the dynamic common-structure contract and its focused local regression target. The literal workflow control produced local structural/materialization evidence only; it does not claim connector-runtime support or Sonar Quality Gate success.

## Checks not run

- Ruff and Pyright were unavailable in the selected repository environment; no tool installation was authorized.
- ShellCheck is not directly applicable to the changed inline GitHub Actions YAML shell block; Framework shell syntax checks ran through `make lint`.
- Full connector, CRS, and MRTS matrices are outside this focused CI repair.
- The independent Sonar Quality Gate requires separate remediation.

## Limitations and residual risk

The native CRS-version-pinning subcheck hard-codes `/tmp`. Its sandbox redirections were denied, so the aggregate `make lint` exit cannot prove that this one subcheck inspected inputs. No source workaround or unregistered temporary location was used. The Draft PR cannot reach a verified Quality Gate while the independent Sonar backlog remains unresolved.

## Final diff and review status

Pre-commit review confirms a focused Framework-only diff, clean whitespace, and no Parent product/gitlink or MRTS change. Commit, push, Draft PR, and exact-head CI/review verification remain pending at record creation.
