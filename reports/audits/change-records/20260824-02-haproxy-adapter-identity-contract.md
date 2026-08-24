# Change record

**Language:** English | [Deutsch](20260824-02-haproxy-adapter-identity-contract.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260824-02-haproxy-adapter-identity-contract` |
| UTC date | 2026-08-24 |
| Framework base revision | `7bf8b7cb771f856a70123451332089a9f24036de` |
| Issue or pull request | Standalone Framework Draft PR pending; independent of Parent PR #279 |

## Motivation and problem statement

The `five-connectors-with-crs-no-mrts` catalog bound the HAProxy Framework
smoke entrypoint to `haproxy-native-htx-filter` / `native-htx-filter`. Static
source tracing shows that entrypoint dispatches the connector-owned SPOE/SPOP
smoke harness, while the native HTX filter remains a separate Parent
full-lifecycle path. The profile therefore needed a closed identity correction
without renaming or promoting the genuine native HTX adapter.

## Affected components and security boundaries

- `ci/checks/catalog/five_connectors_with_crs_no_mrts.py` owns the closed
  profile, untrusted-evidence validation, schema checks, and non-promoting
  result construction.
- The normalized-event and manifest schemas now constrain each
  connector/adapter/mode tuple rather than accepting arbitrary tokens.
- The Framework smoke entrypoint is checked as a static dispatch binding; the
  connector-owned process topology and host-runtime evidence remain outside
  this repository.

No Parent source, Parent Gitlink, MRTS content, workflow privilege, runtime
summary, root/sudo behavior, or connector capability declaration is changed.

## Acceptance criteria

1. The selected HAProxy profile identity is
   `haproxy-spoe-spop-agent` / `spoe-spop-agent`.
2. The retained native HTX identity is
   `haproxy-native-htx-filter` / `native-htx-filter` and remains a separate
   full-lifecycle catalog record.
3. Unknown IDs, wrong modes, and cross-path evidence fail in both schema and
   catalog validation.
4. The profile's static smoke dispatch, report tuple, and non-promoting status
   remain bound to the selected SPOP identity.
5. Apache, Envoy, Traefik, and lighttpd identities remain unchanged.

## Alternatives considered

- Renaming the native HTX adapter was rejected because it would silently alter
  a real full-lifecycle identifier.
- Selecting HTX based only on the smoke-script filename was rejected; the
  source dispatch and Parent harness path show SPOE/SPOP.
- A new profile or schema version was not needed: the native HTX identifier is
  retained unchanged, and an explicit `reject-and-regenerate` profile
  migration record is the migration boundary.
  Legacy five-connector HTX-labelled events are not accepted as SPOP evidence
  and must be regenerated from the actual SPOP path.

## Implementation decision

The Framework now has a closed HAProxy adapter catalog with two records. The
five-connector `ADAPTERS` view selects only the SPOP record. The native HTX
record has no Framework smoke entrypoint and names its separate Parent
full-lifecycle target. Event and manifest schemas use closed
connector/adapter/mode alternatives, and the local schema evaluator validates
that exactly one tuple matches. Aggregate reporting copies the already
validated manifest identity; successful validation remains
`CONTRACT_VALIDATED` with `host_runtime_status: UNATTESTED`.

## Changed files and tests

- `ci/checks/catalog/five_connectors_with_crs_no_mrts.py`
- `tests/schemas/five-connectors-with-crs-no-mrts/normalized-event.schema.json`
- `tests/schemas/five-connectors-with-crs-no-mrts/manifest.schema.json`
- `tests/ci_security/test_five_connector_with_crs_no_mrts_contract.py`
- `docs/testing-and-evidence.md` and `.de.md`
- `docs/connector-integration.md` and `.de.md`
- this paired English/German Change Record

The existing Framework contract test now covers both retained HAProxy records,
closed direct-schema tuple rejection, selected-entrypoint binding, aggregate
report identity, non-promotion, and unchanged non-HAProxy adapters.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| JSON parse of changed schemas with Framework Python | 0 | Both changed schemas parse. | Isolated Framework worktree |
| Initial `py_compile` invocation outside the task worktree | 1 | Corrected immediately; no source or artifact was changed. | Task transcript |
| `python -m py_compile` for changed catalog and test | 0 | Compilation passed with cache outside the worktree. | Registered task cache root |
| Focused `unittest` contract module | 0 | Contract, identity, schema, and security-regression tests passed. | Registered task temp root |
| `make test-five-connectors-with-crs-no-mrts-contract` | 0 | Native Framework target passed. | Registered task build root |
| `make test-ci-security-contract` | 0 | 291 Framework CI-security and contract tests passed, including the HAProxy identity cases. | Registered task build root |
| CRS provenance, Makefile, runtime-component lock, and runtime-component sync targets | 0 | Focused Framework security and regression targets passed. | Registered task build root |
| `make check-documentation` | 0 | Documentation links, bilingual companions, paths, and Change Record contract passed before final evidence rows. | Isolated Framework worktree |
| Full `make lint` final attempt | 2 | A timing-sensitive, unchanged FIFO regression missed one of its own readiness observations; no product code or test was changed. | Task transcript |
| Isolated FIFO regression rerun | 0 | The exact existing FIFO regression passed immediately with task-owned temporary storage. | Registered task temp root |
| Codex Security diff scan and sealed artifact revalidation | 0 | Complete working-tree coverage; zero reportable findings. | Sealed task-owned security-scan receipt (not committed) |
| Final documentation and diff checks | 0 | `make check-documentation` and `git diff --check` passed after the Change Record was finalized. | Isolated Framework worktree |

## Security impact

This is a validation-boundary hardening change. A schema-only consumer can no
longer accept an unknown adapter or mismatched HAProxy mode, and the profile
cannot treat native HTX evidence as SPOE/SPOP evidence or the reverse. The
static entrypoint check is not a runtime claim. No security control was
weakened, no suppression was added, and metadata alone still cannot create a
runtime `PASS` or capability promotion.

The completed Framework-scoped Codex Security diff review found zero
reportable findings with complete changed-file coverage. Its generic source
inventory excludes `ci/`, `docs/`, and `tests/` by design, so the sealed scan
also contains an explicit reviewed-files receipt accounting for all ten changed
files. This is a static contract review, not runtime evidence.

## Documentation and runtime evidence

The paired English/German integration and evidence guides distinguish the
selected SPOP profile from the retained HTX full-lifecycle identity. No
connector host, SPOA process, native HTX runtime, or MRTS process was started
in this Framework-only change. The path conclusion is static source evidence,
not host-runtime evidence.

## Checks not run

Full Parent HAProxy SPOE/SPOP smoke and native HTX full-lifecycle runtime were
not run: they require Parent-owned build artifacts, CRS/runtime dependencies,
and connector-host execution, all outside this Framework-only task. No runtime
workflow summary was regenerated by design.

## Limitations and residual risk

The Framework validates the identity contract and its static dispatch binding;
it cannot authenticate a host producer or prove that a real HAProxy/SPOP or
HTX process executed. Those facts remain Parent-owned and require their own
exact-head runtime evidence.

## Final diff and review status

Pending final documentation and diff checks, exact staging, commit, push, and
standalone Draft PR creation. The completed security-diff review, focused
contract tests, and isolated FIFO rerun are retained as task evidence. All task
source changes are confined to the external Framework worktree; no Parent
Gitlink or MRTS file is staged.
