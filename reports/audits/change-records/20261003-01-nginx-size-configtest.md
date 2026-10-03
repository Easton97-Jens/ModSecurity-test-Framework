# Change record: NGINX size configtest contract

**Language:** English | [Deutsch](20261003-01-nginx-size-configtest.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20261003-01-nginx-size-configtest` |
| UTC date | `2026-10-03` |
| Framework base revision | `c4f53e183ddc9eb69259f7a4b5a200fad784f6c6` |
| Issue or pull request | External Parent PR #396 remains OPEN/DRAFT/UNMERGED; no Framework PR created |

## Motivation and problem statement

Required `invalid_size` lacked a concrete NGINX configuration realization.
The prior Boolean-only descriptor and canonical destination could not validate
an independent size operation without confusing its identity or retained files.

## Affected components and security boundaries

Catalog selection, receipt validation, managed artifact retention and the
generated public contract catalog are Framework-owned. Parent owns actual
host execution and collection. MRTS and Parent gitlinks remain unchanged.
The boundary separates claimed receipt metadata from authorized actual bytes.

## Acceptance criteria

Require actual case-bound size configtest evidence and exact exit 1 with both
size parser diagnostics. Reject Boolean relabeling, wrong modules, mismatched
digests/templates/identities and noninteger expected exits. Retain both explicit
cases separately; do not exempt arbitrary phase-0 or request cases.

## Alternatives considered

Generic nonzero acceptance, Boolean-receipt reuse and reducing required selection
would erase the contract. A second general-purpose driver/schema is unnecessary:
the existing bounded operation receipt can serve two explicitly closed cases.

## Implementation decision

Register `invalid_size` with `modsecurity_phase4_body_limit maybe;`, error class
`invalid_size`, expected exit 1 and fragments
`"modsecurity_phase4_body_limit" directive` and
`invalid value for modsecurity_phase4_body_limit`. Validate the closed per-case
template and retain each bundle at `inventory/configtests/invalid_boolean` or
`inventory/configtests/invalid_size`. Preserve
Boolean semantics and the global HTTP/event/full-lifecycle gate. Refresh the
generated contract catalog through its generator, not manual output edits.

## Changed files and tests

- `ci/checks/catalog/no_crs_baseline.py`
- `tests/cases/no-crs-baseline/catalog.json`
- `tests/no_crs/test_configtest_size.py`
- `modsecurity_test_framework/data/framework-contract-catalog.json` (generated)
- `docs/testing-and-evidence.md` / `.de.md`
- This paired record and archive index pair

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy` wrapping owning CPython 3.14.7 and the five explicit configtest unittest modules | 0 | 34 tests pass, including two-case isolation | External coordinator validation |
| `rtk proxy` wrapping the external `analysis/check-nginx-config-size.py` with the owning interpreter and explicit diagnostic root | 0 | Individual PASS/FAIL, eight validators with zero errors | `nginx-config-size-retained-6si2byjk` |
| RTK-wrapped retained `SHA256SUMS` verification | 0 | All 47 entries verified | `nginx-config-size-retained-6si2byjk` |
| `rtk proxy` wrapping `make test-no-crs-contract` | 0 | 166 tests pass in 111.503 s | External coordinator validation |
| `rtk proxy` wrapping `make test-contract-api` | 0 | 23 tests pass in 28.847 s | External coordinator validation |
| `rtk proxy` wrapping `make check-documentation` with owning interpreter and external build/temp roots | 0 | Links, bilingual variables, repository paths and Change Records pass | Documentation handoff session 39793 |
| `rtk proxy git diff --check` | 0 | Whitespace check passes | Framework task worktree |
| `rtk proxy` wrapping `make lint` | 0 | Complete precommit Framework lint passes | External analysis log `framework-config-size-precommit-lint-20261003.log` and exit receipt |

The focus includes actual artifact binding, separate case bundles, diagnostic
mismatch and strict expected-exit type controls. The subsequent size focus
passed seven tests, including permanent shared-finalizer coverage: two cases
retain ten distinct manifest entries; cross-case aliases and bundle reuse
remain rejected. Complete precommit Framework lint and scoped final review
passed. The separately required postcommit lint is recorded in external run
evidence after the local commit, not forecast as a PASS here.

## Security impact

No validator relaxation or synthetic runtime evidence. Existing non-following,
regular-file, bounded input/copy and source authority controls remain. Both
diagnostics and actual retained byte digests must match the concrete contract;
an unrelated exit 1 stays FAIL. Request/event requirements remain unchanged.

## Documentation and runtime evidence

The testing-guide pair documents both closed contracts and per-case retention.
The actual external Parent-driven diagnostic `nginx-config-size-retained-6si2byjk`
executes real NGINX, collection and canonical finalization. `invalid_size` is
individual PASS; wrong-module control is FAIL despite both exits being 1.
Each retains five operation files and passes eight canonical validators.
Both aggregates remain FAIL; no startup, HTTP requests or events occurred.
This is a precommit source-dirty diagnostic using retained cached C artifacts,
not a new Exact-Head build, Full Lifecycle or Framework runtime certification.

## Checks not run

Full E2E and protocol work are prohibited for this slice. No Gitlink update,
push, PR write or merge was performed. Postcommit lint is a separate follow-up
check. Root/nobody-worker assertions do not apply
to a pure configtest.

## Limitations and residual risk

Eight configuration paths remain unfulfilled. Fresh external
`measure-nginx-config-size.py` revalidates actual bytes, run identities, all
eight validators and all 47 checksums: open paths decreased 52 → 51 and
configuration 9 → 8, with required selection 97 unchanged.
Trusted cached binary/module inputs and independent source/run binding remain
necessary; executed snapshots do not prove a new source-exact C build.

## Final diff and review status

Independent security review found no blocker. Documentation and whitespace
checks and complete precommit lint pass. The scoped diff was reviewed for a
separate local Framework commit. No secrets, raw sensitive material, remote delivery or E2E PASS is
recorded. Framework delivery remains separate from Parent; no Parent pointer
update or MRTS change is authorized by this record.
