# NGINX canonical coverage contract

**Language:** English | [Deutsch](20260930-01-nginx-canonical-coverage-contract.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260930-01-nginx-canonical-coverage-contract |
| UTC date | 2026-09-30 |
| Framework base revision | `cc36b37d0f6a0fbc3512f3878a691751e91c5fbb` |
| Issue or pull request | Parent Draft PR #396; no Framework PR yet |

## Motivation and problem statement

An NGINX HTTP/1 full-lifecycle run selected 112 cases but had canonical evidence
for only 34. Two catalog prerequisites were omitted, 13 H2/H3-only claims were
selected in an H1 run, six narrower claims lacked deterministic reuse, and 54
out-of-scope `NOT_EXECUTED` records blocked aggregate PASS. Separately, 57
selected required claims lacked their own execution or a runnable base.

## Affected components and security boundaries

The Framework catalog, No-CRS selector/finalizer/validator, two case fixtures,
tests, and paired testing documentation are affected. The boundary is canonical
claim integrity: neither a declared capability nor an unselected record may
manufacture runtime PASS. Parent host dispatch and MRTS are unchanged.

## Acceptance criteria

- Missing prerequisites fail catalog validation; H1 excludes H2/H3-only claims.
- Explicit reuse requires validated live base identity and, where required, a
  uniquely matching canonical event; mismatch controls remain unfulfilled.
- Only truly unselected `NOT_EXECUTED` records are ignored by aggregate status;
  selected missing, global FAIL/BLOCKED, and exit 77 still block PASS.
- Every remaining selected required case eventually needs a real execution
  path and host evidence before any exact-head E2E PASS can be claimed.

## Alternatives considered

Reclassifying the 57 unscheduled obligations as optional, synthesizing events,
and relaxing status or protocol validators were rejected. The user explicitly
requires genuine runners and requests. Two focused fixtures exercise a real
lowercase-header denial and a two-header phase-1 rule chain; neither obtains
canonical PASS from HTTP status alone.

## Implementation decision

The catalog declares scenario prerequisites and two distinct, executable
header fixtures. The multiple-header case requires `event_jsonl`, a unique
rule match, and native event identity; an audit-only fallback is rejected by
the full-lifecycle validator. NGINX full-lifecycle select/init require the same
declared downstream protocol. Five explicit reuse mappings and one existing
alias are constrained to a current-run validated base; no new request is
implied. Finalization and validation reselect from the checked-in catalog and
capability inventory, while aggregate status uses the selected case set and
preserves all-record counts and the legacy unscoped API behavior.

## Changed files and tests

`tests/cases/no-crs-baseline/catalog.json`,
`tests/cases/no-crs-baseline/case_insensitive_header_name.yaml`,
`tests/cases/no-crs-baseline/multiple_headers.yaml`, and
`ci/checks/catalog/no_crs_baseline.py` carry the behavior. The public
`modsecurity_test_framework/data/framework-contract-catalog.json` resource was
regenerated from checked-in sources; its exact inventory test was updated
under `tests/contract_api/`. Focused tests under `tests/no_crs/` cover
prerequisites, protocol profiles, exact reuse and
negative mismatches, selected-scope status/tampering, runner parsing, and
audit-only/no-event negative controls for the multiple-header runner.
`tests/no_crs/test_no_crs_baseline.py` updates the exact runner inventory.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `make test-no-crs-contract` with external build root | 0 | Full No-CRS suite passed after final source/fixture edits | Local Framework worktree |
| `make test-contract-api` with existing Framework venv | 0 | Generated catalog check and 20 API tests passed | Local Framework worktree |
| `make check-documentation` | 0 | Links, bilingual variables, repository paths, and Change Records passed | Local Framework worktree |
| Focused prerequisite, protocol, reuse, status, and runner unit tests | 0 | Positive and negative cases passed after red-first checks | Local Framework worktree |
| `python3 ci/checks/catalog/no_crs_baseline.py catalog-check` | 0 | 166 catalog cases passed | Local Framework worktree |
| Read-only exact-reuse probe against retained canonical artifacts | 0 | Six candidate derivations matched; not a new E2E run | Retained run `20260930T164146Z` |
| NGINX H1 selected-runner preflight diagnostic | 1 | Expected red: 55 selected required paths still unavailable after two new fixtures | Task-owned external analysis |
| `make lint` with system Python | 2 | PyYAML absent from system interpreter; no source-lint conclusion | Local Framework worktree |
| First `make lint` with existing Framework venv | 2 | Security/provenance tests passed; generated contract catalog was stale and has since been regenerated | Local Framework worktree |
| Full `make lint` with existing Framework venv, before the second fixture | 0 | Broad lint, security/provenance, contract API, catalog, and documentation checks passed | Local Framework worktree |
| Final `make lint` with existing Framework venv and explicit worktree root | 0 | Full suite, canonical pin sync, catalog, security, and documentation checks passed after the second fixture | Local Framework worktree |
| Two isolated NGINX case host probes | 0 each | Real HTTP 403/200, root master/nobody worker, expected audit rules; diagnostic only, not canonical PASS | `nginx-case_insensitive_header_name-PIeMWckO`, `nginx-multiple_headers-wcDcPOJy` |
| `git diff --check` | 0 | No whitespace errors in tracked diff | Local Framework worktree |

## Security impact

This is evidence-integrity hardening, not a declared vulnerability
remediation. Plan-status tampering is rejected by semantic re-selection; a
missing selected case or foreign reuse identity cannot be promoted to PASS.
The new runner's audit-only fallback and missing-event controls remain FAIL.
The declared protocol still needs binding to observed host traffic in Parent.

## Documentation and runtime evidence

`docs/testing-and-evidence.md` and `.de.md` explain protocol scoping,
selected-scope aggregation, and constrained reuse. Two isolated root-to-nobody
HTTP requests were observed with matching audit rules, but they were not a
canonical full lifecycle and produced no canonical result for this change.
Retained events were read only for a derivation probe.

## Checks not run

No new root-to-nobody full lifecycle or exact-head E2E was run: the required
runner-coverage gate is red. Parent selection wiring, Gitlink update, Parent
focus suite, canonical PASS, and SHA256SUMS remain pending. A final full
Framework lint rerun after the second fixture passed.

## Limitations and residual risk

Fifty-five selected H1 obligations still need real paths (53 direct scenarios
and two dependent derivations). Several need Parent host-driver capabilities
and possibly connector event production; no Parent dispatch defect is proven.
The direct minimal host probes produced no native canonical event. A separate
Parent harness evidence-pointer discrepancy was observed: case results name
an audit path under the private case logs, whereas the validated audit resides
under the worker-visible server logs. No Parent fix is included. H2/H3
selection remains a declared run profile until bound to actual traffic.

## Final diff and review status

The task-owned worktree diff and whitespace check have been reviewed; no
secrets or unrelated source edits were observed. Seven independent local
Framework source commits exist; this paired documentation is the eighth commit.
Parent Gitlink delivery remains deferred while the execution gate is red.
