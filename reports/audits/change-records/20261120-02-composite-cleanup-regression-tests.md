# Change record

**Language:** English | [Deutsch](20261120-02-composite-cleanup-regression-tests.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261120-02-composite-cleanup-regression-tests |
| UTC date | 2026-11-20 |
| Framework base revision | `95f228936efe17fda24f21323ad87cd698940b48` |
| Issue or pull request | Draft pull request from branch `claude/composite-cleanup-regression-tests-20261120`; external dependency: Connector PR [#454](https://github.com/Easton97-Jens/ModSecurity-conector/pull/454) |

## Motivation and problem statement

Connector PR #454 bounds native transaction cleanup in the composite
coordinator, bounds the Traefik companion's waits on an entry that a native
call still holds, validates ForwardAuth redirect targets and corrects the
HAProxy Phase-4 event `rule_id`. Its regression tests were only run as
external Go overlays. Test implementation is Framework-owned
(`docs/test-ownership-migration.md` in the Connector), so this change adds the
regressions as preserved on-demand Framework tests.

## Affected components and security boundaries

- `connector_suite/adapters/envoy/ext_proc/internal/composite/` and
  `.../compositetraefik/`: new Go test sources (test doubles and real
  Common/libmodsecurity variants behind the `libmodsecurity` build tag).
- `connector_native_tests/connectors/haproxy/src/haproxy_spop_diagnostic_runtime.inc`:
  one native self-test case for the Phase-4 event `rule_id`.
- `connector_suite/source-map.json`, the two reviewed source-hash slots of
  these two Framework files in `connector_suite/config/testing/active-cases.json`,
  and the generated `connector_suite/reports/testing/test-selection-archive.generated.json`.

The tests observe fail-closed, cleanup-safety and header-sink boundaries of
Connector code; they change no Framework security control. No connector
behavior or capability is inferred from them.

## Acceptance criteria

- Every new Go test resolves through the source map and appears in the
  regenerated specialist archive; the active default inventory is unchanged.
- Against the fixed Connector, all new tests pass, also with `-race`, using
  libModSecurity v3.0.17 with the bundled pinned PCRE2 10.49.
- Against the unfixed Connector revisions, the targeted tests fail with their
  specific messages while the legitimate controls pass.

## Alternatives considered

- Keeping the tests as task-local overlays: not reproducible for reviewers.
- Adding `*_test.go` to the Connector: rejected by the ownership contract
  (`product-without-test-infrastructure`).
- Adding the cases to the active default suite: the suite is capped at 100
  cases; the tests stay explicit on-demand definitions.

## Implementation decision

New files keep the existing package layout. Tests that depend on the new
Connector APIs (`ClaimContext`, `AbortWithReasonContext`) are isolated in
`entry_wait_bounds_test.go`, so the remaining files still compile against the
unfixed Connector for before/after verification. Channels synchronize the
controlled blocking; fixed upper bounds detect unbounded waits without hanging
the test binary (blocked doubles are released in `t.Cleanup`, and coordinators
are not closed after a detected hang). The HAProxy case serializes into
memory with `open_memstream` and writes no file.

## Changed files and tests

| File | Coverage |
| --- | --- |
| `.../composite/cleanup_bounds_test.go` | Bounded direct cleanup after `Open` when a fault or shutdown arrives before registration (negative), normal close control, default-budget fail-closed cleanup, budget starting at cleanup for a long-lived entry, canceled and nil caller context, empty reason, capacity release, `Sweep` not stalled by a held entry |
| `.../composite/entry_wait_bounds_test.go` | `ClaimContext` returns `ErrBusy` while P1 holds the entry and succeeds afterwards; a busy abort is recorded, the late P1 result cannot activate the reservation, one close and one slot release; idle and wrong-session aborts; empty/unknown token and empty session |
| `.../composite/cleanup_runtime_test.go` (`libmodsecurity`) | Real engine: direct cleanup after a fault with and without a canceled request context leaves the engine usable |
| `.../compositetraefik/companion_bounds_test.go` | Claim during a held ForwardAuth P2 call releases the handler, no late activation, single slot release; response engine work bounded by the frame deadline; normal lifecycle; 11 redirect cases (valid absolute/relative/maximum, CR/LF, LF, NUL, DEL, leading space, invalid UTF-8, empty, over maximum); client disconnect with lock-semantics double |
| `.../compositetraefik/companion_runtime_test.go` (`libmodsecurity`) | Real engine: disconnect after a non-empty and an empty first body read keeps the engine usable |
| `.../haproxy_spop_diagnostic_runtime.inc` | `rule_id` 12345, 1, `INT_MAX` serialize as decimal; 0, -5 and `INT_MIN` as the empty string |
| `connector_suite/source-map.json` | Five new bindings |
| `connector_suite/config/testing/active-cases.json` | Two reviewed source-hash slots (the changed `.inc` and `source-map.json`) via `update-inventory-bindings.py --apply`; selectors, 80 executions and 100 cases unchanged |
| `.../test-selection-archive.generated.json` | Regenerated: 8476 to 8496 on-demand definitions |

## Commands and results

Run ID `claude-pr454-review-20261120`. Evidence paths are relative to that
run's task-owned directory outside the checkout.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `update-inventory-bindings.py --check`, before repair | 1 | `SOURCE_DIGEST_DRIFT` for the `.inc` and `source-map.json` only, with both Connector revisions | claude-pr454-review-20261120 |
| `update-inventory-bindings.py --apply`, then `--check` | 0 / 0 | `INVENTORY_BINDINGS_UPDATED`, `INVENTORY_BINDINGS_VERIFIED`; structural comparison: exactly 2 changed hash fields | claude-pr454-review-20261120 |
| `update-test-archive.py`, then `update-test-archive.py --check` | 0 / 0 | Archive regenerated; check matches | claude-pr454-review-20261120 |
| `python3 -P -m modsecurity_test_framework.connector ... --check` | 0 | `active_case_count` 100 | claude-pr454-review-20261120 |
| `make framework-go-test GO_TEST_MODULE=connectors/envoy/ext_proc` (default inventory) | 0 | 2 of 2 selected cases passed | `logs/default-go-test-2.log` |
| `ON_DEMAND_TESTS=1 python3 -m unittest` of `test_inventory_bindings_maintenance` and two `ActiveTestInventoryTests` | 0 | 8 tests passed, 0 skipped | claude-pr454-review-20261120 |
| `ON_DEMAND_TESTS=1 GOFLAGS='-tags=libmodsecurity -v' make framework-go-test GO_TEST_MODULE=connectors/envoy/ext_proc` against the fixed Connector | 0 | 8 packages ok; 20 new tests pass, 0 skipped | `out-after2/go-test.log` |
| Same with `-race` | 0 | 8 packages ok; 0 data races; 20 new tests pass | `out-after-race/go-test.log` |
| Same overlay without `entry_wait_bounds_test.go` against Connector `a79f78f3e5f9a612d854e3924cf2a7e43eb47ab7` | 1 | Expected failures only: 2 unbounded direct cleanups, stalled `Sweep`, claim waiting beyond 2 s; all other tests pass | `out-before-prhead2/go-test.log` |
| Same overlay without the three coordinator files against Connector `b79c3d93efbb8330f121caf8fb7c1a7874195e57` | 1 | Expected failures only: held claim, unbounded response work, 8 invalid redirects returned 302, fake and real-engine disconnect faulted the coordinator; controls pass | `out-before-base/go-test.log` |
| `ON_DEMAND_TESTS=1 make -C connectors/haproxy self-test-spoa-runtime` with this Framework, Connector `b79c3d93…` | 2 | New case reports `rule_id=0 did not serialize as ""` | `out-haproxy-before2/` |
| Same against the fixed Connector | 2 | New case passes; a later, unchanged protocol self-test fails silently | `out-haproxy-after2/` |
| Same with the unmodified Framework `95f22893…` against both Connector revisions | 2 / 2 | Same silent protocol self-test failure: pre-existing, independent of this change | `out-haproxy-pristine-*/` |
| `gofmt -l` on the new Go files | 0 | No output | claude-pr454-review-20261120 |
| `make check-change-records`, `check-doc-links`, `check-bilingual-docs`, `check-repository-path-references` | 0 | All passed (the path check first rejected a local path in this record, then passed) | claude-pr454-review-20261120 |

## Security impact

No Framework security control changes. The tests retest the original paths of
the Connector fixes (unbounded cleanup and waits, late activation after an
aborted session, unvalidated `Location`, canceled-context cleanup) and their
alternate paths (shutdown instead of fault, response work instead of claim,
empty first read).

## Documentation and runtime evidence

No reader-facing documentation changes. The Go tests are package-level runtime
tests; the real-engine variants use the Common runtime with libModSecurity
v3.0.17 and the bundled pinned PCRE2 10.49. No Traefik, Envoy or HAProxy host
process was started, so no host runtime evidence is claimed.

## Checks not run

- Hosted Framework CI and SonarQube Cloud: pending for the pull request head;
  the SonarQube coverage job is expected to fail compilation until the
  Connector pin is updated (see the merge order below).
- The real-engine variants run only with `-tags libmodsecurity` and CGo flags
  for the Connector Common archive; plain `ON_DEMAND_TESTS=1 make
  framework-go-test` compiles them out.

## Limitations and residual risk

- The HAProxy native self-test target exits non-zero in this environment
  because of a pre-existing, silent protocol self-test failure; the new case
  is observed only through its own message before the fix and its absence
  after it.
- A native call that never returns cannot be produced with the real engine;
  that bound is covered by test doubles that model `commonRuntimeTransaction.Close`.
- **Merge order.** `cleanup_bounds_test.go` uses `Limits.CleanupTimeout` and
  `entry_wait_bounds_test.go` uses `ClaimContext`/`AbortWithReasonContext`.
  The SonarQube workflow compiles `./...` of `connectors/envoy/ext_proc`
  against its pinned `CONNECTOR_REVISION`
  (`cfd5e49cada3fc793ef50993147e3796a0907443`), which predates these APIs,
  so that job cannot compile this change until the pin selects a Connector
  revision that contains the updated PR #454. This pull request must
  therefore stay a draft until PR #454 is merged and the pin is updated here;
  the pin is not changed now because no such Connector revision exists yet.
- Until a Connector gitlink update selects a Framework revision containing
  these tests, the Connector keeps pinning this Framework base revision.

## Final diff and review status

The staged diff was reviewed; `git diff --check` and a Secrets scan of every
changed file were clean. Delivered as a Draft pull request; not merged. The
Connector Framework gitlink is unchanged.
