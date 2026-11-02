# Traefik capture source locations and FIFO operation timing

**Language:** English | [Deutsch](20261102-01-auth-path-and-fifo-validation.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261102-01-auth-path-and-fifo-validation |
| UTC date | 2026-11-02 |
| Framework base revision | 91145b7ba721bdec4e89af754cf40bf496fd2a08 |
| Issue or pull request | Nine-point master reconciliation; delivery coordinated separately |

## Motivation and problem statement

Traefik auth preparation still passed a removed Connector-local capture directory to the central registry and hashed the removed manifest path. The FIFO regression included a fresh interpreter and imports within its two-second operation timeout.

## Affected components and security boundaries

Framework auth preparation and focused tests only. The source exporter still reads committed Connector files. Capture source paths use the reviewed Framework ownership map. The FIFO observation implementation and its `O_NONBLOCK`, `O_NOFOLLOW` and `fstat` checks are unchanged.

## Acceptance criteria

Exercise source-location wiring with separate Framework and Connector checkouts, retain sealed capture rejection, preserve exactly 100 default cases, and test FIFO rejection independently of interpreter/import startup. Full preparation requires a separate resolution of the sealed registry blocker below.

## Alternatives considered

An arbitrary timeout increase, skips, altered sealed expectations and manual rewriting of archived objects were rejected. No existing archive-generation command was found for reconciling the stale registry.

## Implementation decision

Resolve the capture directory and receipt manifest through `source_path`. Add an on-demand test that uses the real Framework registry constructor, with source export and capture admission mocked explicitly to preserve the offline process guard. It proves source-location wiring and export destination arguments only. The FIFO test forks after loading the contract, retains the two-second child-operation watchdog, checks the rejection diagnostic and terminates a stuck child during cleanup.

## Changed files and tests

`connector_suite/adapters/traefik/harness/i12_auth/prepare.py`, its auth regression module, the on-demand active inventory and `tests/no_crs/test_configtest_artifacts.py`. Source bindings are refreshed using the existing inventory maintenance tool. The new test does not replace the existing full-preparation test.

## Commands and results

All project commands use RTK and the existing Framework interpreter. The external task evidence is identified by run `master-reconcile-20261102`, scope `framework`.

| Check | Result |
| --- | --- |
| Original full auth preparation | Failed at removed Connector `ci/runtime/lifecycle/i12/manifest.json` |
| Split-checkout source-location regression | PASS, one test; `split-offline-guarded-final.log` |
| Full auth controls after path correction | Six PASS, one ERROR: `Sealed Traefik profile differs`; `auth-controls-final.log` |
| Artifact regression module | PASS, nine tests; `fifo-after.log` |
| Cold-cache artifact, receipt and fixture-quality regressions | PASS, 27 tests; `fifo-cold-after.log` |
| Three independent cold-cache timing probes | Imports 0.82–0.88 seconds; FIFO rejection 0.00031–0.00035 seconds; `fifo-cold-measurements.json` |
| Inventory binding generator and default selection | PASS; bindings verified and exactly 100 active cases; `bindings-final-check.log`, `inventory-final-default.log` |

The historical timeout was not reproduced on this host. The measurements confirm that interpreter/import work dominated the former watchdog; the new watchdog measures the observation in an already loaded child.

## Security impact

All sealed profile, central implementation, registry object, complete source export and bounded file checks remain fail-closed. No host is launched by the new regression. No security check was weakened to obtain a pass.

## Documentation and runtime evidence

Only source wiring and filesystem-unit behavior are established. No host, H2/H3 or runtime qualification is claimed. The local ignored Framework configuration was missing; a minimal nonsecret local setup selecting the Framework interpreter and external task cache made the actual V3.2 structure validator pass. It is not a versioned personal configuration template.

## Checks not run

Local Sonar secrets scanning was not run, pursuant to the explicit task-specific user exception. No Sonar authentication/installation repair or replacement mandatory gate was introduced. Existing CI checks are unchanged. No archive generator, native host campaign or MRTS mutation was run.

## Limitations and residual risk

Full preparation remains blocked. Both sealed Traefik profile pins predate the observer-C input-binding update from `0d903fc5…` to `5038d006…`; the central implementation pin also predates migration/refactoring. A diagnostic audit found 10 of 19 historical repository-backed registry objects differ from current sources, including the SDK accessor (`89ff282b…` expected, `a2205398…` actual). No pin refresh or archived-object rewrite is retained in this change. A supported archive-generation path and separately reviewed trusted source contract are required before full preparation can succeed. `sealed-contract-review.diff` and `registry-repository-objects.json` retain exact evidence.

## Final diff and review status

Framework delivery, final combined inventory validation and Parent pin selection belong to the coordinator. Maintenance PRs and MRTS source remain outside this change. The unresolved full-preparation failure is explicitly retained.
