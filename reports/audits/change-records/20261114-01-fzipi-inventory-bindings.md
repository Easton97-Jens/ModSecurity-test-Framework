# Change record

**Language:** English | [Deutsch](20261114-01-fzipi-inventory-bindings.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261114-01-fzipi-inventory-bindings |
| UTC date | 2026-11-14 |
| Framework base revision | `3ff8b75c9f4d2cb3614a4dcb7afd2e5360e074d8` |
| Issue or pull request | Not created at preparation; delivery is owned by the coordinating task. |

## Motivation and problem statement

The Framework test changes were already reviewed, but seven schema-5 source digest slots still described older bytes. The full inventory gate rejected `tests/test_runtime_event_sink_failures.py` before test selection. Refreshing the existing bindings restores the provenance check for the reviewed source content.

## Affected components and security boundaries

Only `connector_suite/config/testing/active-cases.json` and this English/German Change Record pair change. Parent revision `80334858a1a1e1ad1ff65e647716584a18cf3e9c` is an external validation dependency. Parent integration requires a later Framework pin update owned by the coordinating task. MRTS remains read-only.

## Acceptance criteria

The canonical refresh checker and the full Parent-bound inventory verifier must pass. Exactly seven existing SHA-256 slots may change. All 529 bound Framework source files, selection fields, indexed ordinals, product snapshots and case membership must remain identical. The maintenance regressions and documentation checks must pass.

## Alternatives considered

Editing digests manually would duplicate the native maintenance owner. Regenerating or changing inventory membership would expand the task. The existing schema-5 updater performs the required bounded refresh and retains the current validation contract.

## Implementation decision

Run the canonical updater in check mode before applying the refresh. Preserve the failing full-verifier result as the original-path negative control, then apply the atomic update and repeat both complete checks. Compare the parsed inventory with only the seven changed digest fields normalized and independently hash all 529 bound Framework sources before and after.

## Changed files and tests

The manifest contains seven refreshed bindings: two Envoy test sources, one Traefik test source, and the Apache lifecycle, HAProxy binding, Runtime event-sink and NGINX body-buffer fixture sources. Test implementations and verifiers are unchanged. All other inventory data is identical. The full verifier reports 100 automatic cases with a limit of 100, 2689 catalog cases and 2589 on-demand cases.

## Commands and results

The actual RTK entry was `rtk bypass python3 -B -` from the Framework checkout. Its Python orchestration started the child argument vectors shown after the arrow; the arrow denotes process creation, not a shell operator. `$PYTHON` abbreviates the configured Framework interpreter. The unittest child received `ON_DEMAND_TESTS=1` through its environment. The documentation child used `rtk make`. The context explicitly sets `FRAMEWORK_ROOT`, `TEST_ROOT`, the external output directory, Parent identity and `CONNECTOR_TEST_PROFILE=h1`. Initial context-only attempts lacked the profile/output metadata and exited 2; these are not counted as digest negative controls.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk bypass python3 -B -` → `$PYTHON connector_suite/modsecurity_connector_ci/tools/update-inventory-bindings.py --check` | 1 / 0 | Before: exactly seven stale digests. After: `INVENTORY_BINDINGS_VERIFIED`. | `framework-inventory-remediation` |
| `rtk bypass python3 -B -` → `$PYTHON -m modsecurity_connector_ci.lib.active_test_inventory --check` | 2 / 0 | Before: reviewed source digest mismatch. After: all bindings and definitions admitted. | `framework-inventory-remediation` |
| `rtk bypass python3 -B -` → `$PYTHON connector_suite/modsecurity_connector_ci/tools/update-inventory-bindings.py --apply` | 0 | Seven existing digest slots refreshed atomically. | `framework-inventory-remediation` |
| `rtk bypass python3 -B -` → `$PYTHON -m unittest -v modsecurity_connector_tests.test_inventory_bindings_maintenance` | 0 | Six maintenance regressions passed, including malformed schema, traversal, symlink and concurrent-change rejection. | `framework-inventory-remediation` |
| `rtk bypass python3 -B -` → `rtk make check-documentation PYTHON="$PYTHON" BUILD_ROOT="$RUNNER_TEMP/build" TMP_ROOT="$RUNNER_TEMP/tmp"` | 0 | Links, bilingual variables, repository paths and Change Record structure passed. | `framework-inventory-remediation` |

## Security impact

No security remediation or control relaxation is performed. The existing digest, path, symlink, schema, duplicate-selection and case-budget checks remain in force. The original failing provenance path is retested successfully after the binding refresh.

## Documentation and runtime evidence

This paired record documents the Framework provenance repair. The checks establish inventory and maintenance behavior; no new host runtime, lifecycle, transport-abort or connector-promotion evidence is claimed.

## Checks not run

Connector runtime matrices and host builds are not repeated for a digest-only inventory repair with unchanged test and product source bytes. Publication, current-head CI and integration are handled by the coordinating task.

## Limitations and residual risk

The refreshed bindings attest to the current reviewed source content. Future source changes require another explicit refresh. Successful catalog verification does not replace execution of the selected tests.

## Final diff and review status

The semantic comparison proves that only seven digest values changed; all 529 source hashes are unchanged. Post-change Secrets checks passed. This is a prepared Framework handoff; commit, pull request and Parent pin work remain with the coordinating task.
