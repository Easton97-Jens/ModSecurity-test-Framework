# Change record

**Language:** English | [Deutsch](20261103-04-mrts-merged-pin-integration.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261103-04-mrts-merged-pin-integration |
| UTC date | 2026-11-03 |
| Framework base revision | d7bc6006cfabbe545ff63685aaccd6ca722e12ab |
| Issue or pull request | Framework #167; separately authorized MRTS #6 dependency |

## Motivation and problem statement

The readiness delivery still selected the pre-integration MRTS revision. The current user explicitly authorized ordered regular squash integration. MRTS #6 actually produced main commit `ee2174431c4edf97e66afe32558ce8454deb2397`; its complete tree equals the reviewed PR head. Select that actual object, rather than a PR head or hypothetical merge revision.

## Affected components and security boundaries

Only the Framework-owned `tools/MRTS` Gitlink and this documentation pair change. MRTS source, Parent pins and protected broker/composite identities remain separate ownership boundaries. The new MRTS commit changes three reviewed policy digests and its semantic review document; no generator implementation changes.

## Acceptance criteria

Select the actual merged MRTS object and materialize it cleanly. Verify actual Parent policy bytes against Framework/MRTS inheritance rows, package/definition/import integrity and native metadata. Preserve all 100 standard cases, 80 execution rows and offline exceptions. Require fresh published-head CI, full Quality Gate A/A and clean committed-head real-generator compatibility before Framework merge.

## Alternatives considered

Dispatching the maintenance publisher would create another constrained Draft instead of updating this authorized existing PR. Broad SHA replacement would alter unrelated immutable identities. Reuse only the updater's exact validated detached-checkout and Gitlink primitive; do not weaken historical source checks.

## Implementation decision

Fetch the actual MRTS main merge, verify the clean official-source checkout, detach at that object and update only the Gitlink. Run the native maintenance metadata writer followed by its checker. Neither inventory nor archive bytes change because their input scopes exclude MRTS. Do not change source classifications or historical bases to hide an unrelated pre-existing migration-map failure.

## Changed files and tests

`tools/MRTS` and this EN/DE record pair. Existing tests are unchanged: updater bypass refusal, definition guards, import atomicity and four package integrity/real-generator checks. No standard cases or expectations are replaced.

## Commands and results

Commands use RTK and the existing Framework-owned regular CPython 3.15.2 with explicit source and private output roots. Exact argv and logs are retained in integration run `20261103T175654Z-integration`, artifact `framework-precommit/commands.json`; the PR identifies its approved evidence root.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `ci/tools/sync-maintenance-test-views.py --root <Framework> --write`, then `--check` | 0 / 0 | Native synchronization and verification; inventory/archive byte-identical to base | framework-precommit/metadata-*.log |
| `-m modsecurity_connector_ci.lib.active_test_inventory --check` | 0 | 100 default cases, 80 rows; offline exceptions unchanged | framework-precommit/inventory.log |
| `checks/common/check-origin-governance.py` | 0 | Existing scaffold scope only | framework-precommit/origin-governance.log |
| Explicit updater/definition/import/package unittest selection | 0 | 26 tests, no skips | framework-precommit/regressions.log |
| Actual inheritance source/catalog comparison | 0 | 27 canonical sources, 21 Framework and 12 MRTS rows match | framework-precommit/actual-inheritance-readback.json |

## Security impact

No rule, scanner, gate, source/path constraint, package seal, provenance guard or protected identity is weakened. Retain refusal of malformed globals, traversal, artifact/revision mismatches and changed runtime-path guards. No publisher, protected broker dispatch or administrative action occurs.

## Documentation and runtime evidence

This pair records the Framework dependency integration only. MRTS merge facts are identified as external dependency facts. No connector host traffic is claimed by these checks. The separately requested 13 actual final-pair invocations follow after Connector integration and retain their real build and source identities.

## Checks not run

The exact-head definition integration entrypoint requires a clean committed Framework tree and therefore runs after this pin commit; its actual result belongs to the current PR/evidence receipts. Hosted analysis also follows publication. Local Sonar preflight, installation and authentication repair remain suspended. No comprehensive campaign, reset/multiplex assessment or protected dispatch is selected.

## Limitations and residual risk

An exploratory migration-map check fails on `caller-f5523da.yml.fixture` missing from its historical base. Exact unchanged bb6 generator, fixture and source-map bytes reproduce the same failure. That generator excludes MRTS and is not called by this pin updater or required metadata coordinator. Preserve the failure separately; it neither becomes PASS nor justifies altering historical blob admission. Final integrated-chain inheritance and master CI still require their own actual revisions.

## Final diff and review status

The source diff contains only the selected Gitlink and paired record. Review metadata invariants and whitespace before publication; the PR retains the actual latest CI, committed-head compatibility and merge decision. No credentials, digest values or runtime artifacts are recorded here.
