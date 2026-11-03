# Change record

**Language:** English | [Deutsch](20261103-01-measurement-sbom-readiness.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261103-01-measurement-sbom-readiness |
| UTC date | 2026-11-03 |
| Framework base revision | `bb6c7580208a05c17d6d6674571731b6a71028cb` |
| Delivery | Reviewable task-worktree changes; no worker commit or PR |

## Motivation and problem statement

The existing measurement runner bound only Parent's revision, while reusable
measurement/test sources live in Framework. Finalization accepted an unbound or
different Framework. No integrated component SBOM export existed for selected
known source, module, environment and artifact inputs.

## Affected components and security boundaries

Framework owns the coverage runner, exporter and regressions. Parent remains the
owner of product sources and promotion. MRTS is unchanged. Explicit regular-file
inputs, bounded JSON, no automatic resolution/execution, external new output and
clean final-pair requirements constrain the new exporter. Local Sonar prechecks
remain suspended by explicit user instruction; hosted checks remain unchanged.

## Acceptance criteria

Reject missing/different Framework provenance before coverage combination;
preserve actual execution, Parent attribution and default 100 cases. Export
deterministic CycloneDX 1.6 with independent expected identities, input/artifact
hashes, actual revisions and always-incomplete scope. Reject stale/dirty final
sources, duplicate input selection, unsafe input and output overwrite.

## Alternatives considered

Calling a source list a complete binary SBOM would misstate linkage. A new
resolver/scanner dependency is unnecessary for explicit known inputs. Retrofitting
historical manifests would misstate their original applicability.

## Implementation decision

Record/check Framework revision and dirty state alongside Parent. Preserve old
evidence without accepting it as final-pair input. Add a stdlib exporter for lock
profiles or explicit source tuples, Go module JSON streams, Python distribution
arrays and streamed artifact SHA-256. Release hashes attach to distribution
references; Git commits are not file hashes. Supplied build metadata stays an
assertion. Composition is always incomplete and no dependency graph is invented.

## Changed files and tests

`ci/tools/export-component-sbom.py`, `tests/ci_security/test_component_sbom.py`,
the coverage runner and `test_sonar_coverage.py`, paired
`docs/testing/measurement-and-sbom-readiness.md` and this paired record.
The coordinator owns shared source-binding/catalog registration; new regressions
remain explicitly on-demand. No standard-suite expansion is requested.

## Commands and results

Task evidence below the invoking project's approved external storage root:
`runs/20261103T115937Z-runtime-readiness/tooling`.

- Framework interpreter, explicit Parent/Framework roots, `ON_DEMAND_TESTS=1`:
  new finalization test before fix failed all three missing/mismatched/dirty
  Framework subcases (`framework-pair-before-corrected.log`). An earlier probe
  lacked `CONNECTOR_REVISION` and failed context admission; it is not defect proof.
- Same context, `python -m unittest -v modsecurity_connector_tests.test_sonar_coverage
  tests.ci_security.test_component_sbom`: 33 tests passed (`targeted-final.log`).
- Exporter's actual runtime lock plus actual selected Framework package metadata:
  exit 0, ten components, explicitly dirty development and incomplete scope
  (`current-development.cdx.json`). This is not a final integrated-pair inventory.

Shell entry points use RTK and explicit Framework interpreter. Official 1.6 schema
was retained under the evidence root; the coordinator records schema validation
and final shared documentation/integrity checks separately.

## Security impact

No product vulnerability remediation or security freedom is claimed. No scanner,
dependency, workflow, admission or hosted gate was removed or weakened. Arbitrary
input values are not echoed in failure messages; inputs/build descriptions must
be reviewed for secrets before selection.

## Documentation and runtime evidence

The paired guide defines supported inputs, prerequisites, exact prepared commands
and scope limits. No runtime campaign, connector promotion or analyzer import
was performed. Existing targeted historical measurements remain historical.

## Checks not run

No full Python/Go/native production measurement or profile/protocol campaign.
No native/container transitive SBOM resolution. No toolchain/dependency install.
No advisory scan or automatic version update based on age. Final canonical
interpreter and final clean-pair execution remain coordinator prerequisites.

## Limitations and residual risk

Only supplied inputs are exported. Eight cache records do not enumerate ten
qualified runtime profiles. Modules/environment packages do not prove binary
linkage; build descriptions do not prove builds. Dirty development cannot qualify
the final pair. A complete native/container SBOM needs an approved resolver and
actual artifact/build/OS evidence.

## Final diff and review status

Focused implementation/tests were reviewed. Shared binding generation and final
repository-level checks belong to the coordinator after combining Framework work.
Parent gitlink unchanged; MRTS default read-only. No worker processes remain.
