# Change record: integrate reviewed MRTS inheritance

**Language:** English | [Deutsch](20261122-01-integrate-reviewed-mrts-inheritance.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261122-01-integrate-reviewed-mrts-inheritance |
| UTC date | 2026-11-22 |
| Framework base revision | `e1964415efcd3cda11614ce13b7d34331ee0cf06` |
| Issue or pull request | External dependency: [MRTS #7](https://github.com/Easton97-Jens/MRTS/pull/7); this Framework follow-up PR has not yet been created. |

## Motivation and problem statement

Adopt the separately reviewed MRTS inheritance update through its actual official main merge commit. The Framework currently pins `ee2174431c4edf97e66afe32558ce8454deb2397`; the selected replacement is `488e75388d917615feecab91650c3278b9c78b1e`. A reviewed PR head is not substituted for the actual squash result.

## Affected components and security boundaries

Only `tools/MRTS` and this English/German Change Record pair change in the Framework. MRTS and Parent remain independently owned repositories. No Framework product, test-source, workflow, inventory-selection or validation-rule changes are included. The later Parent pin update is a separate integration step.

## Acceptance criteria

Require the official merged MRTS commit, forward ancestry from the current pin, a clean materialized nested checkout and truthful review evidence. Preserve the current 100 core cases, 80 execution selectors and 1144 separate offline exceptions. Check registered source bindings, specialist archive, active inventory and applicable documentation contracts. Require fresh exact-head Framework PR checks before its separately authorized regular merge.

## Alternatives considered

Keeping the old pin leaves the reviewed inheritance update unconsumed. Updating integrity values without reading their historical and current policy sources would not demonstrate semantic review. The constrained automatic publisher only admits a gitlink update; it is not used to publish the additional Change Record pair.

## Implementation decision

Root selected the actual MRTS #7 squash merge, verified that its tree equals the reviewed tree and that its single parent is the previous pin, materialized the clean detached checkout and staged the Framework gitlink. The native lineage checker accepts this forward transition. No validator, gate or source-authority control is weakened.

The external MRTS change updates exactly two inherited Parent bindings. The architecture policy removes an example reading-list entry while retaining source authority and repository ownership. The command policy distinguishes installed automatic Secrets hooks from agent shell commands; agent commands still require RTK and the canonical Sonar starter. Full historical policy-byte and semantic review was recorded separately, rather than inferring safety from checksum agreement.

## Changed files and tests

- `tools/MRTS`: previous pin to the actual merged commit above.
- This paired Change Record.

No tests are added or changed. Existing lineage tests cover equal/forward acceptance and backward, divergent, unavailable, noncommit, malformed and replacement-object rejection. Six targeted workflow-contract methods preserve the three lineage guards, resolved identities and publisher restrictions.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk bypass bash ci/tools/verify-mrts-update-lineage.sh tools/MRTS ee2174431c4edf97e66afe32558ce8454deb2397 488e75388d917615feecab91650c3278b9c78b1e` | 0 | Root's recorded native invocation used the equivalent explicit absolute checker and repository paths; forward lineage accepted. | `20261122-readiness-continuation/framework-mrts-pin-commands.json` |
| Framework Python `-B -m unittest tests.ci_security.test_mrts_update_lineage` plus six selected `CiSecurityContractTest` methods | 0 | Root's scoped precheck passed; exact selectors and context are retained in its receipt. | `20261122-readiness-continuation/framework-prechecks/receipt.json` |
| Framework Python `-B ci/checks/security/check-ci-security-contract.py` | 0 | Existing native workflow security contract passed in Root's precheck. | `20261122-readiness-continuation/framework-prechecks/receipt.json` |
| Framework Python: `update-inventory-bindings.py --check` and `update-test-archive.py --check` | 0 / 0 | Registered source bindings and retained specialist archive match; no writer or regeneration used. | `20261122-readiness-continuation/framework-pin-validation/inventory-receipt.json` |
| Framework Python: `run-active-tests.py --check` | 0 | Explicit `CONNECTOR_TEST_PROFILE=parent` and isolated Framework/Parent/revision/output context; counts stayed 100/80/1144. | `20261122-readiness-continuation/framework-pin-validation/active-context-complete.receipt.json` |
| Framework `make check-doc-links check-bilingual-docs check-repository-path-references check-change-records` with the explicit Framework Python | 0 | Four native targets passed after the new pair entered tracked-file discovery; both current source files were included. | `20261122-readiness-continuation/framework-pin-validation/docs-tracked.receipt.json` |

## Security impact

No product security remediation is performed. The change consumes reviewed governance bindings and preserves isolation, credential handling, lineage validation and ordinary delivery gates. No security finding is dispositioned and no runtime security conclusion is inferred.

## Documentation and runtime evidence

This maintained English/German pair records the Framework integration decision. External MRTS main at the selected commit has four successful hosted checks and two successful workflows; its full revision-bound Sonar readback has gate OK, all five conditions OK, overall/new ratings A/A/A and zero unresolved issues, new issues and hotspots. The hosted CPython 3.14.6 governance workflow validates an isolated policy fixture; it is not an actual local Parent/Framework/MRTS inheritance run.

Root's candidate policy-composition result checks 27 Parent entries, 21 Framework bindings and 12 MRTS bindings as a manifest-level check only. No host, protocol, lifecycle, full test campaign or new runtime evidence was collected by this pin integration.

## Checks not run

The initial active-inventory invocation omitted its mandatory explicit profile and exited 2 before execution; the corrected invocation passed without changing any source guard. Both attempts remain in the private evidence.

The intended local MRTS CPython 3.14.6 environment is unavailable; no substitute interpreter is presented as a native MRTS test result. Full product/runtime campaigns are outside this pin change. This Framework PR's fresh hosted checks cannot yet be read because the PR is not created.

## Limitations and residual risk

MRTS hosted fixture governance, local manifest composition and Framework checks establish distinct evidence layers. The currently observed Framework base has a failing current-revision advisory dependency-installation job; its status is not hidden or reclassified as a successful Scorecard run. New exact-head Framework checks and separately reviewed Parent pin propagation remain required. Existing runtime reports are not relabeled to this revision.

## Final diff and review status

The reviewed Framework difference consists of the forward `tools/MRTS` gitlink and this documentation pair. Product code, CI, test sources, active-case selection, registered source bindings and specialist archive remain unchanged. The existing lineage/security prechecks and the sourcebinding, archive, active-inventory and four source-inclusive documentation checks passed. The inventory retains 100 core cases, 80 execution selectors and 1144 separate offline exceptions. The record pair follows all 13 template sections; own-file whitespace and selected whole-file Secrets review accompany the handoff. Fresh published-head CI and the separate Parent pin integration remain outstanding; no Framework commit or merge result is claimed here.
