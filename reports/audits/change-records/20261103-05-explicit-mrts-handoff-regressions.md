# Change record

**Language:** English | [Deutsch](20261103-05-explicit-mrts-handoff-regressions.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261103-05-explicit-mrts-handoff-regressions |
| UTC date | 2026-11-03 |
| Framework base revision | 00de6d61122c85120c3a06e84e46906f87165744 |
| Issue or pull request | Framework #167; Parent #443 |

## Motivation and problem statement

The actual merged MRTS dependency requires an explicitly approved nested-pin handoff in Parent. Extend the existing Framework-owned regression modules for that narrow Parent API and CLI change.

## Affected components and security boundaries

Only the existing updater and candidate-contract test modules, their native inventory/archive companions and this record pair change. Parent source, its ordinary lock and protected broker identities have separate ownership.

## Acceptance criteria

Prove explicit old/candidate Git-object pairing, rejection without writes, unchanged default nested-pin policy, primary/staged reconstruction and preserved immutable identities. Retain 100 standard cases, 80 execution rows and all existing offline exceptions.

## Alternatives considered

Changing only the lock would bypass the existing provenance contract. Broad fixture or rule relaxation would remove useful negative controls. Extend the existing real-object fixtures instead.

## Implementation decision

Use actual temporary Git commits with old/new fixed MRTS gitlinks. Pass the approval through public APIs and copied CLIs. Repair three demonstrably pre-existing fixture assumptions narrowly: admitted inline caller syntax, flock callback keyword forwarding and consistent actual caller SHA.

## Changed files and tests

`test_update_framework_versions.py` and `test_verify_framework_candidate_contract.py`: seven new on-demand tests cover valid/idempotent handoff, strict defaults, malformed/absent approval, wrong or missing objects/gitlinks, dishonest old lock and symlink authority. Existing publication and flock assertions remain active. Regenerate source bindings/archive using the maintenance coordinator.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Both existing updater/candidate unittest modules | 0 | 79 tests passed, including seven new cases | integration run 20261103T175654Z-integration; parent-mrts-handoff/final-regressions-green.log |
| Four focused fixture followups | 0 | Corrected contexts pass; prior assumptions proven from exact Git objects | parent-mrts-handoff/fixture-followup.log and fixture-baseline-provenance.json |
| Native maintenance writer/checker, inventory and documentation checks | Recorded in PR receipts | Required before publication | framework-handoff-checks/commands.json |

## Security impact

No scanner, gate, source/path rule, negative assertion or protected identity is weakened. The optional approval is explicit and checked against both immutable Framework objects; its omission continues to reject the changed candidate MRTS in the verifier. Independent read-only source/trust review found no material defect.

## Documentation and runtime evidence

This EN/DE record documents only regression and metadata changes. No host traffic is claimed here. Thirteen fresh final-pair H2/H3 invocations follow the authorized ordered integration.

## Checks not run

Local Sonar preflight, installation and authentication repair remain suspended. Fresh hosted analysis follows publication; full acceptance/reset/multiplex campaigns and protected dispatches are outside this task.

## Limitations and residual risk

The separate historical migration-map failure is unchanged and has independently reproduced on its original base. These regressions do not repair it or classify it as a pass. Final merged-pair runtime and master CI require separate evidence.

## Final diff and review status

The stable source and test diff was independently reviewed. Final native metadata, documentation, whitespace and actual published-head CI receipts are attached to the PR. No credentials or digest values are included.
