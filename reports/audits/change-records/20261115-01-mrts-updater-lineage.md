# Change record: MRTS updater lineage

**Language:** English | [Deutsch](20261115-01-mrts-updater-lineage.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261115-01-mrts-updater-lineage |
| UTC date | 2026-11-15 |
| Framework base revision | `e4762167bed1ec6a28f7a207c8fb5b9ec258656a` |
| Issue or pull request | Updater repair; delivery status is recorded in the associated PR. |

## Motivation and problem statement

Framework #174 changed `tools/MRTS` from `9a855b092645733ea8ff73a512aff7bfe916407e` to its ancestor `ee2174431c4edf97e66afe32558ce8454deb2397`. The updater checked SHA shape and official branch identity but did not require forward ancestry. Parent run `43690159562`, validator job `132739018750`, correctly rejected this backward nested transition before executing candidate validation.

The user explicitly selected updater-only repair and retained the existing pin. This change prevents future backward publication; it does not resolve that existing Parent candidate conflict.

## Affected components and security boundaries

Framework MRTS updater resolution, read-only validation, privileged publication, and the existing sealed workflow security contract. Candidate Git objects are data; checker code comes from the trusted Framework default revision. Parent source/pins and MRTS source/checkout/branches are outside this change.

## Acceptance criteria

Accept equal or descendant commit objects. Reject backward/divergent history, malformed or unavailable/noncommit objects, Git errors and replacement-object ancestry forgery. Enforce the check before resolver outputs, candidate checkout and index mutation/publication. Bind validator input to both resolver identities. Preserve existing publication restrictions and the current MRTS pin.

## Alternatives considered

Weakening Parent ancestry validation would hide a real backward update. Restoring the MRTS pin was proposed and explicitly declined. Executing the publisher helper from an existing maintenance branch would either use stale code or fail when that branch predates the helper; obtain it from the trusted default revision instead.

## Implementation decision

A dependency-free Bash helper inspects local Git objects with replacement objects and lazy fetching disabled. The workflow fetches both exact revisions from the official MRTS repository and calls the helper at each boundary. Validation also rejects a changed current Framework gitlink. Publication checks lineage against the fetched default-branch pin and loads the helper with `git show origin/$DEFAULT_BRANCH:ci/tools/verify-mrts-update-lineage.sh`.

The canonical publisher SHA-256 is rebound to the independently reviewed profile: `9eb62da1c72de0a2a409a9225bf27bbd6b5682823f5a1b55f21b99a9d2ec54a7`. The exact-profile comparison remains mandatory; required guard calls and resolver bindings are additionally checked.

## Changed files and tests

- `.github/workflows/update-submodules.yml`
- `ci/tools/verify-mrts-update-lineage.sh`
- `ci/checks/security/check-ci-security-contract.py`
- `tests/ci_security/test_mrts_update_lineage.py`
- `tests/ci_security/test_ci_security_contract.py`
- This English/German Change Record pair.

The focused selection is 16 unittest methods, representing 37 expanded Git/contract scenarios. Existing first-party PR, official-ref, credential, force-push and publisher-extension rejection cases remain. This is a scoped selection, not technical enforcement of the broader default-suite inventory cap.

## Commands and results

| Command or procedure | Exit / result |
| --- | --- |
| Framework-owned Python: the new lineage test module and six selected updater contract methods | 0; 16 methods passed, including three guard-removal and three identity-binding mutations. |
| New guard-removal regression against the previous security checker | 1 as expected; all three boundaries lacked the required guard-specific rejection. |
| `rtk bypass bash -n ci/tools/verify-mrts-update-lineage.sh` | 0. |
| `rtk bypass shellcheck ci/tools/verify-mrts-update-lineage.sh` | 0. |
| `rtk bypass actionlint .github/workflows/update-submodules.yml` | 0. |
| Framework-owned Python: `ci/checks/security/check-ci-security-contract.py` | 0; full current workflow security contract passed. |
| Helper against actual existing MRTS objects: `9a855b0 -> ee21744`; reverse; equal | Expected exits 1, 0, 0; Git objects inspected read-only. |
| Explicit SSH Secrets checks | Completed selected source/result scans exited 0; no complete code-quality analysis is implied. |

Exact selected commands and private terminal logs are retained in the task-owned external run directory. The selected contract methods are `test_submodule_updater_requires_lineage_checks_at_all_boundaries`, `test_submodule_updater_requires_both_resolved_identity_bindings`, `test_submodule_updater_uses_the_reviewed_framework_profile`, `test_submodule_updater_rejects_fork_head_pr_identity_bypasses`, `test_submodule_updater_rejects_mrts_ref_token_and_force_push_bypasses`, and `test_submodule_updater_rejects_extra_publisher_code_and_token_steps`.

The first hosted quality job, `132748009785` at `defc43a5376431b9a056a52c236811be1ff376df`, passed Ruff lint and rejected formatting in two test files. The exact reported formatting changes were applied; both Python ASTs remain identical. No additional tool was installed. Current-head hosted results are recorded in the PR.

## Security impact

The repair prevents an official but older MRTS branch tip from becoming an automated downgrade. Actual same/forward controls pass and the reported backward object pair rejects. Replace-ref forgery is exercised with real Git objects. Existing permissions, Draft/first-party PR rules, exact publisher profile and non-force publication remain effective. An independent static review found no material lineage/publisher trust defect.

## Documentation and runtime evidence

Both Change Record languages describe the same scope and limits. There is no new connector or host runtime evidence. The helper tests use real isolated bare Git fixtures; the actual object controls do not modify MRTS.

## Checks not run

The Change Record contract, bilingual documentation and local documentation links passed. At this local verification checkpoint, hosted analysis/delivery had not yet been qualified. No updater publication, MRTS change, Parent candidate quick-check, connector campaign or comprehensive acceptance was launched. Ruff/Pyright are absent locally; no packages were installed.

## Limitations and residual risk

The existing `ee2174431c4edf97e66afe32558ce8454deb2397` pin remains unchanged by explicit user decision. Parent still correctly rejects the current Framework candidate's backward nested transition. This repair is not evidence that that Parent run now passes. Partial-clone lazy-fetch behavior is guarded but was not exercised by the local full-object fixtures. Concurrent remote movement after observed refs remains a normal publication race limitation.

## Final diff and review status

Independent review of the frozen helper/workflow and checker/test changes was CLEAR and reproduced the canonical publisher hash. The scoped source, selected tests and documentation checks are complete. Task-branch delivery and current-head hosted results are recorded separately in the associated PR. No merge authority is inferred.
