# Pin reviewed MRTS governance metadata

**Language:** English | [Deutsch](20261108-04-mrts-governance-pin.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261108-04-mrts-governance-pin |
| UTC | 2026-11-08 |

Framework source base: `9cf786ab99057880028b8db7b56709e5d1e2e3e2`. This record prepares the Framework-owned Gitlink handoff for Draft PR #169.

## Motivation and problem statement

The reviewed Parent command/architecture policies required corresponding MRTS inheritance metadata. External [MRTS Draft PR #7](https://github.com/Easton97-Jens/MRTS/pull/7) publishes exactly one governance-manifest change, replacing two reviewed hashes without product or test changes. The Framework must pin that separately delivered commit before Parent can publish a consistent nested chain.

## Affected components and security boundaries

Framework owns `tools/MRTS` and this EN/DE pair. The intended MRTS revision is `9a855b092645733ea8ff73a512aff7bfe916407e`, replacing `ee2174431c4edf97e66afe32558ce8454deb2397`. The submodule URL and MRTS product/test sources remain unchanged. Parent owns its separate Framework Gitlink, version lock and workflow projections.

## Acceptance criteria

Require the exact reviewed MRTS commit, complete separate Secrets coverage and the native Framework quick-check at the staged candidate. Preserve the default 100-case selection and all negative evidence controls. Later Parent publication must synchronize both revision identities and native projections; this record does not certify that future committed chain.

## Alternatives considered

Blind digest replacement, unrelated MRTS changes, a merge, skipping hooks, installing another integration, weakening native checks or relabelling historical results would violate the task. A current operator change is needed only for the existing Parent Gitlink dispatcher.

## Implementation decision

Select the already published governance-only MRTS revision through the ordinary Framework Gitlink. Keep the original worktrees and historical evidence. Current metadata confirms that the Framework Git common directory has no pre-commit/pre-push dispatchers and no configured hooks-path override; no hook is installed, removed or redirected. Separate manual Secrets results therefore remain explicit; an ordinary Framework commit is not an automatic hook receipt.

## Changed files and tests

Only the Framework Gitlink and this paired record belong to this handoff. The MRTS manifest postimage SHA256 is `fe3a2b31ecc2ffd2869bc67524ea95bd3d920f49fd9f97676f72da422698c676`. This metadata change introduces no Framework test method, selector or product capability.

## Commands and results

The separate MRTS proof covers all 472 Git blobs: 431 regular files and 41 link blobs, including exact framing, lengths, SHA256 and Git object identities. All 41 links and target identities are unchanged from the prior MRTS commit and resolve within its Git tree.

External MRTS validation at the selected revision includes its actual policy-root validator and 41 local standard-library tests under Python 3.14.4. Its existing hosted Python 3.14.6 governance lane passed independently; that lane validates its own fixture, while actual-policy-root validation is a separate local result.

Framework Python 3.15.2 source checks passed 48 workflow methods and 222 subtest executions, plus the 29-method FIFO contract block and explicit positive/fault controls. Two earlier native full-run failures remain recorded: the corrected FIFO startup observation and a runner-umask mismatch in CRS fixtures. Both formerly failing CRS methods and existing mode-negative controls pass with child-only umask 0022; private runner/evidence directories retain 0077/0700 isolation. A fresh complete native run after this record is still required.

## Security impact

The selected MRTS delta changes only reviewed governance hashes. Root-owned operator receipts, the Parent's full staged-index binding and native pin checks remain required for the separate Parent handoff. Normal Secrets checks, exact modes and symlink rejection are not weakened.

## Documentation and runtime evidence

Source-bound receipts are under `$EVIDENCE_ROOT/inheritance/`, `$EVIDENCE_ROOT/hook/parent-only-current/`, `$EVIDENCE_ROOT/quick-check/umask-context-controls/` and the separate MRTS evidence root. The coordinator records actual commands, terminal results and immutable commit identities there. No new runtime acceptance campaign is started.

## Checks not run

The final published-chain regression, Parent Gitlink admission and comprehensive acceptance campaign remain **NOT_RUN** here. A new complete Framework quick-check and exact-head hosted readback are coordinating delivery steps.

## Limitations and residual risk

External MRTS CI and separate Secrets coverage do not prove the Parent's final committed pin or runtime acceptance. Historical claims requiring a new Framework-to-MRTS hook installation do not describe the current topology. The existing Parent dispatcher remains operator-owned; it is not bypassed by this handoff.

## Final diff and review status

The coordinator verifies the staged MRTS identity, paired documentation and native checks before ordinary delivery. All PRs remain Draft. This record declares no merge eligibility or overall readiness.
