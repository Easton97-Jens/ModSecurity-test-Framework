# Fix inherited-upstream snapshot re-entry

**Language:** English | [Deutsch](20260821-02-fix-inherited-upstream-snapshot-reentry.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260821-02-fix-inherited-upstream-snapshot-reentry |
| UTC date | 2026-08-21 |
| Framework initial revision | 89881a1b33219fc18df3cf2f15dda53261d13443 |
| Framework delivery base at rebase | 798bff0c921ab8c7f10b2ca949304d58e7f205a2 |
| Issue or pull request | Parent finding FND-PARENT-0191; Framework Draft PR pending |

## Motivation and problem statement

The Parent/Framework runtime bridge can source `ci/lib/common.sh` once to
export canonical pins and a second time with `set -a` to obtain its guarded
environment. The second source exported the Framework's internal
`CI_INHERITED_UPSTREAM_ENV` snapshot. A later Framework ModSecurity-v3 guard
captured that snapshot again, interpreted its embedded canonical lines as new
inherited input, and correctly blocked the resulting duplicate
`ENVOY_VERSION` before Git access.

## Affected components and security boundaries

- `ci/lib/common.sh`
- `tests/security_regression/test_modsecurity_v3_git_ref_provenance.py`

The boundary is the inert inherited-environment snapshot used to reject
unreviewed active-pin overrides before download, Git, checkout, extraction, or
build sinks. The internal snapshot metadata itself is not an upstream pin and
must not re-enter that input boundary.

## Acceptance criteria

- A Framework-generated `set -a` environment may re-enter the ModSecurity-v3
  provenance guard without a false duplicate-pin block.
- Direct inherited active-pin mismatches, mutable refs, foreign URLs, and an
  incorrect approved commit remain fail-closed before Git.
- A real duplicate active-pin line remains fail-closed.
- Existing static ModSecurity-v3 topology and adjacent APR/CRS provenance
  contracts remain green.
- Parent Gitlink and nested MRTS state remain unchanged.

## Alternatives considered

- Removing the duplicate-pin guard was rejected because it would weaken the
  source-integrity boundary.
- Accepting caller-provided `CI_INHERITED_UPSTREAM_ENV` as trusted input was
  rejected because it is Framework-generated bridge metadata, not provenance.
- A Parent-only strip was not selected for this task because the user selected
  the Framework and the stale metadata originates in the shared Framework
  helper.

## Implementation decision

`common.sh` now unsets only stale `CI_INHERITED_UPSTREAM_ENV` metadata and its
status before it takes the fresh fixed-path `/usr/bin/env` or `/bin/env`
snapshot. Direct inherited pins remain in that fresh snapshot and continue to
be checked byte-for-byte by the existing guard. No release pin, URL, digest,
Gitlink, checkout policy, permission, or source-acquisition behavior changed.

## Changed files and tests

- `ci/lib/common.sh`: excludes stale internal snapshot metadata before the
  next guarded environment capture.
- `tests/security_regression/test_modsecurity_v3_git_ref_provenance.py`:
  reproduces the Parent/Framework re-entry sequence and adds direct mismatch,
  duplicate-line, and incorrect-approved-commit controls.
- This English/German Change Record pair and the paired record indexes.

The new re-entry regression failed before the shell change with
`ENVOY_VERSION is duplicated in the inherited environment` and passes after
the change.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused re-entry regression before the shell change | 1 | Reproduced the fail-closed duplicate `ENVOY_VERSION` blocker. | Framework task worktree |
| Focused re-entry regression after the shell change | 0 | Re-entry reaches the approved ModSecurity-v3 provenance guard. | Framework task worktree |
| `make test-modsecurity-v3-provenance-contract` | 0 | 21 V3 provenance, topology, origin, ref, commit, loader, and Git controls pass. | Framework task worktree |
| `make test-apr-util-provenance` | 0 | 13 APR-util provenance controls pass. | Framework task worktree |
| `make test-crs-provenance-contract` | 0 | 23 CRS provenance and Gitlink controls pass. | Framework task worktree |
| `sh -n ci/lib/common.sh` and `bash -n ci/lib/common.sh` | 0 | POSIX-shell and Bash syntax are valid. | Framework task worktree |
| `make lint` | 0 | Complete Framework lint, security, provenance, runtime-contract, workflow, evidence, and documentation suite passes. | Framework task worktree |

## Security impact

The original duplicate-state path was reproduced before the fix and passes
after it. An alternate genuine duplicate active-pin line still fails closed,
as do a direct `ENVOY_VERSION` mismatch, a foreign URL, mutable ref, and wrong
approved commit before any fake or system Git command is consumed. This repair
removes re-entry metadata only; it does not relax provenance validation.

## Documentation and runtime evidence

This paired Change Record and its index entries are the only reader-facing
documentation changes. The listed checks are hermetic Framework contract
evidence; no hosted Parent connector runtime, request, or matrix success is
claimed.

## Checks not run

- A real `make fetch-modsecurity-v3` was not run because it downloads the
  upstream source and recursive submodules; the hermetic contract suite covers
  the changed guard boundary without an unbounded acquisition.
- Hosted Framework PR checks, SonarQube Cloud, and review checks are pending
  delivery.

## Limitations and residual risk

The Parent remains pinned to its existing Framework Gitlink. A separate Parent
pointer update and rerun of the affected Parent workflows are required to
verify the hosted runtime outcome. No security risk is accepted.

## Final diff and review status

Before commit, the task-owned Framework diff, whitespace check, focused
security review, complete `make lint`, and listed local contracts passed. No
secrets, raw inherited environment values, credentials, or request payloads
are recorded. The Framework branch exists; its Draft PR is pending.
