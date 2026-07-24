# Restore exact ModSecurity v3 recursive topology provenance validation

**Language:** English | [Deutsch](20260723-02-remediate-modsecurity-v3-topology-provenance.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260723-02-remediate-modsecurity-v3-topology-provenance` |
| UTC date | 2026-07-23 |
| Framework base revision | `f98a8739cb13b583f23d646784b144e596b61441` |
| Issue or pull request | Parent-owned remediation handoff; no Framework PR exists at record creation |

## Motivation and problem statement

`ci_require_approved_modsecurity_v3_checkout` categorically rejected a
`.gitmodules` manifest and every Gitlink. That made it reject the known,
reviewed ModSecurity v3 checkout at
`0fb4aff98b4980cf6426697d5605c424e3d5bb60`, even though its exact recursive
topology is available as retained task evidence. The required remedy is not to
allow arbitrary submodules, but to make the existing provenance boundary accept
only that concrete topology and fail closed for every other checkout shape.

## Affected components and security boundaries

- `ci/lib/common.sh` — ModSecurity v3 source provenance and Git execution
  boundary before any source build consumes an existing checkout.
- `ci/provisioning/fetch-smoke-sources.sh` — delegates fresh V3 provisioning
  to the narrow Framework API rather than performing a generic clone path.
- `tests/security_regression/` — hermetic topology controls plus real-Git
  fresh-root regressions for write containment and local configuration.
- English/German documentation — source-boundary contract only; no connector
  runtime behavior is inferred.

The change is supply-chain and source-integrity hardening. It does not modify
the Parent checkout or the original MRTS.

## Acceptance criteria

1. The known root origin, detached commit, and exact eight-child recursive
   `(path, origin, commit)` topology pass without relaxing any input control.
2. Missing, extra, origin- or commit-mismatched, symlinked, escaping, dirty,
   non-normal-index, attached-HEAD, or multi-remote members fail before build
   consumption.
3. Fresh provisioning uses only a verified root-owned, non-group/world-
   writable `/usr/bin/git`; it clears caller Git and dynamic-loader state,
   resets `PATH`, and disables hooks, fsmonitor, automatic recursive fetching,
   local file transport, and interactive credential prompts.
4. The focused regression passes under the supplied isolated CPython 3.14
   interpreter, including real-Git containment/configuration controls and
   legitimate plus alternate bypass controls.
5. Documentation and the paired Change Record describe the static rule rather
   than the obsolete categorical submodule rejection.

## Alternatives considered

- **Keep categorical `.gitmodules` and Gitlink rejection:** rejected because
  it blocks the known legitimate reviewed source and cannot satisfy the
  provenance contract.
- **Parse and trust the checkout's own `.gitmodules` data:** rejected because
  that would let untrusted source metadata select its own accepted topology.
- **Check the root only:** rejected because a nested child can change origin,
  ref, worktree, Gitdir, or index state without changing the root identity.

## Implementation decision

The Framework declares the root Gitlinks and the two nested Gitlink sets as
literal static data in `ci/lib/common.sh`. The guard validates the root and
every individual child against that data, including physical worktree/Gitdir
containment, one literal origin, a detached exact commit, object verification,
and clean normal index state.

Fresh provisioning is centralized in
`ci_provision_approved_modsecurity_v3_checkout`. It accepts only an absent
destination immediately below an existing canonical non-symlinked parent,
creates that root privately with mode `0700`, and never delegates to a generic
clone. The boundary validates a fixed `/usr/bin/git` executable before use,
clears caller Git and dynamic-loader variables, resets `PATH`, and binds every
post-init operation to the canonical physical root with an explicit worktree
setting while retaining Git's normal submodule-helper worktree context. It
does not export `GIT_DIR` or `GIT_WORK_TREE`, suppresses external attributes
and sparse state, and clears local
`core.worktree`, `core.attributesfile`, `core.sparseCheckout`, and every
`submodule.*.update` key immediately before recursive processing. The fetch
consumer calls this API; it does not retain a separate V3 Git sequence.

## Changed files and tests

- `ci/lib/common.sh` — static topology, fail-closed checkout validation, and
  the hardened fresh-root/public-provisioning boundary.
- `ci/provisioning/fetch-smoke-sources.sh` — V3 fetch delegation to the public
  hardened provisioning API.
- `tests/security_regression/git_provenance_test_support.py` and
  `test_modsecurity_v3_git_ref_provenance.py` — exact fake topology, a
  test-local host-Git function override, real-Git write/configuration fixtures,
  legitimate controls, and bypass cases.
- `docs/connector-integration*`, `docs/reference/variables*`, and
  `docs/testing-and-evidence*` — synchronized English/German contract update.
- This paired Change Record and its index entries — change traceability.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `/bin/sh -n ci/lib/common.sh ci/provisioning/fetch-smoke-sources.sh` | 0 | Shell syntax accepted | `20260723T162517Z-fnd-cross-0001-runtime-evidence-bcda7d1d` |
| `make test-modsecurity-v3-provenance-contract` with isolated CPython 3.14.4 and task-owned `BUILD_ROOT`/`TMP_ROOT` | 0 | 18 provenance tests passed in 201.531 seconds, including real recursive Git submodule helper execution | `20260723T162517Z-fnd-cross-0001-runtime-evidence-bcda7d1d` |
| `make test-nginx-archive-digest` with isolated CPython 3.14.4 and task-owned `BUILD_ROOT`/`TMP_ROOT` | 0 | 12 independent archive-integrity tests passed in 217.161 seconds | `20260723T162517Z-fnd-cross-0001-runtime-evidence-bcda7d1d` |
| Parent-owned non-mocked Parent-to-Framework provisioning API validation with CPython 3.14.4 | 0 | Safe bridge provisioned root `0fb4aff98b4980cf6426697d5605c424e3d5bb60`; `status=present`, `git_fsck=PASS`, eight approved submodules, and clean status | retained Parent task-run JSON evidence |
| `make check-documentation` with isolated CPython 3.14.4 and task-owned `BUILD_ROOT`/`TMP_ROOT` | 0 | Links, variable documentation, repository-path references, and Change Record contract passed | `20260723T162517Z-fnd-cross-0001-runtime-evidence-bcda7d1d` |
| `make lint` with isolated CPython 3.14.4 and task-owned `BUILD_ROOT`/`TMP_ROOT` | 0 | Complete Framework lint passed, including 18 V3 tests in 195.261 seconds, 12 NGINX archive tests in 218.834 seconds, workflow/security contracts, documentation, and final `git diff --check` | `20260723T162517Z-fnd-cross-0001-runtime-evidence-bcda7d1d` |

## Security impact

This remediates the false-rejecting provenance control without turning it into
a generic submodule allowance. It also completes the related
FND-FRAMEWORK-0036 fresh-root boundary: no V3 Git executable is selected from
caller `PATH`, post-init Git writes cannot follow a local worktree redirect or
external attributes file, and local custom recursive-update configuration is
removed before it can run. The focused regression covers the legitimate
control and missing, extra, mismatched, symlinked, escaping, dirty, index,
remote, attached-head, hostile-PATH, dynamic-loader, and local-configuration
bypass classes. The original MRTS was not written or changed.

## Documentation and runtime evidence

The English/German documentation now distinguishes an exact static recursive
allowlist from generic submodule support and documents the single hardened
fresh-provisioning entry point. The focused check is contract evidence only:
no connector runtime, network source fetch, or MRTS lifecycle evidence was
collected.

## Checks not run

- Hosted exact-head CI, SonarQube Cloud, and a Framework PR do not yet exist;
  they remain delivery-owner work after this isolated handoff.
- Connector smokes and MRTS-generating targets are out of scope and were not
  run because this change is Framework-only and the original MRTS is read-only.

## Limitations and residual risk

The static graph deliberately applies only to the reviewed root commit. A
future upstream root or submodule update requires a new reviewed provenance
change and matching tests. The Framework clears dynamic-loader variables
before processes that it starts, but sourced shell code cannot retroactively
protect the dynamic-loader state that the caller used to start that shell.
The caller must therefore start the entry shell from a trusted environment.
Hermetic and real-Git controls validate the guard's decision boundary, not a
connector runtime. Local evidence does not replace hosted exact-head PR
validation.

## Final diff and review status

The isolated Framework remains detached at the recorded base revision with an
unstaged task-owned patch. No commit, push, branch creation, pull request, or
merge is authorized or performed by this worker. Shell syntax, focused Make
targets, the Parent-owned non-mocked API control, documentation, complete lint,
and the final whitespace check are recorded above.
