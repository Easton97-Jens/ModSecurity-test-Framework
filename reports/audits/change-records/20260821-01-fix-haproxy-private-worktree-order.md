# Fix HAProxy private-worktree validation order

**Language:** English | [Deutsch](20260821-01-fix-haproxy-private-worktree-order.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260821-01-fix-haproxy-private-worktree-order |
| UTC date | 2026-08-21 |
| Framework base revision | 554df7a75281ac80ea18035f29248b7c7386ffbb |
| Issue or pull request | Parent PR #309 exposed the failure; Framework Draft PR pending |

## Motivation and problem statement

Fresh HAProxy preparation failed before host startup because the Framework
validated `HAPROXY_RUNTIME_BUILD_WORKTREE/Makefile` before extracting the
already SHA-256-verified archive into that private worktree. The failure was a
truthful fail-closed availability error, but it made the valid verified build
path unreachable.

## Affected components and security boundaries

- `ci/provisioning/prepare-haproxy-runtime.sh`
- `tests/security_regression/test_runtime_component_download.py`

The boundary is the transition from the reviewed, re-hashed archive copy in
private `BUILD_ROOT` to the only source tree that may be inspected and built.
The shared source cache remains diagnostic/cache input only and is never a
build input.

## Acceptance criteria

- The private archive extraction precedes Makefile validation.
- Validation and compilation retain the private worktree as their sole source.
- Missing or invalid Makefiles and unsafe paths still fail closed.
- A fresh real preparation produces the staged binary and matching provenance.

## Alternatives considered

- Parent-side pre-creation or bypassing the Framework verifier was rejected:
  it would weaken the Framework-owned provenance boundary.
- Validating the shared extracted cache was rejected because a cache writer
  could alter it after archive verification.

## Implementation decision

Only the two existing calls were reordered:

```text
download_and_verify → extract_source → prepare_build_worktree
→ verify_build_target → build_haproxy
```

No lock, version, URL, digest, cache-reuse rule, path-containment check, or
failure status changed. Existing verified-binary reuse remains before this
sequence and stays unchanged.

## Changed files and tests

- `ci/provisioning/prepare-haproxy-runtime.sh`: creates the private extraction
  before inspecting its Makefile.
- `tests/security_regression/test_runtime_component_download.py`: regression
  contract locks the complete lifecycle ordering.
- This English/German Change Record pair.

The new regression failed against the original order and passes after the
change. The established private-archive/shared-cache control also passes.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `python3 -m unittest -v …test_haproxy_validates_the_makefile_after_private_archive_extraction` before the fix | 1 | Confirmed `verify_build_target` preceded private worktree preparation. | Framework task worktree, retained command result |
| `sh -n ci/provisioning/prepare-haproxy-runtime.sh` | 0 | Shell syntax valid. | Framework task worktree |
| Focused order plus private-archive tests | 0 | Both order and shared-cache boundary controls pass. | Framework task worktree |
| `make -s test-runtime-component-download` | 0 | 20 security-regression tests pass. | Framework task worktree |
| Bounded fresh `prepare-haproxy-runtime.sh` using task-owned external roots | 0 | Downloaded, re-hashed, privately extracted, built, and staged HAProxy 3.2.22. | Task-owned external runtime root |
| Repeated bounded preparation | 0 | Reused the provenance-verified staged binary. | Task-owned external runtime root |
| `make -s test-ci-security-contract` | 0 | 282 CI/security contract tests pass. | Framework task worktree |
| `make -s test-makefile-contract` | 0 | 3 Makefile contract tests pass. | Framework task worktree |
| `shellcheck ci/provisioning/prepare-haproxy-runtime.sh` | 1 | Existing diagnostics on unchanged lines; no new order-specific diagnostic. | Framework task worktree |

## Security impact

The original failed path was rechecked by the pre-fix regression. After the
change, the real provisioner reaches the private extraction, validates its
Makefile, builds, stages, and reuses a provenance-verified binary. The
alternate shared-cache path remains rejected as a build input by the existing
private-archive regression. This is a provisioning availability repair; it
does not accept an unverified source or relax a security check.

## Documentation and runtime evidence

This paired Change Record is the only reader-facing documentation change. The
bounded preparation is Framework provisioning/lifecycle evidence only; it is
not a claim about a Parent connector host request or matrix promotion.

## Checks not run

- `make -s smoke-haproxy` and `make -s runtime-matrix-haproxy` were not run:
  they require the Parent connector/runtime and a separately authorized Parent
  gitlink update to consume this Framework change.
- Hosted Framework PR, SonarQube Cloud, and review checks are pending delivery.

## Limitations and residual risk

The Parent remains pinned to its existing Framework gitlink. The separate
Parent pointer update and the Parent PR #309 rerun are not part of this
Framework-only change. No security risk is accepted.

## Final diff and review status

Before commit, the task-owned Framework diff, whitespace check, and focused
security review passed. No secrets, raw logs, credentials, or request payloads
are recorded here. The Framework branch exists; its Draft PR is pending.
