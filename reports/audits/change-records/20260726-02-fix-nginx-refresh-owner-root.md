# Change record: Restore NGINX cache refresh owner-root containment

**Language:** English | [Deutsch](20260726-02-fix-nginx-refresh-owner-root.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260726-02-fix-nginx-refresh-owner-root` |
| UTC date | 2026-07-26 |
| Framework base revision | `c27c644e088904b71b8380d16ee34f1b36f2c001` |
| Issue or pull request | Parent canonical finding `FND-CROSS-0008`; Framework task branch `agent/fix-nginx-cache-owner-root`. Draft PR is pending at record creation; no Framework merge is authorized. |

## Motivation and problem statement

The Parent runtime matrix supplies a verified cache-backed NGINX build while
each matrix job retains a distinct local `BUILD_ROOT`. The Framework NGINX
provisioner previously used only that local root as the `REFRESH` deletion
owner, so the correct cache build failed closed before the runtime matrix could
produce legitimate evidence. This record covers only the Framework half of the
cross-repository owner-root contract; it does not update the Parent Gitlink or
matrix invocation.

## Affected components and security boundaries

- `ci/provisioning/prepare-nginx-build.sh` receives an explicit, validated
  `NGINX_BUILD_OWNER_ROOT` solely for its existing NGINX `REFRESH` deletion
  guard. It defaults to `BUILD_ROOT`, preserving non-cache callers.
- `safe_remove_runtime_path` remains the deletion sink. Its canonical-path,
  safe-runtime-path, owner-root containment, and unsafe-root checks remain
  unchanged.
- The controlled inputs are the prepared NGINX build path and selected owner
  root. The trusted Parent follow-up must derive the narrow managed
  connector-cache build root; Framework does not discover, broaden, or
  substitute it.
- Parent source, Parent Gitlink, Framework `master`, MRTS source, and the
  Framework-to-MRTS Gitlink remain outside this change.

## Acceptance criteria

- A cache-backed NGINX build below an explicit safe owner root refreshes
  successfully while `BUILD_ROOT` remains distinct.
- A cache build outside the owner root, including one reached through a
  symlink, remains rejected before deletion or download.
- A relative explicit owner root is rejected before archive/network work.
- The default owner root remains the existing `BUILD_ROOT` behavior.
- The Framework-only source, test, and paired Change Record are delivered in
  a normal Draft PR; no merge is performed by Codex.

## Alternatives considered

- Broadening each matrix job's `BUILD_ROOT` to the component cache was
  rejected because it would erase job isolation and widen deletion authority.
- Disabling `REFRESH` or the deletion guard was rejected because it would hide
  the producer failure and weaken a fail-closed containment control.
- Accepting an implicit cache root was rejected: only an explicit caller value
  is used, and it is validated as an absolute safe generated path.

## Implementation decision

`NGINX_BUILD_OWNER_ROOT` defaults to `BUILD_ROOT`, is validated beside the
other generated NGINX paths, and is passed only to `safe_remove_runtime_path`
from `safe_remove_dir`. Existing cache, symlink, and forbidden-root controls
remain in the shared helper. The archive regression harness accepts the
task-scoped `TEST_TMPDIR` so its temporary files can remain outside source and
MRTS checkouts.

## Changed files and tests

- `ci/provisioning/prepare-nginx-build.sh` — explicit owner-root parameter,
  validation, and deletion-guard hand-off.
- `tests/security_regression/test_nginx_archive_digest.py` — cache-contained
  positive control; outside-owner and symlink negative controls; relative
  owner-root rejection; task-scoped temporary-root support.
- This English/German Change Record pair.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused positive regression before the source change | 1 | Expected pre-fix failure: cache-backed NGINX build was outside the job-local `BUILD_ROOT`. | `20260726T110116Z-framework-nginx-owner-root` |
| `rtk sh -n ci/provisioning/prepare-nginx-build.sh` | 0 | Updated shell entry point has valid POSIX shell syntax. | Local task worktree |
| Selected `test_nginx_archive_digest` owner-root controls | 0 | Cache-contained refresh passed; outside-owner, symlink, and relative-owner-root controls rejected safely. | Local task worktree; task-owned `TEST_TMPDIR` |
| Remaining twelve existing `test_nginx_archive_digest` methods, executed in bounded selections | 0 | All pre-existing digest, archive replacement, HTTPS, cache refresh, and override cases passed. | Local task worktree; task-owned `TEST_TMPDIR` |

## Security impact

This is a containment-control remediation, not a claimed runtime exploit.
The original same-boundary proof failed closed because a legitimate cache build
was not under the job-local owner. The positive regression now exercises
the intended explicit owner hand-off. Outside-owner and symlink targets still
fail before deletion; a relative owner root is rejected during path validation.
No guard, cache restriction, or terminal evidence gate is relaxed.

## Documentation and runtime evidence

This paired Change Record is the only reader-facing Framework documentation
change. No host runtime evidence, Parent matrix run, Framework merge, Parent
Gitlink update, SonarQube Cloud result, or MRTS evidence is claimed. Those
remain separate current-head or cross-repository steps.

## Checks not run

- Hosted Framework Actions, SonarQube Cloud, reviews, conversations, and
  branch-protection evaluation are not run yet because they apply to the
  future exact Draft PR head.
- The full Parent runtime matrix is not run in this Framework-only worktree;
  it requires the later Parent Gitlink/matrix follow-up after user-reviewed
  Framework integration.

## Limitations and residual risk

Framework validates that the supplied owner root is absolute and safe, but it
cannot establish which managed cache subtree the Parent should select. The
later Parent #74 follow-up must derive and validate the narrow connector-cache
build root, then obtain new exact-head producer and terminal-gate evidence.
Until then `FND-CROSS-0008` remains a release blocker. No Framework merge or
MRTS action is authorized by this record.

## Final diff and review status

The scoped diff contains only the NGINX provisioner, its focused regression
suite, and this paired record. The original positive failure, the same-boundary
legitimate control, and the alternate outside-owner/symlink controls were
reviewed. Local whitespace, documentation, and Git-boundary checks passed;
the Draft-PR exact-head checks remain pending. No secrets or raw runtime
payloads are included.
