# Change record: 20260718-01-fix-framework-nginx-archive-digest

**Language:** English | [Deutsch](20260718-01-fix-framework-nginx-archive-digest.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260718-01-fix-framework-nginx-archive-digest` |
| UTC date | 2026-07-18 |
| Framework base revision | `cdc91a398d6c156eaff927d742b23018a3817fb6` |
| Issue or pull request | Framework Draft PR pending; this record is updated before the `verified_pr` delivery state. |

## Motivation and problem statement

`NGINX_SHA256` could be empty. The NGINX preparation path recorded a local
hash, skipped comparison, and extracted the selected release archive. A
substituted archive could therefore reach build processing without a reviewed,
matching digest.

## Affected components and security boundaries

The change is limited to the Framework NGINX GitHub release-archive integrity
boundary: `ci/lib/common.sh` configuration, `prepare-nginx-build.sh` archive
selection, cache/refresh, verification, staging, and extraction. It does not
modify a connector, Parent source or Gitlink, MRTS, or FND-FRAMEWORK-0005.

## Acceptance criteria

1. A non-empty, syntactically valid SHA-256 digest is required before NGINX
   latest resolution, archive cache use, download, extraction, or build work.
2. The selected archive and the private archive passed to `tar` both match the
   configured digest.
3. Empty, whitespace-only, trailing-whitespace, malformed, and mismatching
   values stop with no `tar` invocation.
4. A matching local archive succeeds; latest, release/source overrides,
   existing cache, refresh, and an archive replacement are covered.
5. English/German documentation and this paired record state the same
   configuration and evidence boundary.

## Alternatives considered

- Adding an unverified repository-default digest was rejected. This task has
  no approved NGINX digest-maintenance source and intentionally performs no
  real network download; a speculative value would weaken provenance.
- Verifying only a downloaded archive was rejected because cached archives and
  replacement after the first verification would remain unsafe.
- Passing the initially verified cache path directly to `tar` was rejected
  because it does not bind the digest to the actual extraction input.

## Implementation decision

The configuration remains deliberately unset by default, but it is now a
mandatory reviewed caller input. `prepare-nginx-build.sh` validates the digest
and relevant references before NGINX preparation and repeats that validation at
the archive use point. It validates fixed and `latest`-resolved tags before
forming the candidate path.

The script reuses an existing candidate only when `REFRESH` is not `1`; refresh
downloads to a temporary path and atomically places the candidate. In either
case it verifies the candidate, copies it into an isolated
`verified-archives/` directory below `NGINX_BUILD_DIR`, verifies the staged
copy before and after final placement, and gives only that private verified
copy to `tar`.

## Changed files and tests

Versioned Framework changes:

- `ci/lib/common.sh`.
- `ci/provisioning/prepare-nginx-build.sh`.
- `tests/security_regression/test_nginx_archive_digest.py` and isolated local
  payload, digest, and latest-release fixtures under
  `tests/fixtures/nginx-archive-digest/`.
- `docs/reference/variables.md` and `docs/reference/variables.de.md`.
- This paired Change Record.

The focused test invokes the real preparation entry point with deterministic
local archives, a controlled download boundary, the real `tar` program, and a
`tar` sentinel. It covers empty, whitespace-only and trailing-whitespace
digests, malformed values, mismatch, matching, archive-swap, latest-cache,
release/source override, existing-cache, and refresh cases.

## Commands and results

All write-capable commands used the task-owned run temporary directory; no
real NGINX release was downloaded or built.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `rtk env TMPDIR=<task-run>/tmp python3 -B -m unittest tests.security_regression.test_nginx_archive_digest -v` before the fix | 1 | The vulnerable baseline failed the required fail-closed assertions. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk sh -n ci/lib/common.sh ci/provisioning/prepare-nginx-build.sh` | 0 | Both changed shell files parsed successfully. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk env TMPDIR=<task-run>/tmp python3 -B -m unittest tests.security_regression.test_nginx_archive_digest -v` after the fix | 0 | Seven focused tests passed, including every required negative and legitimate control. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk env BUILD_ROOT=<task-run>/build TMPDIR=<task-run>/tmp PYTHONDONTWRITEBYTECODE=1 FRAMEWORK_ROOT=<task-worktree> make lint` | 0 | Native Framework shell, Python, security, catalog, and documentation lint checks passed. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk make check-documentation` and `rtk git diff --check` | 0 | Documentation and whitespace checks passed. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk shellcheck -x ci/lib/common.sh ci/provisioning/prepare-nginx-build.sh` | 1 | Only diagnostics already present in the unchanged Framework base; no task-owned diagnostic was introduced. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |

## Security impact

This remediates FND-FRAMEWORK-0006. The original unset-digest path now blocks
before NGINX archive selection/download/extraction, and malformed/whitespace
and mismatch values have the same fail-closed result. The alternate bypass
review covers latest resolution, release and source overrides, cache/refresh,
pre-existing archives, derived archive-path replacement, and a replacement
between the first candidate hash and private-copy verification. The latter is
blocked before `tar`.

## Documentation and runtime evidence

Paired English/German variable documentation now requires a reviewed,
64-hex-character digest for the exact `github-release` archive and explains
that the default is intentionally not usable for provisioning.

The focused test is controlled local runtime evidence for the archive handling
boundary only. It does not claim a real upstream NGINX download, NGINX runtime,
connector runtime, CI lifecycle, or production evidence.

## Checks not run

- Full Framework and connector matrices are not run: the change is scoped to
  the NGINX archive trust boundary and no connector runtime prerequisites were
  supplied.
- A real release download/build is not run: it is outside the authorized local
  fixture scope and would not establish reviewed digest provenance.
- Delivery, PR checks, reviews, and Sonar status remain pending until the
  Framework-only branch is committed and a Draft PR exists.

## Limitations and residual risk

A caller must obtain and review the digest for every selected NGINX archive;
the Framework deliberately does not invent one. The staged copy binds the
tested candidate replacement case to the extraction input, but no local test
can substitute for external upstream release governance or production runtime
evidence.

## Final diff and review status

The implementation, focused test, staged scope, and final whitespace/
documentation review are locally validated. Delivery and current-head PR
reviews remain pending and will be recorded before `verified_pr`.
