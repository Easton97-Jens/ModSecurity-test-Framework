# Change record: 20260718-01-fix-framework-nginx-archive-digest

**Language:** English | [Deutsch](20260718-01-fix-framework-nginx-archive-digest.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260718-01-fix-framework-nginx-archive-digest` |
| UTC date | 2026-07-19 |
| Framework base revision | `c5e7553cf5f3eb7c5535e392798e03ae21f81981` |
| Issue or pull request | Framework Draft PR [#25](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/25) against `master`; this record is updated before the `verified_pr` delivery state. |

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

1. The normal fixed source-build configuration contains a non-empty reviewed
   SHA-256 for one exact official NGINX release asset.
2. The release tag, matching source ref, asset name, and digest are an atomic
   configuration tuple; a fixed source ref or asset name cannot drift from its
   release tag.
3. The selected archive and the private archive passed to `tar` both match the
   configured digest. Explicitly empty, whitespace-only, malformed,
   mismatching, and tuple-inconsistent values stop before network use or `tar`.
4. The version checker verifies the configured official release asset and its
   published GitHub SHA-256 digest but never updates only the tag.
5. English/German documentation and this paired record state the same
   configuration and evidence boundary.

## Alternatives considered

- A generated GitHub tag archive was rejected because its URL names only a tag
  and does not provide the reviewed release-asset contract required here.
- A fixture hash or a digest calculated from an unreviewed candidate was
  rejected as provenance; neither is independent upstream release evidence.
- Verifying only a downloaded archive was rejected because cached archives and
  replacement after the first verification would remain unsafe.
- Passing the initially verified cache path directly to `tar` was rejected
  because it does not bind the digest to the actual extraction input.

## Implementation decision

The fixed default is the reviewed official GitHub release tuple
`release-1.31.2` / `nginx-1.31.2.tar.gz` /
`af2a957c41da636ddc4f883e4523c6d140b4784dbce42000c364ae5092aa473c`.
The release asset is downloaded from the exact GitHub release-download path,
not from a generated tag archive. `prepare-nginx-build.sh` validates this
tuple before NGINX preparation and repeats the digest check at the archive use
point. For a fixed release, the source ref must equal the release tag and the
asset name must be the derived NGINX release asset for that tag.

The 2026-07-19 preflight queried the official GitHub release metadata for
`release-1.31.2`, which reports the selected asset and the SHA-256 above; a
direct HTTPS download matched it. The annotated Git tag resolves to commit
`2fd01ed47a1fd2965754c83f53b33a789d0e07f1`, but GitHub marks that tag as
unsigned. This record therefore makes no PGP-signature-verification claim.

`check-common-versions.py` verifies the configured release, asset URL, and
published digest. If a different latest release exists, it reports an unknown
state with no generated edits: the tag, asset name, and digest must be reviewed
and changed together.

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
- `ci/tools/check-common-versions.py`.
- `tests/security_regression/test_nginx_archive_digest.py`,
  `tests/security_regression/test_nginx_release_provenance.py`, and isolated
  local payload, digest, and latest-release fixtures under
  `tests/fixtures/nginx-archive-digest/`.
- `docs/reference/variables.md` and `docs/reference/variables.de.md`.
- This paired Change Record.

The focused test invokes the real preparation entry point with deterministic
local archives, a controlled download boundary, the real `tar` program, and a
`tar` sentinel. It covers empty, whitespace-only and trailing-whitespace
digests, malformed values, mismatch, matching, archive-swap, latest-cache,
release/source override, existing-cache, and refresh cases.

## Commands and results

All write-capable commands use the task-owned run temporary directory. The
2026-07-19 continuation downloaded one exact official release asset only for
digest verification; it did not build or run NGINX.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `rtk gh api repos/nginx/nginx/releases/tags/release-1.31.2` | 0 | Official release metadata identified `nginx-1.31.2.tar.gz` and GitHub's `sha256:af2a…aa473c` digest. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0`, `evidence/nginx-release-1.31.2-provenance.md` |
| `rtk proxy curl` of the exact official release asset, then `rtk sha256sum` | 0 | Direct HTTPS asset download hashed to `af2a957c41da636ddc4f883e4523c6d140b4784dbce42000c364ae5092aa473c`. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0`, `evidence/nginx-release-1.31.2-asset-verification.md` |
| `rtk env TMPDIR=<task-run>/tmp PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest tests.security_regression.test_nginx_archive_digest tests.security_regression.test_nginx_release_provenance -v` | 0 | Twelve focused archive and release-provenance tests passed. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0` |
| `rtk sh -n ci/lib/common.sh ci/provisioning/prepare-nginx-build.sh` and `rtk python3 -B -m py_compile ci/tools/check-common-versions.py tests/security_regression/test_nginx_archive_digest.py` | 0 | Changed shell and Python sources parsed successfully. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0` |
| `rtk env ... make ... lint` with all Framework, connector, CI, source, build, temp, log, and output roots under the registered task root | 0 | Native Framework lint passed: shell/Python, Makefile/workflow/security/catalog, documentation/path-reference, and whitespace checks. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0`, `evidence/pr25-release-provenance-local-validation.md` |
| `rtk env BUILD_ROOT=<task-run>/build python3 -B ci/tools/check-common-versions.py --check --json --timeout 20` | 0 | The configured release asset and digest matched official metadata; newer `release-1.31.3` produced `unknown` with no update edits. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0`, `evidence/pr25-release-provenance-local-validation.md` |
| `rtk env TMPDIR=<task-run>/tmp python3 -B -m unittest tests.security_regression.test_nginx_archive_digest -v` before the fix | 1 | The vulnerable baseline failed the required fail-closed assertions. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk sh -n ci/lib/common.sh ci/provisioning/prepare-nginx-build.sh` | 0 | Both changed shell files parsed successfully. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk env TMPDIR=<task-run>/tmp python3 -B -m unittest tests.security_regression.test_nginx_archive_digest -v` after the fix | 0 | Seven focused tests passed, including every required negative and legitimate control. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk env BUILD_ROOT=<task-run>/build TMPDIR=<task-run>/tmp PYTHONDONTWRITEBYTECODE=1 FRAMEWORK_ROOT=<task-worktree> make lint` | 0 | Native Framework shell, Python, security, catalog, and documentation lint checks passed. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk make check-documentation` and `rtk git diff --check` | 0 | Documentation and whitespace checks passed. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk shellcheck -x ci/lib/common.sh ci/provisioning/prepare-nginx-build.sh` | 1 | Only diagnostics already present in the unchanged Framework base; no task-owned diagnostic was introduced. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |
| `rtk gh pr checks 25` | 1 | `scaffold-lint` and SonarCloud passed; `test-common/common-structure` failed because the unchanged workflow expects 141 YAML cases and finds 179. The same check already fails on `master`. | `20260718T092116Z-fnd-framework-0006-nginx-digest-5251a4f1` |

## Security impact

This remediates FND-FRAMEWORK-0006 with a usable reviewed default rather than
only a fail-closed caller override. The fixed release tag, asset, and digest
are bound before NGINX archive selection/download/extraction. An explicitly
empty override, malformed/whitespace value, mismatch, wrong source ref, or
wrong asset name fails closed before network use or `tar`. The alternate-bypass
review covers latest resolution, release/source overrides, cache/refresh,
pre-existing archives, derived archive-path replacement, and a replacement
between the first candidate hash and private-copy verification. The latter is
blocked before `tar`.

## Documentation and runtime evidence

Paired English/German variable documentation records the reviewed fixed
release tuple and explains that future tag, asset, and digest changes require
one atomic review. The current continuation retains the official metadata and
direct asset-digest comparison as task evidence.

The focused test is controlled local runtime evidence for the archive handling
boundary and updater contract. The direct asset comparison is release-asset
provenance evidence only; neither check claims an NGINX runtime, connector
runtime, CI lifecycle, or production result.

## Checks not run

- Full Framework and connector matrices are not run: the change is scoped to
  the NGINX archive trust boundary and no connector runtime prerequisites were
  supplied.
- A full NGINX source build is not run; the task verified the official archive
  digest but did not claim build or runtime coverage.
- Exact-new-head GitHub checks, SonarCloud, review state, and default-branch
  delivery checks remain pending until this continuation is pushed.

## Limitations and residual risk

The fixed default relies on GitHub's published release-asset digest and HTTPS
metadata availability. Future releases require a new reviewed tag/asset/digest
tuple and fresh upstream verification. The staged copy binds the tested
candidate replacement case to the extraction input, but no local test can
substitute for external upstream release governance or production runtime
evidence.

## Final diff and review status

The release-provenance implementation, focused tests, full native lint,
documentation/whitespace review, and current local boundary checks are
validated. An independent focused security review found no reportable
source-to-sink regression; its traceability observation that the new test must
be staged is satisfied by this staged nine-file change set. Exact-new-head
external gate evidence is still required before this Draft PR can be eligible
for integration. No waiver or unrelated CI change is authorized.
