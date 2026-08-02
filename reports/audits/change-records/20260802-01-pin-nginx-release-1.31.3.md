# Change record: 20260802-01-pin-nginx-release-1.31.3

**Language:** English | [Deutsch](20260802-01-pin-nginx-release-1.31.3.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260802-01-pin-nginx-release-1.31.3` |
| UTC date | 2026-08-02 |
| Framework base revision | `5cb371949ceafec6685cf716ba50a75d0f448bd1` |
| Issue or pull request | Framework Draft PR pending; local validation is recorded before the first task commit. |

## Motivation and problem statement

The Framework reviewed NGINX Mainline default was `release-1.31.2`. Official upstream metadata identifies `release-1.31.3` as the current Mainline release. The tag, derived source ref, release asset, and published SHA-256 must advance together rather than drift one member of the provenance tuple.

## Affected components and security boundaries

The change is limited to the Framework NGINX release-archive provenance boundary: the default in `ci/lib/common.sh`, default/provenance regression contracts, and paired reference documentation. Existing fail-closed validation before cache use, download, or extraction remains unchanged. No connector, Parent source or Gitlink, MRTS, or GitHub setting is modified.

## Acceptance criteria

1. The default is the exact reviewed `release-1.31.3` tuple: matching derived ref, `nginx-1.31.3.tar.gz`, and the published SHA-256.
2. Tests cover the current tuple, a newer unreviewed release, and existing digest/tuple negative controls.
3. English/German documentation and this paired Change Record agree.
4. Focused checks pass for the final Framework PR head without Parent or MRTS change.

## Alternatives considered

- A tag-only update was rejected because it would make the asset/digest contract inconsistent.
- A switch to NGINX Stable was rejected because the existing default is Mainline and 1.31.3 is its direct official successor.
- Removing the separately tested runtime `NGINX_RELEASE_TAG=latest` override was rejected as a breaking, out-of-scope policy change.
- Updating the Parent full-smoke `latest` override was rejected as out of scope: it is Parent-owned and follows a distinct Git-tag-archive route.

## Implementation decision

The Framework default is advanced atomically to `release-1.31.3` / `nginx-1.31.3.tar.gz` / `a7657c50811c2d92d9895395e8b873ef60398142c4db21eb647811c38f6dd525`. `NGINX_SOURCE_GIT_REF` remains derived from `NGINX_RELEASE_TAG`, so it resolves to the same exact tag without duplicate literals. Existing generic provisioning and version checking already require fixed-release consistency, verify the digest before and after private staging, and refuse automatic tuple updates.

Official GitHub release metadata and one direct HTTPS release-asset download reported the same SHA-256. The release API does not mark its object immutable; this record claims the reviewed tag, asset, published digest, and existing digest verification, not unsupported upstream immutability.

## Changed files and tests

- `ci/lib/common.sh` updates the reviewed default tuple.
- `tests/security_regression/test_nginx_release_provenance.py` updates the current tuple and keeps the unreviewed-newer-release control at 1.31.4.
- `tests/security_regression/test_nginx_archive_digest.py` updates the default tuple assertion; malformed/missing/mismatched/inconsistent controls remain.
- `docs/reference/variables.md` and `docs/reference/variables.de.md` update the paired documented tuple.
- This paired Change Record records the evidence and boundary.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `rtk proxy gh api repos/nginx/nginx/releases/tags/release-1.31.3` | 0 | Official metadata reported `nginx-1.31.3.tar.gz`, 1,344,885 bytes, and `sha256:a7657c…dd525`. | `20260802T112428Z-framework-nginx-pin-1.31.3`, private run manifest |
| `rtk proxy curl --proto =https --proto-redir =https … nginx-1.31.3.tar.gz`; `rtk proxy sha256sum` | 0 | Exact official HTTPS asset hashed to `a7657c…dd525`; no extraction or build occurred. | `20260802T112428Z-framework-nginx-pin-1.31.3`, private temporary evidence |
| `check-common-versions.py --check --json --timeout 20` | 1 | NGINX itself is `current` with the exact asset/digest; the aggregate reports unrelated existing unknown/outdated components. | `20260802T112428Z-framework-nginx-pin-1.31.3`, private command output |
| `python -B -m unittest tests.security_regression.test_nginx_release_provenance -v` | 0 | 3/3 current-tuple, mismatch, and newer-unreviewed-tuple tests passed. | `20260802T112428Z-framework-nginx-pin-1.31.3` |
| `make test-nginx-archive-digest` | 0 | 15/15 archive integrity, fixed/default, `latest`, cache, symlink, and swap controls passed in 288.612 seconds. | `20260802T112428Z-framework-nginx-pin-1.31.3` |
| `sh -n …`; `shellcheck -x ci/lib/common.sh` | 0 | Changed shell/default and provisioning syntax checked with no diagnostic. | `20260802T112428Z-framework-nginx-pin-1.31.3` |
| `make test-change-record-contract`; `make check-documentation` | 0 | Change Record contract and English/German documentation checks passed. | `20260802T112428Z-framework-nginx-pin-1.31.3` |
| `make lint` | 0 | Native Framework static, security, contract, regression, and documentation gate passed. | `20260802T112428Z-framework-nginx-pin-1.31.3` |

## Security impact

This preserves the release-archive integrity control while refreshing its reviewed default. Existing negative controls still block missing, malformed, mismatched, or tuple-inconsistent values before network use or `tar`. The explicit runtime `latest` compatibility branch remains separate and cannot be represented by the static provenance checker as a reviewed default.

## Documentation and runtime evidence

Paired English/German variable documentation records the same tuple. The direct asset hash is release-asset provenance evidence and focused tests are controlled local contract evidence; neither claims an NGINX, connector, Parent full-smoke, or production runtime result.

## Checks not run

- Full Framework/connector runtime matrices are not run: this is a reviewed default/configuration contract update, not a connector runtime change.
- A full NGINX build is not run: the asset is verified but not extracted/built.
- Parent full-smoke is not run or modified: its `latest` override and Git-tag archive provenance are a separate Parent decision.

## Limitations and residual risk

Future releases require fresh official evidence and an atomic tag/asset/digest review. The Framework PR does not close the Parent full-smoke `latest` override, which can bypass the Framework default and uses a different archive form. F-GS-003 therefore remains partially unresolved pending a separately authorized Parent solution.

## Final diff and review status

Focused and broad local validation passed. An independent diff review found no plausible security regression and confirmed the tuple is changed atomically. The staged-diff review, first task commit, remote equality, Draft PR, and current-head CI/read-back remain pending; no merge is authorized.
