# Change record: 20260802-01-pin-nginx-release-1.31.3

**Language:** English | [Deutsch](20260802-01-pin-nginx-release-1.31.3.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260802-01-pin-nginx-release-1.31.3` |
| UTC date | 2026-08-02 |
| Framework base revision | `5cb371949ceafec6685cf716ba50a75d0f448bd1` |
| Issue or pull request | [Framework PR #60](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/60) on `agent/pin-nginx-current-release-20260802`. The current task requests controlled integration after fresh exact-head evidence; no merge result is recorded at this documentation checkpoint. |

## Motivation and problem statement

The Framework default was advanced to `release-1.31.3`, but the NGINX path
still accepted floating `latest` input and could resolve it through
`/releases/latest`. That made the selected asset and digest non-reproducible
and allowed a legacy cache identity outside the reviewed fixed tuple.

F-GS-003 requires one reviewed source repository, release tag, source ref,
asset name, and SHA-256 selection that fails closed before cache use, network
access, download, or extraction.

## Affected components and security boundaries

This Framework record covers the NGINX release-archive provenance boundary in
`ci/lib/common.sh`, `ci/provisioning/prepare-nginx-build.sh`,
`ci/tools/check-common-versions.py`, focused regression contracts, and paired
documentation. It concerns upstream selection, cache identity, archive
integrity, and the pre-extraction trust boundary.

The Parent full-smoke resolver, Parent runtime evidence, and Parent gitlink are
separate Parent-owned deliverables. MRTS remains unchanged and read-only. This
record does not claim a connector or production-runtime result.

## Acceptance criteria

1. The reviewed default is `https://github.com/nginx/nginx`, `github-release`,
   `release-1.31.3`, `release-1.31.3`, `nginx-1.31.3.tar.gz`, and
   `a7657c50811c2d92d9895395e8b873ef60398142c4db21eb647811c38f6dd525`.
2. NGINX rejects `latest` for tag and ref and rejects missing, empty,
   malformed, mismatched, or tuple-inconsistent values before cache selection,
   network, download, or extraction.
3. NGINX-specific provisioning and provenance queries never call
   `/releases/latest`; metadata is resolved only through `/releases/tags/<tag>`.
4. Cache reuse requires a full-tuple key and matching non-symlinked manifest;
   a legacy latest cache cannot be reused. SHA-256 is mandatory before staging
   and extraction and is checked again after staging.
5. Final-head tests cover the fixed control, `latest` rejection, malformed
   inputs, mismatch controls, no latest-route request, and stale-cache
   non-reuse. EN/DE documentation must remain equivalent.

## Alternatives considered

- Retaining NGINX `latest` compatibility was rejected because it creates a
  floating selection outside the reviewed asset/digest tuple.
- Looking up the newest NGINX release through `/releases/latest` was rejected
  because a new release requires an atomic manual review.
- A filename-only or legacy latest-response cache was rejected because it
  cannot prove the full provenance identity.
- Generic latest behavior for other components is outside this NGINX-specific
  remediation and cannot re-enable an NGINX latest path.

## Implementation decision

The Framework NGINX path uses only `github-release` with
`https://github.com/nginx/nginx`. It resolves the direct tagged asset
`https://github.com/nginx/nginx/releases/download/release-1.31.3/nginx-1.31.3.tar.gz`.
An unset source ref derives from the reviewed tag; an explicitly supplied empty
value fails closed. `latest` is invalid for both NGINX tag and source ref.

The cache key and manifest bind repository, mode, tag, ref, asset name, and
canonical expected SHA-256. The digest is checked before staging or extraction
and rechecked after staging. The NGINX version check resolves the configured
tag only and does not auto-update the tuple.

## Changed files and tests

- `ci/lib/common.sh` preserves explicit empty input for fail-closed validation.
- `ci/provisioning/prepare-nginx-build.sh` validates the fixed NGINX source,
  resolves the direct tagged asset, and binds cache reuse to the full tuple.
- `ci/tools/check-common-versions.py` uses a configured-tag-only NGINX query.
- `tests/security_regression/test_nginx_archive_digest.py` and
  `tests/security_regression/test_nginx_release_provenance.py` must be
  reconciled with the final PR head and their observed results before delivery.
- `docs/reference/variables.md`, `docs/reference/variables.de.md`, and this
  paired Change Record describe the reader-facing contract.

## Commands and results

Earlier PR #60 evidence covered a supported NGINX `latest` branch. It does not
validate this remediation and is not passing evidence for the amended head.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `sh -n ci/lib/common.sh ci/provisioning/prepare-nginx-build.sh` | `0` | PASS: final shell syntax check. | task worktree pre-commit log |
| `git diff --check` | `0` | PASS: no whitespace errors in the amended Framework diff. | task worktree pre-commit log |
| `shellcheck -x ci/lib/common.sh ci/provisioning/prepare-nginx-build.sh` | `1` | BLOCKED by existing unrelated diagnostics at provisioner lines 4, 5, 7, 8, 44, 49, 54, and 420; none is in this remediation diff. | task worktree pre-commit log |
| `make test-nginx-archive-digest` | blocked | BLOCKED locally: this Framework revision requires CPython `3.14.6`; the available Framework environment is `3.14.4`, and no repository-environment creation/repair is authorized. Exact-interpreter PR CI is required. | current `.python-version` and Framework Python policy |
| `python -B -m unittest tests.security_regression.test_nginx_release_provenance -v` | blocked | BLOCKED locally for the same exact-interpreter prerequisite; prior 3.14.4 observations are diagnostic-only and are not delivery evidence. | current `.python-version` and Framework Python policy |
| `make check-documentation`, `make test-change-record-contract`, `make lint` | blocked | BLOCKED locally for the same exact-interpreter prerequisite; these checks remain required on the pushed exact head. | current `.python-version` and Framework Python policy |

## Security impact

This source-provenance and archive-integrity remediation removes the NGINX
floating-release branch, rejects invalid configuration before trust-boundary
actions, prevents cross-tuple cache reuse, and requires a valid SHA-256 before
extraction. Tests must demonstrate the original latest path and an alternate
source-ref bypass are blocked while the reviewed fixed tuple succeeds.

## Documentation and runtime evidence

The paired variable references record the full tuple, rejection rules,
NGINX-specific `/releases/latest` prohibition, cache-manifest binding, and
SHA-256 gate. The official tag-bound release metadata and a fresh direct HTTPS
asset download were independently observed for this task: the named asset and
local archive both hash to
`a7657c50811c2d92d9895395e8b873ef60398142c4db21eb647811c38f6dd525`, and
`src/core/nginx.h` reports `NGINX_VERSION "1.31.3"`. This record has no
connector, Parent full-smoke, or production runtime evidence.

## Checks not run

- Exact-interpreter current-head NGINX regression, documentation, and broader
  Framework checks are pending GitHub CI because local CPython `3.14.6` is
  unavailable and a noncanonical interpreter is not substituted.
- No full NGINX build or connector matrix result is claimed here.
- Parent full-smoke, Parent runtime evidence, and Parent gitlink work are
  separate Parent-owned work, not Framework validation.

## Limitations and residual risk

Future NGINX releases require fresh official metadata, an actual archive
download with hash verification, and an atomic review of the full tuple. Until
final exact-head tests, PR checks, SonarQube result, reviews, controlled
Framework merge, and separately owned Parent remediation are observed,
F-GS-003 is not closed.

## Final diff and review status

The Framework remediation is locally in progress. No amended-head commit,
push, CI result, SonarQube result, review disposition, or merge is recorded by
this Change Record. Framework PR #60 may be integrated only after its current
exact-head, review, CI, SonarQube, and master-integration gates pass; the
controlled merge is pending, not complete.
