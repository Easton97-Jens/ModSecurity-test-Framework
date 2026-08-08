# Change record: 20260808-02-fix-apr-util-provenance

**Language:** English | [Deutsch](20260808-02-fix-apr-util-provenance.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260808-02-fix-apr-util-provenance` |
| UTC date | 2026-08-08 |
| Framework base revision | `54460837def44f13d37e63faa8363cbc8ff16410` |
| Issue or pull request | Task branch `fix/apr-util-164-provenance`; Framework pull request is pending creation after local review. |

## Motivation and problem statement

The active Apache download service returns HTTP 404 for the formerly pinned
`apr-util-1.6.3.tar.bz2`. Both historical Parent full-smoke variants therefore
stopped at APR-util acquisition before an Apache or NGINX runtime could be
prepared. The former Framework runtime configuration also allowed an arbitrary
HTTPS APR-util URL or an empty literal digest to weaken the intended source and
archive-integrity boundary.

## Affected components and security boundaries

This Framework-only change covers the APR-util provider-to-download-to-
extraction boundary in `ci/lib/common.sh` and
`ci/provisioning/prepare-apache-build.sh`, plus the central version checker,
focused regression contracts, and paired documentation. The trusted provider
is the reviewed current Apache asset
`https://downloads.apache.org/apr/apr-util-1.6.4.tar.bz2` and its published
SHA-256 metadata. Parent cache records, Parent full-smoke evidence, the Parent
gitlink, and MRTS are separate boundaries and are not changed here.

## Acceptance criteria

1. The central tuple is exactly APR-util 1.6.4, the canonical
   `downloads.apache.org` asset URL, its same-asset `.sha256` URL, and
   `3e2ae08f40efa0c3701e54a954cefa08242de22a69f91a8ae44fc1e624ba309b`.
2. Version, host, path, asset, literal digest, checksum URL, and unreviewed
   provider-redirect mismatches fail before Apache provisioning, cache use,
   download, or extraction.
3. The literal digest is required, valid hexadecimal, and matching before the
   first APR-util extraction; the checksum URL remains supplementary metadata,
   never a fallback.
4. The common-version check proves the approved tuple against in-memory
   official-provider responses and requires manual atomic review for a future
   release.
5. Focused regressions cover the valid control and the stale, mirror, path,
   asset, missing/malformed/mismatching digest, and checksum-URL bypasses.
6. English and German documentation and this paired record remain equivalent.

## Alternatives considered

- Retaining the 1.6.3 URL or treating its 404 as optional was rejected because
  it leaves a non-reproducible broken provider path.
- Falling back to archive.apache.org or an arbitrary mirror was rejected
  because historical content is not the active reviewed provider and a mirror
  bypasses the canonical asset contract.
- Allowing a caller-supplied source or digest was rejected because a matching
  attacker-controlled digest would no longer prove the reviewed source.
- Updating the Parent workflow to override APR-util was rejected because the
  defect and secure control belong to the Framework.

## Implementation decision

`common.sh` now owns four reviewed APR-util pin values and preserves explicit
caller input only long enough to reject any tuple mismatch. The guard derives
the canonical asset and checksum endpoint from the pinned version, validates a
64-character hexadecimal literal digest, and accepts only values identical to
the reviewed tuple. `prepare-apache-build.sh` invokes that guard before V3
source preparation, downloads APR-util only from the direct canonical endpoint
without following redirects, and uses a required literal-digest helper before
APR-util extraction. The version checker refuses to mechanically advance this
atomic tuple; a future release needs one explicit compatibility and provenance
review.

## Changed files and tests

- `ci/lib/common.sh` owns and enforces the immutable APR-util tuple.
- `ci/provisioning/prepare-apache-build.sh` invokes the guard before side
  effects and requires the APR-util digest before `tar`.
- `ci/tools/check-common-versions.py` validates the approved/runtime tuple and
  disables mechanical tuple updates.
- `tests/security_regression/test_apr_util_provenance.py` exercises the shell
  guard, direct-no-redirect downloader, and real preparer ordering;
  `test_common_versions_sonar_provenance.py` covers offline official-provider
  and mismatch cases. `test_pcre2_archive_digest.py` updates its isolated
  fixture to the same canonical APR-util identity while retaining its own
  synthetic archive digest.
- `Makefile` includes the focused regression in lint.
- `docs/reference/variables.md` and `docs/reference/variables.de.md` document
  the same boundary.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `make test-apr-util-provenance` with task-owned roots and `PYTHON=python3` | 0 | 5 APR-util tuple, guard-order, and direct-no-redirect tests passed. | Task-owned Framework worktree |
| `python3 -B -m unittest tests.security_regression.test_common_versions_sonar_provenance -v` | 0 | 18 offline provenance/checker tests passed. | Task-owned Framework worktree |
| `python3 -B -m unittest discover -s tests/security_regression -p 'test_pcre2_archive_digest.py' -v` | 0 | 3 digest-boundary regression tests passed. | Task-owned Framework worktree |
| `sh -n ci/lib/common.sh ci/provisioning/prepare-apache-build.sh` | 0 | Modified POSIX-shell files parsed successfully. | Task-owned Framework worktree |
| `python3 -B ci/tools/check-common-versions.py --check --json --timeout 20` | 1 | APR-util is current and its official SHA-256 matches; unrelated existing ModSecurity v3/manual and HAProxy update states make the aggregate checker nonzero. | Task-owned Framework worktree |
| `make lint` with task-owned roots and `PYTHON=python3` | 0 | Diagnostic lint, contracts, workflow, documentation, cache, and provenance suites passed; Change Record contract and diff checks were rerun after recording this result. | Task-owned Framework worktree |
| Exact CPython 3.14.6 focused checks | pending | The local host is Python 3.14.4; exact-interpreter GitHub CI on the submitted head is required. | `.python-version` and task plan |

## Security impact

The original 404 path and alternate mirror/empty-digest bypasses are rejected
before the Apache provisioner starts source acquisition. The direct canonical
APR-util downloader does not follow a provider redirect, and the repair makes
literal-digest verification a pre-extraction requirement. The final record
must be updated with exact submitted-head hosted results.

## Documentation and runtime evidence

The paired variable references state the central provider, mandatory literal
digest, checksum-URL role, and rejection behavior. Independent task evidence
already records that the official 1.6.4 asset and published SHA-256 agree; no
Framework connector runtime, Parent full smoke, or production deployment is
claimed by this record.

## Checks not run

- Local diagnostic checks run with Python 3.14.4 are useful regression
  evidence but do not replace the repository-required CPython 3.14.6 result.
- No real Apache build is run locally; the exact-head hosted checks and later
  Parent full-smoke runs remain mandatory.

## Limitations and residual risk

The central pin deliberately requires a manual review for each future APR-util
release. The guard and focused tests do not replace a hosted build against the
official asset, CI review, SonarQube analysis, a Framework merge, or separately
owned Parent runtime evidence. MRTS remains unchanged.

## Final diff and review status

The task-owned Framework worktree has not been committed, pushed, or submitted
for review. No branch protection, approval, CI, SonarQube, merge, Parent
gitlink, Parent PR, or finding-lifecycle result is asserted here.
