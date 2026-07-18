# Change record: CRS source provenance pin

**Language:** English | [Deutsch](20260718-01-crs-source-provenance.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260718-01-crs-source-provenance` |
| UTC date | `2026-07-18` |
| Framework base revision | `cdc91a398d6c156eaff927d742b23018a3817fb6` |
| Issue or pull request | `FND-FRAMEWORK-0004`; Framework Draft PR pending authorized delivery |

## Motivation and problem statement

`FND-FRAMEWORK-0004` confirmed that a mutable `CRS_GIT_REF` could select the
source consumed by Framework CRS provisioning. A detached checkout of
`FETCH_HEAD` did not bind the consumed object to a reviewed immutable commit.

## Affected components and security boundaries

- `ci/lib/common.sh` owns the reviewed CRS source identity and enforcement
  helper.
- `ci/provisioning/fetch-crs.sh` is the Git/provisioning consumption boundary.
- `ci/tools/check-common-versions.py` must not auto-update a release label
  without its reviewed matching commit.
- `ci/checks/catalog/check-crs-version-pinning.sh`, the Make target, and the
  focused regression suite enforce the local contract.

The boundary is Framework-owned supply-chain provenance. Parent product source
and gitlink are unchanged; MRTS source is neither initialized nor modified.

## Acceptance criteria

1. Provisioning accepts only the centrally reviewed CRS URL, release label,
   and full immutable commit before Git use.
2. Fresh and existing checkout paths fetch, check out, and verify that commit
   before submodule processing.
3. Mutable tags, branches, ref namespaces, abbreviated hashes, unrelated full
   hashes, and source overrides are rejected before Git use.
4. A reviewed commit control continues to work through the same boundary.

## Alternatives considered

- Retaining a mutable tag with detached `FETCH_HEAD` was rejected because the
  selected object can change.
- Replacing the release label with only a commit would have broken the
  release-oriented updater contract. The selected design retains a reviewed
  label as metadata and makes the full commit the consumed identity.
- Automatically resolving and rewriting a new release tag plus commit was
  deferred: a source update needs explicit provenance review, so the updater
  reports it for manual paired review instead.

## Implementation decision

The versioned CRS identity contains the expected repository URL, release tag,
and full lower-case commit `55b09f5acfd16413e7b31041100711ceb7adc89c`.
Effective caller values must match those approved values. The fetcher creates
or reuses a repository, fetches only the full commit, checks out that full
commit, compares `HEAD^{commit}`, and performs recursive submodule processing
only after the comparison succeeds. The release tag is never supplied to a
Git source-selection command.

## Changed files and tests

- `ci/lib/common.sh`
- `ci/provisioning/fetch-crs.sh`
- `ci/tools/check-common-versions.py`
- `ci/checks/catalog/check-crs-version-pinning.sh`
- `Makefile`
- `tests/security_regression/test_crs_provenance.py`
- `docs/reference/variables.md` and `docs/reference/variables.de.md`
- `docs/testing-and-evidence.md` and `docs/testing-and-evidence.de.md`

The regression executes the real fetch script against fake Git. It covers the
original class, branch/ref/short-hash and unrelated-full-hash bypasses, URL
override, fresh and existing checkouts, a mismatched `HEAD`, the reviewed
commit control, and updater behavior.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk make … test-crs-provenance-contract` | `0` | 4 focused provenance tests passed | `20260718T082843Z-framework-fnd-0004-79ef062d` |
| `rtk env … make … test-makefile-contract test-no-crs-contract test-protocol-client` | `0` | 3 Makefile-contract, 81 No-CRS, and 16 protocol-client unit/contract tests passed | task-run `build` and `tmp` roots |
| `rtk env … sh ci/provisioning/fetch-crs.sh` (fresh) | `0` | Fetched and verified the approved commit | task-owned `tmp/fnd-0004-real-control` |
| `rtk env … sh ci/provisioning/fetch-crs.sh` (existing) | `0` | Re-fetched and verified the approved commit | task-owned `tmp/fnd-0004-real-control` |
| `rtk env … CRS_GIT_REF=main sh ci/provisioning/fetch-crs.sh` | controlled block | Rejected before fake Git was invoked; regression asserts exit `77` | task-owned `tmp/fnd-0004-reproducer` |
| `rtk make … lint` with task-owned `PYTHONPYCACHEPREFIX` | `0` | Static, unit, contract, documentation, and whitespace checks passed | task run `build/pycache` |
| `rtk make … quick-check` with task-owned `PYTHONPYCACHEPREFIX` | `0` | Broader Framework quick check passed | task run `build/pycache` |
| `rtk shellcheck -S error -x …` | `0` | No ShellCheck errors in changed shell files | Framework worktree |

## Security impact

The original path is revalidated as blocked: a mutable release-ref override is
rejected before a Git invocation. The alternate bypass review is executable in
the regression suite: tag/ref namespace, branch, abbreviated/full unrelated
hash, URL override, existing-checkout refresh, and post-checkout mismatch all
fail safely. The verified control succeeds for both a fresh and an existing
checkout, and Git observed the approved commit in both cases.

## Documentation and runtime evidence

English/German variable and testing documentation now explain the reviewed
tag-and-commit pair and the mocked provisioning contract. No connector runtime
or MRTS evidence was collected; the real control exercised only the CRS fetch
boundary under a registered private task directory.

## Checks not run

- Full connector smoke and `test-with-crs` were not run because this finding's
  regression is the provisioning boundary, and those commands require wider
  connector/runtime prerequisites.
- Framework CI, SonarQube Cloud, PR review, and review-thread checks are
  pending Framework commit, push, and Draft PR creation.
- `ruff`, `pyright`, and `gitleaks` are unavailable in the authorized
  environment; no tool installation was performed. Manual changed-region
  secret/diff review found only the reviewed public commit identity, existing
  checksum metadata, and documented non-executable secret placeholders.

## Limitations and residual risk

The review records a commit identity, not a signed release-attestation chain.
Recursive submodules are selected by gitlinks from that pinned root commit but
are not separately attested here. A future CRS update needs a reviewed
tag-and-commit pair; this is deliberate rather than an automatic updater path.

## Final diff and review status

Local source, test, documentation, whitespace, and changed-region secret
review are complete on the isolated Framework branch. A Framework Draft PR is
pending the authorized commit and non-force push. No Parent commit, Parent
gitlink update, MRTS source change, merge, or force push has occurred.
