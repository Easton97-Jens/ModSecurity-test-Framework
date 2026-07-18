# Change record

**Language:** English | [Deutsch](20260718-01-fix-framework-crs-ref-provenance.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260718-01-fix-framework-crs-ref-provenance` |
| UTC date | `2026-07-18` |
| Framework base revision | `cdc91a398d6c156eaff927d742b23018a3817fb6` |
| Issue or pull request | Pending Framework Draft PR; no merge is authorized. |

## Motivation and problem statement

`FND-FRAMEWORK-0004` / `RC-FW-002-crs-git-ref-provenance` found that the
Framework could give a mutable CRS tag or another caller-controlled ref to Git
and consume `FETCH_HEAD`. This Framework-only change binds provisioning to one
centrally reviewed full commit and rejects divergent source-selection inputs
before a Git operation.

## Affected components and security boundaries

- `ci/lib/common.sh`: central CRS origin, release metadata, and immutable
  commit provenance.
- `ci/provisioning/fetch-crs.sh`: external-source-root, Git, remote-origin,
  commit-object, checkout, and submodule boundary.
- `tests/security_regression/test_crs_git_ref_provenance.py`: process-boundary
  fake-Git regression, control, and bypass evidence.

The security boundary is Framework CRS source provenance only. Parent code and
the Parent gitlink are not changed; MRTS remains untouched and uninitialized in
this task worktree.

## Acceptance criteria

- Only the literal approved HTTPS CRS origin and full
  `55b09f5acfd16413e7b31041100711ceb7adc89c` commit reach a Git sink.
- Tags, branches, namespaces, abbreviated and unrelated IDs, URL/ref
  overrides, and unsafe Git environment values fail closed before consumption.
- Origin, `FETCH_HEAD^{commit}`, the resolved commit object, and final
  `HEAD^{commit}` all match the same approved commit.
- Pre-existing source paths and any `.gitmodules` manifest are fail closed.
- The focused negative, control, and bypass tests pass without a real CRS
  download or MRTS mutation.

## Alternatives considered

- Replacing `CRS_GIT_REF` with a SHA was rejected because current version
  reporting treats it as release metadata. It remains metadata only and is
  never passed to Git.
- Reusing, resetting, or cleaning an existing checkout was rejected because
  dirty files, local configuration, hooks, linked worktrees, and populated
  submodules would extend the trust boundary.
- Recursive submodule initialization was rejected until a separate approved
  submodule provenance rule exists.

## Implementation decision

`CRS_APPROVED_REPO_URL` and `CRS_APPROVED_COMMIT` are literal central values;
environment attempts to set them are overwritten when `common.sh` is sourced.
`CRS_REPO_URL` and `CRS_GIT_REF` retain compatibility metadata roles but a
different value is rejected before Git.

The fetch path atomically creates a fresh source directory, initializes an
isolated Git repository, sets and reads back the literal HTTPS origin, and
fetches only the full commit with tags and submodule recursion disabled. It
sanitizes Git configuration, hook, TLS, Askpass, and SSH environment controls,
enforces TLS verification, compares fetched/resolved/checked-out commit IDs,
and rejects `.gitmodules` after the parent proof. It never uses `--branch`,
`clone`, or `checkout --detach FETCH_HEAD`.

## Changed files and tests

- `ci/lib/common.sh`
- `ci/provisioning/fetch-crs.sh`
- `tests/security_regression/test_crs_git_ref_provenance.py`
- `docs/reference/variables.md` and `docs/reference/variables.de.md`
- this paired Change Record
- `FND-FRAMEWORK-0004` EN/DE/JSON finding records, updated with this task's
  actual evidence before delivery

The focused test has a legitimate fresh-checkout control and negative coverage
for tag/branch/namespace/short-or-unrelated-ID, runtime override, existing
checkout, unexpected origin, fetched/resolved/final-HEAD mismatch, submodule
manifest, and unsafe Git environment inputs.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk env … python -m unittest discover -s tests/security_regression -p test_crs_git_ref_provenance.py -v` (baseline) | `1` | 8 tests / 13 expected failures proved the vulnerable flow before the source fix. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| Same focused command (current) | `0` | 9 mock Git provenance tests passed. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk sh -n ci/lib/common.sh` | `0` | POSIX shell syntax passed. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk sh -n ci/provisioning/fetch-crs.sh` | `0` | POSIX shell syntax passed. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk env … python -m unittest discover -s tests/security_regression -v` | `0` | Full security-regression discovery: 22 tests passed. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk shellcheck -S error -x ci/lib/common.sh ci/provisioning/fetch-crs.sh` | `0` | ShellCheck error-level passed. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk make check-variable-documentation`, `check-bilingual-docs`, `check-doc-links`, and `check-documentation` | `0` | All selected documentation checks passed. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk make lint` with repository-root `OUTPUT_ROOT` and task-owned cache/temp paths | `0` | Framework lint passed. An earlier external `OUTPUT_ROOT` attempt was rejected by the lint harness before source analysis. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk sh ci/checks/catalog/check-crs-version-pinning.sh` | `0` | Direct pinning check passed after sandboxed lint exposed its fixed-`/tmp` temporary-file limitation. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk git diff --check` | `0` | Current Framework diff has no whitespace errors. | Task worktree |
| Framework Draft-PR CI and SonarQube Cloud | Pending | Recorded only after observed exact-head completion. | Pending |

## Security impact

The original mutable-ref path is reproduced by the baseline mock fixture and
blocked by the current implementation. The legitimate control receives the
central origin and commit only. The alternate-bypass review covers tags,
branches, ref namespaces, environment overrides, existing checkouts,
submodules, Git configuration/TLS/Askpass controls, origin, and the
`FETCH_HEAD`/object/`HEAD` equality chain. Independent Codex Security
revalidation found no blocking source-control gap after the final test
additions.

## Documentation and runtime evidence

The English/German variables reference now distinguishes release metadata from
the non-overridable provisioning commit and documents fail-closed existing
source and submodule behavior. No real CRS network fetch, runtime smoke, or
dynamic upstream tag mutation was performed: the task explicitly uses focused
mocked Git provenance testing and does not download CRS content.

## Checks not run

- Framework Draft-PR CI and SonarQube Cloud are pending the requested
  Framework Draft PR and exact-head check completion.
- A real network CRS fetch and dynamic upstream tag mutation are not run:
  both exceed the scoped mocked-proof/non-download contract.

## Limitations and residual risk

`CI_ROOT`, the `git` binary selected from `PATH`, the Framework source tree,
the host TLS trust store, and exclusive job ownership of `SOURCE_ROOT` remain
local trust boundaries. A local concurrent writer with access to the external
source-root parent can still attempt filesystem races after directory creation.
An unavailable approved commit fails closed. The central commit is a reviewed
identity, not a signed release-attestation chain.

## Final diff and review status

The local source/test/documentation review and whitespace check passed.
Independent Codex Security revalidation reported no blocking source-control
bypass under the documented trust limits. The task will record exact Framework
commit/push/Draft-PR facts, current-head CI and SonarQube results, and the
required no-merge/Parent/MRTS integrity evidence before delivery.
