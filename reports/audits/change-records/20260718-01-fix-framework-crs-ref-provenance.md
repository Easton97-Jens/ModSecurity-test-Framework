# Change record

**Language:** English | [Deutsch](20260718-01-fix-framework-crs-ref-provenance.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260718-01-fix-framework-crs-ref-provenance` |
| UTC date | `2026-07-18` |
| Original Framework base revision | `cdc91a398d6c156eaff927d742b23018a3817fb6` |
| Reconciled Framework base revision | `9954b99a31fab0006cdf903ab477c8158c50fea8` |
| Issue or pull request | Framework Draft PR #26 (`codex/fix-framework-crs-ref-provenance`), requiring a new exact-head non-force-push verification cycle. |
| Earlier reconciliation evidence | `e3b9903ddd2607d131e419ff780acbcee14ace3c`; the current normal master reconciliation supersedes the unpublished local synchronization state. |

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

## 2026-07-19 master reconciliation

The published #26 head predated Framework master
`9954b99a31fab0006cdf903ab477c8158c50fea8`. A normal non-rewriting merge was
resolved additively in the version updater: the CRS reviewed-release/immutable-
commit guard remains while current-master NGINX release-tag/exact-release-
asset/required-SHA-256 provenance, its updater check and regressions, PCRE2
digest enforcement, workflow full-SHA controls, and common-structure controls
remain inherited unchanged. The reconciled direct diff contains only the
twelve intended CRS-provenance paths.

## Acceptance criteria

- Only the literal approved HTTPS CRS origin and full
  `55b09f5acfd16413e7b31041100711ceb7adc89c` commit reach a Git sink.
- Tags, branches, namespaces, abbreviated and unrelated IDs, URL/ref
  overrides, and unsafe Git environment values fail closed before consumption.
- Origin, `FETCH_HEAD^{commit}`, the resolved commit object, and final
  `HEAD^{commit}` all match the same approved commit.
- Pre-existing source paths and any `.gitmodules` manifest are fail closed.
- A newer CRS release is reported without an automatic update; a reviewed
  release-tag and immutable-commit pair is required for any provenance change.
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
- `Makefile` and `ci/checks/catalog/check-crs-version-pinning.sh`
- `ci/tools/check-common-versions.py`
- `tests/security_regression/test_crs_git_ref_provenance.py`
- `docs/reference/variables.md` and `docs/reference/variables.de.md`
- this paired Change Record
- `FND-FRAMEWORK-0004` EN/DE/JSON finding records, updated with this task's
  actual evidence before delivery

The focused test has a legitimate fresh-checkout control and negative coverage
for tag/branch/namespace/short-or-unrelated-ID, runtime override, existing
checkout, unexpected origin, fetched/resolved/final-HEAD mismatch, submodule
manifest, unsafe Git environment inputs, and a newer release that must not
generate an unreviewed tag-to-commit update.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk env … python -m unittest discover -s tests/security_regression -p test_crs_git_ref_provenance.py -v` (baseline) | `1` | 8 tests / 13 expected failures proved the vulnerable flow before the source fix. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| Same focused command (initial #26 implementation) | `0` | 9 mock Git provenance tests passed. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk make BUILD_ROOT=… TMP_ROOT=… test-crs-provenance-contract` (2026-07-19 reconciliation) | `0` | 10 mock-Git provenance tests passed, including the reviewed-release-pair updater regression. | Current task run `20260719T081017Z-framework-pr-resolution-20260719-840082e0` |
| `rtk proxy env TMP_ROOT=… BUILD_ROOT=… sh ci/checks/catalog/check-crs-version-pinning.sh` | `0` | The approved literal origin, commit, and release metadata guard passed. | Current task run `20260719T081017Z-framework-pr-resolution-20260719-840082e0` |
| Same catalog guard with `CRS_GIT_REF=main` | `77` (expected negative control) | Runtime release-metadata override was rejected before catalog scanning. | Current task run `20260719T081017Z-framework-pr-resolution-20260719-840082e0` |
| `rtk sh -n ci/lib/common.sh` | `0` | POSIX shell syntax passed. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk sh -n ci/provisioning/fetch-crs.sh` | `0` | POSIX shell syntax passed. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk env … python -m unittest discover -s tests/security_regression -v` | `0` | Full security-regression discovery: 22 tests passed. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk shellcheck -S error -x ci/lib/common.sh ci/provisioning/fetch-crs.sh` | `0` | ShellCheck error-level passed. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk make check-variable-documentation`, `check-bilingual-docs`, `check-doc-links`, and `check-documentation` | `0` | All selected documentation checks passed. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk make lint` with repository-root `OUTPUT_ROOT` and task-owned cache/temp paths | `0` | Framework lint passed. An earlier external `OUTPUT_ROOT` attempt was rejected by the lint harness before source analysis. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk sh ci/checks/catalog/check-crs-version-pinning.sh` | `0` | Direct pinning check passed after sandboxed lint exposed its fixed-`/tmp` temporary-file limitation. | Task run `20260718T092708Z-fnd-framework-0004-crs-ref-provenance-05f04893` |
| `rtk git diff --check` | `0` | Current Framework diff has no whitespace errors. | Task worktree |
| `rtk env … make test-crs-provenance-contract test-workflow-action-pins test-workflow-contract` | `0` | 10 CRS, 21 workflow-action-pin, and 2 common-structure contract tests passed on the reconciled worktree. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0/build/pr26-reconciliation.7k83wI` |
| `rtk env … python3 -m unittest -v tests.security_regression.test_nginx_archive_digest tests.security_regression.test_nginx_release_provenance tests.security_regression.test_pcre2_archive_digest` | `0` | 15 NGINX/PCRE2 archive-integrity and provenance regressions passed on the reconciled worktree. | `20260719T081017Z-framework-pr-resolution-20260719-840082e0/build/pr26-reconciliation.7k83wI` |
| `rtk env … sh -n …; sh ci/checks/catalog/check-crs-version-pinning.sh` | `0` | Changed shell paths parse and the approved CRS control passes; `CRS_GIT_REF=main` independently blocks with exit `77`. | task-owned temporary path |
| `rtk env FRAMEWORK_ROOT=<PR #26 worktree> … make lint` | `0` | Final repository-native lint passed with the reconciled Framework root and external bytecode/temp paths. | task-owned build path |
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

- Framework Draft-PR CI, SonarQube Cloud, review, and review-thread checks
  require the new exact-head non-force-push cycle. Older head results do not
  count as evidence for the reconciled head.
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

The reconciled local source/test/documentation review, final lint, and
whitespace check passed. Independent Codex Security revalidation reported no
blocking source-control bypass under the documented trust limits. The direct
diff against Framework master is limited to the twelve intended CRS paths;
master-only NGINX, PCRE2, workflow, runner, fixture, and Change-Record
controls remain inherited unchanged. A normal follow-up merge commit and
non-force push establish the exact head for new PR CI, SonarQube, review, and
thread evidence. No Framework-master merge, Parent gitlink update, or MRTS
change is authorized.
