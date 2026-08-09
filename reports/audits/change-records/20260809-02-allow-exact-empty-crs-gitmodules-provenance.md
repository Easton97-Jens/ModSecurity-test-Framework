# Change record: Allow only canonical empty CRS `.gitmodules` provenance metadata

**Language:** English | [Deutsch](20260809-02-allow-exact-empty-crs-gitmodules-provenance.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260809-02-allow-exact-empty-crs-gitmodules-provenance |
| UTC date | 2026-08-09 |
| Framework base revision | a7a8dcdd62da8d0e4d7ea36549f7c54c5d614e68 |
| Issue or pull request | User-authorized Phase-A Framework repair on task-owned branch `fix/crs-empty-gitmodules-provenance`; Draft pull request and delivery evidence are pending. |

## Motivation and problem statement

Protected CRS lifecycle run 31328046595 stopped before candidate admission
because approved CRS commit `55b09f5acfd16413e7b31041100711ceb7adc89c`
has a regular zero-byte root `.gitmodules` file. The old fetcher rejected every
such path although the approved tree has no Gitlink and the file is Git's
canonical empty blob `e69de29bb2d1d6434b8b29ae775ad8c2e48c5391`.

## Affected components and security boundaries

The change is confined to Framework CRS source provisioning in
`ci/provisioning/fetch-crs.sh`, `ci/provisioning/crs-provenance.sh`, and
`ci/provisioning/prepare-crs.sh`, its provenance regression suite, and paired
Framework documentation. The boundary admits only the centrally pinned HTTPS
origin and immutable commit before source is later consumed by connector
preparation. Parent, MRTS, Gitlinks, caller workflow authority, and connector
runtime behavior are not changed.

## Acceptance criteria

- An approved checkout with no `.gitmodules` and no Gitlinks remains accepted.
- A present root `.gitmodules` is accepted only as tree/index/worktree `100644`
  canonical empty blob `e69de29bb2d1d6434b8b29ae775ad8c2e48c5391`.
- Recursive tree and checkout index reject every `160000` Gitlink.
- Non-empty, wrong-mode, symlinked, special, untracked, mismatched, duplicate,
  nested, configured, or registered submodule state fails before use.
- A replacement after successful fetch fails before `prepare-crs.sh` reads a
  source template, rule, or plugin or writes a runtime file.
- Git inspection errors fail closed and no path invokes `git submodule`.

## Alternatives considered

Keeping the blanket presence rejection preserves the false positive. Allowing
arbitrary `.gitmodules` files, Gitlinks, or recursive initialization would
expand the provenance boundary beyond the reviewed rule. Deriving behavior from
a release tag or caller input would reintroduce mutable selection. The selected
rule is limited to one immutable blob and no-submodule state.

## Implementation decision

After origin, fetched-object, resolved-object, and checked-out-commit proof,
the fetcher invokes a shared verifier that recursively examines the approved
tree and checkout index. It permits either no root `.gitmodules` entry or exactly
`100644 blob e69de29bb2d1d6434b8b29ae775ad8c2e48c5391` at that root path.
The latter also requires zero object size, a non-symlink regular zero-byte
checkout file, the same raw worktree hash, a clean mode-aware diff, no local
`submodule.*` configuration, no `.git/modules` registry, no untracked source,
and no tree or index Gitlink. `prepare-crs.sh` calls that verifier again before
it consumes source files or writes runtime output. Every inspection error
blocks; neither script invokes `git submodule`.

## Changed files and tests

- `ci/provisioning/fetch-crs.sh` and the new sourceable
  `ci/provisioning/crs-provenance.sh` replace the blanket manifest-presence
  block with the bounded empty-blob/no-submodule-state verifier.
- `ci/provisioning/prepare-crs.sh` rechecks that verifier before it consumes
  CRS source files or writes runtime output.
- `tests/security_regression/test_crs_git_ref_provenance.py` adds exact-empty
  positive, adversarial state, per-inspection failure-injection, and
  successful-fetch-to-replacement-to-prepare coverage.
- `docs/reference/variables.{md,de.md}` and
  `docs/testing-and-evidence.{md,de.md}` describe the bounded rule and limit.
- This paired Change Record and index entry record only Framework Phase A.

## Commands and results

The following replay-safe command templates are identical in the English and
German records. Set lowercase shell variable `task_run_root` to a configured
task-owned external run directory, `framework_python=python3`,
`actionlint_bin="$task_run_root/evidence/runner-temp/actionlint/actionlint"`,
and `zizmor_bin="$task_run_root/evidence/runner-temp/zizmor/zizmor"`. These
templates preserve the observed commands without embedding a local developer
path or secret.

<pre>
C01 rtk proxy sh -n ci/provisioning/fetch-crs.sh ci/provisioning/crs-provenance.sh ci/provisioning/prepare-crs.sh
C02 rtk proxy env BUILD_ROOT="$task_run_root/target/build" TMP_ROOT="$task_run_root/target/tmp" LOG_ROOT="$task_run_root/target/log" PYTHON="$framework_python" make test-crs-provenance-contract
C03 rtk proxy env BUILD_ROOT="$task_run_root/docs-final-verified/build" TMP_ROOT="$task_run_root/docs-final-verified/tmp" LOG_ROOT="$task_run_root/docs-final-verified/log" PYTHON="$framework_python" make check-bilingual-docs check-doc-links check-change-records
C04 rtk proxy env STATE_HOME="$task_run_root/lint/state" BUILD_ROOT="$task_run_root/lint/build" TMP_ROOT="$task_run_root/lint/tmp" LOG_ROOT="$task_run_root/lint/log" PYTHONPYCACHEPREFIX="$task_run_root/lint/pycache" PYTHONNOUSERSITE=1 make PYTHON="$framework_python" lint
C05 rtk proxy env STATE_HOME="$task_run_root/lint-final/state" BUILD_ROOT="$task_run_root/lint-final/build" TMP_ROOT="$task_run_root/lint-final/tmp" LOG_ROOT="$task_run_root/lint-final/log" PYTHONPYCACHEPREFIX="$task_run_root/lint-final/pycache" PYTHONNOUSERSITE=1 make PYTHON="$framework_python" lint
C06 rtk proxy git diff --check
C07 rtk proxy "$actionlint_bin" -shellcheck=/usr/bin/shellcheck .github/workflows/*.yml
C08 rtk proxy "$zizmor_bin" --offline .github/workflows
</pre>

| Command ID | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| C01 | 0 | POSIX shell syntax accepted the shared verifier and both entrypoints. | Task-owned external Framework worktree |
| C02 | 0 | 18 focused provenance tests passed, including inspection-error, adversarial, and replacement-before-prepare cases. | Task-owned external Phase-A evidence |
| C03 | 0 | Documentation, EN/DE links, and Change Record contract passed. | Task-owned external Phase-A evidence |
| C04 | 2 | Initial native lint stopped only because the first record revision embedded a forbidden local developer path; no implementation failure was reported. | Task-owned external Phase-A evidence |
| C05 | 0 | Full native lint passed after the documentation-path correction. | Task-owned external Phase-A evidence |
| C06 | 0 | Final tracked-diff whitespace check passed. | Task-owned external Phase-A evidence |
| C07 | 0 | Lockfile-verified actionlint and ShellCheck accepted all workflows. | Task-owned external Phase-A evidence |
| C08 | 0 | Lockfile-verified zizmor reported no findings; 37 repository suppressions applied. | Task-owned external Phase-A evidence |

## Security impact

This remediation removes one false positive while preserving immutable-origin,
immutable-commit, no-Gitlink, no-recursion, and source-consumption controls.
The original empty-file failure reproduces before the repair; the legitimate
exact empty blob now succeeds. Alternative contents, file types, tree/index
values, configuration, registry, Git-command-error paths, and a replacement
after fetch remain fail closed. An independent source-to-sink review is not
used as delivery evidence; the final hosted PR security gates remain required.

## Documentation and runtime evidence

The English/German variable and testing documentation now describe the exact
exception and its limits. The isolated real fetch is provisioning-boundary
evidence only; it is not connector runtime, Parent lifecycle, hosted CI, or
MRTS evidence. A new resulting-master lifecycle run remains required after the
ordered Parent phases.

## Checks not run

Configured CPython 3.14.6 is not locally available; focused tests use the
available local CPython 3.14.4 and are not CI-equivalent. Hosted PR checks,
CodeQL, SonarQube Cloud, review state, and merge checks remain pending the
completed final diff and Draft PR.

## Limitations and residual risk

The verifier proves the state at each fetch and source-consumption check. It
does not make a connector runtime support claim and does not replace later
protected Parent lifecycle evidence. A same-host concurrent writer could still
race after the final consumption check and would require an independently
established write capability in the verified source root; this Framework rule
does not establish such a capability.

## Final diff and review status

Source, focused tests, EN/DE documentation, and this paired record are local
on the task-owned Framework branch. Native lint, documentation, whitespace,
actionlint, and zizmor passed; the security-diff and delivery reviews remain
required before normal Framework delivery. No commit, push, pull request,
hosted result, Gitlink update, Parent change, or MRTS action is claimed here.
