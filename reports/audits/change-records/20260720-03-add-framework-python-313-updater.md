# Change record

**Language:** English | [Deutsch](20260720-03-add-framework-python-313-updater.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260720-03-add-framework-python-313-updater` |
| UTC date | 2026-07-20 |
| Framework base revision | `9dab40c2b8799dc1e4597cb2a2c223ec3f6cd72b` |
| Issue or pull request | Task branch `agent/add-framework-python-updater`; Draft-PR delivery is authorized after local validation. |

## Motivation and problem statement

The Framework repeated an exact CPython patch in workflow YAML and an
independent CI-lock comment, while `test-common.yml` used Python before any
reviewed interpreter setup. It had no native, bounded updater or a tested
publisher boundary for a future stable CPython 3.13 patch.

## Affected components and security boundaries

This Framework-only change controls workflow YAML, Python metadata parsing,
runner-owned temporary output, a single source-tree version file, automatic
job credentials, and one explicit Draft-PR Action token input. The Parent
gitlink, Parent source, connector runtime, and read-only `tools/MRTS` content
are not affected.

## Acceptance criteria

- `.python-version` is the only exact CPython patch authority and every normal
  setup action reads it with `check-latest: false`.
- A resolver accepts only a strictly higher published stable 3.13 patch from a
  bounded, fixed Python.org JSON endpoint and never writes on uncertainty.
- Read-only candidate validation uses hash-locked dependencies before the
  publisher independently re-resolves the same candidate.
- The only repository content committed by the publisher is `.python-version`;
  its Draft-PR body is runner-temporary, its branch is fixed, and no automatic
  merge path exists.
- Contracts, English/German documentation, and a paired Change Record cover
  the source, workflow, and operational boundaries.

## Alternatives considered

Floating `3.13` or `3.13.x` setup references reduce manual maintenance but
permit invisible patch drift. A manually maintained exact patch retains
reproducibility but has no scheduled candidate evidence. The selected exact
pin plus scheduled resolver/candidate/publisher design keeps the patch
reviewable while bounding automated maintenance to a Draft PR.

## Implementation decision

The native updater uses only the public Python.org release JSON endpoint, no
token, no redirects, a 1 MiB response cap, and strict schema/version checks.
It reports explicit status values and atomically changes only a regular
`.python-version` file after a stale-value check. The maintenance workflow has
exactly `resolve`, `candidate-validate`, and `publish` jobs. Reader jobs declare
no explicit token or secret reference; their checkout credential is
nonpersistent and read-scoped. The publisher is trusted-default-branch gated,
revalidates the candidate, asserts a one-file diff, explicitly supplies its
write-scoped token only to the pinned pull-request Action, and uses
`draft: true` with fixed `add-paths`.

## Changed files and tests

- `.python-version`, all affected workflows, `Makefile`, and
  `requirements-ci.lock` comment.
- `ci/tools/update-python-version.py` and
  `ci/checks/security/check-python-version.py`.
- CI-security, workflow-contract, and updater regression tests.
- English/German CI-security and GitHub Actions security documentation.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| Framework-owned Python 3.14 `-m py_compile` over changed Python files | 0 | Changed implementation and tests compiled. | `20260720T180337Z-framework-python-313-updater-f3349a7e` task storage |
| Framework-owned Python 3.14 focused updater/contract/common-workflow unittest selection | 0 | 27 version-neutral tests passed. | Isolated Framework worktree |
| `check-ci-security-contract.py --root <task-worktree>` | 0 | Current workflows and the three-job writer contract passed. | Isolated Framework worktree |
| `check-python-version.py --root <task-worktree>` | 0 | Canonical source and recursive Python workflow contract passed. | Isolated Framework worktree |

## Security impact

The change removes duplicated patch authority, rejects bare/floating/matrix
selection paths, and ensures a cross-job candidate cannot directly authorize a
write. Resolver transport, candidate materialization, repository write scope,
and Draft-PR publication each have explicit fail-closed controls and negative
tests. The final diff also remediates low-severity Framework hardening finding
`FND-FRAMEWORK-0033`, which proved that the maintenance contract previously
accepted future explicit secret/token references outside the reviewed publisher
input; final local and hosted verification remain required.

## Documentation and runtime evidence

The paired English/German guides document the canonical source, fixed metadata
authority, candidate/publisher separation, no-auto-merge property, and hosted
exact-head controls. Local runtime evidence is deliberately version-neutral;
the exact CPython 3.13 candidate is validated by the GitHub Actions
candidate-validation job before its publisher can run.

## Checks not run

No local CPython 3.13 executable was available, so exact candidate runtime
validation is not claimed locally. actionlint, ShellCheck, zizmor, Ruff,
Pyright, hosted GitHub Actions, SonarQube Cloud, review state, and generated-
PR lifecycle validation remain exact-head PR controls; no global or user-site
tool was installed as a substitute.

## Limitations and residual risk

The repository can constrain the workflow source but cannot locally prove who
may dispatch it, GitHub token policy, branch protection, or whether all hosted
checks and reviews rerun for a token-created Draft PR head. The publisher
therefore remains Draft-only, and a human must verify hosted controls before
merging.

## Final diff and review status

Implementation is pending final local diff, documentation, security-diff, and
delivery review. No commit, push, PR, merge, Parent gitlink change, or MRTS
change has occurred at the time this record was written.
