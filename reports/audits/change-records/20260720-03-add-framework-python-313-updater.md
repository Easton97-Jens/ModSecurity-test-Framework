# Change record

**Language:** English | [Deutsch](20260720-03-add-framework-python-313-updater.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260720-03-add-framework-python-313-updater` |
| UTC date | 2026-07-20 |
| Framework base revision | `9dab40c2b8799dc1e4597cb2a2c223ec3f6cd72b` |
| Issue or pull request | [Draft PR #39](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/39) on task branch `agent/add-framework-python-updater`; the first published head was `4a31df044ea2c2c7526828e54978238639b57dd4`. |

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

The first Draft-PR head exposed three task-owned compatibility and hardening
issues before delivery could be verified. The candidate artifact is now a
fixed direct `RUNNER_TEMP/framework-python-3.13-candidate` file derived inside
the updater, rather than a caller-selected CLI path; the semantic workflow
contract rejects an argument after that flag. Candidate runner paths are
initialized at step runtime through `$GITHUB_ENV`, where the runner context is
valid, and the literal Markdown body has a narrow ShellCheck annotation.
Finally, the dependency-free YAML fallback recognizes a list mapping only when
the colon is followed by whitespace or end-of-value, preserving plain scalars
such as `ARGS:foo.` and existing `name: Content-Type` mappings.

## Changed files and tests

- `.python-version`, all affected workflows, `Makefile`, and
  `requirements-ci.lock` comment.
- `ci/tools/update-python-version.py` and
  `ci/checks/security/check-python-version.py`, the CI-security maintenance
  contract, and the shared fallback YAML parser.
- CI-security, workflow-contract, and updater regression tests.
- English/German CI-security and GitHub Actions security documentation.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| Framework-owned Python 3.14 `-m py_compile` over changed Python files | 0 | Changed implementation and tests compiled. | `20260720T180337Z-framework-python-313-updater-f3349a7e` task storage |
| Framework-owned Python 3.14 focused updater/contract/common-workflow unittest selection | 0 | 27 version-neutral tests passed. | Isolated Framework worktree |
| `check-ci-security-contract.py --root <task-worktree>` | 0 | Current workflows and the three-job writer contract passed. | Isolated Framework worktree |
| `check-python-version.py --root <task-worktree>` | 0 | Canonical source and recursive Python workflow contract passed. | Isolated Framework worktree |
| Focused updater, CI-security-contract, Python-version-contract, and parser-hardening tests | 0 | 36 version-neutral regressions passed after the exact-head remediation. | Isolated Framework worktree |
| `make test-ci-security-contract` | 0 | 85 CI-security tests passed after the exact-head remediation. | Isolated Framework worktree |
| `make test-workflow-contract`, `make check-github-actions-workflows`, `make check-documentation`, and `make lint` | 0 | Workflow, documentation, and final local lint gates passed. | `20260720T180337Z-framework-python-313-updater-f3349a7e` task storage |

## Security impact

The change removes duplicated patch authority, rejects bare/floating/matrix
selection paths, and ensures a cross-job candidate cannot directly authorize a
write. Resolver transport, fixed candidate materialization, repository write scope,
and Draft-PR publication each have explicit fail-closed controls and negative
tests. The final diff also remediates low-severity Framework hardening finding
`FND-FRAMEWORK-0033`, which proved that the maintenance contract previously
accepted future explicit secret/token references outside the reviewed publisher
input. Its completion also covers serialized `${{ toJSON(secrets) }}` and
`${{ toJSON(github) }}` contexts, which now fail closed without rejecting
legitimate `github.sha` or `github.repository` controls; final local and
hosted verification remain required.
The exact-head remediation also tracks `FND-FRAMEWORK-0037` (workflow-context
and literal-body lint), `FND-FRAMEWORK-0038` (fallback YAML scalar parsing),
and release-blocking `FND-FRAMEWORK-0039` (candidate output path). No control
was weakened to clear those checks.
The current quality follow-up additionally tracks `FND-FRAMEWORK-0040`: it
removes the task-owned Ruff F401/E731 failures without suppressing a quality
rule. A fresh complete source review then reproduced
`FND-FRAMEWORK-0041`, a low-likelihood policy bypass where a future
workflow-level token environment could inherit into the write-capable publisher
without the maintenance contract rejecting it. The contract now traverses the
entire parsed maintenance workflow and permits exactly the reviewed
`create-pull-request.with.token` path; its focused regression preserves the
real workflow and existing reader-job diagnostics as legitimate controls.
The final documentation review also corrected `FND-FRAMEWORK-0042`: the German
guide now identifies the automatic checkout token as job-scoped, and explains
that `persist-credentials: false` limits credential persistence rather than the
GitHub permission scope available to the action.

## Documentation and runtime evidence

The paired English/German guides document the canonical source, fixed metadata
authority, candidate/publisher separation, no-auto-merge property, and hosted
exact-head controls. Local runtime evidence is deliberately version-neutral;
the exact CPython 3.13 candidate is validated by the GitHub Actions
candidate-validation job before its publisher can run.

## Checks not run

No local CPython 3.13 executable was available, so exact candidate runtime
validation is not claimed locally. The pinned hosted actionlint, ShellCheck,
zizmor, Ruff, Pyright, GitHub Actions, SonarQube Cloud, review state, and
generated-PR lifecycle validation remain exact-head PR controls; no global or
user-site tool was installed as a substitute.

## Limitations and residual risk

The repository can constrain the workflow source but cannot locally prove who
may dispatch it, GitHub token policy, branch protection, or whether all hosted
checks and reviews rerun for a token-created Draft PR head. The publisher
therefore remains Draft-only, and a human must verify hosted controls before
merging.

## Final diff and review status

Draft PR #39 is open. Its first published head
`4a31df044ea2c2c7526828e54978238639b57dd4` exposed the tracked lint, parser,
and candidate-output findings. The current task-owned source set also includes
the quality and inherited-token-policy repairs described above; it requires a
new exact-head GitHub Actions, SonarQube Cloud, and review/thread assessment
before the task may stop at `verified_pr`. No merge, Parent gitlink change, or
MRTS change is in scope.
