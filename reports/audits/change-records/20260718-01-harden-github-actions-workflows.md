# Change record: 20260718-01-harden-github-actions-workflows

**Language:** English | [Deutsch](20260718-01-harden-github-actions-workflows.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260718-01-harden-github-actions-workflows` |
| UTC date | 2026-07-18 |
| Framework base revision | `9954b99a31fab0006cdf903ab477c8158c50fea8` |
| Issue or pull request | Framework PR #29; master integration is authorized only after fresh exact-head checks and review. |

## Motivation and problem statement

The Framework workflows used mutable major-version Action tags and an inline
pin check that accepted such tags and ignored `.yaml` workflows. Four direct
checkouts retained credentials by default, and one trusted maintenance workflow
gave a write-capable `GITHUB_TOKEN` to every job step. Those conditions weaken
the Action supply-chain and GitHub Actions trust boundary.

## Affected components and security boundaries

This Framework-only change updates all five `.github/workflows/` files, their
source-controlled validation contract, focused fixtures, and paired guidance.
It affects immutable third-party Action selection, workflow/job permissions,
checkout credential persistence, pull-request execution, secret references,
submodules, YAML parsing, and token exposure. It does not alter a connector,
Parent product file or Gitlink, MRTS source or Gitlink, artifact upload,
SARIF upload, CodeQL upload, or a default branch.

## Acceptance criteria

1. Every Framework remote Action uses its validated 40-character lowercase
   official release SHA with an adjacent release comment.
2. Each workflow defaults to `contents: read`; trusted writer permissions are
   scoped to only the necessary job.
3. Every direct checkout disables persisted credentials, PR workflows have no
   write permission or secret/submodule path, and `pull_request_target` is
   prohibited.
4. The pin and permission contract covers `.yml` and `.yaml` workflows and
   has real-workflow, safe-fixture, and unsafe-fixture regression evidence.
5. English/German guidance and this Change Record describe identical action
   provenance, trust boundaries, validation, limitations, and scope.
6. Only the authorized normal Framework commit, push, PR integration, and
   exact-head gate sequence may be used; no Parent Gitlink update or MRTS
   change is allowed.

## Alternatives considered

- Retaining major-version tags was rejected because a tag can be moved after
  review and the original validator demonstrably accepted it.
- Duplicating the old inline shell/Python check was rejected because it omitted
  `.yaml`, did not enforce provenance comments, and was not unit-testable.
- Removing the trusted updater or artifact cleanup workflow was rejected
  because their functions remain necessary; job-local permissions preserve
  them with less default authority.
- Giving a PR job write permissions or secrets was rejected because PR source,
  including fork source, is untrusted by default.

## Implementation decision

The five Action references now use reviewed SHAs for `actions/checkout`
`v7.0.0`, `actions/setup-python` `v6.3.0`, `actions/github-script` `v9.0.0`,
and `peter-evans/create-pull-request` `v8.1.1`, each from its official MIT
upstream and documented in the paired guide.

`ci/checks/security/check-github-actions-workflows.py` separates a
standard-library pin mode from a PyYAML permission/trust-boundary mode.
It rejects mutable or dynamic remote references, missing release comments,
block-scalar `uses` values, flow-style collections or explicit-key YAML, YAML tags,
anchors, aliases, merge keys in key or value position, escaped double-quoted
mapping keys, YAML document markers including after a UTF-8 BOM, duplicate, or
merged YAML,
`pull_request_target`, PR writes, secret references, reusable-workflow secret
forwarding, workflow- or job-level environments exposing `github.token` under
any name, credential persistence, and PR submodules. The Makefile exports
independent pin and permission targets and the existing workflow self-check
runs when the checker, fixtures, test, or Makefile changes.

The current reconciliation is based on `9954b99a31fab0006cdf903ab477c8158c50fea8`.
It retains the merged action-pin checker and its regression suite while the
canonical checker recursively covers nested `.yml` and `.yaml` workflow paths.
Before a file is read, its resolved path must remain below the current
repository root; a path that escapes through a symlink is skipped. Focused
regression cases prove both nested discovery and containment rejection.

`check-common-versions` remains trusted-only and has job-local repository and
pull-request write permissions. Its shell `GITHUB_TOKEN` environment is limited
to the update step; GitHub permissions remain job-scoped, so this reduces
direct shell exposure rather than creating an unavailable per-step permission
primitive. `cleanup-artifacts` retains only job-local `actions: write`.

## Changed files and tests

Versioned Framework changes:

- `.github/workflows/check-action-versions.yml`,
  `.github/workflows/check-common-versions.yml`,
  `.github/workflows/cleanup-artifacts.yml`, `.github/workflows/lint.yml`, and
  `.github/workflows/test-common.yml`.
- `ci/checks/security/check-github-actions-workflows.py` and
  `ci/checks/documentation/check-workflow-yaml.py`.
- `Makefile` and
  `tests/security_regression/test_workflow_security_contract.py`.
- `tests/fixtures/workflow_security_contract/` safe and unsafe fixtures.
- `docs/github-actions-workflow-security.md` and its German companion, the
  paired documentation indexes, and this Change Record pair.

The regression suite validates all real workflows, safe read-only PR and
trusted writer cases, and unsafe mutable/dynamic references, `.yaml`, missing
comments, block-scalar `uses` values, flow-style collections or explicit-key YAML, YAML
tags/anchors/aliases/merge keys in key or value position, escaped double-quoted
mapping keys, YAML document markers including after a UTF-8 BOM, and duplicate YAML,
`pull_request_target`, permission,
credential, workflow/job token exposure under conventional or renamed
variables, submodule, secret-reference, and reusable-workflow-secret-
forwarding cases, nested workflow discovery, and symlink or explicit-root
paths that escape the current repository.

## Commands and results

All write-capable commands used a registered task-run descendant; sensitive
values and local workstation paths are intentionally omitted from this record.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `rtk env <registered roots> python3 ci/checks/security/check-github-actions-workflows.py --check all` | 0 | All five real workflows passed immutable-pin and permission/trust checks | `20260718T081429Z-framework-workflow-hardening-320e9322` |
| `rtk env <registered roots> python3 -m unittest discover -s tests/security_regression -p 'test_workflow_security_contract.py' -v` | 0 | 4 tests passed, including safe and unsafe fixtures | `20260718T081429Z-framework-workflow-hardening-320e9322` |
| `rtk env <registered roots> make check-documentation` | 0 | Links, bilingual pairing, and repository path references passed | `20260718T081429Z-framework-workflow-hardening-320e9322` |
| `rtk env <registered roots> make lint` | 0 | Full Framework static lint, workflow contract, fixtures, catalog, documentation, and diff checks passed | `20260718T081429Z-framework-workflow-hardening-320e9322` |
| `rtk shellcheck -x ci/lib/common.sh ci/checks/catalog/check-common-helpers.sh` | 1 | Existing warnings reproduced unchanged in the clean Framework checkout | Existing `FND-FRAMEWORK-0002` context; no task-owned source changed |
| `rtk actionlint --version` | 127 | Blocked: `actionlint` is not installed; no tool was provisioned | Local environment evidence |
| `rtk zizmor --version` | 127 | Blocked: `zizmor` is not installed; no tool was provisioned | Local environment evidence |
| Literal `test-common / common-structure` count gate through `rtk` | 1 | Existing `expected 141 YAML cases, found 179` baseline reproduced | `FND-FRAMEWORK-0001`; task-run evidence `common-structure-baseline-recheck.md` |
| `rtk gh run list --workflow test-common.yml --branch master --limit 5 --json ...` | 0 | Current `master` run `29527830684` is already failed at the base revision | `FND-FRAMEWORK-0001` |
| `rtk git diff --check` | 0 | No whitespace errors at the recorded review point | Not applicable |

## Security impact

This is a security remediation. The original validator's mutable `@v7`
acceptance and `.yaml` omission were reproduced before the patch; the new
validator rejects both. Regression fixtures also retest alternate bypasses:
dynamic references, absent version comments, block-scalar `uses` values,
flow-style collections or explicit-key YAML, YAML tags/anchors/aliases/merge
keys in key or value position, escaped double-quoted mapping keys, YAML document
markers including after a UTF-8 BOM, and duplicate YAML,
broad permissions, workflow/job-wide token exposure under conventional or
renamed variables, `pull_request_target`, PR secrets including reusable-
workflow forwarding, and static or dynamic
submodules. The retained scan has nine report instances; the workflow contract
resolves their direct source paths without removing required trusted updater or
cleanup behavior.

## Documentation and runtime evidence

The paired guide documents action provenance, exact versions and SHAs,
permissions, fork-PR model, local-Action treatment, artifact/SARIF inventory,
pin-update procedure, and tool limitations. This Change Record is a complete
English/German pair.

No connector runtime or lifecycle evidence was collected because this change
is limited to static GitHub Actions configuration and validation. Static
workflow tests are not a claim that GitHub-hosted lifecycle controls ran.

## Checks not run

- Current-head GitHub Actions, CodeQL, Scorecard, SonarQube Cloud, review, and
  review-thread checks are pending the authorized Draft PR.
- `actionlint` and `zizmor` are blocked because neither executable is locally
  installed; controlled tool provisioning was not part of this change.
- The literal `test-common / common-structure` workflow gate is failed by the
  existing `FND-FRAMEWORK-0001` baseline, not by this diff.
- Connector runtime, CRS/MRTS matrices, generated report refresh, and C/C++
  builds are not applicable to a Framework workflow-only static change and
  would expand beyond the authorized scope.

## Limitations and residual risk

The repository checker complements rather than replaces GitHub branch
protection, human workflow review, upstream release verification, actionlint,
zizmor, CodeQL, Scorecard, or SonarQube Cloud. A job permission cannot be
narrowed per step by GitHub Actions; trusted writer jobs therefore remain
limited to non-PR triggers. The known pre-existing `FND-FRAMEWORK-0001` gate
can block `verified_pr` even if this task's controls and other PR checks pass.
No risk has been accepted and no security control was weakened.

## Final diff and review status

The pre-commit Framework diff has been reviewed for scope, immutable pins,
permission maps, credential persistence, test coverage, generated-file
avoidance, whitespace, and sensitive content. The Parent and its Gitlink,
MRTS and its Gitlink, and every default branch remain outside scope. Framework
commit, push, exact-SHA equality, and current-head review/CI status remain
pending. The current user authorizes Framework master integration only after
those gates are observed as passing; no Parent Gitlink or MRTS change is
authorized.
