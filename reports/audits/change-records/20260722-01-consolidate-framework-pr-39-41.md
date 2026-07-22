# Consolidate Framework PRs 39–41

**Language:** English | [Deutsch](20260722-01-consolidate-framework-pr-39-41.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260722-01-consolidate-framework-pr-39-41` |
| UTC date | 2026-07-22 |
| Framework base revision | `f73f8842f45318e2df8aff1d31855eeb7c20a22f` |
| Issue or pull request | Sources: Framework PRs #39 (`0b0c20f686fcc2fd76a7035daf691bc17566d2e1`), #40 (`c274460a3e27b9fc0dfe904e1ce5eba33042f444`), and #41 (`f5e13dceeebc2b3c13248786861c6f1c984bb4a2`); delivery branch: `agent/framework-pr-39-41-consolidation`. |

## Motivation and problem statement

Combine the approved Python 3.13 contract migration, workflow-tool provenance
hardening, and PyYAML lower-bound update into one reviewable Framework-only
change. Reconciliation uncovered an OSV pull-request bootstrap failure
(`FND-FRAMEWORK-0046`) and a YAML-spelling-dependent Action-lock bypass
(`FND-FRAMEWORK-0047`), both of which must be remediated before integration.
The local workflow-security scanner also found direct repository-metadata
template expansion in the token-bearing workflow-tool publisher
(`FND-FRAMEWORK-0048`), which is remediated in the same consolidation.

## Affected components and security boundaries

The change is confined to the Framework repository: GitHub Actions workflows,
CI-security contract checkers, the workflow-tool updater, its lock, tests, and
English/German security documentation. It protects the untrusted PR-head to
trusted-base OSV boundary, immutable Action provenance immediately before
token-bearing publishers, and the controlled CI Python-version boundary. It
also protects the repository-default-branch metadata boundary before shell
parsing in the write-capable workflow-tool publisher. It
does not modify Parent code, gitlinks, Connector runtime behavior, or the
read-only `tools/MRTS` boundary.

## Acceptance criteria

- All three source PR changes apply cleanly to the verified Framework base.
- Every `setup-python` selection uses the canonical `.python-version` file,
  except for the two explicitly constrained runner-temporary files.
- The OSV PR job reads, bounds, validates, and writes the verified head
  `.python-version` as data without checking out or executing PR-head source.
- Every parsed non-local Action reference is bound to the reviewed action lock,
  including quoted-key and flow-mapping spellings.
- Repository default-branch metadata reaches publisher shell code only through
  reviewed step-local data, is branch-ref validated before use, and is not
  expanded directly into shell source.
- The workflow-tool publisher allowlist, lock, workflow references, tests, and
  paired documentation remain consistent.
- Local contracts, focused tests, documentation checks, and final diff review
  pass; hosted required checks and the resulting-master SonarQube Cloud gate
  remain required before master integration.

## Alternatives considered

- Keep the source PRs separate. Rejected because their overlapping Action,
  Python-version, and lock changes require one coherent contract review.
- Restore the OSV job by checking out the PR head. Rejected because untrusted
  PR code or workflow content must not run in that trusted scanner path.
- Depend solely on source-line `uses:` checks. Rejected because valid YAML can
  express equivalent keys or flow mappings that bypass literal-line matching.
- Permit mutable tags or a generic temporary version-file exception. Rejected
  because both weaken immutable provenance or broaden the PR data boundary.

## Implementation decision

The consolidation keeps the trusted base checkout and fetches only the numbered
PR head reference after SHA verification. It materializes a bounded,
newline-checked `3.13.<patch>` value once beneath private runner temporary
storage for OSV `setup-python`; no head checkout or execution is introduced.
The CI-security contract now recursively examines parsed `uses` values and
compares each external action SHA with `security-tools.lock.yml`, while raw
source/comment validation remains defense in depth. The Python-version checker
allows the OSV file only for `ci-security-osv.yml`/`pull-request-head` and the
existing candidate file only in its reviewed validation job. The action lock
contains the verified `peter-evans/create-pull-request` v8.1.1 tag binding and
the updater allows the matching Python-version workflow explicitly. The
write-capable workflow-tool publisher receives its default branch through
step-local `DEFAULT_BRANCH` environment maps, validates it with
`git check-ref-format --branch`, uses quoted shell expansion, and is bound by
the exact publisher profile.

## Changed files and tests

- `.python-version`, selected Framework workflows, the Makefile,
  `requirements-ci.lock`, and `requirements-dev.txt` carry the PR #39 Python
  3.13 contract and PR #41 PyYAML compatibility update.
- `ci/checks/security/check-ci-security-contract.py` and
  `ci/checks/security/check-python-version.py` implement the two constrained
  remediations; `ci/tools/update-workflow-tools.py` retains the PR #40 updater
  hardening and removes the reported duplicate literal/always-return smells.
- `ci/tooling/security-tools.lock.yml` and affected workflow pins use one
  verified Action inventory, including the explicitly allowlisted Python
  updater workflow.
- `tests/ci_security/test_ci_security_contract.py`,
  `tests/ci_security/test_framework_ci_security_contract.py`, and
  `tests/ci_security/test_python_version_contract.py` and
  `tests/ci_security/test_update_workflow_tools.py` cover current valid
  behavior, the OSV exception boundary, quoted-key and flow-mapping alternate
  bypasses, a different full SHA rejection, and the constrained publisher
  profile.
- `docs/github-actions-workflow-security.{md,de.md}` and
  `docs/security/ci-security-tooling.{md,de.md}` document the corrected
  inventory, security controls, and token/checkout semantics.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `git ls-remote https://github.com/peter-evans/create-pull-request.git refs/tags/v8.1.1 refs/tags/v8.1.1^{}` | 0 | Verified `v8.1.1` resolves to `5f6978faf089d4d20b00c7766989d076bb2fc7f1`. | Consolidation run `20260722T153352Z-framework-pr-39-41-consolidation-54ccc60e` |
| `python3 -B ci/checks/security/check-ci-security-contract.py --root .` | 0 | Current workflow and lock contract passed after remediation. | Same run, local Framework worktree |
| `python3 -B ci/checks/security/check-python-version.py --root .` | 0 | Canonical CPython contract and narrow OSV exception passed. | Same run, local Framework worktree |
| `python3 -B -m unittest -v tests.ci_security.test_ci_security_contract tests.ci_security.test_framework_ci_security_contract tests.ci_security.test_python_version_contract tests.ci_security.test_update_workflow_tools tests.ci_security.test_fetch_security_tool` | 0 | 85 focused CI-security tests passed, including the OSV bootstrap and parsed-action-lock regressions. | Same run, local Framework worktree |
| `make test-ci-security-contract` | 0 | 124 CI-security tests passed. | Same run, local Framework worktree |
| `make test-makefile-contract`, `make test-workflow-action-pins`, and `make test-workflow-contract` | 0 | The 3 Makefile, 25 action-pin, and 3 workflow-contract tests passed. | Same run, local Framework worktree |
| `make check-documentation` and `make test-change-record-contract` | 0 | Documentation links, bilingual variable checks, repository references, and all 4 Change Record contract tests passed. | Same run, local Framework worktree |
| `make lint` | 0 | The native aggregate lint target passed: shell syntax, Python compilation, contracts, security tests, provenance regression suites, and documentation checks. | Same run, local Framework worktree |
| Checksum-verified `ruff check` / `ruff format --check` over the exact CI-quality scope | 0 | Lint passed; all 20 scoped files are formatted. | Same run, `runner-temp/framework-ci-security-tools` |
| Checksum-verified `actionlint` and `zizmor --offline .github` | 0 | Workflow syntax passed; Zizmor reports no active findings (26 retained suppressions). | Same run, `runner-temp/framework-ci-security-tools` |

## Security impact

`FND-FRAMEWORK-0046` is remediated by retaining a trusted base checkout and
accepting head data only after exact-reference verification, a bounded blob
read, a non-overwriting regular-file write, and strict `3.13.<patch>` content
validation. The original missing-base-`.python-version` path is replaced by
the isolated bootstrap; the alternative unsafe remediation (PR-head checkout
or execution) remains absent from the workflow contract.

`FND-FRAMEWORK-0047` is remediated by parsed-YAML action-lock enforcement.
The original literal unquoted `uses:` path remains checked for the release
comment, while quoted-key and flow-mapping actions with a different full SHA
now fail the lock comparison. The regression suite contains both alternative
bypasses and a legitimate current-lock control. No security control, quality
gate, Branch Protection rule, or scanner is weakened.

`FND-FRAMEWORK-0048` is remediated by moving default-branch metadata out of
publisher shell source into exact `DEFAULT_BRANCH` environment maps. The
maintenance-branch step validates the value as a branch ref before ref
construction, while the hashed publisher profile keeps the source form
reviewable. A checksum-verified pre-fix Zizmor scan reported four
template-injection findings; its post-fix scan reports none.

## Documentation and runtime evidence

The paired English/German workflow-security and CI-tooling guides now state
the current Action inventory, read-only common-version checker, constrained
OSV version bootstrap, and parsed Action-lock control. Static/contract evidence
only has been collected locally. No GitHub Actions runtime, Connector runtime,
MRTS, integration, or lifecycle evidence is claimed by this Framework record.

## Checks not run

- Pyright could not run locally because the required Node.js runtime is absent;
  the checked-in workflow provisions reviewed Node 24.18.0 before invoking the
  checksum-verified Pyright bundle.
- The local interpreter is CPython 3.14.4, not the reviewed 3.13.14 runtime.
  Hosted CI must prove the actual runner behavior.
- A live OSV PR-context run, updater publisher behavior, required GitHub
  checks, and resulting-master SonarQube Cloud status are hosted evidence and
  have not yet been observed.
- An exploratory full-repository `ruff check ci tests` is not the project CI
  target and exits 1 with 54 diagnostics outside the CI-security-quality scope;
  the exact scoped command above passes. This consolidation does not make
  unrelated formatting or lint-baseline changes.

## Limitations and residual risk

The static controls and unit tests cannot prove GitHub's event context,
`runner.temp` filesystem behavior, ref availability, or hosted branch
protection. The consolidation may not merge until its exact PR head passes the
required hosted checks and the resulting-master SonarQube Cloud requirement is
satisfied or specifically risk-accepted by the current user. `FND-SONAR-0002`
is not closed or waived by this record.

## Final diff and review status

The combined branch has passed its scoped local contracts, tests, documentation
checks, actionlint, and offline Zizmor scan. The remaining delivery work is a
final exact-diff/security-evidence reconciliation, a reviewed Framework PR,
its exact-head hosted checks, and the normal protected-master merge path. No
Parent/MRTS changes are included and no direct master push is used.
