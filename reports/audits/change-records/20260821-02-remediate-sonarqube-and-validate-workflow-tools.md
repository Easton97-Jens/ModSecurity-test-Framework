# Change record

**Language:** English | [Deutsch](20260821-02-remediate-sonarqube-and-validate-workflow-tools.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260821-02-remediate-sonarqube-and-validate-workflow-tools` |
| UTC date | 2026-08-21 |
| Framework base revision | `414149cf7b73abacd65db67ed290f46f2c98e59c` |
| Issue or pull request | [Framework PR #101](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/101) to `master` |

## Motivation and problem statement

Although its Quality Gate passed, the exact initial PR #101 head had two open
SonarQube Cloud New issues. The user requires that count to be zero and asks
for evidence that the GitHub Action version checker and pinned-tool updater
function. The issues are task-owned Python maintainability findings, not a
Sonar configuration problem: one repeats the exact OSV workflow literal and
one test puts two possibly-throwing calls inside one `assertRaises` body.

## Affected components and security boundaries

- `ci/checks/security/check-ci-security-contract.py`: Framework CI security
  contract; immutable action pins, hash-locked dependency bootstrap, and
  workflow permission controls must retain their exact behavior.
- `tests/ci_security/test_common_version_review_reconciler.py`: failure-closed
  GitHub response-size regression test.
- `ci/tools/update-workflow-tools.py` and
  `tests/ci_security/test_update_workflow_tools.py`: the updater's private
  proposed-tree validation context and its direct regression coverage.
- `.github/workflows/check-action-versions.yml` and
  `.github/workflows/update-workflow-tools.yml`: audited only. Their source,
  permissions, pins, triggers, checkout semantics, and publisher policy are
  not changed by this record.

Parent source and gitlink are unchanged. MRTS is default-read-only, unmodified,
and uninitialized in the task worktree.

## Acceptance criteria

1. The final PR #101 head reports zero open SonarQube Cloud New issues without
   a rule/profile/Quality-Gate/exclusion/suppression change.
2. The OSV workflow name has one module-level literal definition and the
   existing CI-security contract behavior is preserved.
3. The response-size test has exactly one potentially-throwing invocation in
   its exception assertion and preserves its existing failure-closed control.
4. The local Action-version contract and complete CI-security suite pass.
5. A successor PR-head `check-action-versions` run succeeds, while a
   non-default-ref `update-workflow-tools` run proves its resolver and
   structurally skips its publisher. Its proposed-tree validator must receive
   every fixed, read-only canonical input required by the checked contracts.

## Alternatives considered

- Mark the two Sonar findings accepted, suppress them, change a rule/profile,
  add `NOSONAR`, or exclude code: rejected. Each option hides a real,
  straightforward task-owned defect and violates the requested zero count.
- Change the updater resolver to inject `GITHUB_TOKEN`: rejected for this
  repair. It would change a reviewed credential boundary; the updater already
  has a safe non-default-ref validation path and a separate security decision
  would be required for credential expansion.
- Dispatch the updater on `master`: rejected. With an available update, its
  publisher can create or modify a maintenance branch and Draft PR.

## Implementation decision

Move the existing `OSV_WORKFLOW` constant beside the CI dependency-installer
workflow map and use it for the map entry and scanner branch. The literal and
all accepted behavior remain identical. Construct the reconciler `GitHubClient`
before the exception assertion, leaving only `request()` inside `assertRaises`.
No workflow source, action pin, dependency, permission, token, or trigger is
changed. The updater's `ALLOWED_UPDATE_PATHS` remains its complete publisher
write allowlist. A distinct, fixed `PROPOSED_VALIDATION_INPUT_PATHS` adds only
`ci/lib/common.sh` and `ci/tools/install-hash-locked-ci-dependencies.sh` to
the temporary validation input tree. These are read-only checker inputs: they
are not eligible for candidate changes, staging, or publishing.

## Changed files and tests

- `ci/checks/security/check-ci-security-contract.py`: one shared
  `OSV_WORKFLOW` constant reference replaces two duplicate literals.
- `tests/ci_security/test_common_version_review_reconciler.py`: preserves the
  oversized-response failure assertion with one invocation in its assertion
  context.
- `ci/tools/update-workflow-tools.py`: copies the two fixed canonical helper
  inputs required to validate a proposed tree without broadening the publisher
  allowlist.
- `tests/ci_security/test_update_workflow_tools.py`: adds a real tool-only
  proposed-tree validator regression test, which would fail without those
  read-only inputs.
- This English record and its complete German companion document the repair
  and its limits.

Existing direct tests cover the CI-security positive and mutation paths, the
response-size failure-closed path, updater resolver/validator/publisher
separation, publisher scope, no-update behavior, and full-SHA action pins.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused three-file unittest suite | 0 | 91 tests passed, including both repaired contracts and updater tests. | `framework-pr101-sonar-zero-20260821` |
| Direct Action-version workflow check chain | 0 | Pins, CI-security contract/evidence, canonical Python/workflow pins, runtime components, and CRS views passed after the updater correction. | `evidence/workflow-contract-chain-after-updater-fix.log` |
| `tests.ci_security.test_update_workflow_tools` | 0 | 35 tests passed, including the new tool-only proposed-tree regression. | `evidence/test-update-workflow-tools-after-context-fix.log` |
| `ci/tools/safe-make.sh test-ci-security-contract` | 0 | Complete `tests/ci_security` suite: 287 tests passed. | `evidence/test-ci-security-contract-after-updater-fix.log` |
| PR-head `check-action-versions` run `32448256402` | 0 | All hosted steps succeeded for `4ab08112debe3162bee4b4d07b12b931ce8891c8`. | GitHub Actions |
| SonarQube Cloud PR query | 0 | `total: 0`, empty issue list for PR #101 at the preceding repaired head. | `framework-pr101-sonar-zero-20260821` |
| Non-default updater run `32448284801` | 2 | Resolver succeeded and publisher was skipped; validator failed closed because its proposed tree omitted the two canonical helper inputs. | `evidence/workflow-updater-proposed-tree-failure.md` |
| PR-head Python CI-security quality run `32449509572` | 1 | Ruff lint passed; only Ruff formatting rejected one new long test expression. The successor wraps that expression without changing behavior. | `evidence/hosted-python-ci-security-quality-c9cde60-failed.log` |
| `git diff --check` | 0 | No whitespace error. | Task worktree |
| Exact-literal count | 0 | `"ci-security-osv.yml"` occurs once in the repaired checker. | Task worktree |
| `ci/tools/safe-make.sh lint` | 130 | Cancelled after its registered two-minute bound; not counted as a pass. | `evidence/make-lint.log` |

## Security impact

No security remediation is claimed. The affected checker remains a
security-relevant CI contract, so its unmodified positive/mutation tests and
the full CI-security suite are the legitimate controls. The source changes do
not expand credentials, permissions, trusted inputs, network destinations,
download behavior, publishing conditions, publisher write scope, or the
Parent/MRTS boundary. The updater continues to copy the new files through its
existing regular-file and symlink-resistant resolver; the CI checker parses
`common.sh` without executing it.

## Documentation and runtime evidence

This English record and the matching German record are the versioned
documentation changes. No connector runtime, service, package installation,
Parent action, MRTS action, or default-branch workflow dispatch occurred.
The preceding repaired head has hosted Sonar evidence of zero issues and a
successful `check-action-versions` run. The safe updater dispatch exposed a
real validation-context defect while correctly skipping the write-capable
publisher. The corrected source is locally proven and awaits a normal
follow-up PR push and fresh current-head checks. That first follow-up exposed
one Ruff-format-only test expression; the behavior-preserving wrap is locally
covered by the complete CI-security suite and awaits its successor run.

## Checks not run

- The complete `lint` aggregate did not reach a terminal pass before its
  registered time limit and is explicitly not counted as passing.
- No default-branch updater dispatch was run because it can create or update a
  branch and Draft PR.
- The hosted updater cannot yet execute this source correction on the PR ref:
  its reviewed workflow intentionally checks out `master`. Re-running it before
  an authorized merge would execute the old default-branch updater again, not
  the corrected PR code. This is recorded as a safe proof limitation, not
  bypassed by changing checkout, credentials, or publisher conditions.
- No credential-bound resolver change, external package installation, service
  run, full connector matrix, or MRTS test was needed for this narrow
  Framework-only repair.

## Limitations and residual risk

The updater's unauthenticated resolver can still encounter GitHub public API
rate limiting. More immediately, the safe hosted run proved the old
default-branch updater lacks two read-only validation inputs; the narrow PR
source correction cannot receive an exact hosted updater-success result until
an authorized merge makes it the reviewed default-branch source. The
write-capable publisher remains intentionally unexecuted. Fresh hosted Sonar
and PR checks remain required for the final follow-up head.

## Final diff and review status

The scoped unstaged diff contains the two Sonar repairs, the narrow updater
validation-input correction, its direct test, a Ruff-only formatting wrap, and
this paired Change Record. `git diff --check` passed; no secret-bearing files
or Parent/MRTS paths are included. The next state is a normal focused
follow-up commit on the existing PR #101 branch, followed by fresh exact-head
Sonar and PR-check validation. No merge, force push, settings change,
default-branch change, or Parent gitlink update is authorized.
