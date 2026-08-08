# Change record: 20260808-04-separate-common-version-manual-review

**Language:** English | [Deutsch](20260808-04-separate-common-version-manual-review.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260808-04-separate-common-version-manual-review` |
| UTC date | 2026-08-08 |
| Framework base revision | `a8c7210fe57d4ff4fd0206c6d18554f63b0680b0` |
| Issue or pull request | GitHub Actions run [#16](https://github.com/Easton97-Jens/ModSecurity-test-Framework/actions/runs/31274879150); one user-authorized Draft PR is pending the final delivery preflight. |

## Motivation and problem statement

Run #16 failed in the read-only resolver because a newer ModSecurity-v3 release
needed a manual tag-plus-immutable-commit provenance decision. The checker
represented that bounded decision as `unknown`, so its strict exit code stopped
the separately complete HAProxy version-plus-digest update before a candidate
could be validated. The terminal job correctly refused the absent resolver
output; it was not the first cause.

## Affected components and security boundaries

This Framework-only remediation changes the Common-version checker, the
scheduled/manual maintenance workflow, its CI-security contract and regression
tests, workflow-security documentation, and this paired record. The boundary
starts with upstream release/checksum metadata and ends at the isolated
candidate, repository-limited App-token publisher, fixed Draft branch, and
`ci/lib/common.sh`-only PR scope. Parent, MRTS, Gitlinks, and
`ci/lib/common.sh` pins are not changed by this implementation PR.

## Acceptance criteria

1. Strict default checker behavior still fails closed for `unknown`, `blocked`,
   `error`, and a manual provenance review.
2. Only a valid CRS or ModSecurity-v3 fixed repository/tag/immutable-commit
   tuple can become typed `review_required` in explicit maintenance mode.
3. A safe automatic plan is complete, disjoint from every manual provenance
   line, reparsed, byte-checked, and independently revalidated before writing.
4. The workflow distinguishes no update, manual review only, safe updates,
   safe updates with manual review, and fatal outcomes without credential use
   or publication for the first two outcomes.
5. Resolver, validator, publisher, result job, and CI-security contract bind
   the reviewed outputs and fail closed on a mismatch.
6. English/German documentation and a paired record describe the exact
   boundary without claiming a hosted or merged result that was not observed.

## Alternatives considered

- Treating all `unknown` values as non-fatal was rejected because malformed,
  unreachable, contradictory, or untrusted upstream metadata would become
  publishable.
- Auto-resolving a CRS or ModSecurity release tag to a commit was rejected
  because the immutable provenance decision remains manual.
- Deferring APR-util together with the two tag/commit paths was rejected as
  unnecessary scope expansion: its provider/compatibility tuple remains an
  independently fatal review boundary.
- Treating manual review as no update was rejected because it would hide the
  actionable provenance decision.

## Implementation decision

The checker adds a typed `review_required` status only after each explicit CRS
or ModSecurity-v3 function verifies its fixed GitHub repository, expected tag
form, 40-hex reviewed commit, and runtime aliases. It clears automatic updates
for that status. `--defer-reviewed-provenance` enables the maintenance outcome
classifier while the default CLI remains strict. The classifier rejects any
fatal component, malformed review metadata, incomplete plan, duplicate update,
or manual/automatic variable overlap.

Before applying a safe partial plan, the checker renders and parses it in
memory, proves every manual source line byte-identical, rechecks upstream
components with a fresh client, requires the candidate to settle to no updates
or manual review only, then writes and reparses the candidate. The workflow
binds outcome, SHA-256, automatic variables, manual components, and the
manual-pin digest across its read-only stages and publisher. Its Draft PR body
separates automatic changes from unchanged manual reviews.

## Changed files and tests

- `ci/tools/check-common-versions.py` adds the bounded disposition, safe-plan,
  reparse, byte-preservation, and revalidation controls.
- `.github/workflows/check-common-versions.yml` carries the reviewed outcome
  through resolver, validator, publisher, and terminal reporting.
- `ci/checks/security/check-ci-security-contract.py` binds the changed output,
  gate, environment, and static workflow body profiles.
- `tests/security_regression/test_common_versions_sonar_provenance.py` and
  `tests/security_regression/test_crs_git_ref_provenance.py` cover permitted
  manual states, strict defaults, safe partial update, fixed identity, overlap,
  byte preservation, and fatal negatives.
- `tests/ci_security/test_ci_security_contract.py` covers terminal outcomes
  and mutation resistance for the new resolver/publisher contract.
- `docs/github-actions-workflow-security.md` and `.de.md` describe the
  security behavior.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| Strict isolated `check-common-versions.py --update --json --write-files --timeout 20` | 2 (expected) | ModSecurity v3 was `review_required`; the independent HAProxy plan did not write and the external copy stayed byte-identical. | Task-owned Run #16 remediation root |
| Isolated `check-common-versions.py --update --defer-reviewed-provenance --json --write-files --timeout 20` | 0 | Classified `safe_updates_with_manual_review`, retained the manual-pin proof, and changed exactly HAProxy version and SHA-256 in a BUILD_ROOT-confined copy. | Task-owned Run #16 remediation root |
| Focused Common-version, CRS provenance, and CI-security `unittest` modules | 0 | 67 positive, negative, terminal-state, and mutation tests passed. | Task-owned Framework checkout |
| `make lint` with external build/cache/evidence roots | 0 | Full native lint, 142 CI-security tests, provenance suites, workflow/documentation/record checks, and final diff check passed. | Task-owned Run #16 remediation root |
| `ci/checks/documentation/check-workflow-yaml.py` | 0 | All repository workflow YAML files, including the changed workflow, parsed successfully. | Task-owned Framework checkout |
| `ci/checks/security/check-ci-security-contract.py` | 0 | Exact reviewed CI-security profile passed. | Task-owned Framework checkout |
| Ruff check and format check | 0 | Changed Python checker, contract, and regression scope passed after deterministic formatting. | Task-owned checksum-verified tool directory |
| actionlint with ShellCheck; offline zizmor | 0 | All workflows passed actionlint; ShellCheck passed; zizmor reported no findings (37 documented suppressions). | Task-owned checksum-verified tool directory |
| Gitleaks on the uncommitted diff and both records | 0 | No leaks found; output was fully redacted. | Task-owned checksum-verified tool directory |

## Security impact

The original path is now retested by the safe-partial control: a valid manual
ModSecurity-v3 decision does not alter its provenance lines while an unrelated
HAProxy version-and-digest pair can be revalidated. Unknown, blocked, error,
fixed-identity mismatch, malformed immutable commit, conflicting update, and
manual-variable overlap remain non-publishable. The publisher receives its
App token only after the independent candidate matches all bounded proof
values; its default-branch, branch, title, marker, and path checks remain
unchanged and exact.

## Documentation and runtime evidence

The documentation pair now distinguishes manual review from no update and
records the independent comparison values and Draft-PR tables. Run #16
(`31274879150`) supplied the original resolver exit `2`, skipped validator and
publisher, and failed terminal absent-output evidence. GitHub retained no run
artifact or per-component resolver summary; a subsequent isolated execution at
the same source revision provided the stronger available component matrix.

## Checks not run

- Local Pyright was invoked through the checksum-locked package but is blocked
  because this environment has no `node` executable. No runtime was installed;
  the hosted PR quality workflow remains the required Pyright control.
- Hosted exact-head checks, CodeQL, SonarQube, review, and branch protection
  cannot run until the authorized Draft PR exists.
- No merge, Parent runtime test, MRTS action, Gitlink update, or default-branch
  end-to-end workflow run is authorized by this task.

## Limitations and residual risk

Current upstream data is time-varying and is not a substitute for the absent
Run #16 JSON artifact. The remediation confines that uncertainty to a fresh
three-stage candidate process and fails closed on divergence. Manual CRS and
ModSecurity-v3 tag/commit provenance still require a separate human review;
this change deliberately does not manufacture either immutable commit.

## Final diff and review status

Local implementation, evidence, and security review are complete. No Framework
commit, push, Draft PR, hosted check result, review, merge, Parent change,
MRTS change, or Gitlink update is claimed by this record until observed.
