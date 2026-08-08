# Change record: Remediate PR #67 SonarQube Cloud S1192 outcome-condition duplication

**Language:** English | [Deutsch](20260808-04-remediate-pr67-sonar-s1192.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260808-04-remediate-pr67-sonar-s1192 |
| UTC date | 2026-08-08 |
| Framework base revision | a8c7210fe57d4ff4fd0206c6d18554f63b0680b0 |
| Issue or pull request | Framework PR #67, fix/maintenance-publisher-outcomes into master; current user explicitly authorized protected Framework-master integration after all gates pass. |

## Motivation and problem statement

The current SonarQube Cloud analysis of PR #67 reports one open task-owned
python:S1192 code smell, AZ_i2zXawr7A0FAxa6fT. Its Quality Gate passes, but
the PR cannot claim a no-open-task-owned-issues disposition while the
annotation remains open. The issue reports three copies of the exact terminal
outcome condition ${{ always() }} in the CI-security contract.

## Affected components and security boundaries

- ci/checks/security/check-ci-security-contract.py uses one reviewed condition
  in the Python-version, workflow-tool updater, and common-version terminal
  outcome checks.
- The condition is a CI-workflow trust-boundary control: only the exact
  ${{ always() }} form is accepted; missing, success(), malformed, or alternate
  conditions remain fail-closed.
- This is a maintainability remediation, not a security vulnerability fix.
  No Parent file, Parent gitlink, MRTS source, or MRTS gitlink changes.

## Acceptance criteria

1. The three terminal outcome comparisons use one module-level
   ALWAYS_CONDITION constant with the unchanged exact literal ${{ always() }}.
2. Existing positive workflow profiles pass and same-boundary success()
   mutations remain rejected.
3. No Sonar suppression, exclusion, rule/profile/gate change, or unrelated
   refactor is introduced.
4. Current exact-head local, hosted, SonarQube Cloud, review, conversation,
   and protection evidence passes before the authorized protected merge.

## Alternatives considered

- Suppressing or accepting the Sonar issue was rejected because the current
  user did not authorize a suppression and the code has a small native repair.
- Reusing the narrowly named COMMON_VERSION_RESULT_IF value was rejected
  because it would obscure its use in unrelated Python-version and updater
  validation paths.
- Changing terminal workflow behavior or the accepted literal was rejected
  because it would weaken or alter the reviewed CI-security contract.

## Implementation decision

ALWAYS_CONDITION is the single module-level expression for the reviewed
${{ always() }} literal. The three existing comparisons now reference it. The
semantic acceptance set and error paths are unchanged.

## Changed files and tests

- ci/checks/security/check-ci-security-contract.py
- This paired English/German Change Record.

The focused suite tests.ci_security.test_ci_security_contract covers the
unmodified workflow positive control plus negative Python-version,
workflow-tool-updater, and common-version outcome-condition mutations.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| Current-head Sonar check, annotation, PR issue, and source-diff reads | 0 | One task-owned open python:S1192 issue confirmed; raw API payloads were not retained. | 20260808T200500Z-framework-pr67-sonar-s1192 |
| Explicit Framework virtual-environment verification | 0 | Selected Framework .venv is a virtual environment and no dependency was installed. | Local Framework task worktree |
| python -m unittest tests.ci_security.test_ci_security_contract -v | 0 | 34 focused positive and negative CI-security contract tests passed after the repair. | Local Framework task worktree |
| `make lint` with the selected Framework .venv and external task roots | 0 | Complete repository-native aggregate passed, including shell/Python syntax, 142 CI-security tests, Change-Record/documentation checks, workflow contracts, action pins, and final `git diff --check`. | 20260808T200500Z-framework-pr67-sonar-s1192 |

## Security impact

No security remediation was performed. The changed checker enforces
security-relevant workflow controls, so the original positive outcome-job
profile and alternate success()-condition rejection were rerun. The repair
adds no token, secret, permission, workflow, or publication behavior.

## Documentation and runtime evidence

This paired Change Record and FND-FRAMEWORK-0062 document the Sonar finding.
No connector runtime, GitHub App installation, credential value, raw hosted
log, Parent, or MRTS evidence was collected or changed.

## Checks not run

Current-head hosted checks, SonarQube Cloud readback after the follow-up push,
reviews, conversations, branch-protection evidence, and resulting-master
workflow checks are pending the normal task-branch commit and push. They will
not be inferred from the older PR head. No local check was intentionally
substituted for those hosted gates.

## Limitations and residual risk

The exact issue closes only when a fresh SonarQube Cloud analysis for the
follow-up PR head reports it absent. The required protected master integration
also remains conditional on all current-head review, protection, and
post-merge verification gates.

## Final diff and review status

The source diff is deliberately limited to one shared condition constant and
three references. Focused positive/negative validation and the full local
aggregate passed, including whitespace, documentation, Change-Record, and
workflow-contract checks. Final secret/diff review, hosted, Sonar, review,
merge, and resulting-master evidence remains pending. No suppression or
sensitive value is recorded.
