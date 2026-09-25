# Change record: Remediate SonarQube Cloud S1192 HAProxy entrypoint duplication

**Language:** English | [Deutsch](20260925-01-remediate-sonar-s1192-haproxy-entrypoint.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260925-01-remediate-sonar-s1192-haproxy-entrypoint |
| UTC date | 2026-09-25 |
| Framework base revision | 6c248afe85c24ebdfb1cd66e171e908f7ef29d48 |
| Issue or pull request | SonarQube Cloud issue AaA1eamGk8_C4ZaY-OsO on `master`; proposed Framework branch `codex/framework-sonarqube-remediation-20260925` targeting `master`. |

## Motivation and problem statement

The current SonarQube Cloud new-code readback for `master` reports one open,
task-owned `python:S1192` maintainability finding. It identifies three copies
of the HAProxy compatibility smoke-entrypoint literal in the Framework catalog
checker. The Quality Gate passes, but the finding remains open until a fresh
analysis of the repaired pull-request head no longer reports it.

## Affected components and security boundaries

- `ci/checks/catalog/five_connectors_with_crs_no_mrts.py` owns a closed
  Framework catalog for the five-connector evidence contract.
- The HAProxy entrypoint is compatibility-only and remains a static catalog
  value; this change adds no runtime dispatch, credential, permission, or
  connector-capability behavior.
- This is a maintainability remediation, not a security remediation. No Parent
  file, Parent gitlink, MRTS source, or MRTS gitlink is changed.

## Acceptance criteria

1. The three catalog/checker uses of the HAProxy compatibility entrypoint
   reference one narrowly named module-level constant with the unchanged value.
2. Existing catalog validation and contract-test expectations retain the same
   entrypoint and fail-closed identity behavior.
3. No SonarQube suppression, exclusion, rule/profile/gate change, or unrelated
   refactor is introduced.
4. A fresh exact-head GitHub and SonarQube Cloud readback is observed after the
   proposed pull request is created.

## Alternatives considered

- Suppressing, accepting, or marking the finding false-positive was rejected:
  the duplicated literal has a direct, behavior-preserving source repair.
- Reusing a broader generic path constant was rejected because the value
  represents the specifically selected HAProxy compatibility identity.
- Changing the entrypoint or its validation behavior was rejected because it
  would alter the reviewed Framework/Parent boundary rather than repair the
  duplication.

## Implementation decision

`HAPROXY_COMPATIBILITY_ENTRYPOINT` is the sole module-level spelling of
`ci/runtime/run-haproxy-smoke.sh`. The catalog record, expected-entrypoint
mapping, and closed-record validation now reference that constant. The resolved
string and all identity-validation behavior remain unchanged.

## Changed files and tests

- `ci/checks/catalog/five_connectors_with_crs_no_mrts.py`
- This paired English/German Change Record.

The existing focused suite
`tests.ci_security.test_five_connector_with_crs_no_mrts_contract` checks the
selected HAProxy compatibility entrypoint and negative catalog mutations. No
test logic changed because the externally observed value is unchanged.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| Connected SonarQube Cloud new-code readback for `master` | 0 | One open task-owned `python:S1192` issue, AaA1eamGk8_C4ZaY-OsO, confirmed at `ci/checks/catalog/five_connectors_with_crs_no_mrts.py:112`; no raw payload retained. | Project `Easton97-Jens_ModSecurity-test-Framework` |
| GitHub source and policy readback at base revision | 0 | Confirmed exactly three source copies and the existing focused contract coverage. | `6c248afe85c24ebdfb1cd66e171e908f7ef29d48` |

## Security impact

No security remediation was performed. The patch changes only a static
maintainability representation; it adds no token, secret, permission,
workflow, network, shell-dispatch, or publication behavior.

## Documentation and runtime evidence

This paired Change Record documents the Framework-only remediation. No
connector runtime or lifecycle evidence was collected, and no claim about
connector support or promotion is made.

## Checks not run

No local Framework test command was run before the initial connector-backed
commit because this task has no materialized Framework checkout or configured
Framework virtual environment. Current-head GitHub workflows, pull-request
review, and fresh SonarQube Cloud readback are required after branch delivery
and are not inferred here.

## Limitations and residual risk

The issue is resolved only if a fresh SonarQube Cloud analysis for the exact
pull-request head no longer lists AaA1eamGk8_C4ZaY-OsO. Hosted validation remains distinct
from connector runtime evidence; a successful static or contract check does
not establish connector host behavior.

## Final diff and review status

The candidate diff was reviewed against base 6c248afe85c24ebdfb1cd66e171e908f7ef29d48: one constant plus three
references and this paired record, with no suppression or unrelated change.
The task branch is not merged; Parent gitlink disposition is `unchanged` and
MRTS remains `default_read_only`. No secrets or raw sensitive material are
recorded.
