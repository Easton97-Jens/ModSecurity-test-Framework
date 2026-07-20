# Change record

**Language:** English | [Deutsch](20260720-01-fix-common-version-provenance-parser.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260720-01-fix-common-version-provenance-parser |
| UTC date | 2026-07-20 |
| Framework base revision | efdbcbd98afeed0f39f8912ce1140aaa5742f507 |
| Issue or pull request | FND-FRAMEWORK-0027 and FND-FRAMEWORK-0028; Framework Draft PR not yet created. |

## Motivation and problem statement

Current Framework master fails the scheduled common-version check fail-closed
with four empty ModSecurity repository/ref aliases even though common.sh
contains approved ModSecurity v3 repository, commit, and release-tag literals.
The parser only admitted equivalent CRS literal anchors before resolving aliases.
Once fixed, a security review also showed that the generic updater could plan
only the compatibility alias for a newer ModSecurity v3 release without its
approved immutable commit.

## Affected components and security boundaries

- ci/tools/check-common-versions.py
- tests/security_regression/test_common_versions_sonar_provenance.py

The boundary is the Framework supply-chain provenance checker. Approved identity
anchors must be resolved before required aliases, while missing tracked
provenance must remain fail-closed. No Parent or MRTS boundary is changed.

## Acceptance criteria

- The three approved ModSecurity v3 literal anchors resolve before aliases.
- The four required ModSecurity repository/ref aliases resolve from those
  anchors.
- Missing anchors still cause the existing tracked-variable validation to fail.
- A newer ModSecurity v3 release cannot automatically update only its
  compatibility alias.
- No optional-variable entry, provenance pin, Parent file, Sonar control, or
  MRTS file changes.

## Alternatives considered

Marking aliases optional, parsing arbitrary literal assignments, changing a
provenance pin, or suppressing the scheduled check would hide a missing
provenance condition or weaken its control. Restricting the allowlist to the
three reviewed ModSecurity v3 identity names preserves the existing design.

## Implementation decision

The parser now uses one explicit approved-literal allowlist containing the
existing CRS identity names and the three reviewed ModSecurity v3 identity
names. A focused fixture verifies positive literal/alias resolution, the
negative missing-anchor fail-closed control, and a newer ModSecurity v3 release
as an unknown/manual-review state with no update plan.

## Changed files and tests

- ci/tools/check-common-versions.py: recognizes the three reviewed
  MODSECURITY_V3_APPROVED_* literal identity variables and refuses to
  synthesize a partial ModSecurity v3 release-tag-to-commit update.
- tests/security_regression/test_common_versions_sonar_provenance.py: adds
  focused positive, missing-anchor, and partial-auto-update regressions.
- This paired English/German Change Record documents the Framework-only fix.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| python3 -m unittest discover -s tests/security_regression -p test_common_versions_sonar_provenance.py -v | 0 | 15 focused tests passed, including positive aliases, missing-anchor rejection, and the no-partial-update control. | 20260720T080314Z-parent-pr55-57-59-framework-update-3443af13 |
| python3 -m py_compile ci/tools/check-common-versions.py | 0 | The changed checker compiled using an external bytecode root. | 20260720T080314Z-parent-pr55-57-59-framework-update-3443af13 |
| make test-modsecurity-v3-provenance-contract | 0 | 10 provenance-contract tests passed with task-owned build and temporary roots. | 20260720T080314Z-parent-pr55-57-59-framework-update-3443af13 |
| python3 ci/tools/check-common-versions.py --check --json --timeout 20 | 0 | No required variable is missing; a newer ModSecurity v3 release is visible as review-required unknown with no update plan. | 20260720T080314Z-parent-pr55-57-59-framework-update-3443af13 |
| make check-bilingual-docs | 0 | The paired English/German documentation check passed. | 20260720T080314Z-parent-pr55-57-59-framework-update-3443af13 |
| make check-documentation | 0 | Documentation links, variable documentation, repository references, and Change Record contract passed. | 20260720T080314Z-parent-pr55-57-59-framework-update-3443af13 |
| make lint | 0 | The Framework-wide shell, syntax, CI-security, provenance, workflow, catalog, documentation, and diff checks passed. | 20260720T080314Z-parent-pr55-57-59-framework-update-3443af13 |
| git diff --check | 0 | No task-diff whitespace error. | local pre-commit review |

## Security impact

The original parser path was reproduced before the fix: approved literals were
ignored and required aliases became empty. The new regression also removes
those anchors and proves that validate_entries still rejects the aliases. No
optional list, trust pin, scanner control, or MRTS boundary was weakened.
The added release wrapper keeps an unreviewed tag-to-commit change in an
unknown/manual-review state and produces no privileged automatic write.

## Documentation and runtime evidence

This paired Change Record is the only reader-facing documentation change. No
connector runtime or lifecycle evidence was collected because the correction is
limited to a Framework static provenance parser.

## Checks not run

Hosted exact-head CI, CodeQL, SonarCloud, review, and conversation checks are
pending the Framework Draft PR. The observed non-writing `--check --json`
command exits zero with a review-required unknown component state, no missing
ModSecurity provenance variables, and no partial ModSecurity v3 update plan.
The scheduled writing `--update --markdown --write-files` variant was not run
against canonical common.sh; its exact-head workflow evidence remains pending.
MRTS tests are not applicable and MRTS was not touched.

## Limitations and residual risk

The correction does not review or change current upstream pins. A newer
ModSecurity v3 release intentionally remains manual work until a safe
tag-to-immutable-commit resolver is designed and reviewed. The independent
Framework-master Sonar gate remains FND-SONAR-0002.

## Final diff and review status

The task diff is limited to the parser allowlist, its focused regression, and
this paired record. Whitespace review passed. Independent source-security review
and its follow-up completed without a bypass, permission expansion, or MRTS
change. Exact-head hosted CI, CodeQL, SonarCloud, review, and conversation
evidence remain pending after the Draft PR is opened. No secrets or raw
sensitive material are recorded.
