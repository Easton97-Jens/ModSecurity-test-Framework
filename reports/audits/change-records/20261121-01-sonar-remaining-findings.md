# Change record

**Language:** English | [Deutsch](20261121-01-sonar-remaining-findings.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261121-01-sonar-remaining-findings |
| UTC date | 2026-11-21 |
| Framework base revision | `95f228936efe17fda24f21323ad87cd698940b48` |
| Issue or pull request | Follow-up to Framework PR #176 |

## Motivation and problem statement

SonarCloud reports three S1110 findings on Python expressions that need grouping in their original form. Equivalent expressions make the intended evaluation explicit. The baseline analysis `601c9eb1-0472-4b67-af6d-01d4b91765a3` also reports 23 security issues, assessed individually as false positives for the inspected source.

## Affected components and security boundaries

The CI evidence contract and Python version check probe the same path as before. The importer check still requires the expected error from the invalid synthetic overlay.

## Acceptance criteria

The three expressions preserve behavior and the existing checks pass. Each security finding has a source-backed disposition and the actual Cloud state is reported separately.

## Alternatives considered

Deleting the parentheses would change Python evaluation. The revised expressions make grouping explicit in the operands and avoid Sonar suppressions.

## Implementation decision

Use `Path.joinpath()` for both existence checks. Apply the stderr fallback before evaluating the substring test.

## Changed files and tests

- `ci/checks/security/check-ci-security-evidence-contract.py`
- `ci/checks/security/check-python-version.py`
- `ci/checks/catalog/check-mrts-importer.py`
- This English/German Change Record pair.

The existing importer check uses four synthetic fixtures.

## Commands and results

| Command with configured Framework `PYTHON` | Exit code | Result |
| --- | --- | --- |
| `rtk bypass "$PYTHON" -B ci/checks/security/check-ci-security-evidence-contract.py` | 0 | CI security evidence contract passed |
| `rtk bypass "$PYTHON" -B ci/checks/security/check-python-version.py` | 0 | Python version contract passed |
| `rtk bypass env PYTHONPATH="$FRAMEWORK_ROOT" "$PYTHON" -B ci/checks/catalog/check-mrts-importer.py` | 0 | Four synthetic cases imported |
| `rtk bypass git diff --check` | 0 | Source whitespace clean |

The exact environment and command evidence is retained under `framework-sonar-rest-20261121/s1110/results.json` in the configured run root.

## Security impact

The validator expressions retain their original pass and failure behavior. The static assessment of 23 alerts found existing HTTPS servers, local path construction or tests, fixed paths behind directory checks, and operator-selected local inputs. The proposed Sonar comments identify each control or data-flow distinction. The static findings apply to the examined revision and CLI trust contract.

## Documentation and runtime evidence

The paired Change Record documents source and scanner findings. Validation concerns local checkers and synthetic fixtures.

## Checks not run

A fresh Sonar analysis of the changes requires the Framework CI workflow. No host or historical qualification suite was selected.

## Limitations and residual risk

The Sonar SSH capability response shows `allowed_mutations: []`. All 26 Cloud issues remain open before publication or operator-granted disposition. The current master gate fails on security rating E. A new privileged service that forwards untrusted arguments to a local CLI would need a separate assessment.

## Final diff and review status

Local Framework worktree on `codex/framework-sonar-rest-20261121`. The selected source and evidence passed Secrets checks. Publication and Cloud closure are pending.
