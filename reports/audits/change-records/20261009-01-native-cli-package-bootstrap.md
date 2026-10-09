# Change record

**Language:** English | [Deutsch](20261009-01-native-cli-package-bootstrap.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261009-01-native-cli-package-bootstrap |
| UTC date | 2026-10-09 |
| Framework base revision | 7db219af6b6e911b73de8b437f82e63efdb06bde |
| Issue or pull request | None at implementation handoff |

## Motivation and problem statement

Standalone No-CRS execution did not add the Framework package root. Native finalization and offline validation consequently raised `ModuleNotFoundError: No module named 'tests'` before authority validation. Repository-root unit execution masked this defect.

## Affected components and security boundaries

The Framework CLI bootstrap and subprocess regression tests are affected. Explicit native authority, file ownership, byte seals and closed-schema validation remain enforced.

## Acceptance criteria

Isolated subprocesses from unrelated external working directories load current-checkout authority, bundle and contract readers without PYTHONPATH. Finalization retention and offline validation accept a local valid fixture and reject missing or malformed authority. A competing unimported `tests` package cannot shadow the checkout.

## Alternatives considered

A PYTHONPATH wrapper would leave direct file execution broken. Converting imports to bare runner names would not fix package imports inside the authority reader. The CLI therefore supplies its resolved package root.

## Implementation decision

Promote the resolved `FRAMEWORK_ROOT` to the front of `sys.path` before product imports, removing an existing occurrence first. Existing bare-module directories remain available. No authority validation or status semantics change.

## Changed files and tests

- `ci/checks/catalog/no_crs_baseline.py`: package bootstrap.
- `tests/no_crs/test_native_authority_cli_bootstrap.py`: four subprocess tests, with missing and malformed checks for both native paths.
- This English/German Change Record pair.

## Commands and results

The following is a portable rendering of the interpreter prefix actually executed
from the isolated Framework checkout. `<temporary-work-root>` is a presentation
alias for the configured external Codex storage parent, not a literal command
argument. The interpreter was the configured Framework-owned `venv/bin/python`;
TMPDIR was the explicitly selected external task analysis directory for run ID
`nginx-all-required-20261008T124555Z`. The exact resolved local invocation is
retained in that run's external `framework-native-cli-imports-report.md`.

```text
rtk proxy env TMPDIR=<temporary-work-root>/ModSecurity-conector/analysis/nginx-all-required-20261008T124555Z PYTHONNOUSERSITE=1 PYTHONPYCACHEPREFIX=<temporary-work-root>/ModSecurity-test-Framework/cache/pycache <temporary-work-root>/ModSecurity-test-Framework/venv/bin/python
```

| Command suffix / command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `-m unittest tests.no_crs.test_native_authority_cli_bootstrap -v` before fix | 1 | Four tests, six failing subcases; exact missing package and foreign-package failures observed | External task analysis root in prefix |
| Same focused command after fix | 0 | Four tests passed; valid original-byte retention, offline reader, rejection and shadow controls | Same external root |
| `rtk git diff --check` | 0 | No tracked whitespace errors | Framework checkout |
| `rtk --version`, `rtk gain`, `rtk proxy which rtk` | 0 | RTK 0.51.0 available and used | Local command checks |

The same interpreter prefix with `-m unittest discover -s tests/no_crs -v`
completed with exit code 0. The final focused command also passed after
strengthening the shadow test to put the checkout root behind the competing
package. `rtk proxy env PYTHONNOUSERSITE=1 PYTHONPYCACHEPREFIX=<temporary-work-root>/ModSecurity-test-Framework/cache/pycache <temporary-work-root>/ModSecurity-test-Framework/venv/bin/python ci/checks/documentation/check-change-records.py`
passed with exit code 0.

After making this record pair portable, the same documentation-check interpreter
prefix was used for these complete checks; each exited 0:
`ci/checks/documentation/check-repository-path-references.py`,
`ci/checks/documentation/check-variable-documentation.py`,
`ci/checks/documentation/check-change-records.py`, and
`ci/checks/documentation/check-doc-links.py`. These are documentation checks,
not a new runtime execution.

## Security impact

No security remediation claim is made. Current-checkout package precedence is deterministic for modules not already imported. Invalid authority remains a ContractError; no import exception is suppressed.

## Documentation and runtime evidence

This is the paired Framework record. Subprocess probes load the real CLI with `runpy.run_path` under `-I -B` and call the same retention/offline-reader functions as CLI execution. Fixtures do not establish Git/build/runtime authority. No host runtime or lifecycle evidence was collected by this task.

## Checks not run

Full repository lint, CI, source binding and native runtime rerun are coordinator-owned. No dependencies, native operations, administrative actions or delivery operations were performed.

## Limitations and residual risk

The probe covers the failing native seam rather than a full CLI lifecycle. Already imported foreign packages are outside this standalone clean-process contract. Parent integration and subsequent native finalization remain separate evidence requirements.

## Final diff and review status

Scoped source and test changes reviewed; tracked whitespace check passed. No secrets or raw sensitive material recorded. Uncommitted handoff; coordinator owns Git delivery. Parent gitlink unchanged; MRTS remained read-only.
