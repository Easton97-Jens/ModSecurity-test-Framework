# MRTS package integration change record

**Language:** English | [Deutsch](20261028-01-mrts-package-integration.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261028-01-mrts-package-integration |
| UTC date | 2026-10-28 |
| Framework base revision | `3a4f2281568139d94fda6b51dc2e07bb8fc06c67` |
| Issue or pull request | Separate task branch `codex/mrts-package-integration-20261028`; Draft PR created after local verification |

## Motivation and problem statement

Disabled optional demo generation/import could block the base corpus. Raw YAML
mapping keys changed header name `"2"` back into an integer; unquoted strings,
multiline values and repeated headers also lost types/content/order. Sourceable
shell functions could hide failed intermediate commands. Native reports could
invent PASS counts from totals. Existing prepared-file checks did not bind the
actual source selection or artifacts.

## Affected components and security boundaries

Framework provisioning, YAML import, private output publication, runner result
projection and native report consumption. MRTS remains read-only at
`8a6bb546c4c81d8ffc7be801dceac60c6925685f`; its source, fixtures and gitlink
are unchanged. Parent host code and delivery remain a separate repository.

## Acceptance criteria

Disabled demo is untouched; enabled invalid/colliding demo fails. Strings and
ordered/repeated headers roundtrip while strict validation remains. Only a
complete validated package is published; sources, selection, unique IDs and
hashes are verified before reuse. Connector materializations are private.
Missing/skipped/duplicate/forced results and writer failures cannot become
runtime PASS. Imported catalog restrictions survive result projection.

## Alternatives considered

Importing invalid demo requests as pending would retain the original failure
and risk a validation bypass. Renaming the numeric-header fixture would hide
serialization loss. Trusting `PREPARED` or copying old partial output would not
prove package identity. A second importer was rejected in favor of the existing
generator wrapper, definition guard, importer and load writer.

## Implementation decision

`mrts-package.py prepare|verify|materialize` implements the contract documented
in [MRTS preparation](../../../docs/mrts-preparation.md). Private snapshots feed
the guard and existing importer; a complete directory is published by rename.
The manifest binds revisions, relevant source/environment identity, full
definition selection, hashes, IDs and statuses. Materialization adapts only its
private FTW ports/path references. Shell consumers verify the manifest and
create a new copy per host shell. Unique combined preambles avoid self-includes
and propagate writer errors. Existing make entry points use this path.

The importer uses the already-declared PyYAML dependency, quotes strings/keys,
preserves repeated header order and stages complete catalogs. `mrts_results.py`
provides one observed-ID accounting implementation for producer and report.
`runner_core.case_info` retains imported `metadata.runtime_verified=false`,
keeping observed case PASS separate from broad variable/capability promotion;
the real-world-summary validator remains unchanged.

## Changed files and tests

Changes cover `Makefile`, `ci/lib/mrts-common.sh`, new `ci/lib/mrts_results.py`,
`ci/provisioning/{mrts-package.py,generate-mrts.sh,mrts_definition_guard.py,import-mrts-cases.py}`,
`ci/reporting/generate-mrts-native-report.py`, `tests/runners/runner_core.py`,
three existing MRTS regression modules and three new on-demand modules for
import, package and result integrity. Paired integration/variable documentation
links the new preparation guide. No default test selection is enlarged.

## Commands and results

All commands ran in the Framework task worktree under RTK. Python was
`<Framework-python>` (3.14.4,
PyYAML 6.0.3); `PYTHONNOUSERSITE=1`, `PYTHONDONTWRITEBYTECODE=1`, external
`TMPDIR`/`RUNNER_TEMP` and `PYTHONPYCACHEPREFIX` were explicit. Local paths are normalized as `<pinned-checkout>`, `<Framework-python>`
and `<task-root>`; exact executed commands are retained in the external
`evidence/framework-validation-commands.json`, keeping portable documentation
free of developer checkout paths.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk bypass env MRTS_ROOT=<pinned-checkout> RUNNER_TEMP=<task-root>/evidence PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=<task-root>/pycache TMPDIR=<task-root>/evidence <Framework-python> -m unittest tests.security_regression.test_mrts_common_posix_reliability tests.security_regression.test_mrts_common_sonar tests.security_regression.test_mrts_package tests.security_regression.test_mrts_import_integrity tests.security_regression.test_import_mrts_cases_sonar tests.security_regression.test_mrts_definition_guard tests.security_regression.test_mrts_result_integrity -q` | 0 | 67 tests passed | `<task-root>/evidence` |
| `rtk bypass env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX=<task-root>/pycache TMPDIR=<task-root>/evidence <Framework-python> ci/checks/catalog/check-mrts-importer.py` | 0 | Four importer fixture cases | Same external evidence root |
| `rtk bypass sh -n ci/lib/mrts-common.sh ci/provisioning/generate-mrts.sh ci/provisioning/write-mrts-load.sh` | 0 | Shell syntax | None |
| `rtk make check-bilingual-docs check-doc-links check-repository-path-references PYTHON=<Framework-python>` | 0 | Bilingual variables, links and path references | None |
| `rtk bypass git diff --check` | 0 | No whitespace errors | None |

The initial integrated run had five test-environment errors because
`RUNNER_TEMP` was absent; its other 59 methods passed. The result-test temporary
root now supports `TMPDIR` as well. No production failure was hidden. Initial
prepared-load-only tests were updated to require a manifest, with real prepared
acceptance covered through the package CLI.

## Security impact

No control is weakened. Negative coverage includes invalid headers/control
characters, forbidden definition globals, missing/manipulated packages,
definition-selection changes, partial imports, stale generator outputs,
private port isolation, preamble writer errors and fabricated result totals.
Framework source Gitleaks scanning before inspection and after implementation
found no leaks (both exit 0; redacted reports in the external evidence root). This work is not a broad security
scan or a signed-artifact/process-isolation claim.

## Documentation and runtime evidence

Updated paired connector integration and variable reference, added paired
`docs/mrts-preparation.md`. Parent-owned H1 validation uses a task-local
definition with explicit deny status through the real pinned generator,
importer and Apache. The Parent record owns its runtime facts; Framework
generation/catalog success alone does not qualify any host.

## Checks not run

No full historical MRTS/protocol matrix, HTTP/2/HTTP/3, coverage campaign or
complete dependency audit, per task scope. Ruff is absent from the Framework
environment and was not installed. GitHub required checks and applicable
Cloud gates are read back after PR creation; local results do not claim them.

## Limitations and residual risk

The pinned upstream corpus imports as pending where classification is
insufficient; its DetectionOnly init and log-only expectations are not promoted
to a disruptive PASS. The pinned demo contains rule-ID overlap and may fail
when explicitly enabled. Case status and evidence layers remain visible.
Trusted same-UID mutation remains outside process isolation. A package is
bound to its exact preparation location and source identity; revision changes
require regeneration. General test migration remains separate.

## Final diff and review status

Independent review found selection-reuse, inherited-materialization and
preamble-self-include issues; focused corrections and regressions address them.
Final staged diff, secret scanning and delivery verification are completed
before commit/PR. No MRTS delivery, Parent pin update or merge is authorized.
