# MRTS package completeness and source binding

**Language:** English | [Deutsch](20261030-01-mrts-package-integrity.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261030-01-mrts-package-integrity |
| UTC date | 2026-10-30 |
| Framework base revision | `1d1e73fb069598e0f0f809d0bf16b5e59047ff88` |
| Delivery | Separate Framework follow-up; merge and Parent pin update require separate authorization |

## Motivation and problem statement

Nonrecursive selection silently omitted nested YAML definitions. A package
could still verify after adding `extra/additional.yaml`. The merged base
already bound `runtime_path_safety.py`, but omitted four transitive Framework
imports used when loading the runner to validate imported cases.

## Affected components and security boundaries

Framework package preparation, reuse and direct definition-directory guarding.
MRTS source and gitlink remain read-only at
`8a6bb546c4c81d8ffc7be801dceac60c6925685f`. Parent code and pins are unchanged
by this patch. Trusted same-UID operators remain outside process isolation.

## Acceptance criteria

`base.yaml` alongside `extra/additional.yaml` cannot produce a validated
partial corpus. Adding a nested definition invalidates reuse. Changing only a
used Framework guard or runner helper invalidates reuse without a HEAD change.
Existing demo, YAML typing, header/control and partial-publication controls pass.

## Alternatives considered

Recursive preservation would require changing the flat generator/importer
contract and provenance paths. Explicit rejection keeps that contract intact.
A blanket clean-Framework requirement would reject unrelated development edits;
the package instead binds its actual local dependency closure.

## Implementation decision

One `select_definition_files` function in `mrts_definition_guard.py` rejects
subdirectories and nonregular/symlink YAML files. Both the direct directory
guard and package selection use it. Package loading uses a fixed adjacent
Framework source through `runpy`, without adding a module alias or another
global search path. Preparation and verification share this selection.

The existing source list additionally binds `tests/runners/adapter_interface.py`,
`tests/runners/case_roots.py`, `tests/runners/msconnector_models.py` and
`ci/lib/generated_report_utils.py`. Their own imports are standard-library
modules. The existing list retains path guards, shell libraries, provisioning
entry points, importer, classifications and runner core; Python/PyYAML version
identity and clean pinned MRTS requirements remain unchanged.

Composition with migrated public imports additionally binds all Python sources
under the fixed `modsecurity_test_framework/` namespace. Descriptor-relative
traversal/opening never follows symlinks; regular files are read with a 1 MiB
per-file and 16 MiB total limit, at most 1,024 Python files, 4,096 entries and
32 directory levels. Source metadata is checked across each read. Complete map
comparison detects additions/removals as well as mutations. This includes
public context/result helpers and namespace aliases without a Parent dependency.

## Changed files and tests

Two provisioning files, two library files, the paired preparation guide, this paired record, the central bilingual variable reference and
two existing regression modules change. Fourteen separately named methods are
explicit on-demand Framework regressions in `MrtsPackageTests` and
`MrtsDefinitionGuardTests`: two nested package tests, one direct guard test,
five seed-source-change tests, and four public-namespace mutation, addition,
removal and symlink tests, plus real pinned generation under inherited safe-path
mode, plus a standalone result-CLI safe-path case. Each has a direct unittest selector. No automatic
default selection or independent scenario count is enlarged implicitly.

## Commands and results

Commands ran through RTK in the separate Framework worktree with Framework
Python 3.14, declared PyYAML, explicit Framework-only `PYTHONPATH`, no user site
or bytecode writes, and external `TMPDIR`/`RUNNER_TEMP`. The outer interpreter
used `-P`. In the initial 97-method run, inherited `PYTHONSAFEPATH` was unset
because the unchanged pinned MRTS script requires adjacent `path_utils` imports.
The final 99-method joint run preserves `PYTHONSAFEPATH=1` throughout, using the
scoped child and adjacent-loader fixes below. No global path alias was added.

| Command | Result |
| --- | --- |
| `rtk bypass env … <Framework-python> -P -m unittest` with the eight new exact method selectors | Baseline: seven failures, existing runtime-guard binding passes |
| `rtk bypass env … <Framework-python> -P -m unittest tests.security_regression.test_mrts_common_posix_reliability tests.security_regression.test_mrts_common_sonar tests.security_regression.test_mrts_package tests.security_regression.test_mrts_import_integrity tests.security_regression.test_import_mrts_cases_sonar tests.security_regression.test_mrts_definition_guard tests.security_regression.test_mrts_result_integrity -q` | 97 PASS, 65.251 seconds; 85 existing and twelve new methods |
| `rtk bypass env … <Framework-python> -P ci/checks/catalog/check-mrts-importer.py` | PASS, four importer fixtures |
| `rtk bypass env … make PYTHON='<Framework-python> -P' FRAMEWORK_ROOT=<worktree> TEST_ROOT=<worktree> BUILD_ROOT=<task-root>/build TMP_ROOT=<task-root>/tmp OUTPUT_ROOT=<task-root>/output check-documentation` | PASS, links, bilingual variables, repository paths and Change Records |
| Python AST audit of local imports from the bound preparation sources | PASS, 17 fixed seeds plus the complete bounded public Python namespace |
| `rtk bypass env PYTHONSAFEPATH=1 … <Framework-python> -P -m unittest` with all seven MRTS modules | 99 PASS, 68.895 seconds; 85 original and fourteen new methods |
| `rtk bypass <locked-ruff> format --check` on the six owned Python files | PASS; complete module ASTs unchanged by formatting |
| `rtk bypass <locked-ruff> check` on the same six files | Two baseline E402 diagnostics only; no new findings |
| `rtk bypass git diff --check` | PASS |

Exact commands and logs are retained in the external task evidence directory.
An initial test command inherited safe-path behavior into MRTS and failed its
adjacent import before generation; the corrected command above proves the
actual acceptance criteria without changing MRTS.

A subsequent composition check found that the public engine deliberately
inherits `PYTHONSAFEPATH=1`. The Framework guard now uses a fixed isolated
`-I -B -c` child bootstrap, restores the exact generator argument vector, adds
only the resolved trusted generator directory and invokes `runpy.run_path`.
This retains adjacent MRTS imports without inherited Python search paths or
parent module aliases. Explicit `-B` prevents bytecode writes even though `-I`
ignores environment-based bytecode settings. One separately named package
regression prepares and verifies through the real pinned generator in that
inherited environment.

The same inherited mode exposed a separate adjacent-import dependency in the
standalone result CLI. `mrts_results.py` and `mrts_path_safety.py` now bind the
actual adjacent runtime/path functions using fixed `runpy.run_path` sources.
No global search path, module alias or Connector fallback is introduced, and
all original path/ownership/output checks remain. A second independently named
real subprocess regression exercises successful result publication with
`PYTHONSAFEPATH=1`. The complete package scope is twelve files; this follow-up
changes ten of them relative to the published package commit.

## Security impact

Nested inputs fail before publication and reuse cannot ignore added nested
definitions. Source-only changes now invalidate affected packages. No hash,
validator, isolation, path, publication or CI control is weakened. No dependency
is added. Pre-read bounded secret-pattern scanning reported no matches.

## Documentation and runtime evidence

The paired [preparation guide](../../../docs/mrts-preparation.md) documents flat
inputs and transitive source binding. Real pinned generation/import is tested;
these are package-integrity results, not host-runtime or connector promotion.

## Checks not run

No host runtime, historical matrix, coverage campaign, installation or network
download. No MRTS code changes or delivery actions. Checksum-locked Ruff 0.16.10
initially formatted four owned Python files with identical whole-module ASTs
before and after; final format --check passes for all six owned Python files. Lint reports only the same two baseline
E402 imports in mrts-package.py after its required path bootstrap. The other
five files pass lint. No suppression or bootstrap refactor was introduced.

## Limitations and residual risk

Nested directories, including empty ones, are rejected intentionally. Packages
with the older source list require regeneration. Future local dependencies must
be added to the explicit source list. This is neither a signed package system
nor protection against a malicious same-UID process modifying the verifier.

## Final diff and review status

Scoped patch preserves existing assertions and explicit on-demand selection.
Separate Framework delivery and dependent Parent pin integration remain with
the coordinating task; no default-branch write or automatic merge is authorized.
