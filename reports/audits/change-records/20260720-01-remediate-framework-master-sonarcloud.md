# 20260720-01-remediate-framework-master-sonarcloud — Framework master SonarCloud remediation

**Language:** English | [Deutsch](20260720-01-remediate-framework-master-sonarcloud.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260720-01-remediate-framework-master-sonarcloud |
| UTC date | 2026-07-20 |
| Framework base revision | efdbcbd98afeed0f39f8912ce1140aaa5742f507 |
| Issue or pull request | Fresh SonarCloud master inventory; normal task-branch delivery and pull request remain pending |

## Motivation and problem statement

A fresh GitHub master/SonarCloud readback found 32 open rows at the exact base
revision: 15 Framework-owned rows and 17 MRTS-path rows. The current default
branch Quality Gate is ERROR because new_security_rating is 5 against threshold
1. The task repairs only reproducible Framework-owned items and documents the
MRTS items from retained external scanner metadata without source inspection.

## Affected components and security boundaries

Framework changes are limited to the action-pin checker, No-CRS catalog checker,
documentation-variable checker, Apache provisioning helper, two catalog shell
checkers, and focused regression tests. The relevant boundaries are GitHub
Actions action pinning, checksum verification, No-CRS fixture/path/evidence
containment, payload-safe transport evidence, and static-document parsing.

The 17 reported MRTS rows are documented metadata only. MRTS source/content,
generated artifacts, Git state, and gitlink are not a Framework task scope and
were not edited.

## Acceptance criteria

- Preserve SHA-bound evidence for the current master inventory and Quality Gate.
- Classify all 15 Framework rows and repair each reproducible maintainability
  row with focused regression evidence.
- Preserve existing fail-closed/containment controls for scanner security rows;
  do not invent an unsupported patch or false-positive disposition.
- Document all 17 MRTS rows in equivalent English, German, and JSON finding
  records using external metadata only.
- Do not change a Quality Gate, profile, rule, exclusion, accepted issue,
  NOSONAR setting, Parent repository, gitlink, or MRTS source/content.
- Deliver only through a normal task branch and non-merged PR after local
  validation; obtain exact-head remote CI/SonarCloud evidence before closure.

## Alternatives considered

Changing the SonarCloud Quality Gate, accepting rows, adding exclusions, or
using NOSONAR was rejected because it would hide the issue inventory rather
than repair it. Broad refactoring was rejected because the code paths define
security and test contracts. Modifying or inspecting MRTS was rejected because
it is an external read-only boundary. The selected approach uses narrowly
scoped helpers, explicit control flow, focused regressions, and a metadata-only
external handoff.

## Implementation decision

The action-pin scanner now extracts small parser helpers while retaining its
full-SHA and unsupported-YAML protections. The No-CRS catalog code extracts
validation/expectation helpers without changing validation order or closed
transport vocabulary; an unused parameter is removed and an equality check is
made explicit. The Apache checksum pipeline uses a single POSIX helper. The
two shell case statements make their fall-through explicit. The documentation
regex uses an ASCII-scoped word class equivalent to its former ASCII boundary
while retaining Unicode whitespace behavior.

Five Framework scanner security rows received source-to-sink/control analysis,
not speculative code changes: current deterministic output roots, containment,
symlink checks, deny-list behavior, and fail-closed validations are retained
and exercised by existing focused tests.

## Changed files and tests

Changed Framework files:

- ci/checks/security/check-workflow-action-pins.py
- ci/checks/catalog/no_crs_baseline.py
- ci/checks/documentation/check-variable-documentation.py
- ci/provisioning/prepare-apache-build.sh
- ci/checks/catalog/check-open-runtime-provisioning-contract.sh
- ci/checks/catalog/check-crs-version-pinning.sh
- tests/security_regression/test_workflow_action_pins.py
- tests/security_regression/test_variable_documentation_assignment_regex.py
- reports/audits/change-records/20260720-01-remediate-framework-master-sonarcloud.md
- reports/audits/change-records/20260720-01-remediate-framework-master-sonarcloud.de.md

The added tests protect an action-pin flow mapping with a GitHub expression and
the corrected closing-flow-delimiter scan, plus ASCII/non-ASCII boundary and
Unicode-whitespace assignment behavior. Existing No-CRS, transport, runner
containment, runtime-snapshot, checksum, and CRS-pinning tests provide
negative and legitimate controls.

## Commands and results

The following replay-safe command templates are identical in the English and
German records. Set lowercase shell variables task_run_root to a configured
task-owned external run directory and framework_python to the selected existing
Framework interpreter. Fully resolved observed command literals are retained
outside versioned documentation in evidence/validation-command-manifest.md to
avoid embedding a local developer path.

<pre>
C01 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-workflow" TEST_TMPDIR="$task_run_root/tmp/final-workflow" PYTHONPYCACHEPREFIX="$task_run_root/build/final-workflow/pycache" make PYTHON="$framework_python" BUILD_ROOT="$task_run_root/build/final-workflow" test-workflow-action-pins
C02 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-variable" TEST_TMPDIR="$task_run_root/tmp/final-variable" PYTHONPYCACHEPREFIX="$task_run_root/build/final-variable/pycache" "$framework_python" tests/security_regression/test_variable_documentation_assignment_regex.py -v
C03 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-no-crs" TEST_TMPDIR="$task_run_root/tmp/final-no-crs" PYTHONPYCACHEPREFIX="$task_run_root/build/final-no-crs/pycache" "$framework_python" tests/no_crs/test_no_crs_baseline.py -v
C04 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-catalog" TEST_TMPDIR="$task_run_root/tmp/final-catalog" PYTHONPYCACHEPREFIX="$task_run_root/build/final-catalog/pycache" "$framework_python" ci/checks/catalog/no_crs_baseline.py catalog-check
C05 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-transport" TEST_TMPDIR="$task_run_root/tmp/final-transport" PYTHONPYCACHEPREFIX="$task_run_root/build/final-transport/pycache" "$framework_python" tests/no_crs/test_transport_hardening_evidence.py -v
C06 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-runner" TEST_TMPDIR="$task_run_root/tmp/final-runner" PYTHONPYCACHEPREFIX="$task_run_root/build/final-runner/pycache" "$framework_python" tests/security_regression/test_runner_core_output_containment.py -v
C07 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-snapshot" TEST_TMPDIR="$task_run_root/tmp/final-snapshot" PYTHONPYCACHEPREFIX="$task_run_root/build/final-snapshot/pycache" "$framework_python" tests/security_regression/test_runtime_snapshot_sonar.py -v
C08 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-pcre2" TEST_TMPDIR="$task_run_root/tmp/final-pcre2" PYTHONPYCACHEPREFIX="$task_run_root/build/final-pcre2/pycache" "$framework_python" tests/security_regression/test_pcre2_archive_digest.py -v
C09 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-crs" TEST_TMPDIR="$task_run_root/tmp/final-crs" PYTHONPYCACHEPREFIX="$task_run_root/build/final-crs/pycache" "$framework_python" tests/security_regression/test_crs_version_pinning_paths.py -v
C10a rtk sh -n ci/provisioning/prepare-apache-build.sh
C10b rtk sh -n ci/checks/catalog/check-open-runtime-provisioning-contract.sh
C10c rtk sh -n ci/checks/catalog/check-crs-version-pinning.sh
C11 rtk env TMPDIR="$task_run_root/tmp/final-open-runtime" sh ci/checks/catalog/check-open-runtime-provisioning-contract.sh
C12 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPYCACHEPREFIX="$task_run_root/build/final-pycompile/pycache" "$framework_python" -m py_compile ci/checks/catalog/no_crs_baseline.py ci/checks/security/check-workflow-action-pins.py ci/checks/documentation/check-variable-documentation.py
C13 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-lint" TEST_TMPDIR="$task_run_root/tmp/final-lint" PYTHONPYCACHEPREFIX="$task_run_root/build/final-lint/pycache" BUILD_ROOT="$task_run_root/build/final-lint" TMP_ROOT="$task_run_root/tmp/final-lint" STATE_HOME="$task_run_root/state/final-lint" make PYTHON="$framework_python" lint
C14 rtk env PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 TMPDIR="$task_run_root/tmp/final-lint" TEST_TMPDIR="$task_run_root/tmp/final-lint" PYTHONPYCACHEPREFIX="$task_run_root/build/final-lint/pycache" BUILD_ROOT="$task_run_root/build/final-lint" TMP_ROOT="$task_run_root/tmp/final-lint" STATE_HOME="$task_run_root/state/final-lint" make PYTHON="$framework_python" lint
</pre>

| Command ID | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| C01 | 0 | 23 tests passed after the parser extraction and closing-delimiter regression | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C02 | 0 | 3 tests passed | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C03 | 0 | 74 tests passed; expected negative-control diagnostics were emitted | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C04 | 0 | no-crs-catalog PASS, 166 cases | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C05 | 0 | 13 tests passed | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C06 | 0 | 3 containment tests passed | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C07 | 0 | 3 runtime-snapshot control tests passed | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C08 | 0 | 3 checksum/negative-path tests passed | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C09 | 0 | 3 tests passed | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C10a-C10c | 0 | POSIX shell syntax passed for all three changed scripts | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C11 | 0 | open_runtime_provisioning_contract PASS | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C12 | 0 | syntax compilation passed | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C13 | 2 | first native lint stopped only on local developer paths in new versioned records; no source failure | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |
| C14 | 0 | full native lint passed after the documentation-path correction | 20260720T075840Z-master-sonarcloud-remediation-9cc184c6 |

## Security impact

No analysis control was weakened. The action-pin checker continues to require
40-character commit-SHA pins for external actions, including YAML flow mappings.
Checksum comparison remains fail-closed before extraction. The No-CRS
refactoring preserves fixture containment, real-host/no-synthetic-pass
requirements, closed transport metadata, no-body/no-authorization logging
rules, and protocol-client evidence rules.

The local source-to-sink review did not validate an exploitable path for the
five Framework security scanner rows. Existing runner containment tests reject
writes outside a trusted root and traversal-shaped runtime filenames; snapshot
and No-CRS controls preserve deterministic roots, symlink rejection, and
payload-safe evidence. This is not a remote SonarCloud closure claim.

## Documentation and runtime evidence

The task-local finding system contains equivalent English, German, and JSON
records FND-FRAMEWORK-0001, FND-MRTS-0001, and FND-CROSS-0001. The MRTS record
contains the complete metadata-only inventory below:

| Key | Rule | Reported location |
| --- | --- | --- |
| AZ84XDED2YUGB8FZMhlf | python:S3776 | tools/MRTS/mrts/generate-rules.py:122 |
| AZ84XDED2YUGB8FZMhlg | python:S7504 | tools/MRTS/mrts/generate-rules.py:139 |
| AZ84XDED2YUGB8FZMhlh | python:S108 | tools/MRTS/mrts/generate-rules.py:167 |
| AZ84XDED2YUGB8FZMhli | python:S3776 | tools/MRTS/mrts/generate-rules.py:182 |
| AZ84XDED2YUGB8FZMhlj | python:S3776 | tools/MRTS/mrts/generate-rules.py:208 |
| AZ84XDED2YUGB8FZMhlk | python:S8519 | tools/MRTS/mrts/generate-rules.py:336 |
| AZ84XDED2YUGB8FZMhll | python:S8519 | tools/MRTS/mrts/generate-rules.py:343 |
| AZ84XDED2YUGB8FZMhlm | pythonsecurity:S8707 | tools/MRTS/mrts/generate-rules.py:428 |
| AZ84XDED2YUGB8FZMhln | pythonsecurity:S8707 | tools/MRTS/mrts/generate-rules.py:444 |
| AZ84XDDw2YUGB8FZMhle | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:13 |
| AZ84XDDw2YUGB8FZMhlb | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:14 |
| AZ84XDDw2YUGB8FZMhlY | pythonsecurity:S8705 | tools/MRTS/mrts/mrts.py:30 |
| AZ84XDDw2YUGB8FZMhlc | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:30 |
| AZ84XDDw2YUGB8FZMhlZ | pythonsecurity:S8705 | tools/MRTS/mrts/mrts.py:53 |
| AZ84XDDw2YUGB8FZMhld | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:73 |
| AZ84XDDw2YUGB8FZMhla | pythonsecurity:S8707 | tools/MRTS/mrts/mrts.py:83 |
| AZ84XDED2YUGB8FZMhlX | python:S1940 | tools/MRTS/mrts/mrts.py:93 |

The source is retained official API artifact
evidence/sonar-master/issues-page-1-full.json,
SHA-256 698b8fbdf7a99c31c451a693781e5f0ef95061412917cd2fa9afcbe17017dd4a.
No host runtime/lifecycle run was collected; the listed local checks are
static/focused validation, not connector runtime evidence.

## Checks not run

A full unconstrained repository suite was not run because the active task
requires avoiding commands that could traverse or inspect MRTS. Local
SonarCloud analysis is not an accepted substitute for a current GitHub/PR
analysis. Remote GitHub CI, current-head SonarCloud Quality Gate, current-head
issue readback, normal push, and draft PR creation remain pending at this
record's current revision. C14 is the successful full native lint result; it
is local verification, not remote evidence.

An initial PCRE2 test attempt and one Make invocation used non-existent
task-local temporary subdirectories; the former failed before the test could
create its fixture and the latter fell back to /tmp. Those are infrastructure
setup errors, not source failures; the directories were created and both
affected checks were rerun successfully with task-local paths.

## Limitations and residual risk

The 17 MRTS rows remain blocked by external ownership and may independently
keep master red. A documentation delegate made an over-broad rg --files
attempt containing the task worktrees parent. Its filtered output contained no
literal MRTS path or MRTS source content and it made no edits, but enumeration
could have occurred before filtering. The delegate was stopped immediately and
the incident is FND-CROSS-0001. This irreversibly misses the task's strict
no-prohibited-action completion criterion.

## Final diff and review status

The uncommitted Framework diff has passed whitespace review and full native
make lint. An independent security-focused review found no validated functional
regression, security control weakening, compatibility break, or accidental scope
creep. Normal task-branch commit/push, PR creation, and exact-head remote
verification remain pending. No merge is authorized.
