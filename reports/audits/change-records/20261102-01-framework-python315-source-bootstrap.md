# Change record

**Language:** English | [Deutsch](20261102-01-framework-python315-source-bootstrap.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261102-01-framework-python315-source-bootstrap |
| UTC date | 2026-11-02 |
| Framework base revision | `91145b7ba721bdec4e89af754cf40bf496fd2a08` |
| Issue or pull request | Local implementation handoff; no migration PR created at record preparation |

## Motivation and problem statement

Move the Framework interpreter and scheduled patch updater from CPython 3.14 to
3.15 while preserving the trusted-base OSV bootstrap. Official PyYAML 6.0.3 has
no reviewed CP315 wheel; binary-only installation failed. The user authorized
building its verified official source instead of selecting an unofficial wheel.

## Affected components and security boundaries

Framework canonical Python/PyYAML pins, generated selector/lock views,
installer, build-tool lock, updater workflows, exact security contracts,
validation snapshots, analysis baselines, and paired documentation are affected.
Build backend execution remains separated from runtime installation and inherited
credentials. OSV executes trusted-base bootstrap code only. Parent gitlink and
connector runtime behavior are outside this record; MRTS remains read-only.

## Acceptance criteria

The canonical selector and updater accept stable ASCII CPython 3.15 patch
versions only. Candidate/runtime and fixed publisher identity agree. A source
installation verifies official source and four exact build wheels, builds offline
without LibYAML, installs only PyYAML, and passes dependency checks. OSV permits
historical binary bootstrapping only for the exact pinned SHA/version pairs;
current bases use their trusted helper. Snapshot validation includes every newly
hash-bound installer input. Documentation distinguishes local checks, actual
3.15 source builds, advisory snapshots, and unperformed hosted validation.

## Alternatives considered

Keeping 3.14 would not satisfy the requested migration. Floating versions,
unofficial CP315 wheels, unpinned build tools, index-based build isolation, or
fetching bootstrap code from the PR head would weaken provenance. A verified
source build with explicit isolated build dependencies meets the selected scope.

## Implementation decision

The no-argument shell installer delegates to a standard-library Python helper.
The official source archive and four reviewed pure-Python build-tool wheels are
SHA-256 verified before use. A disposable venv builds a pure PyYAML wheel with
no LibYAML; build and installation run with scrubbed environment, no index, and
no dependency resolution. The locally built wheel receives a hash lock before
runtime installation. Build tools stay outside the runtime. Targets must be a
venv or the verified GitHub Actions setup-python prefix. Temporary outputs and
wheel/hash locks stay under external runner/build temporary storage and are
removed on exit. Existing historical wheel installations remain supported.

OSV preserves `f73f8842f45318e2df8aff1d31855eeb7c20a22f` / `3.13.14` and
`91145b7ba721bdec4e89af754cf40bf496fd2a08` / `3.14.10` only. A missing file
fallback belongs solely to the former tuple. Other bases require strict 3.15
and their checked-out central helper; missing helpers never trigger fallback.
Both historical env mappings and the conditional program are review-bound.

## Changed files and tests

Implementation includes `ci/lib/common.sh`, `.python-version`,
`requirements-ci.lock`, `ci/pyyaml-build-tools.lock.json`, the central shell and
Python installers, canonical Python/workflow synchronizers, Python updater,
workflow-tool snapshot inputs, CI workflows/security checkers, and analysis
configuration. Tests cover strict version grammar, metadata/readiness handling,
source/hash/build isolation, target admission, independently tampered bootstrap
inputs, historical routing, malicious workflow changes, and proposed-tree checks.
The two maintained English/German security guides are updated together.

## Commands and results

`PYTHON314`, `PYTHON315`, `PYTHON315_BIN`, `SYSTEM_PATH`, `RUFF`, and `BUILD_EVIDENCE` denote the task's Framework-owned
interpreters and external evidence root; their host-specific mappings remain
in the local execution plan. Commands below ran from the Framework worktree.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk bypass env TMPDIR=$BUILD_EVIDENCE/contracts/tmp PYTHONPYCACHEPREFIX=$BUILD_EVIDENCE/contracts/pycache $PYTHON314 -m unittest tests.ci_security.test_ci_security_contract tests.ci_security.test_framework_ci_security_contract tests.ci_security.test_python_version_contract -q` | 0 | 60 tests passed on the existing 3.14 environment | `framework-python315-20261102`, contracts scoped evidence |
| `rtk bypass env TMPDIR=$BUILD_EVIDENCE/contracts/tmp PYTHONPYCACHEPREFIX=$BUILD_EVIDENCE/contracts/pycache $PYTHON314 -m unittest tests.ci_security.test_update_workflow_tools.WorkflowToolUpdaterTests.test_canonical_validation_snapshot_is_private_and_rejects_redirects tests.ci_security.test_update_workflow_tools.WorkflowToolUpdaterTests.test_proposed_tree_validation_accepts_a_tool_only_candidate tests.ci_security.test_update_workflow_tools.WorkflowToolUpdaterTests.test_proposed_tree_validation_does_not_modify_the_source_checkout -q` | 0 | Three snapshot/proposed-tree tests passed | Same task, contracts scoped evidence |
| `rtk bypass $PYTHON314 ci/checks/security/check-ci-security-contract.py` | 0 | CI security contract passed | Same task, tool transcript |
| `rtk bypass env TMPDIR=$BUILD_EVIDENCE/updater PYTHONDONTWRITEBYTECODE=1 $PYTHON315 -m unittest tests.ci_security.test_update_python_version tests.ci_security.test_updater_readiness tests.ci_security.test_sync_canonical_python_pins tests.ci_security.test_ci_dependency_source_build` | 0 | Source-installer worker reported 50 tests passed on actual CPython 3.15.2 | Same task, source-installer worker transcript |
| `rtk bypass env PATH=$PYTHON315_BIN:$SYSTEM_PATH TMPDIR=$BUILD_EVIDENCE/updater PYTHONDONTWRITEBYTECODE=1 bash ci/tools/install-hash-locked-ci-dependencies.sh` | 0 | Source-installer worker observed actual pure-wheel build/install and pip checks | Same task, source-installer worker transcript |
| Official OSV `POST /v1/querybatch` for PyYAML 6.0.3, setuptools 84.2.1, wheel 0.48.0, Cython 3.3.1, packaging 26.3 | 0 | Coordinator observed no vulnerability IDs in this exact-version advisory snapshot | Same task, coordinator transcript |
| `rtk bypass env TMPDIR=$BUILD_EVIDENCE/contracts/tmp PYTHONPYCACHEPREFIX=$BUILD_EVIDENCE/contracts/pycache PYTHON=$PYTHON314 BUILD_ROOT=$BUILD_EVIDENCE/contracts/build make check-documentation` | 0 | Links, bilingual variable documentation, repository paths, and Change Record structure passed | Same task, documentation worker transcript |
| `rtk bypass $RUFF format ci/checks/security/check-ci-security-contract.py ci/checks/security/check-python-version.py ci/tools/update-workflow-tools.py tests/ci_security/test_python_version_contract.py tests/ci_security/test_ci_security_contract.py tests/ci_security/test_framework_ci_security_contract.py` | 0 | Three files formatted, three unchanged | Same task, contracts worker transcript |
| `rtk bypass $RUFF check ci/checks/security/check-ci-security-contract.py ci/checks/security/check-python-version.py ci/tools/update-workflow-tools.py tests/ci_security/test_python_version_contract.py tests/ci_security/test_ci_security_contract.py tests/ci_security/test_framework_ci_security_contract.py` | 0 | All checks passed; upstream 3.15 support warning remains | Same task, contracts worker transcript |
| `rtk bypass git diff --check` | 0 | Whitespace check passed before documentation handoff | Same task, contracts scoped evidence |

Additional coordinator checks passed on actual Python 3.15.2: 72 contract/generator tests, 16 canonical-maintenance tests, native Python/workflow pin/permission checks, five changed-workflow Actionlint checks, and Ruff lint/format across 19 changed Python files. Independent source-build review found no blocker at helper SHA `cf25436ad89407c416b64635924f8eecd1cb9d66d40faa7776ab7a433aa591ea`. Build-tool licences reviewed: PyYAML/setuptools/wheel MIT, Cython Apache-2.0, packaging Apache-2.0 OR BSD-2-Clause.

Hosted CPython 3.15.2 setup, verified source build, pure-wheel installation and pip checks succeeded; the hosted wheel SHA matched both local builds. Initial CI exposed old inline-install expectations and five test typing/import errors. Follow-up regression updates check actual no-argument delegation and executable helper controls while retaining installation-before-snapshot/apply/validation ordering. The 27 affected workflow/CRS tests and 24 typed builder/maintenance tests passed on 3.15; no runtime helper or security gate was weakened.

Sonar follow-up preserves every gate and addresses the temporary-root boundary
with explicit `RUNNER_TEMP` admission: physical external path, current UID,
no shared write access and trusted ancestry. Generic public-temp environment
fallbacks were removed. ASCII-only regex semantics remain explicit while
complexity, repeated literals and test assertion boundaries were simplified.
Source builds and pip checks passed again; no finding was suppressed or marked
false positive. The combined Framework PR supersedes the initial migration PR.

## Security impact

No vulnerability-remediation claim is made. The migration retains immutable
pins, checksums, restricted publication paths/permissions, and trusted-base
execution. Source builds add backend execution; verified artifacts, isolated
build tools, scrubbed environment, and offline build/install constrain that
surface. Tests reject altered hashes, historical identities, helper commands,
and bootstrap ordering rather than relaxing the gate.

## Documentation and runtime evidence

Both `docs/security/ci-security-tooling` and
`docs/github-actions-workflow-security` language pairs document 3.15, source
build boundaries, historical exceptions, and scan coverage. Actual 3.15.2
source build evidence is separate from the 3.14 contract-test evidence. No
connector host-runtime or production-readiness evidence was collected.

## Checks not run

Hosted CI, published migration PR checks, and Quality Gates had not run at this
record's local handoff. Full repository integration checks remain coordinator-owned until fresh
results are recorded; the four local documentation checks passed. No connector
runtime suite or MRTS execution was required by this Framework change.

Local Pyright execution was unavailable because no Node executable is installed; the unchanged pinned hosted Node/Pyright path remains required. An optional full provenance regression module exposed an existing ModSecurity release-list fixture mismatch outside this Python migration; its new source/OSV boundary cases passed separately.

The local complete CI-security discovery ran 348 tests: two failures came from the unchanged FIFO child-startup readiness limit, directly and through the nested CRS suite; the child still rejected the FIFO. A focused rerun of that unchanged FIFO case passed. The 27 affected workflow/CRS tests had already passed separately. This timing limitation is retained explicitly; timeout and rejection requirements were not relaxed. Fresh hosted checks remain required.

## Limitations and residual risk

OSV's workflow currently scans two named manifests; it does not automatically
recognize the custom JSON build-tool lock. The manual exact-version query is a
point-in-time advisory snapshot, not ongoing workflow scan coverage. Building
from reviewed source is additional code execution and does not establish
future artifact availability or vulnerability absence. Actual hosted Actions
setup-python execution and publisher behavior require subsequent CI evidence.

## Final diff and review status

Unstaged implementation diff and whitespace were reviewed locally; no broad
staging or Git delivery was performed by the documentation/contracts worker.
No credentials or raw sensitive logs are recorded. This record is a local
handoff, not a declaration of PR/CI/merge completion. The coordinator owns final
integrated review, documentation checks, and delivery status.
