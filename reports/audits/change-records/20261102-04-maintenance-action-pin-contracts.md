# Canonical Action pins in maintenance contract tests

**Language:** English | [Deutsch](20261102-04-maintenance-action-pin-contracts.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261102-04-maintenance-action-pin-contracts |
| UTC date | 2026-11-02 |
| Framework base revision | 92bd63630e0593e51b7a248bcfe1dd37fcefc518 |
| Issue or pull request | Follow-up to Actions run 41453911536, job 125307348645; no new PR assigned at documentation handoff |

## Motivation and problem statement

The maintenance candidate applied all 43 canonical updates successfully, then
failed two of its 64 test methods because four assertions still contained old
Action commit literals. The previous maintenance repair was already merged at
this baseline. This follow-up corrects the test contract for legitimate reviewed
canonical pin updates.

## Affected components and security boundaries

Framework CI contract tests validate the identities and immutable commits of
`actions/upload-artifact`, `actions/download-artifact`, `actions/checkout`, and
`actions/setup-python`. This change does not modify canonical pins, workflows,
dependency versions, permissions, artifact bindings, or runtime behavior. Parent
source and its Framework gitlink remain unchanged; MRTS remains unchanged and
was not initialized for the replay.

## Acceptance criteria

Canonical old and updated commits pass without editing expected SHA literals.
Mutable, malformed, foreign, or noncanonical references fail. A simultaneous
foreign repository in canonical data and workflow must fail. Portable workflow
checks select exactly one expected named step in `portable-contract`. The exact
original update plan applies offline, the two original failures reproduce before
the fix, and all four original candidate test modules pass after it. Generated
views remain synchronized through their native generator.

## Alternatives considered

Replacing the four literals with today's commits would repeat the next-update
failure. Accepting any 40-character SHA would lose canonical equality. Reading
both expected repository and commit from the same mutable source would permit a
foreign repository to satisfy the check. The selected helper retains fixed
repository identities and independently reads the canonical commit.

## Implementation decision

`assert_canonical_action_pin` uses the existing nonexecuting
`load_canonical_ci_pins` reader, verifies the fixed expected repository, requires
a lowercase 40-hex commit, and compares the complete `uses` value with
`repository@commit`. YAML parsing binds checkout/setup-python to their exact
named steps in the intended job. Existing security assertions, permissions,
caller-bound artifact names, paths, and downstream controls are retained.

## Changed files and tests

- `tests/ci_security/workflow_contract_test_support.py`: shared canonical pin assertion.
- `tests/ci_security/test_unified_common_maintenance_workflow.py`: upload/download assertions and three regression methods with 19 subcases: two legitimate commits, nine invalid workflow references, and eight invalid canonical tuples, including simultaneous foreign source/workflow identity.
- `tests/ci_security/test_five_connector_with_crs_no_mrts_contract.py`: YAML-based checkout/setup-python assertions with unique named-step checks.
- `connector_suite/reports/testing/test-selection-archive.generated.json`: native generated archive refresh: two affected test-source hashes, three new on-demand test IDs, and count 8034 → 8037; source/evidence/native/extraction/case flags are unchanged. `active-cases.json` is byte-identical.
- This English/German Change Record pair.

## Commands and results

Commands ran through RTK in the Framework task worktree, or in its isolated
replay candidate as stated. Portable variables stand for the existing Framework
Python 3.15.2 interpreter (`FRAMEWORK_PYTHON`), existing Ruff 0.17.3 binary
(`RUFF`), Framework checkout (`FRAMEWORK_ROOT`), and external task temporary and
bytecode-cache directories (`EXTERNAL_TMP`, `EXTERNAL_CACHE`). No tool was
installed. Host-specific paths are retained only in local task evidence.

Focused command (five methods, including the 19 regression subcases):

```sh
rtk bypass env ON_DEMAND_TESTS=1 FRAMEWORK_ROOT="$FRAMEWORK_ROOT" TEST_ROOT="$FRAMEWORK_ROOT" PYTHONPATH="$FRAMEWORK_ROOT:$FRAMEWORK_ROOT/connector_suite" PYTHONPYCACHEPREFIX="$EXTERNAL_CACHE" TMPDIR="$EXTERNAL_TMP" "$FRAMEWORK_PYTHON" -m unittest tests.ci_security.test_unified_common_maintenance_workflow.CanonicalActionPinAssertionTests tests.ci_security.test_unified_common_maintenance_workflow.UnifiedCommonMaintenanceWorkflowTests.test_caller_bound_plan_artifact_is_uploaded_once_and_consumed_by_downstream_jobs tests.ci_security.test_five_connector_with_crs_no_mrts_contract.FiveConnectorWorkflowSecurityContractTest.test_workflow_is_a_read_only_portable_contract_gate -v
```

Exact original four-module selection, executed from the replay candidate with
its external temporary/cache paths and candidate import roots configured:

```sh
rtk bypass "$FRAMEWORK_PYTHON" -m unittest -v tests.ci_security.test_unified_common_maintenance_workflow tests.security_regression.test_common_version_descriptor_series tests.security_regression.test_runtime_component_lock tests.ci_security.test_five_connector_with_crs_no_mrts_contract
```

| Command or recorded procedure | Exit code | Concise result | Evidence reference |
| --- | --- | --- | --- |
| Focused command above | 0 | Five methods passed in 0.516s | Local task evidence |
| `rtk bypass "$RUFF" check tests/ci_security` | 0 | CI security test directory passed lint | Local task evidence |
| `rtk bypass "$RUFF" format --check tests/ci_security` | 0 | 28 files already formatted | Local task evidence |
| `rtk bypass env ON_DEMAND_TESTS=1 PYTHONPYCACHEPREFIX="$EXTERNAL_CACHE" TMPDIR="$EXTERNAL_TMP" "$FRAMEWORK_PYTHON" ci/tools/sync-maintenance-test-views.py --write --root "$FRAMEWORK_ROOT"` | 0 | Native generated archive refreshed | Local task evidence |
| Same native generator command with `--check` replacing `--write` | 0 | Generated views synchronized | Local task evidence |
| `rtk bypass env PYTHONPATH="$FRAMEWORK_ROOT" PYTHONPYCACHEPREFIX="$EXTERNAL_CACHE" TMPDIR="$EXTERNAL_TMP" "$FRAMEWORK_PYTHON" ci/checks/security/check-ci-security-contract.py` | 0 | CI security contract passed | Local task evidence |
| `rtk bypass env FRAMEWORK_ROOT="$FRAMEWORK_ROOT" PYTHONPATH="$FRAMEWORK_ROOT" PYTHONPYCACHEPREFIX="$EXTERNAL_CACHE" TMPDIR="$EXTERNAL_TMP" make PYTHON="$FRAMEWORK_PYTHON" check-canonical-common-pins check-canonical-python-pins check-canonical-workflow-pins` | 0 | All three canonical checks passed | Local task evidence |
| `rtk bypass env FRAMEWORK_ROOT="$FRAMEWORK_ROOT" PYTHONPATH="$FRAMEWORK_ROOT" PYTHONPYCACHEPREFIX="$EXTERNAL_CACHE" TMPDIR="$EXTERNAL_TMP" make PYTHON="$FRAMEWORK_PYTHON" check-documentation` | 0 | Links passed; bilingual variables: 372 pairs; paths: 2187, old paths: 0; Change Records passed | Local task evidence |
| `rtk bypass git diff --check` | 0 | Whitespace check passed | Local task evidence |
| Offline native `apply_safe_updates` using immutable baseline and original plan; network sockets blocked inside applying interpreter | 0 | 43 updates applied across 24 allowed paths; native generated views reconciled | Run 41453911536 replay |
| Original two failing methods before test-file overlay | 1 | Both stale-pin failures reproduced | Run 41453911536 replay |
| Four-module selection after overlay and cache correction, command above | 0 | 67 methods passed in 44.098s; three new methods explain increase from 64 | Run 41453911536 replay |

Replay used the original artifact SHA-256
`1660dda9911d20b979ace329a49608cb91b3473250438d6f0088b03ef97b665d`
and internal plan SHA-256
`e82bd610298c4cb22d7c1d2f18930cfbdd6f705cc5f9bf96e40788705da74448`.
Only the three test/helper files were overlaid onto the applied candidate;
per-file before/source/after hashes were retained. The plan and applied updates
were not edited.

An initial full replay retained 66 passes and one unchanged FIFO startup failure.
Inherited `PYTHONDONTWRITEBYTECODE` had prevented cache warming (zero actual
bytecode files). Removing that variable for the warm process created 209
external bytecode files. The unchanged FIFO test then passed in 1.145s, followed
by the passing full 67-method rerun above. Initial failures remain in evidence;
no timeout, assertion, or FIFO source was changed to obtain the pass.

## Security impact

This repairs maintenance test freshness while preserving supply-chain controls;
it is not a claim of a newly remediated exploitable vulnerability. Negative
coverage rejects mutable tags, short/nonhex/uppercase/mismatched commits,
foreign/nested repositories, trailing newlines, missing values, and invalid
canonical identities. The simultaneous foreign-source/workflow case prevents
matching untrusted identities from validating each other. Existing artifact and
workflow security bindings are unchanged.

## Documentation and runtime evidence

Only this paired reader-facing record is added. Native generated output was
updated through its generator. Evidence is static contract and offline local
subprocess evidence. No live publishing workflow was dispatched; no connector
host, I12, runtime matrix, or hosted publishing success is claimed.

## Checks not run

Hosted PR checks and applicable quality gates, including Sonar, require
separate delivery evidence; no remote result is claimed here. Connector
builds/runtime matrices are outside this test-only correction; live publishing was deliberately not exercised.

## Limitations and residual risk

Offline replay does not prove upstream availability, hosted runner timing, or
publication success. The FIFO result depended on the evidenced local cache
correction; retained initial failures make that environmental condition visible.
Canonical pin review remains an independent prerequisite. No validation or
security control was relaxed.

## Final diff and review status

An independent read-only review of the three code files found no findings.
The generated archive diff was reviewed against its source inventory; only the
expected hashes, new IDs, and count changed. Final code/archive/documentation
review and `git diff --check` passed.
No secrets, raw sensitive logs, credentials, or complete environment values
are included. No new commit, push, PR, merge, or hosted success is asserted
by this record.
