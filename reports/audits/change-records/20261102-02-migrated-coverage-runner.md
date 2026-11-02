# Change record

**Language:** English | [Deutsch](20261102-02-migrated-coverage-runner.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261102-02-migrated-coverage-runner |
| UTC date | 2026-11-02 |
| Framework base revision | `91145b7ba721bdec4e89af754cf40bf496fd2a08`; measured with uncommitted task changes |
| Issue or pull request | Task reconciliation; no PR created at record authoring |

## Motivation and problem statement

After test ownership migration, the coverage runner still invoked removed Parent
paths and expected same-package Go tests in product trees. Evidence-security
fixtures patched pre-migration module aliases and replaced the Python `-P`
argument instead of the script path. These failures obstructed measurement and
validation without demonstrating a product defect.

## Affected components and security boundaries

Framework owns the runner, test overlays, case admission and safety fixtures.
Parent owns product sources and its coverage report. Framework execution data
must not be relabelled as Parent Python coverage. Exact test-source admission,
private external artifacts and non-following evidence reads remain required.

## Acceptance criteria

Resolve migrated helpers through the source map; admit existing Go test sources
through the existing reviewed overlay; preserve exact selectors and all default
build packages in the coverage denominator; report only real Parent Python
files; select the explicit `offline-unit` assessment without implicitly adding
other specialist/native catalogs. Preserve safe Python invocation and evidence
input defenses. Keep the default selection of 100 cases unchanged.

## Alternatives considered

Copying tests back into Parent would violate ownership. Broad discovery would
change the selected assessment. Counting Framework files as Parent sources
would misstate coverage. The chosen changes preserve existing admissions and
separate measured scope from unexecuted or failed stages.

## Implementation decision

Resolve the scope checker, active-test launcher and Common helper checker through
`source_path`. Generate the existing `sonar-coverage` on-demand Go overlay and
supply the same exact overlay to test listing and measurement; retain missing
selector rejection, `-mod=readonly`, `-count=1` and `-coverpkg=./...`.

Collect branch-capable Python data with the child execution witness, omit the
Framework tree from Parent XML and validate reported files against the physical
Parent tree. Ignore unrelated Framework files when finding the admitted witness.
Admit `offline-unit` explicitly and keep timing-sensitive executions in their
separate unmeasured partition. Patch canonical evidence module names and preserve
`-P` when replacing the emitted postprocess script path.

## Changed files and tests

- `connector_suite/modsecurity_connector_ci/checks/analysis/run-sonar-coverage.py`
- `connector_suite/modsecurity_connector_tests/test_sonar_coverage.py`
- `connector_suite/modsecurity_connector_tests/test_evidence_input_security.py`
- `connector_suite/modsecurity_connector_tests/test_nginx_root_broker.py` and its inert historical caller fixture.
- Reviewed source-map/inventory metadata for the fixture and explicit on-demand incompatibility regression.
- This English/German Change Record pair.

Regression coverage checks Parent/Framework attribution, exact Go overlay use in
both commands, offline admission, unrelated witness sources and existing evidence
path safety. Inventory bindings and generated archive synchronization are tracked
with the combined task; no specialist selection is added to the default 100.
The separate `.codex/inheritance-manifest.toml` metadata review updates three
inherited digests after content review; it does not change these runtime contracts.

## Commands and results

Task evidence root, relative to the approved external storage root: `runs/master-reconcile-20261102/coverage`.
`run_measure.py` records the exact interpreter, source roots, environment additions
and command construction; it invokes the following runner command for each
language with the task coverage interpreter. Commands use RTK at their shell
entry point. `publish_focused.py` retains the selected raw branch data and
publishes it through the existing report function.

| Command or recorded procedure | Exit code | Concise result | Evidence |
| --- | --- | --- | --- |
| `run-sonar-coverage.py --language go --on-demand --output-root <coverage>/after --temp-root "$TMP_ROOT"` through `run_measure.py go` | 0 | Four selected Go groups measured with real admitted tests | `go.log`, `after/go/manifest.json` |
| Same launcher and options with `--language native` | 0 | Native helper measurement and real branch observations | `native.log`, `after/native/manifest.json` |
| Same launcher and options with `--language python` | 1 | Named stage: 116 tests passed; full offline stage failed after 56 passed executions at execution 57; timing partition not reached | `python.log`, `summary.json` |
| `publish_focused.py`, calling `publish_python_report` on retained named-stage data | 0 | Selected Parent Python XML published; excludes failed offline assessment | `focused/python/selected-scope.json`, `focused/python/python.xml` |

The focused coverage/evidence-security regression run passed 42 tests. The coordinator observed `Ran 42 tests in 9.933s` / `OK`, exit 0
(tool session 20942), with this command (configured roots and interpreter shown as portable variables;
expanded invocation retained in the task handoff):

```sh
rtk bypass env ON_DEMAND_TESTS=1 CONNECTOR_ROOT="$CONNECTOR_ROOT" CONNECTOR_REVISION=430d3194fa04ca4aafcdaef6aeb256d21dc18f0c TEST_ROOT="$TEST_ROOT" FRAMEWORK_ROOT="$TEST_ROOT" PYTHONPATH="$TEST_ROOT:$TEST_ROOT/connector_suite" TMPDIR="$TMP_ROOT" "$PYTHON" -m unittest -v modsecurity_connector_tests.test_sonar_coverage modsecurity_connector_tests.test_evidence_input_security
```

The 116 named measured tests are a separate observed stage, not evidence of a
complete Python runner pass.

Observed measurements: Go statement coverage Envoy 1104/3971, Traefik native
586/959, composite 383/563 and observer 300/752. Native union: 2869/4290 lines
and 1903/3977 branches. Selected Parent Python: 59/6552 lines and 16/2240
branches across 33 files. Native union uses source/line/gcov-branch identity;
it excludes generated harnesses and Framework test helpers. Go reports statements,
not branch coverage. `summary.json` and `provenance.json` bind the measurements
to Framework source hashes and external Parent base
`430d3194fa04ca4aafcdaef6aeb256d21dc18f0c`; these are not final merged-pair measurements.

The focused historical caller repair uses exact bytes from Parent commit
`f5523da040bd6325b369269ada074be6ba069c4f`, path
`.github/workflows/run-protected-nginx-root-broker.yml`: fixture SHA-256
`d34b01b67d9f88552353186a3c78605b6d99d827541479207efe174bc994b341`.
It retains the selected immutable broker `8ae707d72f1a8acb25d239e55e28a73cbc7522b1`
and Framework `99a7985c1be92a2297b1b59208f64df6768f2cbf` tuple. The original
permission test failed three subcases before repair and passes with unchanged
permission assertions against that valid inline input. All 22 caller-boundary
tests pass, including explicit rejection of the current delegated caller.
The complete broker module reports 45/46 passing: the unchanged current broker
workflow assertion still fails because its delegated wrapper has no `runs-on`.
Evidence: `broker-fixture-validation.json` and `broker-final.log` under the task
coverage root. This test-only repair does not restore protected runtime admission.
The new incompatibility case is explicit on-demand; the default 100 cases remain unchanged.

Hosted SonarCloud feedback on PR159 at624de56a reported python:S3776 for
`child_file_has_witness` (cognitive complexity16, maximum15). Extract only the
existing physical/logical inventory filename matching into `is_inventory_source`;
regular-file, branch and witness guards and evaluation order are preserved.
The same42 coverage/evidence regressions passed before and after this follow-up.
Evidence: task `framework/sonar-S3776-before.log` and
`framework/sonar-S3776-after.log`. Hosted analysis of the new commit is a
separate check; these local tests do not claim closure of the hosted finding.

Parent440 CI also confirmed that Framework156 updated `ci/lib/common.sh` from
Python3.14.8 to3.14.10 without updating its reviewed source binding. Exactly one
of528 bindings drifts at91145. The existing reviewed-binding generator in this
PR includes that correction; source admission remains enforced. Parent must
consume the actual Framework merge commit only after authorized integration.

## Security impact

No product vulnerability remediation is claimed. Existing evidence-input safety
checks and Python safe-path invocation remain; canonical fixture names restore
checks against the actual implementation. No security, workflow or admission
check is disabled to obtain a pass.

## Documentation and runtime evidence

This paired record documents Framework behavior and selected measurement evidence.
No fresh connector-host lifecycle qualification or H2/H3 campaign was performed.
The existing Sonar coverage exception remains; local measurement is not analyzer
import or a Sonar Quality Gate result. No new percentage target is introduced.

## Checks not run

The full Python assessment did not finish. Execution
`offline.nginx-broker-parser.caller-top-level-permissions-remain-exactly-deny-default`
was rejected for an unexpected fixture key set before the expected deny-default
permissions diagnostic. The focused historical fixture repair described above
fixes that test input while preserving the permission invariant; the subsequent
timing partition is unmeasured. The original full-run failure is retained;
the broad assessment has not been rerun at current head. Separately, the
coordinator's source analysis found incompatibility between the current thin
Parent wrapper and the immutable historical broker at actual runtime admission.
That runtime blocker is distinct from fixture repair and remains open. Do not turn selected Python
publication into a full-runner PASS. Final integrated-pair and remote CI evidence
remain the delivery coordinator's separate checks.

Lokale Sonar-Secrets-Prüfung aufgrund ausdrücklicher Benutzeranweisung nicht ausgeführt.

## Limitations and residual risk

Measurement covers the selected product paths and tests only. Framework source
was dirty at measurement; exact source hashes are retained. Additional source or
inventory changes require rechecking applicability. No Sonar exception was removed,
no required CI checks were weakened and no connector promotion follows.

## Final diff and review status

Runner and fixture diffs, source provenance and this language pair were reviewed.
No credential values, raw sensitive bodies or environment dumps are recorded.
No commit, push or merge is performed by this documentation task. Native
Framework documentation and whitespace checks are recorded in the task handoff.
