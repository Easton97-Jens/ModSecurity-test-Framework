# Change record

**Language:** English | [Deutsch](20261102-01-parent-python-bootstrap-contracts.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261102-01-parent-python-bootstrap-contracts |
| UTC date | 2026-11-02 |
| Framework base revision | `91145b7ba721bdec4e89af754cf40bf496fd2a08` |
| Issue or pull request | Requested repair of Parent runs `41412784227` and `41412832386`; PR not created at record time |

## Motivation and problem statement

Current Parent Python updater checks reject Framework composite bootstrap order,
stale job inventories, and unsupported protected/historical workflow composition.
The context binder previously executed Python before setup and interpreter
verification. This Framework change repairs reusable contracts; Parent-native
workflow changes remain a separate delivery.

## Affected components and security boundaries

The 18 `.github/actions/connector-ci/` implementations, Framework-owned Python
workflow checker, and `modsecurity_test_framework/workflow_sources.py` preserve
the boundary between the Parent Gitlink, checked-out Framework code, immutable
remote actions, and authenticated protected execution. MRTS is unchanged.

## Acceptance criteria

Shell-only source proof precedes the checked-out interpreter verifier; setup and
verification precede context binding. Normal inventory matches 47 current jobs.
Protected jobs retain their exact authenticated verifier. Historical composition
accepts only its reviewed immutable shape. Existing bypass negatives pass.

## Alternatives considered

A blanket first-use/context exemption would accept unverified Python. Replacing
the protected wrapper with a direct verifier would lose authentication. Treating
the historical reusable caller as a local ordinary job would invent execution.
Each alternative was rejected.

## Implementation decision

Use shell Gitlink/HEAD equality, exact setup/verifier/context ordering, separate
closed inventory classes, and a closed historical workflow-call mapping. Its six
required string inputs, same-name forwarding, deny-default permissions,
`contents: read`, single immutable nested call at
`8ae707d72f1a8acb25d239e55e28a73cbc7522b1`, and absence of concurrency overrides
are verified. Only two protected broker jobs admit the exact authenticated
`ci/run-trusted-framework.py --tool python-interpreter` verifier.

## Changed files and tests

18 composite action definitions; the connector Python workflow checker and its
`test_python_version_contract.py`; `workflow_sources.py` and
`tests/connector_adapter/test_workflow_sources.py`; paired connector integration
documentation and this record. Tests execute source-gate positive/negative cases,
reject unproven context exemptions, mutate historical grants/pins/inputs/jobs,
and reject direct verifier substitution in protected jobs.

## Commands and results

`FRAMEWORK_PYTHON` denotes the explicit Framework-owned Python 3.14 test venv.
The local execution plan retains complete context/environment command arguments.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk bypass env ON_DEMAND_TESTS=1 PYTHONPATH=.:connector_suite "$FRAMEWORK_PYTHON" -m unittest tests.connector_adapter.test_workflow_sources modsecurity_connector_tests.test_python_version_contract -q` with explicit source/revision context | 0 | 62 tests passed; Parent `430d3194fa04ca4aafcdaef6aeb256d21dc18f0c` callers projected onto feature Framework source | Local scoped verification |
| `rtk bypass git diff --check` | 0 | No whitespace errors in implementation diff | Local scoped verification |

Additional regression work updates `connector_suite/modsecurity_connector_tests/test_framework_workflow_pin_projection.py` and its independent `framework_sha_fixture.py` helper. Against the separate Parent patch, 10 projection tests and 39 updater tests passed: the six early selected-action gate pins remain closed, move with the existing pin synchronizer, reject stale/missing/extra/symbolic identities, and stop a changed Gitlink plus changed checkout before verifier execution. Independent review also passed 24 shell admission cases. Native documentation checks and Ruff lint passed. Whole-file formatter drift in three legacy Python files is present in the base too; those unrelated regions were preserved. The previously formatted `workflow_sources.py` remains formatted.

Hosted scaffold validation identified the immutable connector-source contract as an additional affected owner. Renewed exactly the 18 reviewed composite SHA entries in `ci/tooling/connector-actions.lock.json` and its aggregate in `ci/checks/security/connector_action_pins.py` from a deterministic external script after authenticating the prior contract. This maintained snapshot has no checked-in generator. Action records, source registry, authority and six unaffected sources are unchanged. Native `rtk make check-canonical-common-pins PYTHON="$FRAMEWORK_PYTHON"` and six `tests.ci_security.test_connector_action_pins` tests passed, including tampered early identity/checkout/selector checks across all 18 composites.

## Security impact

This repairs bootstrap/source-contract correctness while retaining immutable
references, permissions, authenticated protected entrypoints, and failure gates.
Original ordering failures and alternate unproven-context/direct-protected
verifier bypasses are covered by negative tests. It is not a connector security
assessment.

## Documentation and runtime evidence

`docs/connector-integration.md` and its German companion describe the new
bootstrap and bounded composition contract. Tests provide static source and
local shell evidence. No hosted CI, connector-host runtime, merge, or Parent pin
update is established by this record.

## Checks not run

Hosted CI and Sonar have not run for this uncommitted patch. Connector runtime
matrices are outside this workflow-contract change. Full default inventory was
not expanded or weakened.

## Limitations and residual risk

Parent-native ordering repairs and consumption of this Framework revision are
separate prerequisites for combined CI compatibility. The old Parent Framework
pin cannot supply these new contracts. Historical nested workflow contents stay
immutable; composing their interface does not execute them.

## Final diff and review status

Implementation diff and whitespace reviewed; no secrets or raw logs recorded.
Independent review found no open blocker; hosted checks remain pending before final delivery.
