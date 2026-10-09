# Change record

**Language:** English | [Deutsch](20261009-44-nginx-phase4-reject-action-projection.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261009-44-nginx-phase4-reject-action-projection |
| UTC date | 2026-10-09 |
| Framework base revision | 567d36acc010a68882462b5ffe23b9e94bff5d73 |
| Issue or pull request | Draft Framework PR #137 follow-up |

## Motivation and problem statement

The `phase4_body_reject` validator expected serialized `action=deny` even
after response commitment. Common's event protocol projects the actual host
action into `action`: a committed rejection preserves `requested_action=deny`
but serializes both `action` and `actual_action` as `abort_connection`.
Before commitment, both action fields remain `deny`.

## Affected components and security boundaries

This change concerns the Framework Phase-4 Reject validator and its synthetic
contract tests. Parent/Common event serialization, runtime behavior, receipt
authority, source provenance, wire validation and cleanup remain unchanged.

## Acceptance criteria

Require the exact Common action projection for committed and precommit
rejections. Continue rejecting mismatched requested action, actual action and
transport outcome. A committed rejection must still prove visible response
headers and incomplete framing; HTTP 0 with curl exit 52 remains rejected.

## Alternatives considered

Changing Common serialization would alter the producer's established actual
host-action contract. Accepting both actions after commitment would conceal
an inconsistent event. Accepting empty wire evidence would conflate internal
NGINX commitment with a response visible to the client.

## Implementation decision

Validate `action=abort_connection` when `response_committed` is true and
`action=deny` otherwise, matching the existing `actual_action` requirement.
Keep `requested_action=deny` in both cases. No HTTP, framing, identity or
cleanup expectation is relaxed.

## Changed files and tests

`tests/runners/nginx_phase4_operations.py`,
`tests/runners/test_nginx_phase4_operations.py`, and this English/German
record pair. The fixture now represents the Common projection. Negative
controls reject action/transport mismatches and the real empty-reply shape
observed in R11.

## Commands and results

Commands ran from the Framework worktree with the Framework-owned interpreter.
The commands below replace only its machine-local executable path with
`"${FRAMEWORK_PYTHON}"` for portability; arguments, wrapper and results are
unchanged. The exact local invocations are retained in task evidence.
The focused RED/GREEN command was:

```text
rtk proxy env PYTHONDONTWRITEBYTECODE=1 "${FRAMEWORK_PYTHON}" -m unittest discover -s tests/runners -p test_nginx_phase4_operations.py -v
```

RED exited 1: 10 tests ran with 2 failing subtests. GREEN exited 0: all 10
tests passed. The neighboring Phase-4 command exited 0 with 19 tests passed:

```text
rtk proxy env PYTHONDONTWRITEBYTECODE=1 "${FRAMEWORK_PYTHON}" -m unittest discover -s tests/runners -p 'test_nginx_phase4*.py' -v
```

The implementation diff check exited 0:

```text
rtk git diff --check -- tests/runners/nginx_phase4_operations.py tests/runners/test_nginx_phase4_operations.py
```

Documentation checks passed with exit 0:

```text
rtk make check-doc-links check-bilingual-docs check-change-records PYTHON="${FRAMEWORK_PYTHON}"
rtk make check-documentation PYTHON="${FRAMEWORK_PYTHON}" FRAMEWORK_ROOT="${FRAMEWORK_ROOT}" CONNECTOR_ROOT="${FRAMEWORK_ROOT}" OUTPUT_ROOT="${FRAMEWORK_ROOT}" BUILD_ROOT="${VALIDATION_ROOT}/build" TMP_ROOT="${VALIDATION_ROOT}/tmp" LOG_ROOT="${VALIDATION_ROOT}/logs" MRTS_BUILD_ROOT="${VALIDATION_ROOT}/mrts" SOURCE_ROOT="${VALIDATION_ROOT}/source" EVIDENCE_ROOT="${VALIDATION_ROOT}/evidence" CI_ROOT="${FRAMEWORK_ROOT}/ci"
```

`FRAMEWORK_ROOT` denotes the active Framework worktree; `VALIDATION_ROOT`
denotes its external task validation root. An earlier documentation attempt
exited 2 because absolute developer paths appeared in the records; replacing
only those local paths with the declared portable notation resolved the
documentation failure without changing the checker.

Full Framework lint on the composed current R11 follow-up worktree exited 0:

```text
rtk make lint PYTHON="${FRAMEWORK_PYTHON}" FRAMEWORK_ROOT="${FRAMEWORK_ROOT}" CONNECTOR_ROOT="${FRAMEWORK_ROOT}" OUTPUT_ROOT="${FRAMEWORK_ROOT}" BUILD_ROOT="${VALIDATION_ROOT}/build" TMP_ROOT="${VALIDATION_ROOT}/tmp" LOG_ROOT="${VALIDATION_ROOT}/logs" MRTS_BUILD_ROOT="${VALIDATION_ROOT}/mrts" SOURCE_ROOT="${VALIDATION_ROOT}/source" EVIDENCE_ROOT="${VALIDATION_ROOT}/evidence" CI_ROOT="${FRAMEWORK_ROOT}/ci"
```

Its log SHA-256 is
`08672fd886ab8aebb02af89b77114a08c344f3e54a9c4b935bf55ba4f755ff17`.
No FAIL, ERROR or SKIP markers were present. Its final documentation check
validated 300 bilingual pairs and 915 files. This is validation of the
composed Framework worktree, not runtime evidence for this case.

The combined current Framework contract suite also exited 0:

```text
rtk make test-no-crs-contract PYTHON="${FRAMEWORK_PYTHON}" FRAMEWORK_ROOT="${FRAMEWORK_ROOT}" CONNECTOR_ROOT="${FRAMEWORK_ROOT}" OUTPUT_ROOT="${FRAMEWORK_ROOT}" BUILD_ROOT="${VALIDATION_ROOT}/build" TMP_ROOT="${VALIDATION_ROOT}/tmp" LOG_ROOT="${VALIDATION_ROOT}/logs" MRTS_BUILD_ROOT="${VALIDATION_ROOT}/mrts" SOURCE_ROOT="${VALIDATION_ROOT}/source" EVIDENCE_ROOT="${VALIDATION_ROOT}/evidence" CI_ROOT="${FRAMEWORK_ROOT}/ci"
```

It ran 410 tests in 165.181 seconds without FAIL, ERROR or SKIP markers.
Its log SHA-256 is
`076340b756dc78ea0c2b4a88c6174a1227ef2f1b0f409555f0b1a14980787739`.
The separate 19-test runner invocation above directly covers this Phase-4
helper; the 410-test suite provides the broader Framework contract gate.

## Security impact

The validator now follows the existing producer contract while requiring
exact fields in both commitment states. Wrong actions, missing wire headers,
HTTP 0/curl 52 and incomplete authority evidence remain failures. No
validator or guardrail is disabled.

## Documentation and runtime evidence

This pair documents a Framework validation correction. Run ID
`nginx_all_required_20261009_r11` remains terminal FAIL evidence. Its
Phase-4 Reject invocation returned HTTP 0/curl 52: the Parent's separate
wire-flush defect remains open. The synthetic GREEN results do not establish
post-fix runtime or Canonical PASS.

## Checks not run

Remote CI/Sonar, Parent gitlink integration and a fresh Required97 lifecycle
remain pending for this change. No new source-bound
runtime invocation was performed as part of this documentation task.

## Limitations and residual risk

Internal NGINX response commitment does not prove that headers reached the
client. The Parent must resolve the wire-flush defect and produce a genuine
response before this Required case can satisfy its current contract.

## Final diff and review status

Focused RED/GREEN, neighboring tests and implementation diff checks are
complete. The combined 410-test contract suite, full Framework lint and
documentation checks passed; the final
Framework integration review is complete. No secrets,
credentials, request/response bodies or sensitive raw logs were recorded.
Commit, push and Parent integration remain pending delivery steps; MRTS is
unchanged.
