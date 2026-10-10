# Change record

**Language:** English | [Deutsch](20261009-43-nginx-repeatable-set-cookie-wire.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261009-43-nginx-repeatable-set-cookie-wire |
| UTC date | 2026-10-09 |
| Framework base revision | 567d36acc010a68882462b5ffe23b9e94bff5d73 |
| Issue or pull request | Draft Framework PR #137 follow-up |

## Motivation and problem statement

Four genuine NGINX MIME invocations retained two separate `Set-Cookie` wire
fields from the existing shared response-header fixture. Their Content-Type
and HTTP/1.1 framing fields were unique and correct, but the Framework MIME
parser rejected every repeated field name before it could validate the MIME
contract.

## Affected components and security boundaries

The reusable NGINX MIME wire parser and its MIME/event-boundary consumers.
Raw bytes, digests, source authority, receipts, roles, cleanup, Content-Type
and framing validation remain unchanged.

## Acceptance criteria

Accept repeated `Set-Cookie` fields without combining them into one field.
Continue rejecting duplicate Content-Type, Content-Length and
Transfer-Encoding fields, mixed Content-Length/Transfer-Encoding framing,
invalid syntax, incomplete responses and body-length mismatches.

## Alternatives considered

Removing the repeated cookies from the Parent fixture was rejected because
they are an intentional shared multi-value response-header contract. Allowing
every duplicate header was rejected because it would make singleton MIME and
framing evidence ambiguous.

## Implementation decision

Declare only case-insensitive `Set-Cookie` repeatable in `wire_fields`. The
parser still validates each physical field line and never comma-joins cookie
values. The authenticated raw artifact remains the exact source of all field
instances; the returned lookup is used only for strict MIME/framing fields.

## Changed files and tests

`tests/runners/nginx_mime_operations.py`,
`tests/no_crs/test_nginx_mime_operations.py`,
`tests/no_crs/test_nginx_event_boundaries.py`, and this paired record. The
positive controls use the two values observed at runtime. Negative controls
retain duplicate singleton and ambiguous framing rejection.

## Commands and results

The focused command was:

```text
rtk proxy env PYTHONDONTWRITEBYTECODE=1 "${FRAMEWORK_PYTHON}" -B -m unittest tests.no_crs.test_nginx_mime_operations tests.no_crs.test_nginx_event_boundaries -v
```

Before implementation it exited 1 with 12 passes and 2 failures at `invalid
or duplicate wire header`; after implementation it exited 0 with all 14 tests
passing. Adding `tests.no_crs.test_nginx_http11_framing` and
`tests.no_crs.test_nginx_native_operation_bundle` to the same command exited 0
with 43 tests passing.

The read-only diagnostic command below replayed the current helper against the
four unchanged original receipts/raw artifacts from safe run ID
`nginx_all_required_20261009_r11`; it exited 0 with 4 accepted and 0 rejected:

```text
rtk proxy env PYTHONDONTWRITEBYTECODE=1 "${FRAMEWORK_PYTHON}" -B <external-task-analysis-root>/replay-r11-mime-current-helper.py
```

The payload-free diagnostic log SHA-256 is
`567fa0ffeed676b16a545086185d5d0569cec44163a5560785ff32f3009e236e`.
This was not a new sealed or Canonical replay because the original source map
correctly remains bound to the original Framework revision.

`FRAMEWORK_PYTHON` denotes the reviewed Framework-owned interpreter; its exact
host path and the diagnostic script remain in the external task handoff rather
than in versioned repository documentation.

`rtk make test-no-crs-contract` with the Framework interpreter and all
Framework/build/tmp/output roots explicitly bound to this worktree and
`<external-task-root>/r11-mime-fix` exited 0: 407 tests
passed in 161.838 seconds. `rtk make check-documentation` with the same roots
exited 0.

After assembling all three independent R11 Framework follow-ups, the same
`test-no-crs-contract` target exited 0 with 410 tests passing in 165.181
seconds and no failure, error or skip marker. The log SHA-256 is
`076340b756dc78ea0c2b4a88c6174a1227ef2f1b0f409555f0b1a14980787739`.

The complete Framework lint, with `PYTHON`, `FRAMEWORK_ROOT`,
`CONNECTOR_ROOT`, `OUTPUT_ROOT`, `CI_ROOT` and all task-data roots explicitly
bound to the reviewed worktree or external validation root, exited 0 on the
assembled R11 follow-up tree. Its log SHA-256 is
`08672fd886ab8aebb02af89b77114a08c344f3e54a9c4b935bf55ba4f755ff17`;
no failure, error or skip marker was present. Two earlier invocations exited 2
for a read-only sandbox output root and an unsupported external output root,
respectively; those are retained as invocation diagnostics, not Source-test
failures.

## Security impact

No validator or authority guard is disabled. The exception is limited to the
HTTP field whose separate wire instances are required for cookie semantics;
security-sensitive MIME and framing fields remain unique and fail closed.

## Documentation and runtime evidence

This English/German Change Record pair documents the Framework contract. The
original R11 Parent lifecycle remains terminal FAIL evidence and is not
relabeled as post-fix runtime proof.

## Checks not run

Remote CI/Sonar, Parent gitlink integration, a fresh build and the Required97
lifecycle have not yet run.

## Limitations and residual risk

Synthetic tests and read-only replay of retained bytes cannot replace a fresh
source-bound Root/nobody runtime. R11 also exposed separate Phase-4 Reject and
engine-timeout contract failures that this change deliberately does not fix.

## Final diff and review status

Focused RED/GREEN, the initial 407-test and combined 410-test suites,
documentation checks, independent code/security review and broad lint are
complete with no findings. No secrets,
credentials, request bodies or sensitive raw payloads were added to this
record. Commit/push/readback and Parent integration remain pending. No merge,
history rewrite or MRTS change.
