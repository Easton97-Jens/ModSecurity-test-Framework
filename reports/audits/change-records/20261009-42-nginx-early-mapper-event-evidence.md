# Change record

**Language:** English | [Deutsch](20261009-42-nginx-early-mapper-event-evidence.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261009-42-nginx-early-mapper-event-evidence |
| UTC date | 2026-10-09 |
| Framework base revision | b283851c1fd70a031832d2e95e10dfcc4bc4f068 |
| Issue or pull request | Draft Framework PR #137 follow-up |

## Motivation and problem statement

Real NGINX Common mapper failures occur before canonical request metadata is
recorded. Their source `protocol_error` therefore has empty `method` and `uri`,
while separately sealed access, fault, configuration and cleanup artifacts
bind the actual request and transaction. The bundle reader incorrectly
required the later access URI in the early event and could not retain genuine
R7 evidence.

## Affected components and security boundaries

The pure Common input-fault contract and strict NGINX native bundle reader.
Source authority, bytes, receipts, containment, revisions, status, worker
identity and cleanup boundaries remain unchanged.

## Acceptance criteria

Accept only an exact early `protocol_error` with empty-string method/URI and
the same transaction. Reject absent, nonempty, foreign, mistyped, duplicate or
misclassified events. Continue requiring exact access/fault/config/cleanup
correlation and `driver_exit_code == 0` before any Canonical projection.

## Alternatives considered

Populating the event from raw NGINX request data was rejected because the
Parent product explicitly limits this error path to already-recorded canonical
metadata. Omitting method/URI checks was rejected because it would broaden the
accepted shape.

## Implementation decision

Declare the two Common input-fault records' pre-mapping fields as exactly empty
in the pure helper and strict reader. Keep request/case identity in the already
authenticated transaction, access row, fixed configuration, own-worker fault
ledger and cleanup event. Never rewrite the retained source event.

## Changed files and tests

`tests/runners/nginx_common_input_faults.py`,
`tests/runners/nginx_native_operation_bundle.py`,
`tests/no_crs/test_nginx_common_input_faults.py`,
`tests/no_crs/test_nginx_native_operation_bundle.py`, and this paired record.
Positive controls cover both Required cases; negatives cover nonempty method
or URI plus existing identity, role, phase, rule, ordering, seal and path
mutations.

## Commands and results

Focused RED: four pure-helper failures because nonempty fields were accepted
(log SHA-256 `984446026f4a7c1afda32d1072cf9683f750de234cd1f2bb70e0311c6a0abf70`),
and one sealed-bundle error at the old URI equality check (log SHA-256
`2e09cc8e7a1c714aa0ae52ca7c7c29b490561404959a7d71be9b25c4af8c71b5`).
Focused GREEN: 30 tests passed (log SHA-256
`df74f19ecb390bc8010ead80d08e78c175943f899efc6123d49d8d9dfab873ed`).
The complete no-CRS contract suite passed 405 tests in 163.603 seconds (log
SHA-256 `a52e74f27d55a938adc4cd89e73964ee4a2021ac1bbf16e07b31b143cd417e8d`).
`make check-documentation` passed. The first broad `make lint` attempt stopped
with exit 2 at the repository-root guard because an ambient `FRAMEWORK_ROOT`
named a different checkout (log SHA-256
`18b7c63ef0d732ecb34719ad419f732b655a35fee2f83908d54e6e3d060ed33c`);
it is not counted as a pass. A fresh run with all repository roots explicitly
bound to this worktree passed with exit 0, including the NGINX archive/digest,
provenance, pin, workflow, catalog, documentation and final whitespace checks
(log SHA-256
`04cc905cee257a016a4c500f30297d15d94afe4e3aba4f0c06d13cad010793d6`).

## Security impact

No validator is disabled. The accepted shape is narrowed to exact empty
strings and remains bound to immutable independent evidence. Security review
found an evidence-contract defect, not a validated vulnerability.

## Documentation and runtime evidence

This English/German Change Record pair documents the Framework contract. R7 is
retained Parent runtime FAIL evidence, not Framework PASS and not relabeled.
No post-fix hosted runtime has run.

## Checks not run

Remote CI/Sonar for the future commit, Parent gitlink integration, fresh build
and the 97-record lifecycle have not yet run. Ruff remains separately
unavailable and was not run.

## Limitations and residual risk

Unit and sealed-fixture success cannot prove NGINX runtime. The Parent selector
must be integrated with this reader, then fresh exact-source artifacts and real
Root/nobody requests must produce final Canonical evidence.

## Final diff and review status

Focused diff and independent code/security review found no actionable issue;
documentation, 405 no-CRS tests and correctly root-bound broad lint are green.
Final commit/push/readback and current-head remote quality status are pending.
No merge, history rewrite or MRTS change.
