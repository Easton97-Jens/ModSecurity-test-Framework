# Change record

**Language:** English | [Deutsch](20261008-08-nginx-phase4-observed-operations.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-08-nginx-phase4-observed-operations |
| UTC date | 2026-10-08 |
| Framework base revision | `044720551348c77ce52b476bd8a20abf4496bceb` |

## Motivation and problem statement

Eight Required operations need strict interpretation of retained native evidence. Upstream chunks do not prove native append boundaries, and Common bytes supplied to the Engine do not establish Engine retained length. Old late Reject observations with an incomplete HTTP 200 and all 65 bytes forwarded do not prove immediate rejection.

## Affected components and security boundaries

Standalone Framework operation validator and focused tests. The enclosing canonical validator still owns revision, artifact, run, host-role and cleanup binding. Parent owns native producers and raw client capture. MRTS is unchanged.

## Acceptance criteria

All eight identities remain selected. Retained byte hashes, exact source reuse, actual append sizes/returns, completion/EOS, SAFE intervention and immediate Engine Reject must agree. Mismatched raw evidence and incomplete ordinary responses fail.

## Alternatives considered

Inferring Engine length from fixture size or accepting upstream split counts would leave the native boundary unproved. The validator consumes transaction-bound native append and completion JSONL instead.

## Implementation decision

`validate_phase4_operation(record_id, receipt, raw_artifacts)` returns an error list. Empty means only this operation layer passed. It does not generate observations or global PASS. Retained files are `phase4-events.jsonl`, `response.headers`, `response.bin`, client stdout/stderr, rules, configuration and Engine error log. Every required file must match its receipt SHA256.

Native append reasons bind actual API return, length, one-based call index and Engine retained bytes. Native completion reasons bind retained bytes and total calls; their source constructor requires actual process return 1 and completed Common phase 4. Common inspected bytes preserve their existing supplied-byte meaning. Split/EOS require exact native 16/11-byte appends and retained 27 bytes; partial-limit operations require supplied 65 and retained 64.

The obsolete minimal Required identity explicitly executes existing SAFE. Engine Reject uses exact rule-free native 403 and diagnostic, with no EOS completion or marker evaluation. Already-sent HTTP 200 headers are admissible only with actual connection abort, zero forwarded body and the exact curl 18 incomplete-framing diagnostic. The old late rejection forwarding 65 bytes fails. A precommit rejection may produce complete HTTP 403.

## Changed files and tests

New standalone helper and `test_nginx_phase4_operations.py`, plus this paired record. Shared catalog/schema/collector changes remain coordinator-owned. The four MIME operations are outside this closed eight-operation helper.

## Commands and results

RTK-wrapped Framework-owned Python unittest discovery initially failed because the helper was absent. Focused phase4 discovery then passed 17 tests, including nine existing input-contract tests. Negative controls cover identity, raw hash, supplied/retained counts, EOS, native split, SAFE mode, ordinary incomplete response and old late Reject. Final checks are recorded in the task handoff.

## Security impact

No Required selection reduction, fixture-derived events, validator relaxation or payload logging. Strict Reject handling is limited to the observed Engine predicate and exact dedicated operation.

## Documentation and runtime evidence

Unit fixtures are deliberately synthetic test inputs and are never runtime evidence. Previously retained diagnostics were inspected; they lack the new native append/completion records and are not promoted. Root must integrate the producer, rebuild and collect fresh source-bound native runs.

## Checks not run

Full integrated Framework suite, native rebuild/runtime and final CI/Sonar remain coordinator-owned. No serialized runtime slot was assigned to this slice.

## Limitations and residual risk

The enclosing validator must authenticate producer/revision/artifact/role/cleanup bindings. Curl exit 0 establishes successful parsing of retained framing; decoded response bytes are not a packet capture.

## Final diff and review status

Focused independent worktree slice; no publication, Gitlink update or MRTS changes.
