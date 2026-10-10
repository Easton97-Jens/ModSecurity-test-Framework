# NGINX observed MIME operation contracts

**Language:** English | [Deutsch](20261008-22-nginx-mime-observed-contracts.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20261008-22-nginx-mime-observed-contracts` |
| UTC date | 2026-10-08 |
| Framework base revision | `e94ed33` |
| Issue or pull request | Framework PR #137 follow-up; local only |

## Motivation and problem statement

HTTP200 and absence of a rule event cannot establish native MIME exclusion or completion. Four existing Required MIME fixtures need observation validation that checks actual wire headers and Engine retention.

## Affected components and security boundaries

Standalone runner helper and tests; coordinator-owned catalog, schema, selection, collectors and runtime producers remain external dependencies. Parent and MRTS source are unchanged by this Framework slice.

## Acceptance criteria

Retained raw hashes, complete client response, exact actual Content-Type or absence, closed backend fixture, real MIME configuration and native append/completion facts must agree. In-scope and charset require actual rule1100301 safe/log-only evidence; out/missing require completion with actual retained0 and no invented rule.

## Alternatives considered

Using only fixture declarations, HTTP status or empty phase4 logs leaves native execution unproved. Resetting the MIME list changes the Engine merge behavior exercised by the existing fixture.

## Implementation decision

`validate_mime_operation(case_id, receipt, raw_artifacts)` checks four closed IDs. Native `phase4_append` and `phase4_completion` JSONL use the same bounded reason shapes as the Phase-4 operations helper. Supplied bytes remain Common's inspected-byte field; actual Engine retained bytes are separate. Append counts are observed and may reflect several native chunks. Out/missing append-return1/retained0 behavior follows actual Engine MIME checks before append writes and rule evaluation.

## Changed files and tests

`tests/runners/nginx_mime_operations.py`, `tests/no_crs/test_nginx_mime_operations.py` and this paired Change Record.

## Commands and results

RTK-wrapped Framework-owned Python focused MIME tests passed7, combined pointer/MIME/fixture tests passed13, exit0. Negative controls cover missing append/completion, wrong native return/retention/TX/rule/EOS, boolean bytes, wrong wire type/body/framing, raw hash tamper, fixture mismatch and duplicate native keys; readiness observations stay separate. Native `make test-no-crs-contract` passed218 tests before the last two small unit additions; latest focused13 passed after them. Corrected `make check-documentation` passed, exit0; it had first rejected a local developer path in the preceding input-fault record. Framework Ruff could not run because its owned environment lacks the module; no packages were installed.

## Security impact

No Required shrinking, synthesized events, validator weakening or MRTS changes. Hash verification here binds supplied bytes to the receipt; the enclosing canonical reader must authenticate safe retained-file access, coherent source/build identity, real producer, process roles and cleanup.

## Documentation and runtime evidence

Old retained in/charset diagnostic runs have genuine native rule1100301/log-only events. Out/missing have empty native logs and remain insufficient. No fresh module build or runtime was performed for this helper. Missing-type acceptance requires final wire header absence, not merely backend omission.

## Checks not run

Final integrated native runtime, rebuilt-module evidence for all four operations, canonical97-case validation and remote CI/Sonar were not run.

## Limitations and residual risk

The coordinator must wire the receipt/raw API and native completion producer and verify actual artifact identities. The raw configuration contract expects the exact self-contained native driver config with one effective safe/default-type/type declaration; include-based producers must preserve and validate their actual include chain.

## Final diff and review status

Only standalone Framework helper, tests and paired record; local commit, no push, gitlink update or merge. Native runtime completion remains unverified.
