# Change record

**Language:** English | [Deutsch](20261008-04-nginx-native-sequence-observations.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-04-nginx-native-sequence-observations |
| UTC date | 2026-10-08 |
| Framework base revision | `11e1d20990d4ecbbcf18641782b04f0bb6369c69` |
| Issue or pull request | Framework Draft PR #137; integrated execution remains coordinator-owned. |

## Motivation and problem statement

Selected lifecycle and transport cases need real sequences and matching native observations. A reconnecting client, HTTP 200 alone, or knowledge of a requested fault cannot prove them.

## Affected components and security boundaries

The new `tests/runners/nginx_lifecycle_sequence.py` helper and dedicated No-CRS tests validate observed operations. They do not change catalog selection, canonical aggregation, product code, or MRTS.

## Acceptance criteria

Exact case/run, H1, request counts/statuses, native request/transaction/connection identities, increasing keep-alive counters, Root/nobody roles and verified cleanup are required. Late intervention additionally needs a real header/marker barrier and matching native Rule 1100301. Write resume requires observed native short-write/EAGAIN, later positive writes, complete client framing and single-pass native body accounting.

## Alternatives considered

Implicit reconnection, driver-created events and relabeling upstream delay as engine timeout are rejected. The helper cannot make an unsupported fault case pass.

## Implementation decision

Use a closed operations table and strict independent observation validation. Host operation validity is distinct from Canonical PASS: existing transport event-field requirements and retained artifact validation remain mandatory for the central normalizer.

## Changed files and tests

`tests/runners/nginx_lifecycle_sequence.py`, `tests/no_crs/test_nginx_lifecycle_sequence.py`, and this EN/DE record. Controls cover reconnection, duplicate transactions, wrong deny status, foreign identity, missing cleanup, wrong fault reason, missing native late event, complete response substituted for abort and restarted worker.

## Commands and results

RTK-wrapped Framework Python ran the dedicated tests: initial absent-operation regressions failed; 14 checks subsequently passed. Actual diagnostic operations are retained under external run ID `nginx-all-required-20261008T124555Z`: 13 sequence/fault/late operations, one short-write and one actual EAGAIN-resume probe passed host validation. A wrongly scoped begin fault remained rejected. Native short-write fixture compilation used C17 warnings-as-errors.

## Security impact

No Required, path, ownership, freshness, identity, event or artifact check is relaxed. Test fault triggers are bounded to the owned worker/request/socket; no global resource manipulation or synthetic event is introduced.

## Documentation and runtime evidence

This EN/DE pair records Framework-only validation behavior. Parent owns genuine host operations. Development focus uses verified preexisting artifacts and separately hashed development helpers; it is not final committed Exact-Head coverage.

## Checks not run

The selected Framework Python environment contains no Ruff module; focused Ruff checks could not run and no package/environment change was made. The native `make check-documentation` passed. Common phase completion is additionally checked from the actual cleanup ledger's `timed_phase_completed=0`, derived from the contract's completed-phase mask rather than the reason text alone.

Complete integrated Framework suite, final standard lifecycle and revision-bound remote CI/Sonar remain coordinator validation.

## Limitations and residual risk

Native transport metadata still needs central producer/wiring integration. Approved finish behavior preserves the already-visible response; the engine-timeout contract measures a default-disabled synchronous soft budget after API return. Fresh integrated host evidence remains required. Existing Required records remain visible and unchanged.

## Final diff and review status

Two framing cases require actual raw downstream HTTP/1.1 captures through EOF. The new `tests/runners/nginx_http11_framing.py` independently parses bounded status/header/chunk bytes, rejects ambiguous CL/TE or duplicate framing headers, incomplete bodies/chunks/terminal delimiters and trailing bytes, and decodes the exact 22-byte `transport fixture body`. The sequence helper rejects client-only framing metadata, origin-only substitution, wrong decoded bodies and foreign native identities. Chunked upstream provenance remains separate from downstream proof.

Both cases require an actual native `phase4_completion` / `MSCONN_PHASE4_COMPLETE`, exact response-body phase/TX/URI, EOS, actual supplied/retained22 bytes and bounded append count, plus a later real `transaction_cleanup` / `MSCONN_TRANSACTION_CLEANUP` with exact `common_return=0;common_complete=1;native_cleanup_completed=1;error_class=none` and `cleanup_reason=normal`. No Rule-ID or native API return is invented. Root/nobody and process/listener cleanup checks remain active. Eight dedicated parser/sequence tests passed after absent-parser regressions failed; the affected Framework focus passes 34 tests. Dedicated tests are `tests/no_crs/test_nginx_http11_framing.py` and `tests/no_crs/test_nginx_http11_sequence.py`. Native module execution, standard registration and canonical artifact/protocol provenance validation remain coordinator-owned.

Approved timeout follow-up: `observation_errors` supports precommit504 and committed200 with actual aborted framing. `native_budget_errors` requires exactly one successful delegated phase-1/phase-4 API return, exact worker/transaction, bounded monotonic measurements and strict over-budget elapsed time. Native events must pair flat `engine_timeout` / `MSCONN_EVENT_ENGINE_TIMEOUT` / canonical reason `engine_timeout` with flat `engine_call_budget_exceeded` / `MSCONN_ENGINE_CALL_BUDGET` / exact payload-free `budget_ms=10;elapsed_ns=<actual>;native_return=1;common_completed=0`. Known Common event canonicalization remains intact. Both events require no Rule-ID, actual visibility and phase/stage identity. Phase4 EOS remains true because the actual terminal Engine API returned, while Common completion was rejected. The separate delegated-cleanup ledger must show return0, complete1 and actual timeout error class4/name `engine_timeout` preserved.

RTK-wrapped Framework Python passed 26 focused sequence/transport/timeout tests, including missing/duplicate/foreign event, wrong Rule-ID, at-budget timing, failed native return, invalid clock, wrong cleanup identity/class and complete-wire/false-EOS negatives. Source and fixture tests do not prove native runtime coverage. Fresh module execution, disabled/under-budget/wrong-transaction native controls, canonical integration and current-head CI/Sonar remain coordinator-owned. Dedicated timeout tests are `tests/no_crs/test_nginx_engine_budget_sequence.py`.

`transport_sequential_requests` now requires one native connection and counters 1/2/3, matching the catalog's existing one-connection contract. Reconnected-request and reset-counter regressions failed before correction and both pass afterward. The two dedicated transport tests are in `tests/no_crs/test_nginx_sequence_transport.py`; native event generation remains Parent-owned.

Approved post-response finish follow-up:

Finish preserves actual HTTP 200 and the exact 23-byte fixture body digest. It requires native logging rejection (-1), delegated cleanup (0), completed cleanup and preservation of the native logging error, bound to the observed worker and transaction. Missing or mismatched observations remain rejected. Seventeen focused tests pass. Diagnostic `stream-d-finish-r3` records positive exit 0 and wrong-transaction control exit 1 with verified cleanup. Earlier internal-redirect fixture attempts remain retained failures; neither evidence nor validator was relaxed. Integrated Canonical evidence remains coordinator-owned.

Exclusive files were reviewed for payload safety and negative controls. Separate Framework commit/handoff is pending; no merge, force push or Parent Gitlink change is performed here.
