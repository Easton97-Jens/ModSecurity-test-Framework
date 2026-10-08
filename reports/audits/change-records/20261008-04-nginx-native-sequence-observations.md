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

Complete integrated Framework suite, final standard lifecycle and revision-bound remote CI/Sonar remain coordinator validation.

## Limitations and residual risk

Native transport metadata still needs central producer/wiring integration. Finish-failure timing and engine-timeout semantics remain explicit decisions, not invented policies. Existing Required records remain visible and unchanged.

## Final diff and review status

Exclusive files were reviewed for payload safety and negative controls. Separate Framework commit/handoff is pending; no merge, force push or Parent Gitlink change is performed here.
