# Change record

**Language:** English | [Deutsch](20261010-02-nginx-mime-aggregate-schema.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261010-02-nginx-mime-aggregate-schema |
| UTC date | 2026-10-10 |
| Framework base revision | e8a8f98a4c24958616b15b98aadedcc73345a786 |
| PR | Framework137; Parent integration396 separately |

## Motivation and problem statement

Two MIME-Allow Case-PASS records caused four nested schema enum errors.

## Affected components and security boundaries

Framework coordinator, schema and tests; source/receipt/byte authority preserved. MRTS and product unchanged.

## Acceptance criteria

allow/allow only for the exact two case/result pairs without Rule, late intervention or abort.

## Alternatives considered

Defaults, invented evidence and weakened validators rejected.

## Implementation decision

Aggregate projector unchanged. Narrow anyOf schema for existing MIME nonintervention. Null/completed transport remains preserved.

## Changed files and tests

tests/schemas/no-crs-baseline/result.schema.json, tests/no_crs/test_nginx_native_canonical_binding.py and this pair.

## Commands and results

RTK + Framework Python3.14.7, working-source overlay on the original 4c6c21e8622840b4c218d8ea5520dd0b10b3fac9: unittest C/D14 tests exit0; unittest discover -s tests/no_crs -p test*.py:413 tests exit0. D RED two subtests/four enum errors; GREEN eight negative controls per MIME case. C offline pipeline rejects event deletion and six canonical tamper controls. Full producer replay schema-valid, overall status still FAIL. Clean-commit and fresh-runtime checks are separate integration evidence.

## Security impact

No H2/H3 relabelling, Required reduction or provenance bypass.

## Documentation and runtime evidence

HISTORICAL INPUT / CURRENT VALIDATOR REPLAY / NOT A NEW RUNTIME RUN. Originals unchanged; external local logs c-historical-replay-v3.log, d-historical-replay.log and no-crs-suite.log.

## Checks not run

Real bounded H1/MIME focus, integrated clean SHAs, full lint and fresh CI/Sonar separately. Full97/Protected not authorized.

## Limitations and residual risk

Local Python3.14.7 is not exact Framework CI3.14.8. Historical replay authority explicitly uses unchanged same-SHA checkouts.

## Final diff and review status

Assigned files only; git diff --check exit0. Coordinator reviews, commits causes separately and updates Parent gitlink.
