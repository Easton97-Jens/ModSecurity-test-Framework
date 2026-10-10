# Change record

**Language:** English | [Deutsch](20261010-01-nginx-native-h1-binding.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261010-01-nginx-native-h1-binding |
| UTC date | 2026-10-10 |
| Framework base revision | 4c6c21e8622840b4c218d8ea5520dd0b10b3fac9 |
| PR | Framework137; Parent integration396 separately |

## Motivation and problem statement

Native Strict-H1 observations genuinely existed; canonical protocol fields and matching event were missing.

## Affected components and security boundaries

Framework coordinator, schema and tests; source/receipt/byte authority preserved. MRTS and product unchanged.

## Acceptance criteria

H1 requires actual version11 and matching URI/TX/case/run/phase/Rule; mismatches stay FAIL.

## Alternatives considered

Defaults, invented evidence and weakened validators rejected.

## Implementation decision

Project protocol from reopened reader observations. Original events remain unchanged. Revalidate retained bytes, append and seal a case-scoped canonical event. Final and offline checks require its matching event.

## Changed files and tests

ci/checks/catalog/no_crs_baseline.py, tests/no_crs/test_nginx_native_h1_projection.py and this pair.

## Commands and results

RTK + Framework Python3.14.7: working overlay on base4c6c21e8: unittest C/D14 tests exit0; unittest discover -s tests/no_crs -p test*.py:413 tests exit0. Committed revision0c7f224731cda059decee026c7bd32e58bf9aa21: native make test-no-crs-contract,413 tests, no SKIPs, exit0. D RED two subtests/four enum errors; GREEN eight negative controls per MIME case. C offline pipeline rejects event deletion and six canonical tamper controls. Full producer replay schema-valid, overall status still FAIL.

## Security impact

No H2/H3 relabelling, Required reduction or provenance bypass.

## Documentation and runtime evidence

HISTORICAL INPUT / CURRENT VALIDATOR REPLAY / NOT A NEW RUNTIME RUN. Originals unchanged; successful external local logs framework-cd/c-historical-replay-v3.log and framework-cd/d-historical-replay.log; committed-suite log framework-quality/no-crs-suite.log, in external task nginx-full97-followup-20261010T084822Z. Earlier failed replay attempts remain retained separately. These local files are not published downloads.

## Checks not run

Real bounded H1/MIME focus, integrated clean SHAs and fresh CI/Sonar separately. Full native lint on0c7f2247 ended exit2 because the invocation supplied an external report-reading OUTPUT_ROOT; preceding604 test executions succeeded. The existing read-only report-path contract remains unchanged; a corrected native lint is still required. Full97/Protected not authorized.

## Limitations and residual risk

Local Python3.14.7 is not exact Framework CI3.14.8. Historical replay authority explicitly uses unchanged same-SHA checkouts.

## Final diff and review status

Assigned files only; git diff --check exit0. Coordinator reviews, commits causes separately and updates Parent gitlink.
