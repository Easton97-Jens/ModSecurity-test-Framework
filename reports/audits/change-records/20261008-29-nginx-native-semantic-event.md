# Change record

**Language:** English | [Deutsch](20261008-29-nginx-native-semantic-event.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-29-nginx-native-semantic-event |
| UTC date | 2026-10-08 |
| Framework base revision | `fa0efc012a6a3b2e7b3f4d660956eab63a94bc67` |
| Issue or pull request | Coordinator-approved bounded semantic-event correction |

## Motivation and problem statement

The first retained Phase4 event can be an append allow, while a later actual intervention is log-only. Selecting the first row as the semantic summary loses the genuine cause. No native execution is claimed by this change.

## Affected components and security boundaries

Only the owned fact contract, focused tests and this paired record. Strict reader authentication, central acceptance, catalog, schemas, Parent, MRTS and Gitlinks are unchanged.

## Acceptance criteria

Return an unchanged actual event and its original JSONL origin, selected by the closed operation/phase/Rule contract. Reject missing facts, foreign identity and contradictory same-kind meanings. Never substitute append allow or LOGGING cleanup for an earlier decision.

## Alternatives considered

Rewriting event fields or copying expectations into native evidence would fabricate observations. Keeping a first-row summary preserves the incorrect append interpretation. Neither is used.

## Implementation decision

Return semantic_native_event, semantic_native_event_origin and semantic_native_event_origins. Pre-connector rejection returns None/None/empty origins. Technical cases select the actual error; event-boundary cases select the genuine truncated Rule match; Rule-based Phase4 selects intervention, ruleless completion selects completion, and Reject selects body_limit. Request denial selects engine_decision. Phase1 allow requires genuine request_headers_complete. Phase5 selects the actual technical error or LOGGING cleanup. Source-first selection among equivalent rows is deterministic; all eligible origins are exposed. Every returned field is copied unchanged from retained native evidence.

## Changed files and tests

tests/runners/nginx_native_operation_contract.py and tests/no_crs/test_nginx_native_operation_contract.py plus this pair. Controlled tests include the twelve strict-reader Phase4/MIME variants, truncated over-variant, pre-connector absence, pointer/finish errors, cleanup and negative TX/Rule/phase/meaning controls.

## Commands and results

Test-first semantic-selection checks exited1 with missing semantic_native_event before implementation. After implementation, `rtk proxy env TMPDIR=<external-task-runs> PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 python -m unittest tests.no_crs.test_nginx_native_operation_contract tests.no_crs.test_nginx_native_operation_projection tests.no_crs.test_nginx_native_operation_bundle -q` passed50 tests, exit0, using the Framework-owned interpreter. `rtk proxy make check-documentation PYTHON=<framework-python>` and `rtk proxy git diff --check` both exited0.

## Security impact

Evidence selection remains strict and payload-free. No product remediation or acceptance bypass; original bytes, event dictionaries and receipt seals are not rewritten.

## Documentation and runtime evidence

Paired EN/DE record. Pure controlled Source-shaped fixtures, not runtime evidence or canonical PASS.

## Checks not run

Native build/runtime/full E2E and remote scans were not authorized. No tools installed.

## Limitations and residual risk

Root must consume and seal this summary with explicit caller authority and offline revalidation. Missing genuine producer fields still reject; no all42 positive-runtime claim is made.

## Final diff and review status

Four scoped files; no central edits. Separate normal commit after focused validation and documentation review.
