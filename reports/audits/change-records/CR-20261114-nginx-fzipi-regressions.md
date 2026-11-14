# Change Record: CR-20261114-nginx-fzipi-regressions

**Language:** English | [Deutsch](CR-20261114-nginx-fzipi-regressions.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | CR-20261114-nginx-fzipi-regressions |
| Date (UTC) | 2026-11-14 |
| Base revision | `31531f74cfe26c2a40d4bb5f6eaae4c0920127e1` |

Evidence alias `<evidence-root>` denotes the private external root for run `20261114-fzipi-review`; its exact host binding is retained in the private task receipts.

## Motivation and problem statement

Add targeted regressions for the externally owned native NGINX/Common corrections requested from fzipi upstream PR377 review.

## Affected components and security boundaries

Existing Framework regression locations, affected Common helper/adoption-checker contracts and this paired record only. Parent product files and MRTS are separate; Parent gitlink unchanged.

## Acceptance criteria

Compile and execute actual product seams for audit/routing/configuration, optional Safe events vs Strict/real failures, observation widths, discarded controls, parser provenance and append-state native limits. Retain old-code negative controls where practical.

## Alternatives considered

Source-string assertions and a new Parent tests directory cannot prove the requested behavior. Reuse actual C functions with controlled collaborators, real Engine serialization and a bounded native host runner.

## Implementation decision

Keep tests on demand under existing selectors; do not enlarge the100-case automatic inventory or historical I12 campaign. Parent source is selected explicitly with CONNECTOR_ROOT/CONNECTOR_REVISION and test infrastructure with TEST_ROOT.

## Changed files and tests

`test_nginx_native_logging.py`, `test_nginx_error_page_intervention.py`, `test_nginx_late_error_results.py`, `test_nginx_context_accounting.py`, `test_nginx_phase4_observation.py` fixture, `test_nginx_response_body_limit.py` fixture; new `test_nginx_replaced_body.py`, `test_rule_id_metadata.py`; affected `checks/common/check-common-helpers.sh` fixture and `checks/connectors/nginx/check-nginx-common-adoption.py` with its guard-removal mutation tests. New `run_nginx_fzipi_review.py` and static fixture `replaced-followup` exercise real audit/routing/configuration and writer completion. The writer double now rejects empty non-special links and no-work NULL calls, preserving pending-output drain cases.

## Commands and results

Final explicit unittest selection passed75 methods across10 affected modules, including28 parser scenarios with genuine system libModSecurity3.0.14 and36 actual collector append-mode/commit/prose limit variants. Original-code controls compiled and produced intended runtime failures. Common helper smoke passed. Common adoption checker passed;11 mutation methods rejected28 negative variants. Four existing request-file/memory test methods plus two existing-helper scenarios preserved ProcessPartial and independent file errors. Exact commands/receipts in `<evidence-root>`.

## Security impact

Negative controls protect against error-page bypass, payload rule-ID spoofing, Safe sink failure aborts and genuine error downgrades. No guards, active inventory or mandatory CI were weakened.

## Documentation and runtime evidence

This EN/DE pair records only Framework validation. Parent native build is an external compilation result, not Framework host/runtime promotion. Externally owned Parent H1 source `b478aeb02c26bf6e44627f43b49678f1abc3081b` passed9 host/configuration scenarios with the changed runner/fixture hashes admitted. Receipt `<evidence-root>/native-host-v2/private/result.json`, SHA256 `0364231b54ca098f69666f52777bb0162460b1b1f5ae39001789f0c92388738b`; root-master/nobody-worker preflights and cleanup passed. This is scoped H1 evidence only.

## Checks not run

No broad matrix/I12/other-connector campaign or MRTS execution. No current-head CI/Sonar pass is asserted; consult the PR checks.

## Limitations and residual risk

New parser rejects ambiguous raw metadata as unknown. Test doubles do not prove native HTTP delivery; the separately observed9-scenario H1 run supplies that scoped layer.32-bit and sink-fault tests remain compiled models, not live32-bit/fault-host campaigns. Framework delivery does not update Parent pin.

## Final diff and review status

Task branch `test/nginx-fzipi-review`; actual commit/push/PR facts are recorded in the delivery readback. No merge is authorized. Final combined diff/whitespace and Framework Change Record checks passed before delivery. Remote CI/Sonar and PR state require current-head readback; no merge is authorized.

CI follow-up: the first lint run rejected literal local host paths in this record. Portable evidence aliases replace those paths; no checker or validation rule was changed.
