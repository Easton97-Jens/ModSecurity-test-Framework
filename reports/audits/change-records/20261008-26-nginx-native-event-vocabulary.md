# Change record

**Language:** English | [Deutsch](20261008-26-nginx-native-event-vocabulary.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-26-nginx-native-event-vocabulary |
| UTC date | 2026-10-08 |
| Framework base revision | `7ea908b8c0404621f9f979317c6d3f40f6b22178` |

## Motivation and problem statement

Current Common emits closed allow/pass/error actions and concrete transaction error classes that the canonical vocabulary did not represent.

## Affected components and security boundaries

Canonical vocabulary constants, event/case-result schemas and focused tests. No selection, Required scope, runtime identity or source authority change.

## Acceptance criteria

Accept actual documented Common scalar values; continue rejecting arbitrary actions, stages, cleanup causes, nested fields and payloads.

## Alternatives considered

Dropping actual native fields or allowing arbitrary strings would obscure the original observation and weaken validation.

## Implementation decision

Extend only explicit enum members for Common actions, engine-call phases and Common cleanup error classes. Logging cleanup is not request-header allow evidence.

## Changed files and tests

`ci/checks/catalog/no_crs_baseline.py`, `tests/schemas/no-crs-baseline/event.schema.json`, `case-result.schema.json`, `tests/no_crs/test_nginx_native_event_vocabulary.py` and this EN/DE pair.

## Commands and results

Observed three red controls before the change. RTK-wrapped 31 vocabulary, transport-hardening, selected-status and case-binding tests passed; external log `root-native-vocabulary-green.log`. Documentation and whitespace checks are required before commit.

## Security impact

Enum validation stays closed; no arbitrary strings, payload exceptions, synthetic events or cleanup-to-request promotion are introduced.

## Documentation and runtime evidence

This record documents source contract validation only. No fresh NGINX request or canonical PASS is proved.

## Checks not run

Full lint, fresh integrated E2E and protected Exact-Head workflow remain outstanding; current native canonical integration is incomplete.

## Limitations and residual risk

Recognizing an enum does not establish event identity or authenticity. Strict source-bound retained evidence remains mandatory.

## Final diff and review status

Four focused production/test files and paired record; Required selection and status priorities remain unchanged.
