# Change record

**Language:** English | [Deutsch](20261008-01-nginx-target-config-rejections.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-01-nginx-target-config-rejections |
| UTC date | 2026-10-08 |
| Framework base revision | `dc41bd22c335156cae02d9049098b92af65b7c57` |
| Issue or pull request | Authorized follow-up branch `fix/nginx-seven-contracts-20261008`; Parent PR #396 is an external integration dependency and remains Draft. |

## Motivation and problem statement

Four selected configuration records lacked explicit executable NGINX contracts:
`missing_rules_file`, `invalid_rule_syntax`, `unknown_config_key`, and
`unsafe_event_path`. A generic nonzero exit cannot identify their required
rejection boundaries.

## Affected components and security boundaries

Framework catalog, configtest receipt schema, normalization, artifact retention,
and No-CRS regression tests. Parent execution is an external dependency. MRTS,
Common product semantics, protocol selection, and protected infrastructure are
unchanged.

## Acceptance criteria

Each case has an explicit closed configtest descriptor, exit `1`, its exact
diagnostic, and bound raw configuration/binary/module/output artifacts. Wrong
case, operation, run, module, reason, missing artifact, or modified bytes must
not pass. Existing boolean/size configtests remain compatible; selection and
required status are not reduced.

## Alternatives considered

Neither arbitrary nonzero success nor changing rejection expectations to match
acceptance is permitted. Reuse the existing strict receipt architecture instead
of introducing an independent evidence system.

## Implementation decision

The missing file is a controlled absent leaf; invalid syntax uses fixed inline
`SecRule REQUEST_URI`; the unknown key is the NGINX directive
`modsecurity_unknown_config_key`, not an Engine-language substitute. The unsafe
event target is an owned directory leaf rejected by the NGINX
`modsecurity_phase4_log` private-file boundary. Closed fixture metadata and
retained fixture-state checks distinguish the two path cases. Configtest-only
proof does not claim a worker, request, reload, or native event.

## Changed files and tests

`ci/checks/catalog/no_crs_baseline.py`,
`tests/cases/no-crs-baseline/catalog.json`,
`tests/schemas/no-crs-baseline/configtest-receipt.schema.json`, and
`tests/no_crs/test_configtest_target_rejections.py`; this EN/DE pair.

## Commands and results

Focused red and green execution logs are retained under
`nginx-seven-contracts-20261008T080604Z` (external analysis run ID).
`framework-config-red.log` records the pre-fix regression failure;
`framework-config-green.log` records 52 passing tests. These are unit/contract
results, not runtime coverage. Exact invocation reconciliation and final native
suite results are still part of integration review.

## Security impact

Path, ownership, symlink, artifact integrity, operation identity, and provenance
checks remain required. No validation, required record, or status precedence is
weakened. No security-remediation or protected-runtime certification is claimed.

## Documentation and runtime evidence

This complete EN/DE record documents the Framework contract only. Discovery
probes using a historical module helped identify diagnostic wording but are not
new-head coverage. Fresh artifact-bound host execution and Canonical evaluation
remain necessary external integration evidence.

## Checks not run

The complete Framework lint/API/Canonical suite and integrated standard host run
are not yet concluded for this working revision. CI/Sonar for a future published
commit are not available at record preparation time.

## Limitations and residual risk

`PRODUCT DECISION REQUIRED — invalid_status`: an Engine status action and a
Common/adapter default-status field have different owners and rejection
semantics. No range or directive is invented; this record remains required and
unfulfilled. `valid_rules_file` needs separate successful load plus genuine rule
execution proof. The other historical coverage gaps are not repaired here.

## Final diff and review status

This is an implementation-stage handoff record. Final source diff, full suite,
runtime evidence, delivery SHA, and independent review must be reconciled before
completion. No secrets, raw bodies, or unreviewed logs are embedded.
