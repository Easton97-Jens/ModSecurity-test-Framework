# Change record

**Language:** English | [Deutsch](20261008-03-nginx-valid-rules-compound-startup.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-03-nginx-valid-rules-compound-startup |
| UTC date | 2026-10-08 |
| Framework base revision | `dc41bd22c335156cae02d9049098b92af65b7c57` |
| Issue or pull request | Authorized branch `fix/nginx-seven-contracts-20261008` and new Draft follow-up PR; external Parent PR #396 remains Draft. |

## Motivation and problem statement

`valid_rules_file` requires successful configuration loading and genuine rule
execution. A successful `nginx -t`, a supplied rule ID, or an unrelated HTTP
response alone cannot establish this compound contract.

## Affected components and security boundaries

Framework catalog, configtest receipt schema, artifact normalization, public
contract API and its generated catalog, and No-CRS regression tests. Parent owns
actual host operations. Common serialization and MRTS remain unchanged.

## Acceptance criteria

The closed startup descriptor requires configuration exit `0` and the exact
accepted template and baseline rules. Retained native rule `1100001` evidence
must match run, transaction, method `GET`, URI `/no-crs/deny`, phase and status.
Separate actual client evidence requires HTTP `403` and client exit `0`.
Root-Master/nobody-Worker identities and verified process/listener cleanup are
mandatory. Missing or rehashed mismatched evidence must not pass.

## Alternatives considered

Configtest-only success, literal fixture rule IDs, and an event relabeled as an
observed host action are insufficient. Extend the existing bound receipt
contract rather than introduce synthetic events or change product semantics.

## Implementation decision

Retain raw binary, module, configuration, rules, configtest output, native
events, request result, roles and cleanup artifacts with strict digests and
identity checks. The native Common event is `engine_decision` with
`MSCONN_EVENT_ENGINE_DECISION`, requested deny and HTTP `403`; `actual_action`
is empty, `visible_http_status` is `0`, and `transport_result` is
`not_observable`. This event alone does not prove a host action. The separately
bound real HTTP request supplies that observation without rewriting the event.
Explicit `access_log off` keeps copied configurations from using a historical
compile-prefix output path. Public API startup support remains bounded to the
declared NGINX contract and combines configuration, HTTP, rule and lifecycle
assertions. Existing rejection configtests remain configtest-only.

## Changed files and tests

`ci/checks/catalog/no_crs_baseline.py`,
`tests/schemas/no-crs-baseline/configtest-receipt.schema.json`,
`tests/cases/no-crs-baseline/catalog.json`,
`tests/cases/no-crs-baseline/valid_rules_file.yaml`,
`tests/no_crs/test_valid_rules_file_receipt.py`,
`ci/tools/generate-framework-contract-catalog.py`,
`modsecurity_test_framework/contracts.py`,
`modsecurity_test_framework/data/framework-contract-catalog.json`, and
`tests/contract_api/test_public_contract_api.py`; this EN/DE pair. The catalog
resource is regenerated through its native generator.

## Commands and results

Focused red/green logs are retained under
`nginx-seven-contracts-20261008T080604Z` (external analysis run ID).
`framework-valid-actual-event-kind-red.log` records the pre-correction failure;
`framework-valid-actual-event-kind-green.log` records 11 passing receipt tests.
The native `make test-contract-api` run recorded 24 passing tests and exit `0`
in `framework-startup-api-green.log`; catalog freshness also exited `0`.
These checks prove Framework contracts, not current-head runtime coverage.
`make check-documentation` exited `0` after documentation updates: link,
bilingual-variable, repository-path and Change Record checks passed.
`git diff --check` exited `0`. All command payloads used the required RTK proxy.

## Security impact

No path, symlink, ownership, artifact, provenance, status or Required check is
weakened. Additional schema conditions and negative bindings preserve strict
validation. No protected-runtime certification or product remediation is claimed.

## Documentation and runtime evidence

This EN/DE pair records Framework behavior. The external diagnostic
`diagnostic-valid-r2` observed a genuine Root-Master/nobody-Worker HTTP `403`,
native rule event and cleanup, using a dirty working revision and historical
binary/module artifacts. It is diagnostic evidence only, not fresh committed
Exact-Head coverage. A standard integrated `full_lifecycle` run remains pending.

## Checks not run

Complete Framework lint/Canonical regressions and fresh committed standard
lifecycle results are not yet reconciled. Revision-bound remote CI/Sonar and
protected workflow evidence are not available at record preparation time.

## Limitations and residual risk

`PRODUCT DECISION REQUIRED — invalid_status` remains selected and required;
no status range or directive is invented. Other required coverage gaps remain.
Matching hashes or an aggregate exit `0` cannot establish overall Exact-Head PASS.

## Final diff and review status

The documentation pair was reviewed for equivalent facts and technical literals;
native documentation and whitespace checks passed. Implementation-stage handoff
awaiting final source diff, complete validation, fresh
runtime and delivery reconciliation. No secrets, raw bodies or unreviewed logs
are embedded. No merge or history rewrite is authorized.
