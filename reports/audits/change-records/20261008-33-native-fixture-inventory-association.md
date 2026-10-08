# Change record

**Language:** English | [Deutsch](20261008-33-native-fixture-inventory-association.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-33-native-fixture-inventory-association |
| UTC date | 2026-10-08 |
| Framework base revision | 74e7e52831ba01f64c4831a777b307c9dde582be |
| Issue or pull request | Parent NGINX all-required integration; no separate Framework issue |

## Motivation and problem statement

The actual deferred NGINX `phase4_body_reject` YAML deliberately declares no
HTTP expectation. Inventory generation incorrectly routed it through generic
YAML expectation construction and failed with `missing declared expectation`.

## Affected components and security boundaries

Only the Framework inventory generator, its package resource, Contract API
tests and paired documentation change. Inventory provenance must not become
native execution proof. Parent, MRTS, canonical validators and catalog/schema
product contracts are not modified.

## Acceptance criteria

The actual fixture associates with its existing No-CRS ID and explicit closed
native descriptor. Foreign identities, paths, fixture classes, rules, statuses
and descriptors fail. Generic expectation, phase, capabilities and
applicability remain unchanged; no new public expectation is introduced.

## Alternatives considered

A default HTTP expectation or restoring obsolete Rule-based rejection would
invent semantics. A new native expectation API would require a separate product
contract. The selected fix adds provenance only.

## Implementation decision

Only the exact known source path can use `native_operation_fixture`. Typed
fixture metadata, actual Engine directives and the current catalog descriptor
must match the closed schema and supported Reject contract. The existing
generic API contract is retained; selected native descriptors and strict
original receipts remain the sole actual Canonical native proof.

## Changed files and tests

The generator and generated package JSON, paired Contract API documentation,
new `test_native_fixture_source_association.py`, existing public API inventory
count/source assertions, and this paired record change.
Six focused tests cover positive provenance, API shape, deterministic payload-
free serialization and identity/path/descriptor/fixture contradictions.
Regeneration also incorporates previously checked-in Config3 contracts and
eleven event/P4/MIME YAML inventory records; these are source refreshes, not new
runtime claims or manually altered expectations.
All eleven added identities have an existing matching checked-in YAML path.
Exact inventory counts are 350 total and 200 YAML-membership records: eleven
new identities and the existing Reject ID's additional YAML membership.

## Commands and results

Commands use RTK, the Framework-owned Python, explicit `FRAMEWORK_ROOT`, and
external cache/temp roots. Logs are under
`/var/tmp/codex/ModSecurity-conector/analysis/nginx-all-required-20261008T124555Z/`.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `python -m unittest -v tests.contract_api.test_native_fixture_source_association` before fix | 1 | RED: six failing/erroring controls | `stream-c-source-association-red.log` |
| Same command after fix | 0 | Six tests pass, including rule/directive mismatches | `stream-c-source-association-green3.log` |
| `python ci/tools/generate-framework-contract-catalog.py` | 0 | Resource regenerated from actual sources | `stream-c-source-association-generate.log` |
| `make test-contract-api PYTHON=/var/tmp/codex/ModSecurity-test-Framework/venv/bin/python FRAMEWORK_ROOT=/var/tmp/codex/ModSecurity-conector/worktrees/all-required-framework-source-association-20261008 BUILD_ROOT=/var/tmp/codex/ModSecurity-conector/analysis/nginx-all-required-20261008T124555Z/build TMP_ROOT=/var/tmp/codex/ModSecurity-conector/analysis/nginx-all-required-20261008T124555Z` | 2 | 29 pass; stale inventory count 339 versus actual 350 fails | `stream-c-source-association-api.log` |
| Same Make command after exact count/source assertion refresh | 0 | All 30 Contract API tests and generator check pass | `stream-c-source-association-api-green.log` |
| `python -m unittest -v tests.no_crs.test_nginx_native_selection tests.no_crs.test_nginx_native_canonical_binding` | 0 | 23 tests pass | `stream-c-source-association-focus.log` |
| `python -m py_compile ci/tools/generate-framework-contract-catalog.py tests/contract_api/test_native_fixture_source_association.py` | 0 | Syntax passes | Task command output |
| `python ci/checks/documentation/check-doc-links.py` | 0 | Links pass | `stream-c-source-association-links.log` |
| `python ci/checks/documentation/check-variable-documentation.py` | 0 | Variable/bilingual checks pass | `stream-c-source-association-vars.log` |
| `python ci/checks/documentation/check-change-records.py` | 0 | Paired record structure passes | `stream-c-source-association-records.log` |
| `python ci/tools/generate-framework-contract-catalog.py --check` | 0 | Generated resource matches current sources | Task command output |
| `rtk proxy git diff --check` | 0 | Whitespace passes | Task command output |

## Security impact

No security remediation or connector behavior change is claimed. The guard
rejects source substitution and contradictory contract metadata without copying
rules, payloads or native expectations into the public inventory.

## Documentation and runtime evidence

English/German Contract API documentation explains the provenance boundary.
No native runtime, Engine ingestion or lifecycle evidence was collected.

## Checks not run

Native build/E2E and broad repository checks are outside the bounded task.
Ruff could not run: it is absent from the Framework environment and PATH; no
package installation was authorized. Python syntax checks ran instead.

## Limitations and residual risk

The narrow association intentionally fails if the supported source contract
changes. The generic API expectation is not the NGINX-native variant contract.
Native runtime gaps remain unverified.

## Final diff and review status

Focused final diff, whitespace and payload review retain generic contracts.
All 30 Contract API tests, 23 Selection/Canonical focus tests and documentation
checks pass. No secrets or raw sensitive evidence are recorded. The normal
atomic Framework commit is supplied at handoff.
