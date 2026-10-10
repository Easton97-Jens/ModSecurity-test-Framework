# NGINX configuration migration contracts

**Language:** English | [Deutsch](20261008-13-nginx-config-migration-contracts.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20261008-13-nginx-config-migration-contracts` |
| UTC date | 2026-10-08 |
| Framework base revision | `11e1d20990d4ecbbcf18641782b04f0bb6369c69` |
| Issue or pull request | Framework PR #137 follow-up; not published |

## Motivation and problem statement

Three selected required configuration cases lacked explicit host operations.

## Affected components and security boundaries

The new `ci/lib/nginx_migration_config_contracts.py` declares contracts, not
observations. Strict artifact and actual-operation evidence remain required.

## Acceptance criteria

Exactly three closed contracts, precise failure reasons, independent copies,
no new numeric status range or claim of Engine MIME-file parsing.

## Alternatives considered

No new Common status directive or restoration of the removed connector API.
The user chose existing lexical parser and removed-API rejection contracts.

## Implementation decision

`invalid_status` uses malformed Engine action `status:not-a-number`.
`phase4_invalid_scope_file` and `phase4_wildcard_scope_rejected` reject the
removed `modsecurity_phase4_content_types_file` API, not their file contents.
The coordinator must integrate strict catalog, receipt and Parent dispatch
binding. Declarations alone are not canonical evidence.

## Changed files and tests

The helper, `tests/no_crs/test_nginx_migration_config_contracts.py`, and this
English/German pair. Four tests protect exact operations and mutation isolation.

## Commands and results

RTK-wrapped Framework Python unittest discovery: missing-helper RED exit 1;
implemented helper GREEN exit 0, four tests. Native documentation check first
rejected record structure; corrected records are checked before handoff.

## Security impact

No validator, Required selection, product policy or MRTS changes. Arbitrary
nonzero exits do not satisfy the contract.

## Documentation and runtime evidence

Genuine diagnostic NGINX-1.31.6 configtests observed exit 1 for lexical status
syntax and two removed-API rejections with exact diagnostics. Actual configs,
fixture bytes, captures and artifact digests remain under external task
`nginx-all-required-20261008T124555Z`. They use unchanged committed artifacts,
not a new integrated Exact-Head or canonical PASS. Both records are equivalent.

## Checks not run

Integrated runtime, full Framework lint and remote CI/Sonar await integration.

## Limitations and residual risk

Central catalog, validator, schema and Parent wiring are coordinator-owned.
No source policy is inferred from the test expectations.

## Final diff and review status

Explicit slice staging only; no push, merge or Parent gitlink update by this
workstream. Integrated final acceptance remains pending.
