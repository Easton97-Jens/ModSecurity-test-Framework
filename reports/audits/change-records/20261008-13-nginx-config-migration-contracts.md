# NGINX configuration migration contracts

**Language:** English | [Deutsch](20261008-13-nginx-config-migration-contracts.de.md)

## Identity

Change ID: `20261008-13-nginx-config-migration-contracts`. UTC date: 2026-10-08.
Framework base: `11e1d20990d4ecbbcf18641782b04f0bb6369c69`.
Follow-up context: Framework PR #137; this worktree is not published.

## Motivation and implementation

Three required configuration cases previously lacked explicit host operations.
The user selected the existing Engine lexical parser contract for
`invalid_status`: malformed `status:not-a-number`, not a newly invented numeric
range or Common default-status directive. Two scope-file cases explicitly test
rejection of the removed `modsecurity_phase4_content_types_file` adapter API.
They do not claim that the Engine parsed or rejected their MIME-file contents.

`ci/lib/nginx_migration_config_contracts.py` declares exactly these three closed
operations and returns independent copies. A coordinator must integrate them
into the catalog, strict receipt validation and actual Parent dispatcher;
declarations alone are not canonical runtime evidence.

## Tests and runtime evidence

RTK-wrapped Framework Python unittest discovery for
`test_nginx_migration_config_contracts.py` initially exited 1 because the helper
was absent; after implementation, four tests exited 0. They protect lexical
status identity, precise removed-directive reason, the closed case set and
mutation independence.

Separate genuine diagnostic NGINX-1.31.6 configtests observed exit 1 with
`Expecting an action, got:  status:not-a-number` and two exit-1 removed-directive
diagnostics. Raw configs, fixture bytes, captures and artifact digests are
retained under the external `nginx-all-required-20261008T124555Z` task run.
These diagnostic operations use the unchanged committed native artifacts and
are not a new integrated Exact-Head or canonical PASS claim.

## Security, compatibility and limitations

No validator, selection, Required record, product API, numeric status policy,
MRTS source or protected infrastructure changed. Arbitrary nonzero exits do not
fulfil these contracts. Parent dispatch, receipts and schema integration remain
coordinator-owned. Full Framework lint, integrated runtime and remote CI/Sonar
must be run after integration. English/German records describe the same scope.

## Review and delivery

Only the new helper, its focused tests and this documentation pair belong to
this configuration-contract slice. No push, gitlink update or merge is performed
by this workstream. Final integrated acceptance remains pending.
