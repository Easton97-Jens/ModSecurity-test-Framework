# Change record: 20260808-03-fix-portable-apache-audit-fixture

**Language:** English | [Deutsch](20260808-03-fix-portable-apache-audit-fixture.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260808-03-fix-portable-apache-audit-fixture` |
| UTC date | 2026-08-08 |
| Framework base revision | `da28e6da58fa8b1135d3631612a78e73ff98584b` |
| Issue or pull request | Related Parent run `31258666144`, no-CRS job `93105942184`; task branch `fix/apache-portable-audit-fixture`, with Framework pull request pending. |

## Motivation and problem statement

The shared portable case `action_status_401_phase1_block` correctly produced
HTTP 401 in the observed Parent no-CRS smoke. Its contract nevertheless
required audit evidence while its own rules omitted the canonical `SecAudit*`
directives needed to create that evidence. The Framework assertion correctly
failed closed on the missing or empty audit file. This is a Framework fixture
defect, not a reason to relax a Parent assertion or synthesize an audit file.

## Affected components and security boundaries

This Framework-only change covers the portable phase-1 fixture, shared runner
validation and materialization, focused regression coverage, the case-catalog
guide, and this paired record. The boundary is the YAML-rules-to-rendered-
private-audit-path-to-host-created-audit-artifact path. The Parent Apache
harness owns actual path preparation, Apache startup, the real HTTP transaction,
and cleanup. Parent source, Parent Gitlinks, MRTS, APR-util provenance, CRS
materialization, and NGINX privilege handling are not changed here.

## Acceptance criteria

1. The case still expects exact HTTP 401 and rule `2320`.
2. Required audit fixtures without `SecAuditEngine`, serial type, canonical
   parts, or either exact placeholder are rejected at validation.
3. Missing, out-of-root, symlinked, or stale audit targets are rejected before
   materialization reaches a host.
4. A missing or empty audit file remains a failure; matching URI, rule, and
   message are all required together with HTTP 401.
5. A different request/run marker, rule, message, transaction identity, or
   HTTP status is not accepted by the focused assertion controls.
6. No synthetic audit file is created by the fixture renderer.

## Alternatives considered

- Removing `expect.audit_log.required` or treating HTTP 401 alone as a PASS
  was rejected because it weakens the observed evidence contract.
- Creating a fixture-side audit file was rejected because it would not prove a
  ModSecurity/Apache transaction.
- Hard-coding a host or repository audit path was rejected because portable
  fixtures must materialize only beneath the private runtime output root.
- A Parent-only workaround was rejected because the incomplete fixture is
  Framework-owned and shared by connector runners.

## Implementation decision

The fixture now uses the existing canonical portable serial configuration:
`SecAuditEngine RelevantOnly`, `SecAuditLogType Serial`, `SecAuditLogParts
ABHZ`, and exact `@@AUDIT_LOG@@` / `@@AUDIT_LOG_DIR@@` placeholders. It also
binds the expected URI, rule ID, and message to the required audit assertion.

For every runtime-materializable case that requires an audit log, the shared
runner requires the same canonical configuration. At materialization, both
host-supplied paths must be absolute, non-symlinked descendants of an existing
current-user-owned output root that is neither group- nor world-writable. The
audit directory and audit-file parent must already exist and meet the same
ownership rule; a pre-existing audit file is rejected before server startup as
stale evidence. The runner replaces placeholders only. It never creates,
copies, or marks an audit file as passing.

## Changed files and tests

- `tests/cases/phases/phase1/action_status_401_phase1_block.yaml` adds only
  canonical serial audit directives and stable URI/message expectations.
- `tests/runners/runner_core.py` validates required-audit fixture directives
  and private, fresh audit-render targets.
- `tests/security_regression/test_portable_audit_fixture_contract.py` covers
  the legitimate control and missing-engine, bad-path, symlink, stale-file,
  group-writable-directory, wrong-request/rule/message/transaction,
  missing-file, and wrong-status negatives.
- `docs/catalog-and-cases.md` and `.de.md` describe the portable boundary.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| `python3 -B -m unittest -v tests.security_regression.test_portable_audit_fixture_contract` | 0 | Nine focused positive and negative fixture/materialization/assertion tests passed using the local diagnostic interpreter. | Task-owned Framework worktree |
| `make lint` with task-owned `BUILD_ROOT`, `TMP_ROOT`, and `PYTHONPYCACHEPREFIX` | 0 | Shell syntax, Python compilation, 137 CI-security tests, provenance contracts, workflow/YAML checks, documentation, record contract, and whitespace checks passed. | Task-owned Framework worktree |

## Security impact

The original broken path is revalidated by the missing-engine and missing/stale
audit-target controls: a fixture cannot claim required audit evidence while
omitting the canonical configuration, and a prior file cannot be reused.
Group-writable audit directories are also rejected. The alternative
path/rule/message/transaction/status controls fail closed. This
change does not claim that a local synthetic test is a host-generated audit
record; exact-head hosted runtime evidence remains required before merge.

## Documentation and runtime evidence

The English/German catalog pair now documents required-audit configuration,
private path materialization, stale-file refusal, and host ownership of real
audit creation and cleanup. The retained Parent run `31258666144` observes the
pre-fix HTTP 401 and missing audit file only; it is not evidence for this
unsubmitted Framework change.

## Checks not run

- Repository-required CPython 3.14.6 checks are pending; the local interpreter
  is Python 3.14.4.
- Apache configuration and a real Apache 401/audit transaction are pending
  exact-head hosted or controlled host validation.
- Sonar, review, branch protection, Framework merge, Parent
  gitlink update, and Parent full-smoke evidence are pending.

## Limitations and residual risk

The local tests prove schema, private path materialization, stale-file refusal,
and assertion behavior. They do not create an Apache audit record and do not
claim host cleanup. A later exact-head Parent hosted smoke must prove that this
specific 401 request produced a fresh nonempty audit log inside its private
root and that the host cleaned up after both success and failure paths.

## Final diff and review status

At authoring this task-owned Framework worktree has an unstaged focused diff;
`git diff --check` passed and no secret-bearing material was added. It has not
been committed, pushed, or submitted. No Framework pull request number,
branch-protection result, approval, Sonar result, merge, Parent gitlink update,
or Parent PR result is asserted by this record.
