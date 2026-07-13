# Change traceability

**Language:** English | [Deutsch](change-traceability.de.md)

This document defines the Framework-only record for non-trivial changes. It
makes reviewable decisions and verification evidence durable without turning a
record into a log archive or a connector-runtime claim.

## Scope and ownership

Each record concerns this Git repository only. Do not mix Framework changes,
tests, security findings, revisions, or commits with those of a parent
connector repository. Connector-owned host behavior, capability declarations,
runtime artifacts, and promotion decisions remain connector evidence.

## Location and naming

Records live in `reports/audits/change-records/`. Create an English and German
pair named `YYYYMMDD-SEQ-short-name.md` and
`YYYYMMDD-SEQ-short-name.de.md`, where the UTC date and sequence make the ID
unique. Start from the paired template in that directory.

## When a record is required

Create a record for a non-trivial implementation, bug fix, security
remediation, change to a test or validation contract, generator change,
documentation-policy change, workflow change, or meaningful integration
decision. Small typo-only changes may omit a record when they do not affect a
contract, command, evidence boundary, or user guidance.

## Required facts

Both language versions contain the same facts.

| Area | Required content |
| --- | --- |
| Identity | Change ID, UTC date, Framework base revision, issue or pull request reference |
| Rationale | Motivation, problem statement, affected components, and relevant security boundary |
| Decision | Acceptance criteria, alternatives considered, and implementation decision |
| Scope | Changed files, tests added or changed, documentation changes, and compatible behavior considered |
| Verification | Exact commands, exit code, concise outcome, approved run ID or evidence path when available |
| Evidence | Runtime or lifecycle evidence, or an explicit statement that none exists |
| Risk | Security impact, skipped checks with reasons, known limitations, and residual risk |
| Review | Final diff status, review status, and confirmation that no secrets or raw sensitive material were recorded |

## Safe evidence handling

Do not copy complete logs, request or response bodies, cookies, credentials,
tokens, secrets, or full environment values into a record. Prefer the command,
exit code, short result, approved artifact path, run ID, reviewed hash, size,
and redaction fact. A static check or generator run must be described as such;
it is not host-runtime or lifecycle evidence.

## Review and validation

Before commit, keep the record synchronized with the final Framework diff and
its paired translation. Run the focused check for changed validation code, then
the relevant bilingual, link, documentation, lint, and diff checks. State every
check not run and why. Use the record template and the rules in
[development](development.md); do not hand-edit generator-owned reports to
make a record appear complete.

## Security work

Security scans, validation, and fixes are separate phases. A confirmed finding
needs an evidenced attack path, boundary, control, sink or broken contract,
impact, preconditions, counterevidence, and safe reproduction. A remediation
record must show the original path and an alternative bypass were rechecked
without weakening a security control for test convenience.
