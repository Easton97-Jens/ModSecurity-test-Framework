# Protocol artifact terminal-outcome integrity

**Language:** English | [Deutsch](20261030-02-protocol-terminal-integrity.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261030-02-protocol-terminal-integrity |
| UTC date | 2026-10-30 |
| Framework base revision | `d3b47aec9410f7adc3bb40df1ea413c00c438e89` |
| Issue or pull request | Separate Framework Draft follow-up to merged PR #112; delivery recorded in its PR |

## Motivation and problem statement

The protocol artifact reader trusted a normal `PASS` without checking Curl's
terminal outcome. A contradictory failed transfer could therefore pass the
reader's protocol and provenance checks. Primary schema versions were unchecked;
strict independent follow-up success also lacked terminal-outcome validation.
Producer/caller source tracing established these gaps, not a new runtime run.

## Affected components and security boundaries

Framework-owned protocol artifact admission, including the existing canonical
no-CRS consumer. Parent source and Framework gitlink remain unchanged. MRTS is
read-only and untouched. This does not change connector protocol support.

## Acceptance criteria

Require integer schema version1; reject missing, mistyped or contradictory
successful terminal outcomes. Preserve HTTP-denial evidence with Curl22 and
`http_response_error`, ordinary unknown-length success and strict failed-primary
reset evidence. Require Curl0/`none` for any `PASS` follow-up. Add no test cases,
assertions, selectors or harnesses while the user reorganizes tests.

## Alternatives considered

Trusting `PASS` leaves the contradiction unchecked. Requiring Curl0 for primary
evidence rejects valid WAF denials. Requiring `response_complete: true` rejects
supported Curl write-out formats without content length. Modifying the Parent
gitlink or copying reader logic into Parent would cross repository boundaries.

## Implementation decision

Validate successful terminal outcomes at artifact admission, rather than
changing the reusable protocol-only observation validator. Require the actual
integer exit code, its matching transport-error category and an observed HTTP
status; Curl22 additionally requires an HTTP error status. Apply the success
check to normal primary evidence and `PASS` follow-ups, including optional
follow-ups. Validate primary and follow-up schema versions as integer1, not
JSON booleans or floats. Strict primary evidence additionally requires an
integer failed exit code outside0/22 and its known producer category, or a
bounded stderr-derived failure category for unknown/signal outcomes. Its
committed/partial/reset/follow-up requirements remain separate and mandatory.

## Changed files and tests

Changed `ci/checks/protocol/check_protocol_evidence.py`, paired testing/evidence
documentation and this paired record. Two existing positive observations in
`tests/protocol_client/test_check_protocol_evidence.py` and
`tests/no_crs/test_no_crs_baseline.py` receive only producer-written terminal
metadata for their existing HTTP403 denial. No test definitions or assertions
were added or changed; existing negative fixtures remain unchanged.

## Commands and results

Commands use RTK, Framework-owned Python3.14.4 and external temporary/cache
roots. `<Framework-python>` denotes the configured Framework interpreter;
`<task-evidence>` denotes external run-scoped evidence, not a source path.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk bypass make test-protocol-client PYTHON=<Framework-python>` before implementation | 0 | 31 existing tests passed | External command record |
| Existing protocol and four no-CRS checks before positive-data maintenance | 2 / 1 | Old positive observations rejected for missing terminal facts | `<task-evidence>/protocol-client.log`, `<task-evidence>/no-crs-protocol.log` |
| `rtk bypass <Framework-python> -m unittest` selecting four existing no-CRS protocol methods | 0 | Four existing checks passed | `<task-evidence>/no-crs-protocol-final.log` |
| `rtk bypass <Framework-python> -m py_compile` on three changed Python files | 0 | Compilation passed | External command record |
| `rtk bypass make test-protocol-client check-documentation PYTHON=<Framework-python>` after strict-primary repair | 0 | 31 existing tests, links, bilingual/path checks and Change Records passed | `<task-evidence>/final-local-checks.log` |
| Four existing no-CRS protocol methods after strict-primary repair | 0 | Four passed | `<task-evidence>/no-crs-protocol-strict-final.log` |
| `rtk bypass git diff --check` | 0 | No whitespace errors | External command record |

Independent read-only source/compatibility review found no blocking issue.
Hosted CI/Sonar and delivery results remain revision-bound in the Draft PR.

## Security impact

Strengthens evidence integrity without changing authentication, isolation,
Quality Gates or scanner settings. This is a consistency repair, not an
authenticated-attestation mechanism or a connector vulnerability claim. No new
negative regression cases were authored under the user's current constraint;
source review and existing checks are the available evidence layers.

## Documentation and runtime evidence

The English/German `docs/testing-and-evidence` pair explains terminal results,
HTTP-denial compatibility and unknown-length completion semantics. No live
host, HTTP2/HTTP3 transport or connector lifecycle qualification was collected.

## Checks not run

No new tests, full runtime matrix, native connector build, dependency audit or
new coverage campaign. Focused existing checks match this Python reader scope.
Hosted CI/Sonar require a published revision and must be reported separately.
The optional local Gitleaks executable is unavailable; it was not installed.
The scoped source/documentation diff received a manual no-secrets review.

## Limitations and residual risk

Consistent external observations are not thereby authenticated. Existing
run/case/transaction/stream and checksum binding remains required. The Parent
keeps its existing Framework pin until a separately authorized integration.
The broader protocol-parity workstream remains incomplete.

## Final diff and review status

Task-owned Framework worktree only; no main-checkout edits, merge, history
rewrite, default-branch push or Parent gitlink change. Final scoped diff,
whitespace, independent review and revision-bound delivery are recorded in
external evidence before handoff.
