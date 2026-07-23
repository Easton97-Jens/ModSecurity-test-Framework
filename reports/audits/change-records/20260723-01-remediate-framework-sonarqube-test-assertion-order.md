# Remediate Framework SonarQube test assertion argument order

**Language:** English | [Deutsch](20260723-01-remediate-framework-sonarqube-test-assertion-order.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260723-01-remediate-framework-sonarqube-test-assertion-order` |
| UTC date | 2026-07-23 |
| Framework base revision | `935cf14c676a24672be5c336e92cd13457cc35c8` |
| Issue or pull request | Framework Draft PR to be created from `agent/framework-sonarqube-test-issues-507` |

## Motivation and problem statement

The current Framework `master` SonarQube Cloud analysis
`dda3ea04-2721-4ee6-a9c1-74bd2925f139` reports 507 Framework-owned
`python:S3415` test diagnostics in 29 files. Each reports an inverted
`unittest` diagnostic convention: expected value first and actual value second.
The equality relation itself is symmetric, but actual-first ordering gives the
intended failure diagnostic and meets the configured static-analysis rule.

This is a Framework-only test maintenance change. It does not change a
connector, a server/proxy runtime, a catalog result, a rule, a Quality Gate, or
the separate MRTS-only Sonar security finding.

## Affected components and security boundaries

- `tests/no_crs/` — 220 test assertions for bounded evidence, lifecycle, and
  transport controls.
- `tests/protocol_client/` — 23 test assertions for payload-free protocol
  evidence and artifact containment controls.
- `tests/security_regression/` — 262 test assertions for CI, provenance,
  path, archive, runtime-evidence, and workflow-contract controls.
- `tests/makefile_contract/` — 2 Makefile contract assertions.

No production security control is changed. The test source exercises
security-relevant boundaries, so the change preserves every asserted relation,
message, fixture, and expression evaluation order. Two computed expected lists
are evaluated into local `expected_*` values immediately before their
actual-first assertion, preserving the original expression evaluation order.

## Acceptance criteria

1. Every one of the 507 live S3415 locations uses `actual, expected` without
   changing its relation, message, fixture, or test flow.
2. The two nontrivial expected expressions preserve their prior evaluation
   order.
3. No `NOSONAR`, exclusion, false-positive state, rule/gate change, test
   weakening, Parent edit, or MRTS edit is introduced.
4. The relevant Framework test suites, source-quality checks, documentation
   checks, and final diff review pass.
5. A normal Framework Draft PR is created; no master merge is part of this
   record.

## Alternatives considered

- **Suppress or accept the Sonar issues:** rejected because it would conceal a
  consistent diagnostic-quality defect and weaken the requested remediation
  evidence.
- **Blindly swap all first two arguments:** rejected because an expected
  expression can have observable evaluation behavior.
- **Refactor assertion helpers or test logic:** rejected because this task
  needs a narrow, source-preserving remediation with clear Sonar traceability.

## Implementation decision

Each live location was mapped against the Sonar API and Python AST. 505 calls
swap only their first two positional arguments. For the two computed expected
lists in `test_no_crs_finalize_argument_safety.py`, the old expected expression
is bound before the assertion and used as the second argument. A whole-AST
equivalence check against the base revision confirms that no other Python
semantic change exists in the 29 files.

## Changed files and tests

The 29 changed files are exactly the live Sonar inventory: 4 No-CRS/Makefile,
2 protocol-client, and 23 security-regression tests. No new test cases are
needed because the remediation corrects existing assertions; existing positive
and negative security-control fixtures remain the regression coverage.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | ---: | --- | --- |
| SonarQube Cloud S3415 pages 1 and 2 | 0 | 507 open `python:S3415` master locations (500 + 7) | `20260723T092456Z-framework-sonarqube-test-issues-507-10387697` |
| Whole-AST remediation verifier | 0 | 29 files; 505 direct swaps and 2 evaluation-order-preserving cases; no other AST change | sealed security scan artifact `artifacts/02_discovery/verify_s3415_whole_ast.py` |
| `make test-no-crs-contract` | 0 | 97 tests passed | task run external build roots |
| `make test-protocol-client` | 0 | 24 tests passed | task run external build roots |
| `python -m unittest discover -s tests/security_regression -v` | 0 | 254 tests passed | task run external build roots |
| `make test-makefile-contract` | 0 | 3 tests passed; Make warned that its non-existent supplied `TMPDIR` fell back to `/tmp`, with no retained test output | task run external build roots |
| Diff-scoped Codex Security review | 0 | 29/29 full-file receipts, zero reportable findings | sealed `report.md` in current task run |
| `make lint` | 0 | Native Framework lint passed, including shell/Python checks, focused contracts, catalog checks, documentation checks, and `git diff --check` | task run external build roots |
| `make check-change-records` | 0 | English/German Change Record contract passed | task run external build roots |
| `make check-documentation` | 0 | Links, variable documentation, repository paths, and bilingual pairs passed | task run external build roots |
| Final `git diff --check` | 0 | No whitespace errors in the complete Framework task diff | task run external build roots |

## Security impact

No security remediation is performed. The completed diff-scoped security review
found no reportable finding: the whole Python AST differs only by the approved
actual/expected transformations and the two order-preserving bindings. The
original path, parser, provenance, workflow, and artifact-containment controls
were rerun through their existing Framework suites; their negative controls
continue to pass. This change does not address `FND-SONAR-0002` or claim a
green master Quality Gate.

## Documentation and runtime evidence

This English/German Change Record pair documents the test-maintenance decision.
No generated report or user-facing behavior changed. No connector runtime or
lifecycle evidence was collected: the executed checks are static/contract test
evidence only.

## Checks not run

- Full connector smokes, runtime matrices, and MRTS-generating targets were
  not run: they are outside this Framework-only assertion-order scope and may
  cross runtime/MRTS boundaries.
- Local Ruff/Pyright parity was not established because the approved CI tool
  environment is not provisioned locally; hosted checks remain required for
  the submitted PR head.
- Fresh SonarQube Cloud PR analysis is not yet available because this record
  precedes Draft PR creation.

## Limitations and residual risk

The local test evidence does not replace hosted exact-head CI or SonarQube
Cloud analysis. The S3415 correction must appear on the pushed Draft PR before
Sonar can confirm that no original issue remains. The current master
Security-C condition arises from separate read-only MRTS paths and remains out
of scope.

## Final diff and review status

The task completed scoped whitespace, suppression, secret, and whole-AST
reviews before delivery. The Parent checkout, its Framework gitlink, the
canonical Framework checkout, and MRTS are not delivery targets. At record
creation the Framework task branch is uncommitted; commit, push, and Draft PR
details are recorded only after their exact heads are observed.
