# Change record: Framework SonarCloud quality-gate remediation

**Language:** English | [Deutsch](20260719-01-remediate-framework-sonarcloud-quality-gate.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260719-01-remediate-framework-sonarcloud-quality-gate` |
| UTC date | 2026-07-19 |
| Framework base revision | `7a12073c28e62a67492dd501b6513b9914fe5df8` |
| Issue or pull request | Draft PR pending; no merge authorization |

## Motivation and problem statement

The Framework's fresh SonarCloud inventory at the base revision contained
current Framework-owned code-quality, reliability, and security findings.
This Framework-only remediation reconciles those findings with concrete source
changes and regression controls. It deliberately does not inspect, change, or
reconcile `tools/MRTS` source.

## Affected components and security boundaries

- CI shell bootstrap, provenance, version/update, and finalizer helpers:
  untrusted environment, source-origin, command-argument, and runtime-path
  boundaries.
- Case runners, YAML/workflow/checker parsers, protocol evidence, and
  transport evidence: untrusted input, parser, request/evidence, and
  non-promotion boundaries.
- Reporting/import utilities: CLI path, generated-file, private-runtime-root,
  symlink, and payload-redaction boundaries.
- Documentation and canonical variables: English/German reader-facing
  documentation consistency.

No Connector implementation, Parent repository file, or `tools/MRTS` source
was modified.

## Acceptance criteria

1. All current Framework-owned Sonar rows from the recorded base inventory
   have a source-level reconciliation without suppressions or quality-gate
   weakening.
2. Security-sensitive paths fail closed for traversal, foreign/symlinked or
   publicly writable roots, unsafe command input, mutable provenance, and
   malformed parser input as applicable.
3. Focused positive and negative regression controls pass, as do the complete
   Framework security-regression suite and repository-native lint target.
4. The Framework worktree has no `tools/MRTS` gitlink change; no MRTS content
   was read for this task.
5. A normal branch push and Draft PR are created only after local validation;
   merge remains out of scope. Remote SonarCloud and CI must confirm the final
   head before a quality-gate-success claim.

## Alternatives considered

- Suppress findings, alter the Sonar profile, or weaken a gate: rejected,
  because this would hide rather than remedy the source behavior.
- Use shared temporary-directory fallbacks or broad current-working-directory
  path allowances: rejected in favor of explicit, contained private roots.
- Probe or modify MRTS source to obtain additional evidence: rejected by the
  task boundary; synthetic Framework fixtures cover importer/report behavior.
- Mechanically flatten complex security checkers: rejected. Refactors retain
  error ordering and split validation into semantic helpers.

## Implementation decision

The implementation uses narrow, behavior-preserving refactors plus security
contracts at actual I/O and invocation boundaries. Examples include canonical
script-relative bootstrap sourcing, immutable V3/CRS provenance, argv-based
No-CRS finalization, bounded YAML/protocol parsing, loopback/control-root
validation, atomic no-follow report writers, and non-promoting runtime/strict
transport evidence handling. New tests use task-owned synthetic temporary
directories and include outside-root, symlink, malformed-input, and legitimate
control cases.

The case-matrix fallback now requires an explicit private build root instead of
writing under a shared temporary location. This is intentionally fail-closed
and documented as a compatibility consideration.

The sourced common-shell library now preserves its library-safe return
semantics without allowing a blocked prerequisite to become success. Every
affected command/header wrapper propagates `77` or `1`, and CI returns before
any local provisioning attempt after a block.

The initial Draft-PR `common-structure` run correctly rejected a legitimate
case-materialization output outside its declared verified root. The follow-up
keeps that containment fail-closed and changes only the workflow layout: shared
case output is now `$VERIFIED_RUN_ROOT/case-runner`, not a sibling temporary
directory. No output-root allowlist or runner validation is widened.

## Changed files and tests

The change spans Framework CI/checker, runner, reporting, provisioning, shell
library, Makefile, documentation, and test files. Major new controls cover:

- parser and workflow YAML resource limits;
- No-CRS finalizer argument safety, catalog behavior, and protocol evidence;
- V3/CRS source provenance and safe archive/path handling;
- CI-root bootstrap, loopback/control-root, and shell-contract hardening;
- contained report/import/case output paths and generated-report redaction;
- transport evidence ordering, counter short-circuiting, and strict-abort
  non-promotion.

The English/German documentation pairs `docs/connector-integration.*`,
`docs/reference/variables.*`, and `docs/testing-and-evidence.*` describe the
new Framework contracts where readers need them.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused worker test/compile/diff commands | 0 | All reported focused controls passed; no MRTS access | `20260719T131321Z-sonarcloud-quality-gate-f4bb3370` |
| Common-shell prerequisite regression | 0 | Blocked, failed-local, success, and sourced-library controls passed | external finding `FND-FRAMEWORK-SHELL-BLOCK-RETURN` |
| Common-workflow verified-root regression | 0 | Legitimate materialization below the verified root passes; sibling-root rejection remains active | external finding `FND-FRAMEWORK-CI-VERIFIED-ROOT` |
| `python -m unittest discover -s tests/security_regression` | 0 | Complete Framework security-regression suite passed after the final shell correction | task validation `full-security-after-shell/` |
| `make lint` with task-owned roots and verified Framework Python | 0 | Shell syntax, compilation, contracts, security/documentation checks, and diff check passed after the final shell correction | task validation `lint-after-shell/` |
| `git diff --check` | 0 | No whitespace errors | Framework task worktree |
| Changed-line suppression search | 0 | No `NOSONAR`, Sonar configuration weakening, `noqa`, or `type: ignore` introduced | Framework task worktree |
| Framework index-only `tools/MRTS` diff check | 0 | No gitlink change | Framework task worktree |

## Security impact

This is a security remediation. The original unsafe-path, shell-input,
provenance, parser, and evidence-boundary controls were rerun through focused
legitimate and negative controls. Alternative bypasses—foreign roots,
symlinks, traversal, public temporary directories, malformed/escaped YAML,
mutable source selectors, raw protocol identifiers, and payload-bearing
evidence—are rejected. The change does not relax authentication,
authorization, isolation, validation, logging, tests, CI, or quality gates.
The final common-shell regression specifically confirms that an unavailable
prerequisite cannot be reported as success and cannot trigger local
provisioning from CI.
The CI workflow correction consumes the existing verified root rather than
adding a second trusted temporary location.

## Documentation and runtime evidence

English/German Framework documentation pairs were updated as listed above.
This change validates Framework code and synthetic controls; it does not claim
a live Connector runtime pass, a fresh remote SonarCloud quality gate, or an
MRTS runtime result.

## Checks not run

- Local `sonar-scanner`: not installed; no package installation was performed.
- Remote SonarCloud analysis and GitHub CI: pending the normal branch push and
  Draft PR for the exact committed head.
- Full Connector runtime matrix: not run because this task changes the
  Framework quality/security layer and no runtime dependency matrix was
  provisioned.
- MRTS source/integrity readback: intentionally not run under the explicit
  no-access task boundary.

## Limitations and residual risk

Local source and regression evidence cannot substitute for the remote scanner's
analysis of the final pull-request head. The pre-existing protocol artifact
reader rejects over-limit files after reading them; this change adds regression
coverage but does not claim an operating-system-level streaming size bound.
No `tools/MRTS` source conclusion is made.

## Final diff and review status

Before delivery, the whole unstaged Framework diff received whitespace and
suppression review. A focused independent security review found no validated
regression in the protocol evidence refactor. A second independent review
found no remaining status-overwrite bypass after the common-shell correction.
Initial staging, commit, normal push, and Draft PR creation completed; the
first current-head common-structure run found the verified-root layout defect
above. A normal follow-up commit and current-head CI/SonarCloud readback are
pending; merge remains unauthorized.
