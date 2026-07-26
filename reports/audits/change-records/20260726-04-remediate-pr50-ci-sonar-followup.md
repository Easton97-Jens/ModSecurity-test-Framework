# Change record: PR #50 CI and SonarQube Cloud follow-up

**Language:** English | [Deutsch](20260726-04-remediate-pr50-ci-sonar-followup.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260726-04-remediate-pr50-ci-sonar-followup` |
| UTC date | 2026-07-26 |
| Framework base revision | `a7ebf5a1d9cad2b0a65a7603476a1434fdb16cf6` |
| Issue or pull request | Framework PR [#50](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/50), follow-up to its current exact head `b0f3e745075d57ee727bdfcd61f6258d488d4dc1`; no merge result is claimed by this record. |

## Motivation and problem statement

PR #50's SonarQube Cloud Quality Gate passed but reported two new source-code
issues: one repeated redaction marker in the protocol artifact validator and a
redundant control-flow statement in the command renderer. Its exact-head OSV
comparison also failed before it could produce evidence because the scanner
received an upstream `service unavailable` response while resolving the
unchanged base manifest and returned status `127`.

## Affected components and security boundaries

- `ci/checks/protocol/check_protocol_evidence.py` validates copied protocol
  command artifacts, including their mandatory redaction representation.
- `ci/checks/protocol/protocol_client.py` emits that bounded artifact.
- `.github/workflows/ci-security-osv.yml` compares exact base and pull-request
  dependency manifests with a checksum-verified scanner and only retains
  validated evidence.
- No Parent source or Gitlink, Framework-to-MRTS Gitlink, MRTS source, scanner
  lock, scanner version, permissions, gate, exclusion, or suppression changes.

## Acceptance criteria

- The validator uses one named canonical redaction marker for all three
  relevant comparisons.
- The renderer has no redundant final-loop `continue` and preserves the same
  rendered output.
- A scanner status `127` receives exactly two bounded retries; `0` and `1`
  preserve existing result handling, while a final `127` or any other status
  remains a failing job and cannot mark evidence valid.
- Focused protocol and CI-security regressions pass locally; hosted checks and
  SonarQube Cloud are re-run against the amended exact PR head before delivery.

## Alternatives considered

- Marking status `127` successful, using `continue-on-error`, removing the
  OSV job, or retaining partial evidence was rejected because each would hide
  a missing security result.
- Retrying every error indefinitely was rejected because deterministic scanner
  failures must fail quickly and visibly.
- Changing SonarQube Cloud configuration or adding a suppression was rejected;
  both reported source issues have direct source-level corrections.

## Implementation decision

The artifact validator defines `REDACTED_COMMAND_VALUE` and reuses it at every
redaction comparison. The renderer drops only the no-op `continue`. The OSV
workflow performs the first scanner invocation through the existing visible
helper, then retries only status `127` after one and two seconds. The third
result is handled by the original fail-closed status rule. A focused shell
regression supplies a fake scanner to prove transient recovery, persistent
failure, and the legitimate vulnerability-result (`1`) case without contacting
an external service.

## Changed files and tests

- `ci/checks/protocol/check_protocol_evidence.py` and
  `ci/checks/protocol/protocol_client.py` for the two Sonar findings.
- `.github/workflows/ci-security-osv.yml` for bounded, status-specific retry
  behavior without a control downgrade.
- `tests/ci_security/test_ci_security_evidence_contract.py` for the three
  scanner outcomes.
- This English/German record pair and the paired record index.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused CI-security and protocol test selection | 0 | 30 tests passed, including transient `127` recovery, persistent `127` failure after three attempts, and preserved `1` handling. | External task worktree local evidence |
| `make lint` | 0 | Framework shell, Python, CI-security, provenance, action-pin, workflow, data-flow, documentation, Change Record, and whitespace contracts passed. | External task worktree local evidence |
| Prior exact-head OSV comparison | 127 | Scanner could not resolve the unchanged base manifest because its upstream service was unavailable; no comparison evidence was created. | GitHub Actions `30204914941` / job `89801198064` |

## Security impact

The original failure path is reproduced by a fake scanner that returns `127`:
the first two failures are retried, while a third returns `127` and fails the
caller. The alternate unexpected-status path still fails immediately. The
legitimate scanner finding status `1` remains accepted for later comparison,
as before. Thus the remedy improves availability for a transient external
dependency without treating a missing security scan as valid evidence.

## Documentation and runtime evidence

This paired record and its index entries document the Framework-only follow-up.
The local regression is a hermetic scanner-interface test; no live scanner
service call, connector lifecycle, Parent operation, MRTS operation, hosted
check, SonarQube Cloud analysis, review, or merge has yet been claimed.

## Checks not run

- Hosted Actions, SonarQube Cloud, reviews, branch protection, and resulting
  master verification require the amended exact PR head.

## Limitations and residual risk

If the upstream scanner service remains unavailable through all three attempts,
the job correctly remains failed and PR integration is blocked. The retry does
not make scanner results reproducible offline and does not remediate any
separate external dependency outage.

## Final diff and review status

The local follow-up is uncommitted at record creation. It is limited to the
two reported Sonar issues, the verified OSV availability fix, focused tests,
and required bilingual traceability. A final diff/security review, local
validation, exact-head push, hosted validation, protected merge, and finding
archive disposition remain required.
