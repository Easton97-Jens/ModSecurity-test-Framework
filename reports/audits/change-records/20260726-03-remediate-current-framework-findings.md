# Change record: Remediate current Framework findings

**Language:** English | [Deutsch](20260726-03-remediate-current-framework-findings.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260726-03-remediate-current-framework-findings` |
| UTC date | 2026-07-26 |
| Framework base revision | `a7ebf5a1d9cad2b0a65a7603476a1434fdb16cf6` |
| Issue or pull request | Current-state reconciliation of `FND-FRAMEWORK-0002`, `FND-FRAMEWORK-0011`, `FND-FRAMEWORK-0053`, and `FND-FRAMEWORK-0056` in Framework Draft PR [#50](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/50) on branch `agent/framework-findings-current-state`; no merge is authorized. |

## Motivation and problem statement

The current Framework master retained one ShellCheck error, allowed opaque URL
paths and direct `--resolve` values into copied protocol command artifacts,
contained a PCRE2 archive-digest fixture that stopped at an earlier V3
provenance gate, and retained a stale PR #42 resulting-master statement in a
paired Change Record. This change corrects those current conditions without
rewriting historical findings, weakening provenance, or claiming host-runtime
evidence that was not collected.

## Affected components and security boundaries

- `ci/lib/mrts-common.sh` remains a sourceable POSIX helper and now declares
  that shell explicitly for ShellCheck.
- The protocol client and its independent artifact validator redact opaque URL
  paths and every direct `--resolve` value before canonical evidence can retain
  them. Only bounded health paths remain visible.
- The PCRE2 fixture models the smallest approved synthetic V3 topology through
  the existing hermetic Git model. Production `/usr/bin/git` binding and the
  V3 provenance guard are unchanged.
- The PR #42 Change Record pair now distinguishes observed merge evidence from
  unresolved current-master Sonar and queued Cloudflare conditions.
- Parent source, Parent Gitlink, Framework-to-MRTS Gitlink, and MRTS source
  are outside this Framework-only change.

## Acceptance criteria

- Framework ShellCheck has no current error-level diagnostic from
  `ci/lib/mrts-common.sh`.
- Synthetic opaque path, percent-encoded path, query, and `--resolve` markers
  cannot appear in a managed `client-command.txt`; a safe `/health` control is
  preserved.
- The independent artifact validator rejects a forged command artifact with
  those unredacted values.
- Every invalid PCRE2 digest reaches the intended digest blocker before `tar`,
  while the matching digest reaches the local extraction control.
- The historical PR #42 record binds the normal merge to
  `935cf14c676a24672be5c336e92cd13457cc35c8` without calling unresolved
  Sonar or Cloudflare conditions passing.
- The change is delivered only through a normal Framework Draft PR; no merge,
  Parent update, or MRTS action is performed.

## Alternatives considered

- Suppressing ShellCheck or adding a broad source exemption was rejected;
  the helper is POSIX and can declare its actual interpreter.
- Retaining arbitrary endpoint paths for diagnostics was rejected because the
  canonical command artifact is copied into evidence and may contain opaque
  request data. A small health-path allowlist retains the needed control.
- Relaxing the V3 provenance guard to revive the PCRE2 test was rejected. The
  fixture instead supplies the approved synthetic topology through the existing
  hermetic test model.
- Editing Parent findings, the merged PR #42 body, or Sonar/Cloudflare settings
  was rejected as outside the Framework source PR and unnecessary for the
  stale-record correction.

## Implementation decision

The shell helper receives a POSIX shebang only. The protocol renderer maps all
non-allowlisted paths to `/[redacted-path]`, redacts query values and resolver
arguments in both split and `--option=value` forms, and the independent
validator rejects command artifacts that bypass this representation. The PCRE2
regression copies the real Apache path and shared helper into task-owned
temporary storage, replacing only its host-Git binding with the existing exact
approved-topology model. The historical Change Record is corrected in English
and German with the observed normal merge facts and explicit remaining limits.

## Changed files and tests

- `ci/lib/mrts-common.sh` and the focused ShellCheck control.
- `ci/checks/protocol/protocol_client.py` and
  `ci/checks/protocol/check_protocol_evidence.py`, with protocol and no-CRS
  regressions for redaction and validator bypass resistance.
- `tests/security_regression/test_pcre2_archive_digest.py`, using the existing
  approved V3 topology helper without changing production provenance code.
- The corrected PR #42 Change Record pair and this English/German pair.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Current-master workflow, pin, CRS, protocol, and documentation checks | 0 | Confirmed that several older active records are already protected by current master. | `a7ebf5a1d9cad2b0a65a7603476a1434fdb16cf6` local review |
| Current-master `test_pcre2_archive_digest.py` | 1 | Five assertions reproduced: the stale fixture stopped at the V3 `.gitmodules` provenance guard before PCRE2 verification. | `FND-FRAMEWORK-0056` baseline |
| Current-master Framework ShellCheck error scope | 1 | The only error-level result was `SC2148` for `ci/lib/mrts-common.sh`. | `FND-FRAMEWORK-0002` baseline |
| Current-master synthetic protocol renderer check | 0 | A synthetic opaque path and direct resolver value were visibly retained, proving FND-0011 before the correction. | `FND-FRAMEWORK-0011` safe synthetic reproducer |
| Framework `make lint` after the correction | 0 | Full local suite passed, including V3 provenance (18 tests), NGINX/protocol/no-CRS coverage, workflow contracts, security-data-flow checks, documentation, and Change Record validation. | Task worktree lint log |
| Framework ShellCheck error scope after the correction | 0 | All Framework shell files outside the read-only MRTS submodule passed at error level. | `FND-FRAMEWORK-0002` regression |
| `git diff --check` | 0 | No whitespace errors in the scoped Framework diff. | Task worktree |

## Security impact

This change closes an evidence-retention boundary, not a live request-routing
or authorization boundary. The protocol command artifact now retains only an
authority, an allowlisted harmless path or a redacted path marker, a redacted
query marker, and redacted sensitive curl option values. The independent
validator protects canonical copying from a forged external artifact. The V3
provenance, host-Git, action pinning, CI permissions, and test controls are not
relaxed.

## Documentation and runtime evidence

The paired historical PR #42 record now accurately retains the observed
normal merge and states its limitations. This new paired record documents only
the Framework source/test scope. No host lifecycle, connector runtime,
Python.org live updater, Parent Gitlink update, MRTS operation, hosted exact
PR-head check, Sonar result, Cloudflare result, or merge is claimed before it
is observed for this Draft PR.

## Checks not run

- Native Apache or NGINX lifecycle validation remains outside this fixture-only
  and protocol-artifact scope.
- Hosted Actions, SonarQube Cloud, reviews, branch protection, and Cloudflare
  status apply to the current exact Draft PR #50 head and are not yet observed.
- Findings requiring Codex Cloud access, external-tool changes, or native H2
  and Apache lifecycle evidence remain separately tracked and are not hidden
  by this change.

## Limitations and residual risk

The protocol allowlist intentionally exposes only root and standard health
paths. A caller that needs a different harmless diagnostic path must add a
reviewed explicit control rather than relying on arbitrary path retention. The
PCRE2 fixture validates the archive boundary with an exact hermetic topology;
the independent V3 provenance suite remains the authoritative production
host-Git and fresh-checkout control. This record does not close blocked native
lifecycle, external-tool, Codex Cloud, Sonar, or Cloudflare findings.

## Final diff and review status

The scoped diff is limited to the four current Framework-owned finding paths,
their regression coverage, and required paired records. Full local lint,
ShellCheck, documentation, security-data-flow, protocol, provenance, and
diff-format evidence passed on the task worktree. Hosted validation remains
for the current exact Draft PR #50 head. No secrets, credentials, raw request
payloads, Parent changes, MRTS changes, direct master push, or merge are
included.
