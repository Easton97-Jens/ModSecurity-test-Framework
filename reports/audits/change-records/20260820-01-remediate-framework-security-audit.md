# Change record

**Language:** English | [Deutsch](20260820-01-remediate-framework-security-audit.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260820-01-remediate-framework-security-audit` |
| UTC date | 2026-08-20 |
| Framework base revision | `bd69ee96e0e7082317d4afe1232bee625665eb9a` |
| Issue or pull request | User-authorized Framework Draft-PR delivery; the commit-time record deliberately does not invent a PR number, commit SHA, or hosted-check result |

## Motivation and problem statement

A defensive Framework audit confirmed five independent controls that could
accept an unsafe input or preserve unsafe evidence: source-tree symlinks,
archive links, external or stale runtime-snapshot data, and rejected request
body payloads emitted by JSONL normalizers. The work fixes only those Framework
controls and records `FND-FRAMEWORK-0093` through `FND-FRAMEWORK-0097`.

## Affected components and security boundaries

- `ci/provisioning/materialize-connector-source.py`: untrusted source-tree
  entries must not escape the source root while being materialized.
- `ci/lib/runtime-component-common.sh`: a verified archive must still contain
  only regular files and directories before extraction.
- `ci/reporting/update-runtime-snapshot.py`: runtime-report input must not
  read a case outside the configured roots or turn stale `PASS` evidence into a
  current result.
- `tests/normalizers/*.py`: a rejected body-like field must never be written to
  normalized output.

No connector, Parent product source, Gitlink, or MRTS source/runtime surface is
changed.

## Acceptance criteria

- A materializer rejects file and directory symlinks before copying.
- gzip and xz archives with link members are rejected, while regular members
  continue to extract.
- Runtime snapshots only use a trusted, in-root case path and only current-run
  evidence; `not_run` cannot be promoted to `PASS`.
- Event, decision, and hash-chain normalizers return no output for standard,
  nested camel-case, or hyphenated body payload keys.
- Focused regression tests and static checks pass without network, host smoke,
  matrix, or MRTS execution.

## Alternatives considered

Skipping unsafe entries or sanitizing output after it has been produced was
rejected because it leaves ambiguous partial artifacts or a leak window. The
selected controls fail closed at the shared boundary: reject links before
extraction/copy, constrain report paths before metadata loading, and produce an
empty normalizer output whenever validation fails.

## Implementation decision

The changes preserve valid regular-file source and archive paths. The snapshot
report now models missing current evidence explicitly instead of reusing prior
runtime state. Body-field aliases are canonicalized before policy matching, so
spelling variants do not bypass the redaction control. No security gate is
weakened and no external artifact or target was accessed.

## Changed files and tests

- Source controls: `ci/provisioning/materialize-connector-source.py` and
  `ci/lib/runtime-component-common.sh`.
- Evidence controls: `ci/reporting/update-runtime-snapshot.py` and
  `tests/normalizers/security_event_normalizer.py`,
  `tests/normalizers/decision_jsonl_normalizer.py`, and
  `tests/normalizers/integrity_hash_chain_normalizer.py`.
- Regression coverage: `tests/security_regression/test_materialize_connector_source.py`,
  `test_runtime_component_download.py`, `test_runtime_snapshot_sonar.py`, and
  `test_normalizer_payload_safety.py`, plus the normalizer security checker.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Private deterministic materializer proof | 0 | Pre-fix symlink was dereferenced; post-fix test rejects file and directory links | `20260820T185914Z-framework-defensive-security-audit` |
| Private deterministic archive proof | 0 | Pre-fix tar link member was accepted; regression rejects symlink and hardlink members | Same run ID |
| `python3.14 -m unittest ...test_materialize_connector_source.py` | 0 | 2 tests passed | Same run ID |
| `python3.14 -m unittest ...test_runtime_component_download.py` | 0 | 19 tests passed, including regular xz control and link rejection | Same run ID |
| `python3.14 -m unittest ...test_runtime_snapshot_sonar.py` | 0 | 7 tests passed | Same run ID |
| `python3.14 -m unittest ...test_normalizer_payload_safety.py` | 0 | 3 tests passed | Same run ID |
| `python3.14 ci/checks/security/check-security-data-flow-normalizers.py` | 0 | Normalizer data-flow control passed | Same run ID |
| `sh -n ci/lib/runtime-component-common.sh` | 0 | Shell syntax passed | Same run ID |
| `make check-documentation` | 0 | Links, bilingual pairing, path checks, and Change Record contract passed | Same run ID |
| `make check-no-crs-catalog` | 0 | PASS (166 cases) | Same run ID |
| Final `make lint` | 0 | Full local lint, contract, workflow, provenance, documentation, and whitespace suite passed | Same run ID |
| Final `make quick-check` | 0 | Full lint prerequisite plus static MRTS importer check passed; no MRTS source was initialized or run | Same run ID |

## Security impact

The original paths and sibling bypass variants were retested only with harmless,
private fixtures. Links now fail closed, stale and out-of-root snapshot inputs
do not produce a current pass, and rejected body payloads do not appear on
stdout. Independent final review found a stale-count/text-evidence sibling path
in the snapshot correction; it was fixed and added to the regression before the
final suite. These are local source-level results; no hosted CI or production
runtime claim is made.

## Documentation and runtime evidence

This English record and its German counterpart document the remediation. A
sanitized local evidence receipt is retained under the Parent finding store. No
connector runtime, host smoke, full matrix, or MRTS evidence was collected.

## Checks not run

- `make check-test-matrix` was not run because it refreshes Framework reports
  through the with-MRTS path, which is outside the user's authorization.
- No networked provisioner, download, connector smoke, full runtime matrix, or
  external target was run.
- The hosted Codex Security Deep Scan coordinator was unavailable in this
  session; a manual multi-surface review and a ready diff-scan preflight were
  retained instead.
- A clean-worktree `make lint` delivery run encountered one unrelated,
  timing-sensitive writerless-FIFO observation test. Its one permitted focused
  rerun passed; this record does not call that full delivery-lint invocation
  green, and hosted current-head CI remains the authoritative follow-up.

## Limitations and residual risk

The audit did not establish production reachability of every deferred candidate,
including mutable upstream opt-in sources and native-MRTS report producers.
Archive-member inspection is intentionally fail-closed for all link and special
member types; a future format requirement must add a separately reviewed safe
representation.

## Final diff and review status

The original Framework audit working tree contained only local, unstaged
remediation and this record pair. The user later authorized delivery of this
exact Framework-owned change through one task branch, commit, push, and Draft
PR. This versioned record deliberately does not invent the later commit SHA, PR
number, hosted checks, or merge state; delivery evidence records those observed
facts separately. Parent Gitlink and MRTS remain unchanged. Final git diff
--check, focused tests, documentation, no-CRS catalog, make lint, and make
quick-check passed in the associated original local finding evidence. The
formal Deep Scan coordinator remains blocked_environment; manual multi-surface
review does not claim to replace it.
