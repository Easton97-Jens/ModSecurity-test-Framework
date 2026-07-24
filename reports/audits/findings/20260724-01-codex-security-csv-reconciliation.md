# Codex Security CSV reconciliation

**Language:** English | [Deutsch](20260724-01-codex-security-csv-reconciliation.de.md)

## Scope and method

This is the Framework-only reconciliation of the explicitly supplied 23-row Codex Security export
`codex-security-findings-2026-07-24T17-04-36.095Z.csv` (SHA-256
`e28d182304f854ce01935f6f08e880900241fc67c45a4289e83f03f3192da7a4`, scan
`user-cTR8W8YixbRnTZ4QJJXk1jpW:github-1240166325`). The export was parsed with
the standard RFC-4180-compatible Python CSV dialect: all 23 data rows have 17 fields. A Sniffer
disagreement about doubled quotes is recorded as parser diagnostic only, not as a malformed export.

The current Framework default is `77d73decd094a8f289fbe0ef2582f12430923e24`. Every scan
revision exists and is its ancestor; therefore each row was revalidated against the current default
before a task-branch change was considered. `confirmed_open_fixed_in_task_branch` means the
cumulative task branch contains the named, focused regression-tested correction; it is not a Cloud
closure. `documented_false_positive` means the alleged unsafe outcome is prevented by the named
current control. `not_applicable` means the reported runtime interpretation is outside the classified
inventory's scope.

Path history was resolved rather than assumed: scanner-era `ci/*.py` and `ci/*.sh` paths were
reorganized by `428dfb2741785ad`; current ownership is under `ci/checks/`, `ci/lib/`,
`ci/provisioning/`, `ci/reporting/`, and `ci/tools/`. No Parent file, gitlink, or MRTS content
was changed. MRTS remains a pinned, read-only dependency.

## Per-row disposition matrix

| # | Finding ID | Severity | Disposition | Current code evidence / task action |
| --- | --- | --- | --- | --- |
| 1 | `3e5b4a68b3288191a46e2e897019db4f` | high | documented_false_positive | `.gitmodules` pins the user-authorized `Easton97-Jens/MRTS`; Framework workflows use `submodules: false` and do not make remote submodule updates. A normal update consumes the recorded gitlink, not an arbitrary fork URL. |
| 2 | `6e64449e9d4481918fbcc63aef4ab41e` | high | confirmed_open_fixed_in_task_branch | `import-mrts-cases.py` now emits `MRTS_SOURCE_REPOSITORY = "Easton97-Jens/MRTS"`, not the stale upstream label. Commit `d2d3320`; six focused importer tests passed. |
| 3 | `990e73aec6948191a3206a204a7d5881` | high | already_fixed_on_default | `ci/tools/check-github-actions-workflows.py` rejects serialised `secrets` and `github` contexts; current contract tests cover the negative cases. |
| 4 | `932c7c43d8d88191a06ca768bba69f42` | high | already_fixed_on_default | `ci/lib/connector-smoke-common.sh` does not discover a shared temporary root; verified roots must be configured explicitly. |
| 5 | `49dfbbb3887c819187fdbd9b670341c1` | high | confirmed_open_fixed_in_task_branch | Lighttpd source staging first requires canonical cache containment (19d8494) and then rejects every preexisting staged source before configure/autogen.sh can run (e60cb8c). The 11-case bootstrap suite covers external, traversal, and in-cache executable-marker cases. |
| 6 | `6645193c8a4081919df834437048f38c` | high | documented_false_positive | A displayed response-body `PASS` retains `not_auto_promoted`, `response_body_non_verified`, `runtime_verified=false`, and `promotion_allowed=false`; it cannot become promotable evidence. |
| 7 | `f2c4b104dc288191b7976a77bc5d6f02` | medium | confirmed_open_fixed_in_task_branch | `ci_modsecurity_v3_require_clean_checkout` now includes `--ignored=matching`, so ignored build residue fails closed. Commit `e94074c`; the 16-case provenance suite covers it. |
| 8 | `ca36c37a1b8c8191bf5bba672b843f46` | medium | documented_false_positive | The response-body runtime presentation is non-promotable by the same explicit evidence flags as row 6. |
| 9 | `de250c7664b88191be2cf8ec9caf52f2` | medium | confirmed_open_fixed_in_task_branch | Protocol evidence accepts exactly one profile-required forced selector; `--http3`, `--http2`, duplicate, and conflicting selectors fail. Commit `75f15ab`; 16 protocol-client tests passed. |
| 10 | `864b7d9ee20081919d081396d2a233ad` | medium | already_fixed_on_default | The workflow checker detects `toJSON(secrets)` and `toJSON(github)` serialisation patterns and has regression coverage. |
| 11 | `ee0623b9b9388191b29b09766e413ad8` | medium | already_fixed_on_default | Protocol capture command parsing forbids output/payload-capturing options, including output-file variants. |
| 12 | `a0aff086d85c8191b2082624edf5307f` | medium | already_fixed_on_default | No-CRS engine-version reads are bounded and regex-constrained; secret-like or overlong content is rejected. |
| 13 | `712cf426a780819188abe4928484b4d7` | medium | already_fixed_on_default | No-CRS result summaries validate identity, schema, profile, connector, and security claims before a PASS result is accepted. |
| 14 | `ce59a7b5dfa881919172d51d9b5f02bd` | medium | already_fixed_on_default | An explicit `HAPROXY_BIN` is recorded as configured runtime input and fails if it cannot be verified; no silent fallback applies. |
| 15 | `c9ca53a179948191addf07c5cfa34f67` | medium | already_fixed_on_default | Phase-1 connector-gap inventory carries `classification: connector_gap` and `former_xfail`, and is non-promotable. |
| 16 | `2ad2602367208191955e63da621fcf3f` | medium | already_fixed_on_default | `RUN_ONE_CASE` validates strict results identity and live execution evidence before accepting a case result. |
| 17 | `f4db578ad0948191a1edcd79e393c733` | medium | already_fixed_on_default | MRTS generated paths are constrained below the verified task build root. |
| 18 | `a4235836148c81919fe06cfb7046d481` | medium | already_fixed_on_default | The case-matrix normalizer converts a raw non-promotable pass to `NOT_EXECUTABLE`. |
| 19 | `6f134b6136c481918d5576fa425a5957` | medium | documented_false_positive | Strict response-body aborts preserve non-promotable state and normalize semantic status; a presentation string alone cannot count as PASS evidence. |
| 20 | `0c88f026e99c819184283536e5ca8af5` | medium | already_fixed_on_default | Existing HAProxy source or binary reuse requires a verified provenance marker. |
| 21 | `0648f667c8a08191ab140169675aacb4` | low | confirmed_open_fixed_in_task_branch | The common-version checker now blocks absent or malformed ModSecurity v3 immutable commit anchors before network checks. Commit `f3aac14`; 16 provenance tests passed. |
| 22 | `2f9959fe71ec8191bb9c335685e68c15` | informational | documented_false_positive | The comma-form `except OSError, UnicodeError` is a valid Python 3 exception tuple. An invalid UTF-8 `.python-version` control produced the intended decode diagnostic. |
| 23 | `3677a6db8d74819181aa8258ae94b410` | informational | not_applicable | Security-data-flow YAML files are connector-gap inventory rather than materialized runtime cases; the runner filters them before runtime parameter validation. |

## Validation, residual risk, and Cloud handoff

The five task-branch corrections have focused negative and legitimate-control tests recorded in the
paired Change Record `20260724-01-reconcile-codex-security-csv-findings`. The tests validate
Framework control behavior only; they make no connector-runtime claim.

Cloud disposition or re-scan is not available through an authenticated Codex Security service in this
environment, so Cloud closure is `blocked_permissions`. The retained source CSV, its digest, the
normalized 23-row evidence, and this matrix provide a reproducible handoff. The eventual Draft PR is
the only delivery container and is not authority to merge, update Parent, or alter MRTS.
