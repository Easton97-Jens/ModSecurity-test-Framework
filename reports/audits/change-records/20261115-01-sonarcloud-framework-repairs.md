# Change record

**Language:** English | [Deutsch](20261115-01-sonarcloud-framework-repairs.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261115-01-sonarcloud-framework-repairs |
| UTC date | 2026-11-15 |
| Framework base revision | e4762167bed1ec6a28f7a207c8fb5b9ec258656a |
| Issue or pull request | Task branch `codex/framework-sonar-repair-20261115`; PR creation follows the initial commit |

## Motivation and problem statement

The bound project `Easton97-Jens_ModSecurity-test-Framework` returned all 115 open/confirmed issues: 32 vulnerability labels and 83 maintainability reports. Analysis `f1f25af4-6af9-4df5-8b96-5a0645ac66cd`, dated `2026-11-14T23:21:13Z`, covers `452f7fc7ca1d9c44c9e768cef565f52882a40e2d`. Only the MRTS gitlink differs from the base revision; reported Framework source is identical. The last Cloud gate is `ERROR`, solely because new-code security rating is E. Hotspot pagination returned total 0.

## Affected components and security boundaries

Framework parser/runner helpers, private test-client filenames, qualification evidence input admission, shell guards, OSV result routing and report formatting. Parent source, its existing changes/gitlink, and MRTS remain unchanged by this task. Repairs do not establish connector runtime qualification.

## Acceptance criteria

Inventory every issue against current source; repair demonstrated defects and applicable maintainability findings without weakening analyzer scope, validation or gates; preserve valid behavior and ASCII protocol semantics; prove path rejection and legitimate receipts; review the combined diff and paired documentation. Fresh Cloud clearance and disposition of candidate false positives remain separate, unperformed external steps.

## Alternatives considered

No rule disablement, broad exclusion, `NOSONAR`, forced HTTPS rewrite or removal of required Python parentheses. Existing HTTPS servers remain intact. Trusted operator-selected CLI roots retain their contract. An isolated worktree preserves the original checkouts.

## Implementation decision

Two Traefik clients now accept only a bounded filename component before any filesystem/network use. Patched lighttpd proposal input JSON uses the existing `read_json()` / `evidence_path()` admission boundary. Pure helper extraction reduces parser/runner complexity, regex use retains ASCII digits, repeated values become constants, and exception/collection handling is simplified. Nine shell default branches explicitly preserve successful fallthrough. OSV passes its result path into the attempt helper and binds it locally, retaining the exact scanner command and retry contract. Report lines retain their order through one `extend()`.

## Changed files and tests

- `connector_suite/adapters/traefik/harness/i12/native/client.py`, `connector_suite/adapters/traefik/harness/i12_auth/client.py` and `connector_suite/modsecurity_connector_ci/runtime/lifecycle/i12/lighttpd/patched_qualification.py`.
- Runner modules: `nginx_lifecycle_sequence.py`, `nginx_native_operation_bundle.py`, `nginx_native_operation_contract.py`, `runner_core.py`, `nginx_event_boundary_operations.py`, `nginx_http11_framing.py`, `nginx_mime_operations.py`, `nginx_native_operation_projection.py`, `nginx_phase4_operations.py`, `nginx_raw_h1.py` under `tests/runners/`.
- `tests/normalizers/integrity_hash_chain_normalizer.py`, `tests/security_regression/git_provenance_test_support.py`, `ci/lib/common.sh`, `.github/workflows/ci-security-osv.yml`, `ci/reporting/generate-case-matrix.py`.
- New focused `tests/security_regression/test_sonar_path_boundaries.py`; seven methods cover 15 expanded scenarios. Existing active-inventory selection is unchanged.
- This English/German Change Record pair. Generated reports are not edited.

## Commands and results

| Command / procedure | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk bypass /usr/local/bin/sonar-with-env list issues -p Easton97-Jens_ModSecurity-test-Framework --format json --page-size 500 --page 1` | 0 | 115/115 issues returned | `framework-sonar-20261115/issues.json` |
| Same starter, `api get` for explicitly bound project analyses, gate and hotspots | 0 | Exact analyzed revision; gate ERROR; 0 hotspots | Analysis identity above |
| Explicit `analyze secrets --stdin` before reads and after edits | 0 | Selected bytes passed; raw output suppressed | Task-owned selected content |
| Protocol group: five selected unittest methods and `verify_protocol.py` | 0 | 16 existing scenarios plus 14 old/new parity scenarios; syntax for eight modules; Git fixture bytes identical | `framework-sonar-20261115/protocol-quality/RESULTS.md` |
| Path group: `test_sonar_path_boundaries` | 0 | 15 scenarios pass; same baseline selectors expose the original defects (5 failures, 7 errors) | `framework-sonar-20261115/path-findings/` |
| Root: four selected shell/OSV/report unittest methods | 0 after correction | Shell compatibility and report ordering pass; OSV command contract and five retry scenarios pass | `framework-sonar-20261115/coordinator/` |
| `rtk bypass "$PYTHON" -B "$CODEX_RUN_ROOT/framework-sonar-20261115/coordinator/verify_report.py"` | 0 | One report-failure output matches baseline and required metadata order | `framework-sonar-20261115/coordinator/verify_report.py` |

Run-relative evidence paths are beneath the configured `CODEX_RUN_ROOT`. Final integrated verification appears below; the exact command/selector manifest is retained with task evidence.

## Security impact

Nine security report locations are targeted by the filename/evidence fixes. Negative tests reject traversal, absolute paths, backslashes, control characters and overlong tokens before I/O; legitimate names retain request/response/failure receipts. Evidence tests reject either an external case root or external source-binding input while allowing admitted input to reach the existing qualification boundary. These are focused admission checks, not historical I12 execution.

The remaining 23 security reports are candidate false positives or intentional trusted CLI input choices: 13 in CFamily/native-context/native-receipt/runtime-snapshot helpers, seven in protocol/lighttpd/nginx helpers, two already-HTTPS servers and one C path-formatting operation mislabeled as logging. JSON content cannot redirect a fixed output filename. Snapshot `--build-root` intentionally selects local input and has no private-input allowlist; do not infer one from the separate constrained report output. A future privileged service with untrusted CLI input would need a separate contract. Three `python:S1110` reports concern parentheses required by Python precedence. No Cloud transition or hotspot review was performed.

## Documentation and runtime evidence

Only this paired Change Record changes reader-facing documentation. No host runtime, full lifecycle, matrix or historical I12 qualification was run. Focused tests exercise parser behavior and path admission only. No Parent integration or MRTS change is implied.

## Checks not run

Fresh complete Sonar analysis belongs to existing CI. On 2026-11-15 the user authorized commit, push and Draft PR for this reviewed task branch; Cloud disposition and merge are outside that approval. Current delivery and analysis evidence is recorded in the task plan and PR after publication. The local aggregate/agentic scanner and Sonar MCP were not used. Ruff is absent from the Framework environment; no package was installed. Full `make lint` expands unrelated suites and was replaced by scoped validation. The configured Framework venv reports Python 3.14.4 while `.python-version` pins 3.15.2; exact pinned-interpreter CI remains unverified. No toolchain/dependency files were changed.

## Limitations and residual risk

Local edits target 80 maintainability reports and nine security locations; only fresh Cloud analysis can confirm rule closure. Twenty-six reports (23 security, three required-parentheses reports) retain source-backed review recommendations; they have not been silently accepted or marked false positive. Cloud remains at its prior failing analysis. Scoped scenario counts do not claim project-wide active-inventory cap enforcement. Overall service-level outcome remains partial pending delivery, current-head analysis and reviewed disposition.

## Final diff and review status

Local task branch `codex/framework-sonar-repair-20261115` in the isolated Framework worktree. At completion of local verification, staging, commit, push and PR had not yet occurred. Subsequent user approval permits those delivery steps; merge and switching the original checkout are outside this delivery. Parent pre-existing handoffs and Framework checkout identity are preserved. Initial automatic edit hooks could not complete on the external worktree; successful explicit scans resolved that prerequisite before further reads. OSV initially failed its exact-command test and passed after retaining helper-local `result_file`; an initial external report verifier import error was corrected before its scenario ran. No secret values or raw findings are recorded.


Independent full-diff review found one introduced regression: an extracted body-limit mapper referenced unbound `field`. The `NameError` was reproduced and corrected with the fixed `"body_limit_outcome"` key. A real existing reject fixture now checks both value and original-event provenance. Repeated symbol analysis found no further undefined globals; full review reports no other material findings.

Final integrated invocation, normalized to the documented Framework `PYTHON` and `CODEX_RUN_ROOT`, from the task worktree:

```sh
rtk bypass "$PYTHON" -B "$CODEX_RUN_ROOT/framework-sonar-20261115/coordinator/run_integrated.py"
```

Observed: exit 0. Manifest `framework-sonar-20261115/coordinator/verification.json` records actual expanded argv, cwd, complete test selectors, bounded non-secret environment values and every exit result. The six selections cover exactly 100 task-specific scenarios: runner 36, protocol tests 16, protocol parity 14, paths 15, shell/OSV/report tests 18 and report parity 1. All passed. Changed-Python syntax, static symbol checks, `sh -n ci/lib/common.sh` and `git diff --check` also passed. This repeat exercises the integrated source; the same scenarios are not counted again as new cases.

Native documentation checks are `rtk make check-doc-links check-change-records check-bilingual-docs check-repository-path-references` with configured Framework `PYTHON` and external `BUILD_ROOT`. The local-path check initially rejected machine-specific evidence references; documentation now uses portable configured roots. EN/DE review found equivalent facts and requested the exact command manifest now added. No scanner rule or check was weakened.
