# Add Framework contract API

**Language:** English | [Deutsch](20260824-01-add-framework-contract-api.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20260824-01-add-framework-contract-api |
| UTC date | 2026-08-24 |
| Framework base revision | c40e924ec5c341032908e0082feba1d37ed1dfda |
| Issue or pull request | Framework Draft PR #110 (OPEN/Draft). API/remediation head `dad53dbe63fbfce97030836663ac35afbd7bb90f` passed Sonar check `97501291097` with zero annotations and terminal hosted checks; this record is a documentation-only reconciliation. |

## Motivation and problem statement

External consumers previously loaded catalog scripts by file path. The
five-connector CRS script then attempted a bare sibling import and failed
outside the Framework working directory. The Framework needed a stable public
package boundary for inventory, selection, metadata, typed expectations,
result validation, and profile contracts without consumer sys.path changes.

## Affected components and security boundaries

- modsecurity_test_framework/: public package, static contract resource, and
  dependency-free wheel builder.
- ci/tools/generate-framework-contract-catalog.py: deterministic maintenance
  generator from checked-in sources.
- ci/checks/catalog/five_connectors_with_crs_no_mrts.py: bounded legacy sibling
  lookup for direct-file compatibility.
- tests/contract_api/: API, package-install, external-CWD, safety, and
  compatibility controls.

The relevant boundary is untrusted JSON capability/result input and package
resource loading. The public API has no caller-selected Python module loading,
dynamic case discovery, or CWD-based Framework resource lookup.

## Acceptance criteria

- An installed public package exposes the seven requested contract operations.
- The JSON-only module CLI supports inventory, select, describe, and validate,
  and contract errors have documented exit code 2.
- No-CRS and CRS profile metadata load with schema and Framework commit binding.
- Expectations are a strict closed tagged union and preserve non-HTTP semantics.
- Existing catalog commands remain compatible, including direct external
  loading of the five-connector legacy script.
- Public input handling rejects duplicate JSON keys, unsafe paths, oversized
  documents, invalid types, and conflicting test identities.
- The package resource is reproducibly checked against checked-in sources.

## Alternatives considered

- Telling Parent consumers to add Framework directories to sys.path was
  rejected because it preserves the fragile import boundary.
- Reusing the YAML runner dynamically at consumer runtime was rejected because
  it would add unbounded source discovery and parser input to the public path.
- Adding a runtime YAML dependency was rejected because a generated,
  payload-free JSON resource can serve the consumer API directly.

## Implementation decision

The new public module loads only its bundled static contract catalog through a
package-relative resource. A checked-in generator creates that catalog from the
166 No-CRS entries and the YAML corpus, merges only generic identical No-CRS
source representations, and rejects ambiguous identities. A minimal
dependency-free PEP 517 backend records the checked-out source commit into a
wheel while source checkouts resolve their live HEAD using a fixed non-shell
Git invocation.

The legacy five-connector script retains its CLI and receives only a fixed
Framework-owned catalog-directory lookup. New consumers use the package API
instead of that internal fallback.

## Changed files and tests

- pyproject.toml, modsecurity_test_framework/, and the generated contract JSON:
  public installable API and package data.
- ci/tools/generate-framework-contract-catalog.py and Makefile: deterministic
  catalog freshness and focused test target.
- ci/checks/catalog/five_connectors_with_crs_no_mrts.py: direct-file sibling
  import compatibility.
- tests/contract_api/test_public_contract_api.py: external package/CLI,
  catalog/profile, typed union, result, duplicate, path, commit, category, and
  wrapper controls.
- Paired public API documentation and this English/German Change Record pair.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| make test-contract-api with the selected Framework Python and task-owned build roots | 0 | 20 focused public package, external-CWD, CLI, metadata, typed-expectation, path-alias/intermediate-symlink/FIFO, generator-output, and legacy controls passed. | framework-contract-api-20260824 |
| python ci/tools/generate-framework-contract-catalog.py --check | 0 | Generated payload-free catalog matches the checked-in source catalog and YAML cases. | framework-contract-api-20260824 |
| make test-no-crs-contract | 0 | 98 native No-CRS contract tests passed. | framework-contract-api-20260824 |
| make test-five-connectors-with-crs-no-mrts-contract | 0 | 26 tests passed on the complete retry after one known FIFO-observer timing race; the focused control also passed. | framework-contract-api-20260824 |
| make check-documentation, make test-change-record-contract, make test-makefile-contract, and make check-no-crs-catalog | 0 | Documentation, traceability, Makefile, and 166-case catalog contracts passed. | framework-contract-api-20260824 |
| Changed-Python py_compile and git diff --check | 0 | Compilation and whitespace checks passed. | framework-contract-api-20260824 |
| Local make lint and corrected canonical-pin check | guarded / 0 | The inherited ambient `FRAMEWORK_ROOT` made the broad local lint stop at its intended root-identity guard; the worktree-corrected canonical-pin check passed. Final exact-head hosted `scaffold-lint` checks passed twice. | framework-contract-api-20260824 |
| Successor Codex Security Diff Scans and final Sonar evidence | 0 | The remediation and generator-minimal patch-exact scans are valid with complete coverage and zero reportable findings. Sonar check `97501291097` passed with zero annotations on `dad53dbe63fbfce97030836663ac35afbd7bb90f`. | framework-contract-api-20260824 |

## Security impact

The new API rejects duplicate JSON keys, malformed UTF-8, absolute/traversal
and path-alias input, intermediate/final symlinks, special files, oversized
input, unknown expectation kinds, unexpected fields, and Boolean HTTP
statuses. The final descriptor open is nonblocking, so a writerless FIFO is
rejected rather than hanging. It emits only stable JSON error codes. The
implementation uses no eval, exec, caller-controlled module name, shell
interpolation, suppression, or exception-path disclosure. Generator
output-parent symlinks and malformed unhashable enum values are also rejected;
the latter returns the documented contract error/exit code 2. The successor
and generator-minimal Security Diff Scans are complete and valid with zero
reportable findings; no suppression, exclusion, or scanner-policy change was
used.

## Documentation and runtime evidence

The paired public API guide explains installation, imports, operations, typed
expectations, JSON CLI, exit codes, input restrictions, maintenance, and
legacy compatibility. The listed tests are static/package contract evidence;
no connector host runtime, request payload, or lifecycle runtime success is
claimed.

## Checks not run

- Full connector smoke, runtime matrix, protocol, and MRTS matrix checks are
  not part of this package/API change and require connector-owned runtimes or
  separately scoped MRTS authority.
- Ruff is unavailable in the selected Framework virtual environment and was
  not installed because this task has no dependency-installation authority.
- The initial Draft PR #110 SonarCloud check failed its new-code quality gate
  on task-owned complexity/path findings. The normally pushed remediation heads
  `6ff376f00c050520f4d01d8b0337a77253384a4b`,
  `049f73e6c4f6328fd0dd8f6615d7ad1035b59741`, and
  `dad53dbe63fbfce97030836663ac35afbd7bb90f` resolved them without suppression.
  The last head passed Sonar check `97501291097` with zero annotations; relevant
  terminal hosted checks passed and three advisory-only checks were intentionally
  skipped. This documentation-only reconciliation does not change API source.

## Limitations and residual risk

The public resource exposes structured metadata, not raw request, response,
rule, or log payloads. A source archive built without Git cannot supply a
commit and reports unavailable rather than inventing provenance. Parent
integration, a Parent gitlink update, and MRTS changes remain out of scope.
No security risk is accepted.

## Final diff and review status

The initial task-owned Framework commit was pushed as independent Draft PR
#110. Its initial SonarCloud run identified 13 task-owned findings. The bounded
remediation was normally pushed in
`6ff376f00c050520f4d01d8b0337a77253384a4b`,
`049f73e6c4f6328fd0dd8f6615d7ad1035b59741`, and
`dad53dbe63fbfce97030836663ac35afbd7bb90f`; the final API/remediation head
passed Sonar check `97501291097` with zero annotations and all relevant
terminal hosted checks. The branch remains independent, OPEN, and Draft with
no reviews or merge. This Change Record update is documentation-only; no
merge, rebase, force-push, auto-merge, automatic ready-for-review, Parent
change, or MRTS action is authorized.
