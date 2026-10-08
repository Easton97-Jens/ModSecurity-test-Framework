# Change record

**Language:** English | [Deutsch](20261008-26-nginx-captured-wire-loader.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261008-26-nginx-captured-wire-loader |
| UTC date | 2026-10-08 |
| Framework base revision | f22f03cc30253d6e5839a0a2272b22f209fc4b13 |
| Issue or pull request | Parent-coordinated bounded native reader fix; no independent issue |

## Motivation and problem statement

The strict reader captured and authenticated the framing parser, but the sequence
helper reopened its live sibling through `__file__`. Different or missing live
bytes could therefore change the executed proof helper after source capture.

## Affected components and security boundaries

Framework native bundle helper loading and sequence parser initialization only.
The captured-source execution boundary is security relevant. Source whitelists,
source reopening, artifact authority, central normalization and schemas are unchanged.

## Acceptance criteria

Captured parsing ignores foreign or missing live siblings; missing captured parser
bytes fail closed. Successful and failed helper execution restores scoped modules.
Ordinary driver loading retains strict valid/invalid response parsing.

## Alternatives considered

Reopening and hashing the sibling again would still leave an execution race.
Changing global import paths would widen authority. The reader instead executes
the existing captured dependency and injects that exact module privately.

## Implementation decision

`load_helpers` compiles the captured framing dependency under the existing lock
and restoration block, then supplies `_AUTHENTICATED_WIRE` to the sequence helper
before execution. The sequence initializer uses it when supplied; normal drivers
keep their existing sibling loader. No captured dependency means an explicit error.

## Changed files and tests

- `tests/runners/nginx_native_operation_bundle.py`: only `load_helpers` changes.
- `tests/runners/nginx_lifecycle_sequence.py`: bounded initializer seam.
- `tests/no_crs/test_nginx_captured_wire_loader.py`: five controlled loader tests.
- This paired English/German record.

## Commands and results

Framework Python is `/var/tmp/codex/ModSecurity-test-Framework/venv/bin/python`;
commands use RTK, `PYTHONNOUSERSITE=1`, and external temporary/cache roots. Logs
are under `/var/tmp/codex/ModSecurity-conector/analysis/nginx-all-required-20261008T124555Z/`.

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy env … python -m unittest -v tests.no_crs.test_nginx_captured_wire_loader` before fix | 1 | Five controls: one failure, three errors; ordinary fallback passed | stream-c-captured-wire-red.log |
| First combined unittest invocation | 1 | 31 passing checks; incorrect `tests.runners` sequence test path caused one import error | stream-c-captured-wire-green.log |
| `rtk proxy env … python -m unittest -v tests.no_crs.test_nginx_captured_wire_loader tests.no_crs.test_nginx_native_operation_bundle tests.no_crs.test_nginx_lifecycle_sequence tests.no_crs.test_nginx_http11_framing` | 0 | 52 tests passed | stream-c-captured-wire-regressions.log |
| `rtk proxy env … python -m py_compile` for the three changed Python files | 0 | Syntax passed | External bytecode cache |
| Current `check-change-records.py` / focused `record_errors` on this pair | 1 / 0 | Global checker blocked only by unchanged historical sequence record headings; this pair passed | stream-c-captured-wire-docs.log |
| Current `check-doc-links.py` and `check-variable-documentation.py` | 0 / 0 | Links and bilingual documentation passed | stream-c-captured-wire-links.log; stream-c-captured-wire-bilingual.log |
| `rtk git diff --check` | 0 | No whitespace errors | Focused worktree |

## Security impact

The original live-file execution path and alternate missing-captured dependency
fallback are blocked by controlled tests. Existing authority checks and namespace
restoration are preserved; no blanket imports or validation exceptions are added.

## Documentation and runtime evidence

This English/German record documents the change. Only pure source-loader tests
were executed; no native connector runtime or lifecycle coverage is claimed.

## Checks not run

Native build/runtime, E2E and full repository lint are outside this bounded slice.
Root integration must validate its independently expanded dependency whitelist.
The full Change Record checker did run but remains blocked by the unchanged
`20261008-04-nginx-native-sequence-observations` pair's historical headings;
those out-of-scope records were not modified.

## Limitations and residual risk

Authenticated source bytes remain supplied by the existing reader authority.
This change does not authenticate ordinary driver loading or establish build trust.
Parent gitlink is unchanged; MRTS remains read-only.

## Final diff and review status

Focused diff reviewed for scope, whitespace, secrets and cleanup behavior. Only
the two bounded source seams, new tests and paired record are delivered. Normal
Framework commit is handed to the Parent coordinator; no push or gitlink update.
