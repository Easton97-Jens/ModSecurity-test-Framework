# Change record: Exclude MRTS from Framework documentation link checks

**Language:** English | [Deutsch](20260726-04-exclude-mrts-from-documentation-link-checks.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260726-04-exclude-mrts-from-documentation-link-checks` |
| UTC date | 2026-07-26 |
| Framework base revision | `de705a5efb872f95f010346fe2e6143c88876ad4` |
| Issue or pull request | Draft Framework PR [#52](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/52) from task branch `agent/remediate-active-framework-findings-20260726`; no merge is authorized. |

## Motivation and problem statement

`FND-FRAMEWORK-0010` requires the Framework documentation aggregate to prove
that it never traverses the independently owned MRTS submodule. The variable
and repository-path checks already have explicit `tools/MRTS/` exclusions, but
the Markdown-link checker previously depended on Git's current omission of
submodule contents. That implicit behavior did not provide a direct boundary
control if a future inventory reported a nested Markdown path.

## Affected components and security boundaries

- `ci/checks/documentation/check-doc-links.py` owns the Framework Markdown
  inventory for local-link validation.
- `tools/MRTS` remains a separately owned, read-only submodule. It is not
  Framework documentation and is not parsed, validated, or modified here.
- The control narrows Framework traversal only; it does not suppress checks
  for tracked Framework Markdown outside the MRTS boundary.
- Parent source and Gitlink, Framework-to-MRTS Gitlink, and MRTS source are
  not changed.

## Acceptance criteria

- A `tools/MRTS/...` path is ignored even when the Markdown inventory reports
  it explicitly.
- A tracked Framework Markdown path remains selected by the same inventory.
- The focused regression, complete Framework documentation aggregate, and
  Change Record validation pass.
- No MRTS file is read by the regression beyond its task-owned synthetic
  fixture, and no production MRTS source or Gitlink changes.

## Alternatives considered

- Relying solely on current `git ls-files` submodule behavior was rejected
  because it is an implicit and untested boundary.
- Recursively validating MRTS documentation was rejected because it crosses
  the repository ownership boundary and would treat MRTS content as Framework
  documentation.
- Broadly disabling Markdown-link validation was rejected because Framework
  documentation must remain covered.

## Implementation decision

The Markdown-link checker's excluded directory set now explicitly contains
`tools/MRTS`. A focused regression supplies a synthetic Git inventory with one
Framework guide and one deliberately broken MRTS Markdown file. It proves that
only the Framework guide is returned, so the aggregate cannot reach the
submodule even if the inventory is unexpectedly broadened.

## Changed files and tests

- `ci/checks/documentation/check-doc-links.py`: explicit MRTS-submodule
  exclusion for the Markdown inventory.
- `tests/security_regression/test_parser_hardening.py`: direct regression for
  an inventory that contains both a Framework document and an MRTS path.
- This paired English/German Change Record.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| Focused parser/documentation regression | 0 | Eleven tests passed, including the explicit MRTS inventory exclusion. | Task worktree local validation |
| `make check-documentation` on the candidate | 0 | Link, bilingual, path-reference, and Change Record checks passed; the aggregate retained the MRTS-submodule exception. | Task worktree local validation |
| `make lint` | 0 | Framework syntax, contracts, regressions, documentation, and diff checks completed on the candidate. | Task worktree local validation |

## Security impact

This is an ownership and traversal-boundary hardening. It prevents an
independent submodule document from influencing the Framework documentation
result or causing the Framework checker to read unowned Markdown. It does not
weaken Framework link validation, workflow security, provenance controls, or
any scanner.

## Documentation and runtime evidence

The behavior is a static documentation-inventory control and has no connector
runtime claim. The regression uses only a task-owned temporary fixture and a
mocked Git inventory; it does not inspect or execute MRTS content.

## Checks not run

- Native Apache lifecycle and NGINX H2 execution remain blocked by absent host
  tools and are not substituted by this static documentation control.
- The external Codex Security rank-input helper is not Framework source, and
  no Codex Cloud scan/finding interface is available in this task environment.
- Hosted exact-head PR checks are pending until the draft PR exists.

## Limitations and residual risk

This change does not manufacture the native evidence required by
`FND-FRAMEWORK-0007` or `FND-FRAMEWORK-0009`, repair the external-plugin scope
of `FND-FRAMEWORK-0025`, or substitute GitHub results for
`FND-FRAMEWORK-0029` Codex Cloud evidence. On refreshed master,
FND-FRAMEWORK-0013, 0018, 0019, 0031, 0036, 0054, and 0057 already have their
respective passing source controls; this PR deliberately does not duplicate
or weaken them.

## Final diff and review status

The final diff is limited to the explicit Framework documentation boundary,
its focused regression, and this required paired record. Parent, both
Gitlinks, and MRTS remain outside scope. Local and hosted final review status
will be recorded from the exact pushed draft-PR head; no merge is authorized.
