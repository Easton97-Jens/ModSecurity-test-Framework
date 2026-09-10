# Change record

**Language:** English | [Deutsch](20260910-02-fix-canonical-runtime-lock-fixture.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260910-02-fix-canonical-runtime-lock-fixture` |
| UTC date | 2026-09-10 |
| Framework base revision | `9bb956e1b4bfaea1e1e6bbee5745c937d91d4726` |
| Issue or pull request | Pending a separate Framework Draft PR; no merge, dispatch, or existing-PR mutation is authorized. |

## Motivation and problem statement

Trusted canonical maintenance run `34464725066` correctly updated Envoy from
`1.39.0` to `1.39.1`, but a post-apply positive control still used the old
literal tuple. The runtime-lock checker correctly failed closed, so the one
canonical Draft-PR publisher was not reached. This Framework-only correction
changes the regression fixture, not runtime metadata, the updater, workflow
permissions, a token, a downloader, or an executable path.

## Affected components and security boundaries

The only behavior change is in
`tests/security_regression/test_runtime_component_lock.py`. The relevant
boundary is the static lock-profile checker in the trusted canonical
maintenance candidate; no workflow token, Action pin, publisher scope,
runtime URL, digest, downloader, or executable sink changes.

## Acceptance criteria

- The positive override follows the current reviewed Envoy profile and returns
  `0`.
- The altered version remains blocked with `77` and `ENVOY_VERSION drift`.
- No runtime-lock control or publisher authority broadens.

## Alternatives considered

Hard-coding the next Envoy release would make the same fixture stale again.
Weakening the checker would remove a valid provenance control. Both are
rejected.

## Implementation decision

The positive Envoy override now derives version, URL, and digest from the
current `envoy-ext-authz` lock profile. The negative control derives an
unambiguously altered patch version and must still report
`ENVOY_VERSION drift` with exit `77`. Hard-coding the next current release
would recreate the defect; the correction therefore remains data-derived and
test-only.

## Changed files and tests

- `tests/security_regression/test_runtime_component_lock.py`
- this paired Change Record

## Commands and results

| Command | Exit code | Concise result | Evidence |
| --- | --- | --- | --- |
| `python3 -m unittest tests.security_regression.test_runtime_component_lock -v` | 0 | 13 runtime-lock tests passed, including the changed positive and negative controls. | Isolated corrective worktree |
| `python3 -m unittest tests.security_regression.test_runtime_component_sync -v` | 0 | 19 runtime synchronization and fail-closed tests passed. | Isolated corrective worktree |
| `.venv/bin/python -m unittest tests.ci_security.test_update_workflow_tools -v` | 0 | 41 updater and native-candidate controls passed. | Existing repository Python environment |
| `.venv/bin/python -m unittest tests.ci_security.test_unified_common_maintenance_workflow -v` | 0 | 15 trusted-publisher and workflow-contract tests passed. | Existing repository Python environment |
| `python3 -m py_compile tests/security_regression/test_runtime_component_lock.py ci/tools/check-runtime-component-lock.py ci/tools/sync-runtime-components.py` | 0 | Relevant Python sources compiled. | Task-owned pycache root |
| `bash -n ci/lib/common.sh` | 0 | The unchanged canonical shell source remains syntactically valid. | Isolated corrective worktree |
| `python ci/tools/check-runtime-component-lock.py --lock ci/provisioning/runtime-component-lock.json --common ci/lib/common.sh --manifest ci/provisioning/runtime-components.manifest.json` | 0 | Checked-in runtime lock passed. | Existing repository Python environment |
| `python ci/tools/sync-runtime-components.py --check` | 0 | Checked-in runtime components are current. | Existing repository Python environment |
| `python ci/checks/documentation/check-change-records.py` | 0 | Paired Change Record contract passed. | Existing repository Python environment |
| `git diff --check` | 0 | No whitespace errors. | Isolated corrective worktree |

## Security impact

This repairs a fail-closed test fixture and does not relax a security control.
The alternate altered-version control remains active. No security remediation
or security-boundary relaxation is performed.

## Documentation and runtime evidence

This English/German record documents the test-only correction. Hosted run
`34464725066` and its retained caller-bound plan are the runtime/lifecycle
evidence; no new dispatch is performed.

## Checks not run

The system `python3` lacks PyYAML, but the existing repository Python
environment supplied it and the related tests passed. Ruff is unavailable both
there and on `PATH`; it was not installed. Exact-head hosted checks are pending
a Draft PR.

## Limitations and residual risk

A new master merge, a second canonical-maintenance dispatch, and closure of
#113/#114 need fresh current user authorization. Parent, MRTS, Gitlinks, and
existing PRs are unchanged.

## Final diff and review status

Local implementation and focused controls are complete; final diff, whitespace,
security review, and delivery evidence are pending. No default-branch write,
force operation, or branch-protection bypass is used.
