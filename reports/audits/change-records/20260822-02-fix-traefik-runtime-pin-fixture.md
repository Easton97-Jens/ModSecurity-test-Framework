# Change record

**Language:** English | [Deutsch](20260822-02-fix-traefik-runtime-pin-fixture.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20260822-02-fix-traefik-runtime-pin-fixture` |
| UTC date | 2026-08-22 |
| Framework base revision | `52fe6ee334f1381c35d5c3b7140433c626469523` |
| Issue or pull request | `FND-FRAMEWORK-0112`; Framework pull request pending at record creation |

## Motivation and problem statement

Framework master lint run `32557675044` failed after the trusted maintenance
change in PR #106 updated the reviewed Traefik release tuple to `3.7.11`.
The implementation, lock, and manifest were consistent, but this regression
fixture still embedded the former version, archive name, and digest. Its stale
positive archive therefore did not reach the intended digest control.

## Affected components and security boundaries

- `tests/security_regression/test_traefik_runtime_pin_contract.py`: derives
  its legitimate tuple from the checked-in runtime-component lock and retains
  deliberately non-canonical negative values.
- The exercised boundary remains the verified Traefik archive path:
  provenance validation, SHA-256 verification before extraction, and staged
  binary-version validation.

No production provisioning script, GitHub Actions permission, publisher path,
Parent gitlink, or MRTS revision is changed.

## Acceptance criteria

1. The legitimate test fixture follows the current canonical Traefik lock
   tuple without a manually duplicated release version, archive, or digest.
2. A bad archive digest fails before extraction or staging.
3. A verified archive stages and runs in the download-disabled offline path.
4. A same-version bare binary cannot bypass verified staging.
5. The native lock and synchronisation checks pass, followed by Framework lint
   and current-head hosted evidence before merge.

## Alternatives considered

- Updating only the three `3.7.10` literals was rejected because the next
  reviewed Traefik update would recreate this CI failure.
- Weakening the digest or staging assertions was rejected because they are the
  security boundary that this fixture protects.
- Changing the runtime provisioner was rejected because the failure is test
  fixture drift; the provisioner already fails closed.

## Implementation decision

The test reads version, asset name, SHA-256, OS, and architecture from every
Traefik profile in `runtime-component-lock.json`, rejects missing or divergent
profiles, and uses that one tuple only for legitimate controls. Negative cases
derive a distinct version, platform, or digest at runtime. This removes stale
maintenance coupling while preserving the test's independent assertions that
`common.sh` matches the reviewed lock-derived tuple.

## Changed files and tests

- `tests/security_regression/test_traefik_runtime_pin_contract.py`
- this paired English/German Change Record

The updated test covers the lock-derived positive path, incorrect digest before
extraction, offline verified staging, environment mutations, and the
same-version bare-binary bypass attempt.

## Commands and results

| Command | Exit code | Concise result | Run ID or approved evidence path |
| --- | --- | --- | --- |
| `rtk proxy …python -m py_compile tests/security_regression/test_traefik_runtime_pin_contract.py` | 0 | The modified test compiles with the Framework-owned virtual environment. | Isolated Framework worktree |
| `rtk proxy …python -m unittest discover -s tests/security_regression -p test_traefik_runtime_pin_contract.py -v` | 0 | 11 Traefik archive-boundary tests passed. | Isolated Framework worktree |
| `rtk proxy … make check-runtime-component-lock` | 0 | The common, lock, and manifest tuple passed the native lock checker. | Task-owned external build/TMP root |
| `rtk proxy … make check-runtime-components` | 0 | Canonical runtime-component synchronisation passed. | Task-owned external build/TMP root |
| `rtk proxy … make … lint` | 0 | Complete Framework lint passed, including runtime-pin, workflow-security, documentation, and whitespace checks. | Task-owned external build/TMP root |

## Security impact

This is a CI-availability repair at a security regression boundary. The
original bad-digest path now reaches and passes its fail-closed assertion; a
legitimate offline archive succeeds; and the alternate bare-binary bypass test
continues to fail before execution. The verified provisioner and its trust
boundaries are unchanged.

## Documentation and runtime evidence

This English/German Change Record documents the Framework-only repair. Parent's
canonical `FND-FRAMEWORK-0112` evidence ledger retains the failed hosted run
and local reproduction receipt. No connector or MRTS runtime was changed or
run.

## Checks not run

A Framework pull request, current-head hosted checks, SonarQube Cloud,
review/thread validation, and the protected master merge remain pending.

## Limitations and residual risk

The lock-derived fixture intentionally relies on the lock schema being checked
in and internally consistent; malformed, missing, or divergent Traefik
profiles fail the test rather than silently accepting a tuple. Hosted service
behavior remains unverified until a fresh PR and resulting-master runs finish.

## Final diff and review status

The implementation is in an isolated task-owned Framework worktree. Complete
Framework lint, whitespace validation, and the focused security/diff review
passed before commit. No Parent gitlink or MRTS content is staged.
