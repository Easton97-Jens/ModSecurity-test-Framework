# Real pinned MRTS entrypoint integration

**Language:** English | [Deutsch](CR-20260929-mrts-real-integration.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `CR-20260929-mrts-real-integration` |
| Date (UTC) | 2026-09-29 |
| Base revision | `37315b43366d1f56045d3e9dc91d9d05782ff285` |
| Delivery target | Existing Framework Draft PR #128; no merge |

## Motivation and problem statement

The merge review required real generator/corpus evidence in addition to the
launcher tests using a harmless substitute. The user authorized completing
that bounded integration work. No other finding or repository is included.

## Affected components and security boundaries

The Framework shell entrypoint and its guard invoke the real separately pinned
MRTS generator. MRTS source and the gitlink remain unchanged. Test inputs and
outputs live in a fresh private child of RUNNER_TEMP, never in either source tree.

## Acceptance criteria

Both upstream-config-tests and feature-demo must produce nonempty rules and
FTW inventories whose paths and bytes equal direct generation with the same
pinned generator. The complete selected source identity must remain clean.
Undocumented global expdir/testdir/content must return the specific guard
rejection and leave outside sentinels unchanged. Absolute, traversal and
symlink output escapes must reach the real generator's path rejection without
altering their outside sentinels. An unrelated nonzero exit cannot count as pass.

## Alternatives considered

More fake-generator tests would not close the compatibility gap. Importing or
rewriting the generator would violate ownership. A full connector matrix is
not necessary for this generator-entrypoint contract and is not claimed.

## Implementation decision

Extend the existing read-only exact-head findings workflow without changing
its existing unit-test command, action pins, dependency lock or publisher
registrations. Initialize only the recorded MRTS gitlink in the fresh runner
checkout, with no remote-branch selection. A new bounded Python check executes
the actual shell entrypoint and generator, compares content hashes and checks
specific negative diagnostics. Each process has a timeout; private logs remain
in runner temporary storage. Only a small metadata receipt is printed.

## Changed files and tests

- `ci/checks/security/check-mrts-definition-integration.py`
- `.github/workflows/ci-findings-regressions.yml`
- This English/German Change Record pair.

## Commands and results

Source inspection of the actual entrypoint, generator and path helper was
performed. The new check was parsed as a Python AST, not executed locally.
The editor lacks required RTK and a provisioned checkout. The existing
launcher unit tests are retained unchanged. New-head CI must execute both
those tests and the real integration check; no future result is assumed.

## Security impact

Negative cases target only task-owned temporary paths. No installed service,
MRTS file, gitlink, CI token right or existing gate is changed. The explicit
rejection diagnostic prevents environment failures from masquerading as a
successful containment test.

## Documentation and runtime evidence

A successful integration emits a SHA-bound metadata receipt with corpus counts,
byte equality, rejected keys and preserved sentinels. Raw rules, original scan
payloads and diagnostic logs are not automatically published. This is generator
integration evidence, not ModSecurity host enforcement or a complete B03 fix.

## Checks not run

Local project tests and real corpus generation were not run in the editing
environment because the required execution wrapper and checkout are absent.
Actual CI/Sonar results must be read for the published follow-up SHA.

## Limitations and residual risk

Direct MRTS invocation remains outside the guard. The test does not claim
hostile same-UID isolation or full connector security. The earlier intake
record's open B03 status remains valid. No Parent gitlink is advanced.

## Final diff and review status

Only the bounded integration check, its workflow wiring and paired record are
added. The PR remains Draft; no merge, finding closure or waived check occurs.
