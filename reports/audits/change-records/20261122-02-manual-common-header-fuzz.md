# Change Record 20261122-02-manual-common-header-fuzz

**Language:** English | [Deutsch](20261122-02-manual-common-header-fuzz.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261122-02-manual-common-header-fuzz |
| UTC date | 2026-11-22 |
| Framework base revision | `b4d619127a3fbd2a4074998e874c592d693413b9` |
| Issue or pull request | Prepared for the manual-fuzzing draft PR. |

## Motivation and problem statement

Make the existing Common HTTP header fuzz test available to maintainers through GitHub Actions.

## Affected components and security boundaries

Framework owns the harness. The fixed Connector checkout supplies the shared C sources.

## Acceptance criteria

The workflow starts with `workflow_dispatch`, runs the existing bounded Make target on a GitHub-hosted runner, and fails the job when the test fails.

## Alternatives considered

A pull-request trigger would add randomized work to the fixed test selection. Manual dispatch keeps the existing on-demand model.

## Implementation decision

The selected Framework revision supplies the harness. The separately checked out Connector fixture is pinned to `d21e34eb42b7e12793f670e318954798293bb897`. The workflow checks the fixture HEAD before invoking the Connector Makefile against the selected Framework.

On the default branch, use **Actions → Common HTTP header fuzzing → Run workflow**.

## Changed files and tests

- `.github/workflows/fuzz-common.yml`
- This English and German Change Record pair.

## Commands and results

Repository-pinned `actionlint` with the repository's configuration and `bash -n` both exited `0`. The exact workflow shell step, exercised locally with Clang 19.1.7, exited `0`.

With Clang available and `BUILD_ROOT` set to a writable absolute path outside the worktrees, run:

```sh
rtk make -C "$CONNECTOR_ROOT" FRAMEWORK_ROOT="$TEST_ROOT" ON_DEMAND_TESTS=1 BUILD_ROOT="$BUILD_ROOT" check-common-http-header-fuzz
```

## Security impact

The job uses a five-minute limit, read-only repository permissions and checkout without persisted credentials. The build, compiler temporary files and full fuzz output stay in a per-run temporary directory. The job publishes only the test status.

## Documentation and runtime evidence

The existing in-process fuzz harness completed in the local check. The test does not start a Connector service.

## Checks not run

A hosted manual dispatch is pending until the workflow is available on the default branch. The local validation disabled LeakSanitizer because the scratch sandbox restricts its process inspection.

## Limitations and residual risk

The checks cover the shared HTTP header helper against the fixed Connector revision. Refresh the fixture pin after reviewing compatibility with a newer Connector revision. The bounded run samples generated inputs for 15 seconds. Retain the fixed regression suite for continuous coverage.

## Final diff and review status

The diff adds the manual workflow and the paired Change Record. The current pull-request test inventory stays in effect.
