# Framework Sonar CLI security analysis

**Language:** English | [Deutsch](20261026-01-framework-sonar-cli-security.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261026-01-framework-sonar-cli-security |
| UTC date | 2026-10-26 |
| Framework base revision | 99a7985 |
| Issue or pull request | [PR #138](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/138) |

## Motivation and problem statement

Provide Framework-owned Sonar CLI security analysis across maintained languages instead of relying only on external automatic analysis.

## Affected components and security boundaries

Framework workflow, scanner properties, native compile capture, workflow secret boundary, canonical Action source/lock and paired docs. Parent/gitlink unchanged; MRTS read-only and excluded as an independent repository.

## Acceptance criteria

Broad root scope; real native compilation database; exact SHA; restricted scanner token; terminal server/gate wait; explicit coverage opt-out. Live scanner/server evidence remains pending.

## Alternatives considered

AutoConfig cannot provide CFamily taint analysis. Clang -MJ failed native C99 -Werror on a duplicate typedef in third-party headers. Actual GCC command capture preserves the unchanged native flags and compiles the complete one-unit inventory.

## Implementation decision

Pinned official scanner Action/CLI. Compile-only native Make records real successful compiler argv and rejects translation-unit inventory mismatch; no fake compile records, runtime execution or warning suppression. Coverage alone is excluded by explicit user request.

## Changed files and tests

New sonarqube.yml, sonar-project.properties, prepare-sonar-cfamily.py, prepare-sonar-sdk.sh and test_sonar_analysis_contract.py; narrow workflow checker exception; canonical Sonar Action group plus generated lock; exact generated-view registration in check-common-versions.py; paired security documentation.

## Commands and results

Actual GCC compile-only native Make: exit 0, one real source, strict original flags; repeated with the genuine canonical native SDK build layout. Fourteen focused test methods passed (40 expanded checks), including rejection of replaced SDK producer, mixed SDK layouts, workflow-level execution overrides and staging symlinks. Existing workflow-security suite: 9 passed; canonical-workflow-pin suite: 12 passed before Hosted remediation. Canonical-common validation reproduced the Hosted copied-pin failure and passed after registering only the new generated workflow. Evidence root: external task run `framework-sonar-cli-security-20261026`. Local interpreter 3.14.4 is an alternative to exact hosted 3.14.8; no cached exact interpreter found in inspected toolchain locations.

## Security impact

No security PASS claimed. A confirmed integration-checker bypass was fixed: three variants (second checkout, inserted git checkout and changed reviewed script body) were first incorrectly accepted by the full checker, then rejected after the fix. Exact reviewed step equality rejects extra Actions, environments and wrappers. Action SHAs follow the validated canonical source/lock contract; a regression verifies its update and fail-closed drift behavior. Private output directories and symlink rejection protect pre-existing external sentinel files; repeated real compilation passes. Same-repository PR guard, exact checkout, read-only GitHub permissions and token confined to the pinned scanner step are validated; privileged triggers, token reuse and changed arguments are rejected.

## Documentation and runtime evidence

Updated docs/security/ci-security-tooling.md and .de.md. No connector runtime or lifecycle evidence collected. Successful native compilation proves compiler context only.

## Checks not run

Live Sonar upload, CE completion, findings/hotspot readback and exact-head gate: coordinator-owned pending provider execution. The first Hosted run used exact Python 3.14.8 but failed before scanning because the distribution SDK lacks maintained C API declarations; strict flags correctly rejected it. The follow-up builds the existing canonical approved SDK instead. That Hosted SDK build and the live scanner remain pending. Broad runtime/matrix tests are outside scope.

## Limitations and residual risk

Automatic analysis must be disabled on the existing Sonar project before CLI analysis; token existence is not authorization proof. Language/rule availability and terminal analysis/gate require live evidence. Coverage targets are explicitly outside scope.

## Final diff and review status

Initial reviewed implementation published in Draft PR #138 at 47ebce8. Focused local Hosted-remediation checks completed; follow-up coordinator review/delivery and exact-head live analysis remain pending. No merge is authorized and the task remains partial.
