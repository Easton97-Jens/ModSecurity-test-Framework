# Framework updater readiness remediation

**Language:** English | [Deutsch](20261026-02-framework-updater-remediation.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261026-02-framework-updater-remediation |
| UTC date | 2026-10-26 |
| Framework base revision | e337869 |
| Issue or pull request | [PR #138](https://github.com/Easton97-Jens/ModSecurity-test-Framework/pull/138) |

## Motivation and problem statement

Scheduled Common maintenance stopped on an empty generated-catalog status message (run 40317131728); Python maintenance selected a released patch before its matching setup-python runner build existed (run 40328143037). The new generated Sonar workflow also lacked automatic publisher path authority.

## Affected components and security boundaries

Framework planning, Python metadata preflight, exact generated-view publisher paths and their strict checker. Parent gitlink unchanged; MRTS remains read-only.

## Acceptance criteria

Silent generators retain explicit nonempty bounded statuses; latest Python candidates require official release and exact maintained runner build; all exact Sonar update-path consumers agree. Keep current pins, no downgrades, token scopes or auto-merge expansion.

## Alternatives considered

Relaxing the reconciler or broadly permitting workflow paths would hide broken contracts. Installing a not-yet-published interpreter is impossible; silently choosing an older candidate misstates the latest release.

## Implementation decision

Fix status production, retain consumer validation, add only the Sonar workflow path and update its exact reviewed publisher profile. Both Python resolvers share a bounded tokenless/no-redirect manifest check for Ubuntu 24.04/x64; both Common and separate Python workflows pin that runner, and the strict Common contract rejects runner drift. Missing builds produce a blocked result without source writes.

## Changed files and tests

Maintenance producer, Python updater/manifest helper, workflow-tool path contracts, common/Python workflows, exact security checker, offline readiness and existing regressions; paired workflow documentation.

## Commands and results

Producer/consumer and path/readiness regressions reproduced the original failures before correction. 156 focused updater/security methods passed after correction; after completing the runner contract, 74 affected workflow/installability/security methods passed. Logs are retained under the external task evidence root. Read-only live Python resolution returned current 3.14.8, candidate 3.14.10, update_available and updated=false after the official runner manifest caught up.

## Security impact

No secret values or write-capable provider actions. Strict bounded reconciler, exact publisher paths, App scopes, Draft-only publication and independent candidate validation remain enforced. Availability preflight does not substitute for actually installing/testing the candidate.

## Documentation and runtime evidence

Updated paired GitHub Actions security guide. No connector/runtime tests or new lifecycle evidence.

## Checks not run

Scheduled default-branch publication and actual generated maintenance PR remain pending separately authorized master integration; no live publication was invoked.

## Limitations and residual risk

Official release and runner manifest availability can change independently; missing or malformed manifests fail closed. A successful offline check or read-only resolver does not prove a maintenance branch or PR was created.

## Final diff and review status

Local implementation and focused evidence prepared for coordinator review and normal PR follow-up. No Git/provider mutation by this worker.
