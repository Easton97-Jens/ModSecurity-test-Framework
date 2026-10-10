# NGINX fixed native event boundary contracts

**Language:** English | [Deutsch](20261008-23-nginx-event-boundaries.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | `20261008-23-nginx-event-boundaries` |
| UTC date | 2026-10-08 |
| Framework base revision | `93154133105fbeb2144ca02f6957282a1fc3b808` |
| Issue or pull request | Framework PR #137 follow-up; local only |

## Motivation and problem statement

Two Required IDs need actual phase1 rule callbacks with bounded projected metadata, not fabricated log-only events or configurable writer directives.

## Affected components and security boundaries

New standalone input/raw validator and unit tests. Catalog/schema/selection remain Root-owned; Parent runtime and URI producer are separate dependencies.

## Acceptance criteria

Actual native request_rule_match/pass/rule1100402, HTTP200, exact projected URI/truncated/redacted flags, no body/query payload and JSONL below actual NGX4096 buffer. Fixed URI256 contract requires independent at255/over256 child runs/receipts.

## Alternatives considered

Driver summaries or HTTP200 alone cannot prove native callback/truncation. No configurable product event-limit directive exists; fixed source contracts must be explicit.

## Implementation decision

Closed operation inputs produce nonsensitive long-query/at255/over256 requests. Raw validation binds actual bytes/hashes to one native TX per child and same-run Root/nobody cleanup. The enclosing receipt seals child basename/run/revision identity and exact receipt bytes. Query marker remains at long/escaped prefixes; Common validation of other fields is unchanged.

## Changed files and tests

tests/runners/nginx_event_boundary_operations.py, tests/no_crs/test_nginx_event_boundaries.py and this EN/DE pair. Existing pointer-role and MIME-wire pure helpers are reused and authenticated as explicit input dependencies by Parent.

## Commands and results

Framework-owned Python through RTK: event helper5 and mixed event/MIME/pointer16 tests passed, exit0. Deliberately accepting an invalid truncatedfalse unit fixture produced expected assertion RED exit1; correct negative suite GREEN. These are synthetic unit controls, not runtime observations. Repository/documentation results appear in the external handoff.

## Security impact

No Required shrinking, invented rule, Common validator weakening or MRTS writes. Wrong native rule/action/TX/flags, payload, oversized JSON, receipt seals, cleanup and identities are rejected.

## Documentation and runtime evidence

Actual Root source callback is MSCONN_EVENT_RULE_MATCHED/request_rule_match/pass with rule1100402. Source URI buffer is256, NGX writer4096; the 255/256 generator wording is explicitly source-bound. No native run/build occurred for this slice.

## Checks not run

Fresh native callback/URI projection, current module/artifact identity, integrated canonical97 and remote CI/Sonar await Root runtime integration.

## Limitations and residual risk

The canonical reader must safely reopen raw children and authenticate actual build/producer/process identity. Hashes alone cannot prove those layers. Shared runtime request-header/callback hooks are required before native invocation.

## Final diff and review status

Only standalone delegated Framework files; local commit without push/Gitlink/merge/MRTS. Overall runtime acceptance remains partial.
