# Private hosted Sonar diagnostics

**Language:** English | [Deutsch](20261109-01-private-sonar-diagnostics.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261109-01-private-sonar-diagnostics |
| UTC | 2026-11-09 |

## Motivation and problem statement

Passing hosted Gates coexist with Shell/JSON omissions and CFamily parser/IR gaps. Public DEBUG output can disclose secrets. A private producer is needed for causal facts.

## Affected components and security boundaries

Framework owns the new regular Node action and offline tests. Phase 1 changes no token-bearing workflow. After review and publication, a later caller commit must use the exact previous immutable remote action SHA. PR-head local executable code must not receive the token. Native pins/checkers must bind that same previous SHA. Parent and MRTS retain separate ownership.

## Acceptance criteria

Preserve official action pin, scanner version, signature verification, full scope, source identity, native inputs and Gate waits. Account all warning/error lines with fixed categories or explicit unknown counts. Publish only inventory-bound source-relative locations, fixed codes and bounded numbers. Keep raw logs/command files private, remove them and terminate inherited process groups.

## Alternatives considered

Public DEBUG, local PR-head token execution, custom profiles, exclusions, reduced JSON baselines and speculative semantic changes are rejected.

## Implementation decision

Runner-managed Node 24 invokes the unchanged pinned official action with the same interpreter. Raw output and child workflow commands remain private. Framework keeps Compile-Commands and its exact cfd5 fixture; Parent keeps AutoConfig and its exact include/std/project/Gate contracts. No executable workspace code is imported. Known JSON budgets, parse counters and IR signals remain distinct; unknowns do not become coverage proof.

## Changed files and tests

Action metadata/main, offline Node subprocess tests and this paired record. Later workflow/native contract templates remain non-runnable until the previous reviewed wrapper commit is frozen.

## Commands and results

Syntax validation exited 0 and all 14 focused offline tests passed for the reviewed source. Tests cover warning tails, inherited-group descendants, credential and command confinement, validated identity/readback, canonical include containment, safe counters and the cumulative raw-file budget. No canary appeared in test output. Private task receipts retain exact-source evidence. No hosted run or delivery is claimed.

## Security impact

No hook is disabled or redirected. Unrelated credentials and execution-injection variables are excluded. Raw bytes and exception text are never replayed. The complete capture file is limited to 128 MiB across all children. Include paths must retain canonical spelling and resolved containment. Output project/scanner identity is fixed by owner; CE task identifiers come only from bounded, no-follow regular report readback with exact project agreement. The immutable caller boundary is mandatory. DEBUG remains sensitive; historical public engine source does not certify current Cloud context confidentiality.

## Documentation and runtime evidence

Private candidate/evidence stays in external task roots. No connector runtime campaign, deployment or MRTS change is claimed.

## Checks not run

Native mutation suites for the later caller changes, immutable caller integration, hosted complete-scope diagnostics and exact-head Gate readback remain pending.

## Limitations and residual risk

Inherited process groups are controlled; deliberate new-session escapes require runner containment. Unknown diagnostics remain explicit. Similar Parent/Framework counters do not prove identical causes. No analyzer gap is closed by this preparation.

## Final diff and review status

Private correction for independent review; overall readiness remains open.
