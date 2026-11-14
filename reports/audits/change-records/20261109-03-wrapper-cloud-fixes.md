# Private Sonar wrapper source fixes

**Language:** English | [Deutsch](20261109-03-wrapper-cloud-fixes.de.md)

## Identity

| Field | Value |
| --- | --- |
| Change ID | 20261109-03-wrapper-cloud-fixes |
| UTC | 2026-11-09 |

## Motivation and problem statement

The hosted Framework PR analysis reported 21 JavaScript issues in the private diagnostics wrapper and its offline tests. Fixed Git execution, bounded parsing and smaller functions address their source causes before a new immutable action can be published.

## Affected components and security boundaries

Framework owns the wrapper, offline tests and this paired record. Parent and MRTS sources and gitlinks are unchanged. Caller publication and hosted validation remain separate steps.

## Acceptance criteria

Preserve diagnostic accounting, bounded source identities, private captures, credentials, cleanup and scanner inputs. Remove PATH-based Git resolution, repeated regex retries, excessive function complexity and awaits in loops without introducing concurrent bootstrap steps.

## Alternatives considered

Suppressions, exclusions, accepted findings, weaker tests and concurrent dependent bootstrap operations were rejected.

## Implementation decision

Git uses the Ubuntu system executable at `/usr/bin/git`. Fixed delimiters identify compilation counters before a backwards digit scan; project bindings use trimming and an anchored literal key followed by a delimiter. Helpers separate path containment, severity, signals, counters and locations. Git initialization, fetch and checkout remain explicit sequential operations. Independent timeout/overflow cases retain individual cleanup assertions; descendant polling uses a bounded timer helper.

## Changed files and tests

`.github/actions/sonar-private/main.cjs`, `tests/security_regression/sonar-private-diagnostics.test.cjs` and this paired record. A hostile PATH regression reads the actual repository through system Git and asserts that a shadow executable never runs. A subprocess deadline covers long digit runs, malformed and duplicate project bindings, overlong severity/parser tails and privacy canaries.

## Commands and results

Node 24 syntax checks passed for both JavaScript files. All 17 offline tests passed, with zero skips: the original 14 cases remain covered, timeout/overflow are separate cases, and two new regressions cover Git shadowing and adversarial parsing. The adversarial subprocess completed in approximately 121 ms within its 2500 ms hard deadline. Exact-file Secrets checks passed before reads and after source changes. No private canary appeared in output.

## Security impact

No token, environment, inventory, signature-verification, cumulative 128 MiB capture, process-group cleanup, scanner-version or analysis-scope control is weakened. Raw logs and child command files stay private. Unknown diagnostics remain explicit and `diagnosis_complete` remains false.

## Documentation and runtime evidence

This is an offline wrapper source qualification. It proves no connector runtime behavior or analyzer-gap closure. The action metadata remains unchanged with SHA-256 `2f8f446c1ec1fe765060fdadb54c854f29f474f4eb0091e2001e43d6e6474229`.

## Checks not run

Fresh hosted analysis, exact-head Cloud issue closure and Gate verification await separate publication. The new immutable wrapper commit SHA is unfrozen and pending; previous caller/frozen-SHA contracts must be updated separately after publication.

## Limitations and residual risk

Existing hosted Shell/JSON/CFamily diagnostics remain open. Offline tests do not certify Cloud issue closure. The fixed Git path targets the supported Ubuntu hosted action environment.

## Final diff and review status

Source changes are qualified locally for independent review; publication and overall integration readiness remain pending.
